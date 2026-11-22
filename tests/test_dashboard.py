import pytest
from aiohttp.test_utils import AioHTTPTestCase
from aiohttp import web
from unittest.mock import AsyncMock, MagicMock
from src.config import Settings
from src.storage import StorageEngine
from src.device_resolver import DeviceResolver
from src.dashboard import SentinelDashboard, ACTIVE_SHIELDS_LIST
from src.device_shield import is_essential_companion_domain

class TestSentinelDashboard(AioHTTPTestCase):
    async def get_application(self):
        settings = Settings()
        storage = MagicMock()
        resolver = MagicMock()
        self.dashboard = SentinelDashboard(settings, storage, resolver)
        
        # Mock _fetch_adguard_stats so unit test doesn't depend on network
        self.dashboard._fetch_adguard_stats = AsyncMock(return_value={
            "num_dns_queries": 36000,
            "num_blocked_filtering": 10000,
            "top_blocked_domains": [
                {"domain": "api.ad.intl.xiaomi.com", "count": 1500},
                {"domain": "criteo.com", "count": 300}
            ]
        })
        return self.dashboard.app

    async def test_dashboard_html_render(self):
        resp = await self.client.get("/")
        assert resp.status == 200
        text = await resp.text()
        assert "Sentinel Core" in text
        assert "Minacce &amp; Tracker Bloccati" in text or "Minacce & Tracker Bloccati" in text
        assert "Matrice degli Scudi Attivi" in text
        assert "Risparmio Stima Dynamic Pricing" in text
        assert "Risoluzione Rapida Companion App" in text
        assert "Zero-Knowledge" in text

    async def test_dashboard_api_stats(self):
        resp = await self.client.get("/api/stats")
        assert resp.status == 200
        data = await resp.json()
        assert data["dns_queries"] == 36000
        assert data["blocked_queries"] == 10000
        assert data["blocked_percentage"] == 27.8
        assert data["shields_total"] == 14
        assert data["shields_active"] == 14
        assert len(data["shields"]) == 14
        assert len(data["top_blocked"]) == 2
        assert data["top_blocked"][0]["domain"] == "api.ad.intl.xiaomi.com"
        assert data["estimated_savings_eur"] > 0
        assert data["system_status"] == "MASSIMA PROTEZIONE ATTIVA"

    async def test_dashboard_api_blocked_queries(self):
        resp = await self.client.get("/api/blocked_queries")
        assert resp.status == 200
        data = await resp.json()
        assert "blocked_domains" in data
        assert len(data["blocked_domains"]) == 2
        assert data["blocked_domains"][0]["domain"] == "api.ad.intl.xiaomi.com"

    async def test_dashboard_api_unbreak(self):
        target_domain = "unbreak-test.ecouser.net"
        assert is_essential_companion_domain(target_domain) is False

        resp = await self.client.post("/api/unbreak", json={"domain": target_domain})
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "success"
        assert data["domain"] == target_domain
        assert data["rule"] == f"@@||{target_domain}^"

        # Check in-memory allowlist updated
        assert is_essential_companion_domain(target_domain) is True

    async def test_dashboard_api_unbreak_invalid_domain(self):
        resp = await self.client.post("/api/unbreak", json={"domain": "invalid..domain!!"})
        assert resp.status == 400
        data = await resp.json()
        assert data["status"] == "error"

    async def test_dashboard_api_report_unbreak(self):
        resp = await self.client.post("/api/report_unbreak", json={
            "domain": "api-app.test-vacuum.com",
            "device_name": "Test Vacuum Cleaner",
            "device_category": "Robot Aspirapolvere",
            "notes": "L'app compagna dava errore di connessione."
        })
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "success"
        assert data["domain"] == "api-app.test-vacuum.com"
        assert "Test Vacuum Cleaner" in data["issue_title"]
        assert "https://github.com/umbette/sentinel/issues/new" in data["github_issue_url"]
        assert "Zero-Knowledge" in data["issue_body"]

    async def test_dashboard_api_report_unbreak_invalid(self):
        resp = await self.client.post("/api/report_unbreak", json={"domain": ""})
        assert resp.status == 400
