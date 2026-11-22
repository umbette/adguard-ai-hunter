import pytest
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp import web
from unittest.mock import AsyncMock, MagicMock
from src.config import Settings
from src.storage import StorageEngine
from src.device_resolver import DeviceResolver
from src.dashboard import SentinelDashboard, ACTIVE_SHIELDS_LIST

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
