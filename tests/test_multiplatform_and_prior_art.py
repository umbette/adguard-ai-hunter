import plistlib
from pathlib import Path
from unittest.mock import MagicMock

from aiohttp.test_utils import AioHTTPTestCase

from scripts.generate_ios_dns_profile import build_mobileconfig_bytes
from src.config import Settings
from src.dashboard import SentinelDashboard


def test_ios_mobileconfig_doh_and_dot():
    doh_xml = build_mobileconfig_bytes(
        doh_url="https://dns.example.ts.net/dns-query",
        server_addresses=["100.64.0.10"],
    )
    parsed = plistlib.loads(doh_xml)
    assert parsed["PayloadType"] == "Configuration"
    dns_settings = parsed["PayloadContent"][0]["DNSSettings"]
    assert dns_settings["DNSProtocol"] == "HTTPS"
    assert dns_settings["ServerURL"] == "https://dns.example.ts.net/dns-query"
    assert dns_settings["ServerAddresses"] == ["100.64.0.10"]

    dot_xml = build_mobileconfig_bytes(dot_hostname="dot.home.internal")
    parsed_dot = plistlib.loads(dot_xml)
    assert parsed_dot["PayloadContent"][0]["DNSSettings"]["DNSProtocol"] == "TLS"
    assert parsed_dot["PayloadContent"][0]["DNSSettings"]["ServerName"] == "dot.home.internal"


def test_hybrid_open_core_licenses_and_prior_art_present():
    root = Path(__file__).resolve().parent.parent
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in (root / "LICENSE").read_text(encoding="utf-8")
    assert "PolyForm Noncommercial License" in (root / "LICENSE-COMMERCIAL-HARDWARE").read_text(encoding="utf-8")
    assert "PolyForm Noncommercial License" in (root / "hardware" / "LICENSE").read_text(encoding="utf-8")
    assert "SNT-PRIOR-ART-2026-01" in (root / "docs" / "PRIOR_ART.md").read_text(encoding="utf-8")


class TestDashboardPWAEndpoints(AioHTTPTestCase):
    async def get_application(self):
        dash = SentinelDashboard(Settings(), MagicMock(), MagicMock())
        return dash.app

    async def test_pwa_manifest_and_sw_served(self):
        r_index = await self.client.get("/")
        assert r_index.status == 200
        html = await r_index.text()
        assert 'rel="manifest"' in html

        r_manifest = await self.client.get("/manifest.json")
        assert r_manifest.status == 200
        data = await r_manifest.json()
        assert data["display"] == "standalone"
        assert data["short_name"] == "Sentinel"

        r_sw = await self.client.get("/sw.js")
        assert r_sw.status == 200
        assert "addEventListener" in await r_sw.text()
