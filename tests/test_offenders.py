import pytest
import tempfile
from aiohttp.test_utils import AioHTTPTestCase
from aiohttp import web
from src.config import Settings
from src.storage import StorageEngine
from src.device_resolver import DeviceResolver
from src.dashboard import SentinelDashboard
from src.offenders import OffendersAnalyticsEngine

def test_identify_domain_heuristics():
    engine = OffendersAnalyticsEngine()
    
    # Samsung TV
    samsung_res = engine.identify_domain("samsungqbe.com")
    assert samsung_res["brand"] == "Samsung"
    assert samsung_res["category"] == "SMART_TV"
    assert samsung_res["country_code"] == "KR"

    # Ecovacs vacuum
    ecovacs_res = engine.identify_domain("sa-eu-datasink.ecouser.net")
    assert ecovacs_res["brand"] == "Ecovacs"
    assert ecovacs_res["category"] == "VACUUM_ROBOT"
    assert ecovacs_res["country_code"] == "CN"

    # Criteo dynamic pricing
    criteo_res = engine.identify_domain("static.criteo.com")
    assert criteo_res["brand"] == "Criteo"
    assert criteo_res["category"] == "DYNAMIC_PRICING"
    assert criteo_res["country_code"] == "FR"

    # LexisNexis automotive
    lexis_res = engine.identify_domain("telemetry.lexisnexis.com")
    assert lexis_res["brand"] == "LexisNexis Risk Solutions"
    assert lexis_res["category"] == "CONNECTED_CAR"
    assert lexis_res["country_code"] == "US"


def test_compute_offenders_overview_4_vectors():
    engine = OffendersAnalyticsEngine()
    
    top_blocked = [
        {"domain": "samsungqbe.com", "count": 1000},
        {"domain": "sa-eu-datasink.ecouser.net", "count": 500},
        {"domain": "static.criteo.com", "count": 500},
    ]
    
    overview = engine.compute_offenders_overview(top_blocked)
    assert overview["total_offenses"] == 2000
    
    # 1. By brand
    assert len(overview["by_brand"]) >= 3
    assert overview["by_brand"][0]["brand"] == "Samsung"
    assert overview["by_brand"][0]["count"] == 1000
    assert overview["by_brand"][0]["percentage"] == 50.0

    # 2. By category
    cats = {c["category_id"]: c["count"] for c in overview["by_category"]}
    assert cats["SMART_TV"] == 1000
    assert cats["VACUUM_ROBOT"] == 500
    assert cats["DYNAMIC_PRICING"] == 500

    # 3. By geography
    geos = {g["country_code"]: g["count"] for g in overview["by_geography"]}
    assert geos["KR"] == 1000
    assert geos["CN"] == 500
    assert geos["FR"] == 500

    # 4. Summary statement
    assert "Samsung" in overview["summary"]
    assert "Corea del Sud" in overview["summary"]


class TestOffendersDashboardAPI(AioHTTPTestCase):
    async def get_application(self):
        settings = Settings()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db")
        storage = StorageEngine(self._tmp.name)
        resolver = DeviceResolver(settings)
        self.dashboard = SentinelDashboard(settings, storage, resolver)
        return self.dashboard.app

    async def test_api_offenders_endpoint(self):
        # 1. Cold empty stats remain honest (0 offenses, no fabricated devices/brands)
        resp = await self.client.get("/api/offenders")
        assert resp.status == 200
        data = await resp.json()
        assert data["total_offenses"] == 0
        assert data["by_brand"] == []
        assert data["by_device"] == []

        # 2. Live blocked domains compute 4-vector analytics without fake device injection
        from unittest.mock import AsyncMock
        self.dashboard._fetch_adguard_stats = AsyncMock(return_value={
            "num_dns_queries": 500,
            "num_blocked_filtering": 25,
            "top_blocked_domains": [{"domain": "samsungqbe.com", "count": 25}]
        })
        resp2 = await self.client.get("/api/offenders")
        assert resp2.status == 200
        data2 = await resp2.json()
        assert data2["total_offenses"] == 25
        assert data2["by_brand"][0]["brand"] == "Samsung"
        assert data2["by_device"] == []
