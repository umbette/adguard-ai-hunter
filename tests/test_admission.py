import pytest
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.test_utils import AioHTTPTestCase
from aiohttp import web
from src.config import Settings
from src.storage import StorageEngine
from src.device_resolver import DeviceResolver
from src.dispatcher import Dispatcher
from src.dashboard import SentinelDashboard

def test_storage_device_upsert_and_admission(temp_storage):
    # 1. Upsert new device with default PENDING
    is_new, dev = temp_storage.upsert_device(
        ip="192.168.1.199",
        mac="AA:BB:CC:DD:EE:FF",
        hostname="Smart Kettle",
        vendor="Tuya",
        category="SMART_APPLIANCE",
        icon="🍳",
        default_status="PENDING"
    )
    assert is_new is True
    assert dev["ip"] == "192.168.1.199"
    assert dev["approval_status"] == "PENDING"
    assert temp_storage.is_device_approved("192.168.1.199") is False

    # 2. Upsert same device again: should not be new, metadata preserved
    is_new2, dev2 = temp_storage.upsert_device(
        ip="192.168.1.199",
        hostname="Smart Kettle Updated"
    )
    assert is_new2 is False
    assert dev2["approval_status"] == "PENDING"

    # 3. Approve device
    assert temp_storage.set_device_status("192.168.1.199", "APPROVED", notes="Approved by user") is True
    assert temp_storage.is_device_approved("192.168.1.199") is True

    # 4. Filter by status
    pending_list = temp_storage.get_devices(status="PENDING")
    assert len(pending_list) == 0

    approved_list = temp_storage.get_devices(status="APPROVED")
    assert any(d["ip"] == "192.168.1.199" for d in approved_list)


@pytest.mark.asyncio
async def test_dispatcher_send_new_device_alert(temp_storage):
    settings = Settings()
    dispatcher = Dispatcher(settings, temp_storage)

    with patch.object(dispatcher, "get_session") as mock_get_session:
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_session.post.return_value.__aenter__.return_value = mock_resp

        sent = await dispatcher.send_new_device_alert(
            ip="192.168.1.220",
            name="Xiaomi Robot Vacuum",
            icon="🧹",
            category="VACUUM_ROBOT",
            quarantine=True
        )
        assert sent is True

        # Check call arguments to Home Assistant notify service
        call_args = mock_session.post.call_args_list[0]
        payload = call_args[1]["json"]
        assert "Xiaomi Robot Vacuum" in payload["title"]
        actions = payload["data"]["actions"]
        assert any(a["action"] == "APPROVA_DEVICE::192.168.1.220" for a in actions)
        assert any(a["action"] == "QUARANTENA_DEVICE::192.168.1.220" for a in actions)


@pytest.mark.asyncio
async def test_dispatcher_handle_admission_actions(temp_storage):
    settings = Settings()
    dispatcher = Dispatcher(settings, temp_storage)

    # Pre-register device as PENDING
    temp_storage.upsert_device(ip="192.168.1.140", hostname="Guest Phone", default_status="PENDING")
    assert temp_storage.is_device_approved("192.168.1.140") is False

    with patch.object(dispatcher, "inject_adguard_rule", new_callable=AsyncMock) as mock_inject, \
         patch.object(dispatcher, "get_session") as mock_get_session:
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_session.post.return_value.__aenter__.return_value = mock_resp

        # 1. Action: APPROVA_DEVICE
        await dispatcher._handle_notification_action("APPROVA_DEVICE::192.168.1.140")
        assert temp_storage.is_device_approved("192.168.1.140") is True

        # 2. Action: QUARANTENA_DEVICE
        await dispatcher._handle_notification_action("QUARANTENA_DEVICE::192.168.1.140")
        dev = temp_storage.get_device("192.168.1.140")
        assert dev["approval_status"] == "BLOCKED"
        mock_inject.assert_called_with("||*$client=192.168.1.140")


class TestAdmissionAndScanDashboardAPI(AioHTTPTestCase):
    async def get_application(self):
        settings = Settings()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db")
        self.temp_db = StorageEngine(self._tmp.name)
        resolver = DeviceResolver(settings)
        self.dashboard = SentinelDashboard(settings, self.temp_db, resolver)

        # Pre-populate one device
        self.temp_db.upsert_device(
            ip="192.168.1.155",
            hostname="Philips Hue Bridge",
            category="IOT",
            icon="💡",
            default_status="PENDING"
        )
        return self.dashboard.app

    async def test_api_devices_and_approval(self):
        # 1. Fetch devices
        resp = await self.client.get("/api/devices")
        assert resp.status == 200
        data = await resp.json()
        assert "devices" in data
        assert any(d["ip"] == "192.168.1.155" and d["approval_status"] == "PENDING" for d in data["devices"])

        # 2. Approve device
        resp_app = await self.client.post("/api/devices/approve", json={"ip": "192.168.1.155"})
        assert resp_app.status == 200
        data_app = await resp_app.json()
        assert data_app["status"] == "success"
        assert data_app["approval_status"] == "APPROVED"

        # Verify in storage
        assert self.temp_db.is_device_approved("192.168.1.155") is True

        # 3. Block / Quarantine device
        resp_blk = await self.client.post("/api/devices/block", json={"ip": "192.168.1.155"})
        assert resp_blk.status == 200
        data_blk = await resp_blk.json()
        assert data_blk["status"] == "success"
        assert data_blk["approval_status"] == "BLOCKED"

    async def test_api_scan_and_latest(self):
        # Trigger on-demand scan via API
        resp = await self.client.post("/api/scan")
        assert resp.status == 200
        data = await resp.json()
        assert "health_score" in data
        assert "devices_audit" in data
        assert "vulnerabilities_audit" in data
        assert "threats_audit" in data
        assert "dns_audit" in data

        # Fetch latest scan
        resp_latest = await self.client.get("/api/scan/latest")
        assert resp_latest.status == 200
        latest_data = await resp_latest.json()
        assert latest_data["health_score"] == data["health_score"]
