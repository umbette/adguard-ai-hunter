import pytest
import time
from aiohttp import web
from src.crypto_shield import (
    evaluate_crypto_financial_threat,
    activate_sterile_chamber,
    deactivate_sterile_chamber,
    get_sterile_chamber_status,
    is_client_in_sterile_chamber,
    evaluate_sterile_chamber_domain,
    sterile_chamber_manager,
    DEFAULT_ESSENTIAL_TRANSACTION_INFRASTRUCTURE,
    reset_to_defaults
)
from src.dashboard import SentinelDashboard
from src.config import Settings
from src.storage import StorageEngine
import tempfile
import os

def test_essential_transaction_infrastructure_never_blocked():
    reset_to_defaults()
    # 1. Apple APNs push channels must be completely unhindered
    assert evaluate_crypto_financial_threat("courier.push.apple.com") is None
    assert evaluate_crypto_financial_threat("push.apple.com") is None
    assert evaluate_crypto_financial_threat("17.courier.push.apple.com") is None

    # 2. Google FCM Android push channels
    assert evaluate_crypto_financial_threat("fcm.googleapis.com") is None
    assert evaluate_crypto_financial_threat("mtalk.google.com") is None

    # 3. WebAuthn caBLE cross-device hybrid rendezvous
    assert evaluate_crypto_financial_threat("cable.auth.com") is None

    # 4. WalletConnect v2 relays
    assert evaluate_crypto_financial_threat("relay.walletconnect.com") is None
    assert evaluate_crypto_financial_threat("relay.walletconnect.org") is None

    # 5. MEV & Private Mempools
    assert evaluate_crypto_financial_threat("rpc.flashbots.net") is None

def test_sterile_chamber_lifecycle():
    client_ip = "192.168.1.188"
    deactivate_sterile_chamber(client_ip)
    assert not is_client_in_sterile_chamber(client_ip)

    # 1. Activate sterile chamber for 10 minutes
    session = activate_sterile_chamber(client_ip, duration_minutes=10, reason="Tangem Card Activation")
    assert session["client_ip"] == client_ip
    assert session["status"] == "ACTIVE"
    assert is_client_in_sterile_chamber(client_ip)

    # 2. Check status output
    status = get_sterile_chamber_status(client_ip)
    assert status["is_active"] is True
    assert status["session"]["reason"] == "Tangem Card Activation"

    # 3. Deactivate
    deactivated = deactivate_sterile_chamber(client_ip)
    assert deactivated is True
    assert not is_client_in_sterile_chamber(client_ip)

    # Deactivating non-active returns False
    assert deactivate_sterile_chamber(client_ip) is False

def test_sterile_chamber_domain_filtering():
    client_ip = "192.168.1.205"
    activate_sterile_chamber(client_ip, duration_minutes=15, reason="Cold Seed Backup")

    try:
        # A. Allowed in Sterile Chamber:
        # 1. Local LAN & localhost
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "gateway.local")
        assert ok is True
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "localhost")
        assert ok is True

        # 2. Essential 2FA push & WalletConnect
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "courier.push.apple.com")
        assert ok is True
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "fcm.googleapis.com")
        assert ok is True
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "relay.walletconnect.com")
        assert ok is True

        # 3. Official RPC endpoints
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "mainnet.infura.io")
        assert ok is True
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "eth.llamarpc.com")
        assert ok is True

        # 4. Verified brand official domains
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "metamask.io")
        assert ok is True
        ok, _ = evaluate_sterile_chamber_domain(client_ip, "uniswap.org")
        assert ok is True

        # B. BLOCKED in Sterile Chamber:
        # 1. Advertising / Tracking networks
        ok_track, reason = evaluate_sterile_chamber_domain(client_ip, "criteo.com")
        assert ok_track is False
        assert "BLOCKED_BY_STERILE_CHAMBER" in reason

        # 2. Social media & non-essential web
        ok_social, _ = evaluate_sterile_chamber_domain(client_ip, "tiktok.com")
        assert ok_social is False

        # 3. Third-party unapproved portals
        ok_random, _ = evaluate_sterile_chamber_domain(client_ip, "unknown-drainer-target.xyz")
        assert ok_random is False

    finally:
        deactivate_sterile_chamber(client_ip)

    # When inactive, evaluate_domain returns True
    ok_inactive, _ = evaluate_sterile_chamber_domain(client_ip, "criteo.com")
    assert ok_inactive is True

from aiohttp.test_utils import AioHTTPTestCase
from unittest.mock import MagicMock

class TestDashboardSterileRoom(AioHTTPTestCase):
    async def get_application(self):
        settings = Settings()
        storage = MagicMock()
        resolver = MagicMock()
        self.dashboard = SentinelDashboard(settings=settings, storage=storage, resolver=resolver)
        return self.dashboard.app

    async def test_dashboard_sterile_room_api(self):
        test_ip = "192.168.1.99"
        deactivate_sterile_chamber(test_ip)

        try:
            # 1. Activate via API
            resp = await self.client.post("/api/sterile-room/activate", json={
                "ip": test_ip,
                "duration": 20,
                "reason": "Tangem Physical Tap"
            })
            assert resp.status == 200
            data = await resp.json()
            assert data["status"] == "success"
            assert data["session"]["client_ip"] == test_ip
            assert data["session"]["reason"] == "Tangem Physical Tap"

            # 2. Get status via API
            status_resp = await self.client.get(f"/api/sterile-room/status?ip={test_ip}")
            assert status_resp.status == 200
            status_data = await status_resp.json()
            assert status_data["status"] == "success"
            assert status_data["is_active"] is True

            # 3. Deactivate via API
            deact_resp = await self.client.post("/api/sterile-room/deactivate", json={"ip": test_ip})
            assert deact_resp.status == 200
            deact_data = await deact_resp.json()
            assert deact_data["status"] == "success"
            assert deact_data["is_active"] is False

            # 4. Check status again
            status_resp2 = await self.client.get(f"/api/sterile-room/status?ip={test_ip}")
            status_data2 = await status_resp2.json()
            assert status_data2["is_active"] is False
        finally:
            deactivate_sterile_chamber(test_ip)


@pytest.mark.asyncio
async def test_ingestion_enforces_active_sterile_chamber(tmp_path):
    """IngestionWorker must actively block and dispatch AdGuard rules for unauthorized queries during Stanza Sterile."""
    from unittest.mock import AsyncMock, MagicMock
    from src.ingestion import IngestionWorker
    from src.heuristics import HeuristicsEngine
    from src.gemini_client import GeminiClassifier
    from src.dispatcher import Dispatcher

    settings = Settings()
    storage = StorageEngine(str(tmp_path / "sterile.db"))
    heuristics = HeuristicsEngine()
    gemini = GeminiClassifier(settings.gemini.api_key)
    dispatcher = Dispatcher(settings, storage)
    dispatcher.inject_adguard_rule = AsyncMock(return_value=True)
    dispatcher.send_mobile_alert = AsyncMock(return_value=True)

    worker = IngestionWorker(settings, storage, heuristics, gemini, dispatcher)
    client_ip = "192.168.1.212"
    storage.upsert_device(ip=client_ip, hostname="Vault Device", default_status="APPROVED")
    activate_sterile_chamber(client_ip, duration_minutes=10, reason="Vault Session")
    try:
        await worker._process_entries(
            [
                {"question": {"name": "criteo.com"}, "client": client_ip, "time": "2026-11-24T20:00:00Z", "reason": "NotFilteredNotFound"},
                {"question": {"name": "metamask.io"}, "client": client_ip, "time": "2026-11-24T20:00:01Z", "reason": "NotFilteredNotFound"},
            ]
        )
        dispatcher.inject_adguard_rule.assert_awaited_once_with(f"||criteo.com^$client={client_ip}")
        dispatcher.send_mobile_alert.assert_awaited_once()
        assert dispatcher.send_mobile_alert.call_args.kwargs["classification"] == "STERILE_CHAMBER_BLOCK"
    finally:
        deactivate_sterile_chamber(client_ip)
