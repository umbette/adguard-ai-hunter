import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.config import Settings
from src.dispatcher import Dispatcher, get_apex_domain

class MockAsyncContext:
    def __init__(self, response):
        self.response = response
    async def __aenter__(self):
        return self.response
    async def __aexit__(self, exc_type, exc, tb):
        pass

@pytest.mark.asyncio
async def test_read_modify_write_rule_injection(temp_storage):
    settings = Settings()
    dispatcher = Dispatcher(settings, temp_storage)

    existing_rules = ["||existing-tracker.com^", "127.0.0.1 custom.lan"]

    with patch.object(dispatcher, "get_session") as mock_get_session:
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        mock_get_resp = AsyncMock()
        mock_get_resp.status = 200
        mock_get_resp.json = AsyncMock(return_value={"user_rules": list(existing_rules)})
        mock_session.get.return_value = MockAsyncContext(mock_get_resp)

        mock_post_resp = AsyncMock()
        mock_post_resp.status = 200
        mock_session.post.return_value = MockAsyncContext(mock_post_resp)

        success = await dispatcher.inject_adguard_rule("||new-telemetry.com^$client=192.168.1.210")
        assert success

        call_args = mock_session.post.call_args
        posted_rules = call_args[1]["json"]["rules"]
        assert "||existing-tracker.com^" in posted_rules
        assert "127.0.0.1 custom.lan" in posted_rules
        assert "||new-telemetry.com^$client=192.168.1.210 # sentinel" in posted_rules
        assert len(posted_rules) == 3


def test_get_apex_domain_psl_awareness():
    # Multi-part ccTLDs and public suffixes must not be truncated to the suffix
    assert get_apex_domain("tracking.cdn.example.co.uk") == "example.co.uk"
    assert get_apex_domain("login.service.gov.it") == "service.gov.it"
    assert get_apex_domain("app.corp.com.br") == "corp.com.br"
    assert get_apex_domain("sub.bank.co.in") == "bank.co.in"
    assert get_apex_domain("simple.com") == "simple.com"
    assert get_apex_domain("deep.nested.sub.domain.org") == "domain.org"


@pytest.mark.asyncio
async def test_handle_mobile_action_ignora_prevents_cctld_wildcard(temp_storage):
    settings = Settings()
    dispatcher = Dispatcher(settings, temp_storage)

    with patch.object(dispatcher, "get_session") as mock_get_session:
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_session.post = AsyncMock(return_value=mock_resp)

        # Trigger 30-day snooze for a domain with a multi-part ccTLD
        await dispatcher._handle_notification_action("IGNORA::tracking.telemetry.samsung.co.uk::192.168.1.100")

        # Verify decision is stored for *.samsung.co.uk, NOT *.co.uk
        decision = temp_storage.match_decision("anything.samsung.co.uk", "192.168.1.100")
        assert decision is not None
        assert decision["action"] == "ALLOW"
        assert decision["domain_pattern"] == "*.samsung.co.uk"

        # Crucial security check: *.co.uk must NEVER match or be whitelisted!
        assert temp_storage.match_decision("evil-site.co.uk", "192.168.1.100") is None


@pytest.mark.asyncio
async def test_send_mobile_alert_enriched_device(temp_storage):
    settings = Settings()
    mock_resolver = MagicMock()
    from src.device_resolver import DeviceInfo
    mock_resolver.resolve = AsyncMock(return_value=DeviceInfo(
        ip="192.168.1.104",
        name="Samsung Smart TV",
        icon="📺",
        device_type="SMART_TV",
        display_name="📺 Samsung Smart TV (192.168.1.104)"
    ))

    dispatcher = Dispatcher(settings, temp_storage, device_resolver=mock_resolver)

    with patch.object(dispatcher, "get_session") as mock_get_session:
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_session.post.return_value = MockAsyncContext(mock_resp)

        notified = await dispatcher.send_mobile_alert(
            domain="samsung-telemetry.com",
            client_ip="192.168.1.104",
            classification="TELEMETRY",
            summary="Raffica telemetrica anomala",
            suggested_rule="||samsung-telemetry.com^$client=192.168.1.104"
        )

        assert notified
        # Verify first call was to notify service with enriched payload
        calls = mock_session.post.call_args_list
        assert len(calls) == 2 # mobile notify + persistent notification
        mobile_payload = calls[0][1]["json"]
        assert "📺 Samsung Smart TV (192.168.1.104)" in mobile_payload["message"]
        # Verify action title shows friendly name and icon
        actions = mobile_payload["data"]["actions"]
        assert actions[0]["title"] == "Blocca per 📺 Samsung Smart TV"
        assert actions[0]["action"] == "BLOCCA_DEVICE::samsung-telemetry.com::192.168.1.104"
