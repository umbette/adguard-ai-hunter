import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.config import Settings
from src.dispatcher import Dispatcher

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
        assert "||new-telemetry.com^$client=192.168.1.210 # ai-hunter" in posted_rules
        assert len(posted_rules) == 3
