import json
import pytest
from src.config import Settings

def test_config_ha_options_and_supervisor_token(tmp_path, monkeypatch):
    options_file = tmp_path / "options.json"
    options_data = {
        "adguard_url": "http://core-adguard:80",
        "adguard_username": "addon_admin",
        "adguard_password": "super_secret_pw",
        "gemini_api_key": "test_gemini_key_123",
        "entropy_threshold": 3.90,
        "rate_burst_threshold": 25,
        "rate_window_sec": 45,
        "notify_service": "notify.mobile_app_pixel_8"
    }
    options_file.write_text(json.dumps(options_data), encoding="utf-8")

    monkeypatch.setenv("OPTIONS_PATH", str(options_file))
    monkeypatch.setenv("SUPERVISOR_TOKEN", "mock_supervisor_token_abc")

    settings = Settings.load(config_path=str(tmp_path / "non_existent.yaml"))

    # Verify AdGuard settings loaded from HA Add-on options
    assert settings.adguard.host == "core-adguard"
    assert settings.adguard.port == 80
    assert settings.adguard.username == "addon_admin"
    assert settings.adguard.password == "super_secret_pw"
    assert settings.adguard.base_url == "http://core-adguard:80"

    # Verify Gemini & Heuristics
    assert settings.gemini.api_key == "test_gemini_key_123"
    assert settings.heuristics.entropy_threshold == 3.90
    assert settings.heuristics.rate_burst_threshold == 25
    assert settings.heuristics.rate_window_sec == 45

    # Verify Home Assistant auto-configured via Supervisor token
    assert settings.home_assistant.token == "mock_supervisor_token_abc"
    assert settings.home_assistant.base_url == "http://supervisor/core"
    assert settings.home_assistant.ws_url == "ws://supervisor/core/websocket"
    assert settings.home_assistant.notify_service == "mobile_app_pixel_8"
