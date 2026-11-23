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


def test_empty_env_vars_do_not_clobber_supervisor_token(tmp_path, monkeypatch):
    monkeypatch.setenv("SUPERVISOR_TOKEN", "valid_supervisor_token_xyz")
    # Simulate empty env var defined in a container or .env template
    monkeypatch.setenv("HASS_TOKEN", "")
    monkeypatch.setenv("ADGUARD_USERNAME", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    # Config has adguard user
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("adguard:\n  username: existing_user\n", encoding="utf-8")

    settings = Settings.load(config_path=str(cfg_file))

    # Empty HASS_TOKEN must not clobber SUPERVISOR_TOKEN
    assert settings.home_assistant.token == "valid_supervisor_token_xyz"
    # Empty ADGUARD_USERNAME must not clobber existing_user
    assert settings.adguard.username == "existing_user"


def test_adguard_credentials_loaded_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ADGUARD_USERNAME", "custom_adguard_admin")
    monkeypatch.setenv("ADGUARD_PASSWORD", "custom_adguard_pw_456")

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("adguard:\n  host: 127.0.0.1\n  port: 8080\n", encoding="utf-8")

    settings = Settings.load(config_path=str(cfg_file))
    assert settings.adguard.username == "custom_adguard_admin"
    assert settings.adguard.password == "custom_adguard_pw_456"

