import os
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
import yaml

class AdGuardConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    username: str = ""
    password: str = ""
    poll_interval_sec: int = 15
    batch_limit: int = 200

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

class HomeAssistantConfig(BaseModel):
    base_url: str = "http://127.0.0.1:8123"
    ws_url: str = "ws://127.0.0.1:8123/api/websocket"
    token: str = ""
    notify_service: str = "notify"

class GeminiConfig(BaseModel):
    api_key: str = ""
    model: str = "gemini-2.0-flash"
    timeout_sec: float = 5.0

class HeuristicsConfig(BaseModel):
    entropy_threshold: float = 3.85
    rate_burst_threshold: int = 30
    rate_window_sec: int = 60
    cleanup_interval_sec: int = 600

class StorageConfig(BaseModel):
    db_path: str = "/app/data/hunter_decisions.db"

class Settings(BaseSettings):
    adguard: AdGuardConfig = Field(default_factory=AdGuardConfig)
    home_assistant: HomeAssistantConfig = Field(default_factory=HomeAssistantConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    heuristics: HeuristicsConfig = Field(default_factory=HeuristicsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    @classmethod
    def load(cls, config_path: str = "/app/config.yaml") -> "Settings":
        data = {}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        # Merge environment variables
        adguard_data = data.get("adguard", {})
        adguard_data["username"] = os.getenv("ADGUARD_USERNAME", adguard_data.get("username", ""))
        adguard_data["password"] = os.getenv("ADGUARD_PASSWORD", adguard_data.get("password", ""))
        data["adguard"] = adguard_data

        # Check Home Assistant Supervisor Add-on options (/data/options.json)
        options_path = os.getenv("OPTIONS_PATH", "/data/options.json")
        if os.path.exists(options_path):
            try:
                import json
                from urllib.parse import urlparse
                with open(options_path, "r", encoding="utf-8") as f:
                    ha_options = json.load(f)

                if "adguard_url" in ha_options:
                    parsed = urlparse(ha_options["adguard_url"])
                    data.setdefault("adguard", {})["host"] = parsed.hostname or "127.0.0.1"
                    data.setdefault("adguard", {})["port"] = parsed.port or (443 if parsed.scheme == "https" else 80)
                if "adguard_username" in ha_options:
                    data.setdefault("adguard", {})["username"] = ha_options["adguard_username"]
                if "adguard_password" in ha_options:
                    data.setdefault("adguard", {})["password"] = ha_options["adguard_password"]
                if "gemini_api_key" in ha_options:
                    data.setdefault("gemini", {})["api_key"] = ha_options["gemini_api_key"]
                if "entropy_threshold" in ha_options:
                    data.setdefault("heuristics", {})["entropy_threshold"] = float(ha_options["entropy_threshold"])
                if "rate_burst_threshold" in ha_options:
                    data.setdefault("heuristics", {})["rate_burst_threshold"] = int(ha_options["rate_burst_threshold"])
                if "rate_window_sec" in ha_options:
                    data.setdefault("heuristics", {})["rate_window_sec"] = int(ha_options["rate_window_sec"])
                if "notify_service" in ha_options:
                    svc = ha_options["notify_service"]
                    if svc.startswith("notify."):
                        svc = svc.replace("notify.", "")
                    data.setdefault("home_assistant", {})["notify_service"] = svc
            except Exception:
                pass

        # Check Home Assistant Supervisor Token (auto-authentication in HA OS Add-on)
        supervisor_token = os.getenv("SUPERVISOR_TOKEN")
        if supervisor_token:
            data.setdefault("home_assistant", {})["token"] = supervisor_token
            data.setdefault("home_assistant", {})["base_url"] = "http://supervisor/core"
            data.setdefault("home_assistant", {})["ws_url"] = "ws://supervisor/core/websocket"

        ha_data = data.get("home_assistant", {})
        ha_data["token"] = os.getenv("HASS_TOKEN", ha_data.get("token", ""))
        ha_data["notify_service"] = os.getenv("HASS_NOTIFY_SERVICE", ha_data.get("notify_service", "notify"))
        data["home_assistant"] = ha_data

        gemini_data = data.get("gemini", {})
        gemini_data["api_key"] = os.getenv("GEMINI_API_KEY", gemini_data.get("api_key", ""))
        data["gemini"] = gemini_data

        storage_data = data.get("storage", {})
        data_dir = os.getenv("DATA_DIR")
        if data_dir:
            storage_data["db_path"] = os.path.join(data_dir, "hunter_decisions.db")
        data["storage"] = storage_data

        return cls(**data)
