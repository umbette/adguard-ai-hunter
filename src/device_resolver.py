import asyncio
import base64
import logging
import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
import aiohttp
from src.config import Settings

logger = logging.getLogger("ai_hunter.device_resolver")

DEVICE_KEYWORDS = [
    # TVs & Streaming
    (["tv", "samsung", "tizen", "lg", "webos", "sony", "bravia", "appletv", "apple-tv", "chromecast", "firetv", "roku", "shield"], "📺", "SMART_TV"),
    # Mobile & Tablets
    (["iphone", "ipad", "android", "galaxy", "pixel", "xiaomi", "redmi", "oppo", "huawei", "oneplus", "phone"], "📱", "MOBILE"),
    # Gaming Consoles (Nintendo Switch, PS5, Xbox, Steam Deck)
    (["switch", "nintendo", "playstation", "ps5", "ps4", "ps3", "xbox", "steamdeck", "steam-deck"], "🎮", "GAMING_CONSOLE"),
    # Robot Vacuums (Roborock, Dreame, Ecovacs, Roomba)
    (["roborock", "dreame", "ecovacs", "deebot", "roomba", "irobot", "mova", "valetudo", "vacuum"], "🧹", "VACUUM_ROBOT"),
    # Smart Home & IoT
    (["camera", "cam", "reolink", "ring", "nest", "tuya", "shelly", "sonoff", "tasmota", "hue", "philips", "echo", "alexa", "homepod", "esp32", "esp8266"], "💡", "IOT"),
    # Computers & Laptops
    (["macbook", "imac", "mac", "pc", "laptop", "desktop", "thinkpad", "dell", "windows", "linux", "workstation"], "💻", "COMPUTER"),
    # 3D Printers & Maker Lab (Bambu Lab, Prusa, Voron, Klipper)
    (["bambu", "bambulab", "x1c", "p1s", "p1p", "a1-mini", "prusa", "creality", "ender", "voron", "klipper", "octoprint", "elegoo"], "🖨️", "3D_PRINTER"),
    # Standard Paper Printers
    (["printer", "epson", "hp", "canon", "brother"], "🖨️", "PRINTER"),
]

@dataclass
class DeviceInfo:
    ip: str
    name: str
    icon: str
    device_type: str
    display_name: str

class DeviceResolver:
    """
    Enriches raw client IP addresses with friendly device names and contextual icons.
    1. Queries AdGuard Home /control/clients (configured clients + DHCP auto-clients).
    2. Falls back to reverse DNS PTR lookup if unlabelled.
    3. Categorizes devices (Smart TV, Mobile, IoT, Computer) to render rich push notifications.
    """
    def __init__(self, settings: Settings, ttl_sec: int = 1800):
        self.settings = settings
        self.ttl_sec = ttl_sec
        # Cache: ip -> (DeviceInfo, timestamp)
        self._cache: Dict[str, Tuple[DeviceInfo, float]] = {}
        self._last_adguard_fetch = 0.0
        self._adguard_clients: Dict[str, str] = {} # ip -> client name

    def categorize_device(self, name_or_hostname: str) -> Tuple[str, str]:
        """Categorizes a device based on its name and returns (icon, device_type)."""
        lower = name_or_hostname.lower()
        for keywords, icon, dev_type in DEVICE_KEYWORDS:
            if any(kw in lower for kw in keywords):
                return icon, dev_type
        return "🔌", "DEVICE"

    async def _fetch_adguard_clients(self, session: aiohttp.ClientSession):
        """Fetches clients and auto_clients from AdGuard Home REST API."""
        now = time.time()
        if (now - self._last_adguard_fetch) < self.ttl_sec and self._adguard_clients:
            return

        base_url = self.settings.adguard.base_url
        creds = f"{self.settings.adguard.username}:{self.settings.adguard.password}".encode("utf-8")
        auth_header = f"Basic {base64.b64encode(creds).decode('ascii')}"
        headers = {"Authorization": auth_header}

        try:
            url = f"{base_url}/control/clients"
            async with session.get(url, headers=headers, timeout=5.0) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    mapping = {}

                    # 1. Configured static clients
                    for client in data.get("clients", []):
                        name = client.get("name", "").strip()
                        for cid in client.get("ids", []):
                            if name and cid:
                                mapping[cid.strip()] = name

                    # 2. Auto-discovered DHCP clients
                    for auto_client in data.get("auto_clients", []):
                        name = auto_client.get("name", "").strip()
                        ip = auto_client.get("ip", "").strip()
                        if name and ip and ip not in mapping:
                            mapping[ip] = name

                    self._adguard_clients = mapping
                    self._last_adguard_fetch = now
                    logger.info(f"Loaded {len(self._adguard_clients)} client device labels from AdGuard Home.")
                else:
                    logger.warning(f"AdGuard /control/clients returned HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"Failed to query AdGuard Home clients: {e}")

    async def _reverse_ptr_lookup(self, ip: str) -> Optional[str]:
        """Performs non-blocking reverse DNS PTR lookup on local network with 1.5s timeout."""
        loop = asyncio.get_running_loop()
        try:
            name, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getnameinfo, (ip, 0), 0),
                timeout=1.5
            )
            if name and name != ip:
                return name
        except Exception:
            pass
        return None

    async def resolve(self, client_ip: str, session: Optional[aiohttp.ClientSession] = None) -> DeviceInfo:
        """
        Resolves a client IP into a DeviceInfo object with icon, friendly name, and display text.
        """
        now = time.time()
        if client_ip in self._cache:
            device, cached_at = self._cache[client_ip]
            if (now - cached_at) < self.ttl_sec:
                return device

        # Fetch AdGuard clients mapping if session provided
        if session:
            await self._fetch_adguard_clients(session)

        # 1. Look in AdGuard Home clients
        friendly_name = self._adguard_clients.get(client_ip)

        # 2. If not found, try reverse PTR lookup
        if not friendly_name:
            friendly_name = await self._reverse_ptr_lookup(client_ip)

        # 3. Fallback to IP if still unnamed
        if not friendly_name or friendly_name.strip() == "":
            name = client_ip
            icon = "🔌"
            dev_type = "DEVICE"
            display = f"{icon} Dispositivo ({client_ip})"
        else:
            name = friendly_name.strip()
            icon, dev_type = self.categorize_device(name)
            display = f"{icon} {name} ({client_ip})"

        device = DeviceInfo(
            ip=client_ip,
            name=name,
            icon=icon,
            device_type=dev_type,
            display_name=display
        )

        self._cache[client_ip] = (device, now)
        return device
