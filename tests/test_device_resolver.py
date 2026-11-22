import pytest
from unittest.mock import AsyncMock, MagicMock
from src.config import Settings
from src.device_resolver import DeviceResolver, DeviceInfo

class MockAsyncContext:
    def __init__(self, response):
        self.response = response
    async def __aenter__(self):
        return self.response
    async def __aexit__(self, exc_type, exc, tb):
        pass

def test_categorize_device():
    resolver = DeviceResolver(Settings())

    assert resolver.categorize_device("Samsung Smart TV 65") == ("📺", "SMART_TV")
    assert resolver.categorize_device("LG webOS TV") == ("📺", "SMART_TV")
    assert resolver.categorize_device("Apple-TV-Salotto") == ("📺", "SMART_TV")
    assert resolver.categorize_device("iPhone di Mario") == ("📱", "MOBILE")
    assert resolver.categorize_device("Galaxy-S24-Ultra") == ("📱", "MOBILE")
    assert resolver.categorize_device("Reolink-Front-Camera") == ("💡", "IOT")
    assert resolver.categorize_device("Shelly-Plug-Cucina") == ("💡", "IOT")
    assert resolver.categorize_device("MacBook-Pro-M2") == ("💻", "COMPUTER")
    assert resolver.categorize_device("HP-LaserJet-Pro") == ("🖨️", "PRINTER")
    assert resolver.categorize_device("Unknown-Generic") == ("🔌", "DEVICE")

@pytest.mark.asyncio
async def test_resolve_with_adguard_clients(monkeypatch):
    settings = Settings()
    resolver = DeviceResolver(settings)
    # Mock reverse PTR to isolate unit test from external AWS/LAN DNS environments
    monkeypatch.setattr(resolver, "_reverse_ptr_lookup", AsyncMock(return_value=None))

    mock_session = MagicMock()
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={
        "clients": [
            {
                "name": "Samsung Smart TV",
                "ids": ["192.168.1.104", "00:11:22:33:44:55"],
                "tags": ["user_device"]
            },
            {
                "name": "Reolink Cam Garage",
                "ids": ["192.168.1.120"],
                "tags": ["camera"]
            }
        ],
        "auto_clients": [
            {
                "name": "Galaxy-S23-Android",
                "ip": "192.168.1.155"
            }
        ]
    })
    mock_session.get.return_value = MockAsyncContext(mock_resp)

    # 1. Configured static client (Smart TV)
    dev1 = await resolver.resolve("192.168.1.104", session=mock_session)
    assert dev1.name == "Samsung Smart TV"
    assert dev1.icon == "📺"
    assert dev1.device_type == "SMART_TV"
    assert dev1.display_name == "📺 Samsung Smart TV (192.168.1.104)"

    # 2. Configured static client (Camera)
    dev2 = await resolver.resolve("192.168.1.120", session=mock_session)
    assert dev2.name == "Reolink Cam Garage"
    assert dev2.icon == "💡"
    assert dev2.device_type == "IOT"

    # 3. DHCP auto-client (Mobile)
    dev3 = await resolver.resolve("192.168.1.155", session=mock_session)
    assert dev3.name == "Galaxy-S23-Android"
    assert dev3.icon == "📱"
    assert dev3.device_type == "MOBILE"

    # 4. Unknown client fallback
    dev4 = await resolver.resolve("192.168.1.200", session=mock_session)
    assert dev4.name == "192.168.1.200"
    assert dev4.icon == "🔌"
    assert dev4.display_name == "🔌 Dispositivo (192.168.1.200)"

@pytest.mark.asyncio
async def test_resolve_with_reverse_ptr(monkeypatch):
    settings = Settings()
    resolver = DeviceResolver(settings)
    monkeypatch.setattr(resolver, "_reverse_ptr_lookup", AsyncMock(return_value="MacBook-Pro-M2.local"))

    dev = await resolver.resolve("192.168.1.88")
    assert dev.name == "MacBook-Pro-M2.local"
    assert dev.icon == "💻"
    assert dev.device_type == "COMPUTER"
    assert dev.display_name == "💻 MacBook-Pro-M2.local (192.168.1.88)"

