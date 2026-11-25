import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from src.config import Settings
from src.storage import StorageEngine
from src.device_resolver import DeviceResolver
from src.audit import NetworkAuditEngine, HIGH_RISK_PORTS

@pytest.fixture
def audit_engine(temp_storage):
    settings = Settings()
    resolver = DeviceResolver(settings)
    return NetworkAuditEngine(settings, temp_storage, resolver)

@pytest.mark.asyncio
async def test_audit_devices_baseline_and_storage(audit_engine, temp_storage):
    # Honest cold-start: empty storage returns 0 devices without fabricating sample hosts
    res = await audit_engine.audit_devices(session=None)
    assert res["total_devices"] == 0
    assert res["approved_count"] == 0
    assert res["pending_count"] == 0
    assert res["devices"] == []

    # Add real approved and pending devices
    temp_storage.upsert_device(
        ip="192.168.1.1",
        hostname="Router Gateway",
        category="GATEWAY",
        icon="🌐",
        default_status="APPROVED"
    )
    temp_storage.upsert_device(
        ip="192.168.1.185",
        hostname="Unknown ESP32 Board",
        category="IOT",
        icon="💡",
        default_status="PENDING"
    )

    res2 = await audit_engine.audit_devices(session=None)
    assert res2["total_devices"] == 2
    assert res2["approved_count"] == 1
    assert res2["pending_count"] == 1
    assert any(d["ip"] == "192.168.1.185" and d["approval_status"] == "PENDING" for d in res2["devices"])

@pytest.mark.asyncio
async def test_probe_port(audit_engine):
    # Closed / non-listening port on loopback should return False quickly
    is_open = await audit_engine.probe_port("127.0.0.1", 59999, timeout=0.1)
    assert is_open is False

@pytest.mark.asyncio
async def test_audit_vulnerabilities_detection(audit_engine):
    devices = [
        {"ip": "192.168.1.1", "hostname": "Router Gateway"},
        {"ip": "192.168.1.50", "hostname": "Generic Camera"}
    ]

    # Mock probe_port so that port 23 is open on 192.168.1.50 and port 1900 on 192.168.1.1
    async def mock_probe(ip, port, timeout=0.25):
        if ip == "192.168.1.50" and port == 23:
            return True
        if ip == "192.168.1.1" and port == 1900:
            return True
        return False

    with patch.object(audit_engine, "probe_port", side_effect=mock_probe):
        res = await audit_engine.audit_vulnerabilities(devices, check_ports=True)
        assert res["open_ports_count"] == 2
        assert res["high_risk_count"] == 2
        assert res["upnp_detected"] is True
        services = [e["service"] for e in res["exposures"]]
        assert "Telnet" in services
        assert "UPnP SSDP" in services

@pytest.mark.asyncio
async def test_audit_threat_backtracking(audit_engine, temp_storage):
    # Record an unresolved candidate in storage
    temp_storage.record_candidate(
        domain="exfiltration.stealth-c2.cc",
        client_ip="192.168.1.104",
        entropy=4.12,
        classification="C2_BOTNET",
        summary="Beaconing to known Badbox proxy network",
        status="PENDING"
    )

    res = await audit_engine.audit_threat_backtracking(session=None)
    assert res["threats_found"] >= 1
    assert any(t["domain"] == "exfiltration.stealth-c2.cc" for t in res["flagged_queries"])

@pytest.mark.asyncio
async def test_audit_dns_health(audit_engine):
    # Without session, should return degraded/offline notice
    res = await audit_engine.audit_dns_health(session=None)
    assert "dns_healthy" in res
    assert "latency_ms" in res

@pytest.mark.asyncio
async def test_run_audit_end_to_end_scoring_and_report(audit_engine, temp_storage):
    # Run full audit in offline/mock mode
    report = await audit_engine.run_audit(session=None, check_ports=False)

    assert "health_score" in report
    assert 0 <= report["health_score"] <= 100
    assert "status_text" in report
    assert "status_badge" in report
    assert "recommendations" in report
    assert len(report["recommendations"]) > 0

    # Verify report is persisted in database
    latest = temp_storage.get_latest_audit()
    assert latest is not None
    assert latest["health_score"] == report["health_score"]
    assert latest["report"]["status_badge"] == report["status_badge"]
