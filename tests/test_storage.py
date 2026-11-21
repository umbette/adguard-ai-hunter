import datetime
from src.storage import StorageEngine

def test_wildcard_matching(temp_storage):
    # Record wildcard decision
    temp_storage.record_decision("*.lge.com", "GLOBAL", "ALLOW")

    # Should match subdomains
    match1 = temp_storage.match_decision("eu.telemetry.lge.com", "192.168.1.210")
    assert match1 is not None
    assert match1["action"] == "ALLOW"

    match2 = temp_storage.match_decision("api.lge.com", "192.168.1.100")
    assert match2 is not None
    assert match2["action"] == "ALLOW"

    # Should not match other domains
    match3 = temp_storage.match_decision("samsung.com", "192.168.1.210")
    assert match3 is None

def test_client_scoped_precedence(temp_storage):
    temp_storage.record_decision("ad.com", "GLOBAL", "ALLOW")
    temp_storage.record_decision("ad.com", "192.168.1.210", "BLOCK")

    # Client specific match overrides global
    match_tv = temp_storage.match_decision("ad.com", "192.168.1.210")
    assert match_tv["action"] == "BLOCK"

    # Other clients get global
    match_other = temp_storage.match_decision("ad.com", "192.168.1.150")
    assert match_other["action"] == "ALLOW"

def test_snooze_expiration(temp_storage):
    # Expired decision
    yesterday = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
    temp_storage.record_decision("expired.com", "GLOBAL", "ALLOW", expires_at=yesterday)

    match = temp_storage.match_decision("expired.com", "192.168.1.1")
    assert match is None

    # Active snooze
    future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).isoformat()
    temp_storage.record_decision("active.com", "GLOBAL", "ALLOW", expires_at=future)

    match_active = temp_storage.match_decision("active.com", "192.168.1.1")
    assert match_active is not None
