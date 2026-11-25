#!/usr/bin/env python3
"""
Sentinel Apple iOS / macOS Encrypted DNS Profile Generator (.mobileconfig)
==========================================================================
Generates a standard Apple Configuration Profile routing Safari, apps, and
cellular/public Wi-Fi DNS queries through your self-hosted Sentinel / AdGuard
DoH or DoT endpoint with zero third-party cloud VPN middlemen.
"""

import argparse
from pathlib import Path
import plistlib
import uuid


def build_mobileconfig_bytes(
    doh_url: str = "",
    dot_hostname: str = "",
    server_addresses: list[str] | None = None,
    profile_name: str = "Sentinel Encrypted DNS",
    org_name: str = "Sentinel Self-Hosted",
) -> bytes:
    if not doh_url and not dot_hostname:
        raise ValueError("Provide either --doh-url (https://.../dns-query) or --dot-hostname.")

    dns_settings: dict = {}
    if doh_url:
        dns_settings["DNSProtocol"] = "HTTPS"
        dns_settings["ServerURL"] = doh_url
    else:
        dns_settings["DNSProtocol"] = "TLS"
        dns_settings["ServerName"] = dot_hostname

    if server_addresses:
        dns_settings["ServerAddresses"] = [ip.strip() for ip in server_addresses if ip.strip()]

    dns_payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.umbette.sentinel.dns.settings",
        "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"sentinel-dns-{doh_url or dot_hostname}")).upper(),
        "PayloadDisplayName": "Sentinel Encrypted DNS Settings",
        "DNSSettings": dns_settings,
    }

    profile = {
        "PayloadContent": [dns_payload],
        "PayloadDisplayName": profile_name,
        "PayloadDescription": "Routes iOS/macOS DNS queries cleanly through your private Sentinel Core + AdGuard Home instance.",
        "PayloadIdentifier": "com.umbette.sentinel.dns.profile",
        "PayloadOrganization": org_name,
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"sentinel-root-{doh_url or dot_hostname}")).upper(),
        "PayloadVersion": 1,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an iOS/macOS .mobileconfig encrypted DNS profile for Sentinel.")
    parser.add_argument("--doh-url", default="", help="DNS-over-HTTPS URL (e.g. https://adguard.home.ts.net/dns-query)")
    parser.add_argument("--dot-hostname", default="", help="DNS-over-TLS hostname (if not using DoH)")
    parser.add_argument("--server-ip", action="append", default=[], help="Optional bootstrap/resolver IP(s)")
    parser.add_argument("--output", default="sentinel-ios-dns.mobileconfig", help="Output .mobileconfig file path")
    args = parser.parse_args()

    xml_bytes = build_mobileconfig_bytes(
        doh_url=args.doh_url,
        dot_hostname=args.dot_hostname,
        server_addresses=args.server_ip,
    )
    out = Path(args.output)
    out.write_bytes(xml_bytes)
    print(f"Generated Apple DNS configuration profile: {out} ({len(xml_bytes)} bytes)")


if __name__ == "__main__":
    main()
