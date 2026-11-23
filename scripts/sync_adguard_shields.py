import json
import os
import urllib.request
import base64

try:
    import yaml
except ImportError:
    yaml = None

ADGUARD_URL = os.getenv("ADGUARD_URL", "http://127.0.0.1:8080")
USERNAME = os.getenv("ADGUARD_USERNAME", "umbette")
PASSWORD = os.getenv("ADGUARD_PASSWORD", "Agraria86-")

auth_str = f"{USERNAME}:{PASSWORD}".encode("utf-8")
headers = {
    "Authorization": f"Basic {base64.b64encode(auth_str).decode('ascii')}",
    "Content-Type": "application/json"
}

# 1. Fetch current status
req = urllib.request.Request(f"{ADGUARD_URL}/control/filtering/status", headers=headers)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode("utf-8"))

current_rules = data.get("user_rules", [])

NEW_SHIELD_RULES = [
    "! --- 🎮 Gaming Console Diagnostic & Crash Telemetry Shield (SysNAND Safe) ---",
    "||receive-lp1.er.srv.nintendo.net^",
    "||receive-lp1.dg.srv.nintendo.net^",
    "||crash-report.nintendo.net^",
    "||telemetry.playstation.com^",
    "||telemetry.xboxlive.com^",
    "! --- 🧹 Vacuum Floorplan & Camera Privacy Shield ---",
    "||open.ecovacs.com^",
    "||sa-eu-datasink.ecovacs.com^",
    "||bigdata-europe.ecovacs.com^",
    "||gl-iot-media.ecouser.net^",
    "@@||api-app.ww.ecouser.net^",
    "@@||api-app.dc-eu.ww.ecouser.net^",
    "@@||iot-api-nlp.dc-eu.ww.ecouser.net^",
    "@@||codepush-base.dc-na.ww.ecouser.net^",
    "@@||gl-es-api.ecovacs.com^",
    "@@||api-eu.roborock.com^",
    "@@||api.roborock.com^",
    "@@||mqtt-eu.roborock.com^",
    "@@||api.dreame.tech^",
    "@@||iot.dreame.tech^",
    "||log.dreame.tech^",
    "||tracking.roborock.com^",
    "||api-telemetry.roborock.com^",
    "! --- 🖨️ 3D Printer & Maker IP Guard (LAN Mode Safe) ---",
    "||log.bambulab.com^",
    "||analytics.bambulab.com^",
    "||crash.bambulab.com^",
    "||telemetry.creality.com^",
    "||log.crealitycloud.com^",
    "@@||api.bambulab.com^",
    "@@||user-cloud.bambulab.com^",
    "! --- 🍳 Smart Kitchen Appliance & Air Fryer Profiling Shield ---",
    "||ad.intl.xiaomi.com^",
    "||data.mistat.intl.xiaomi.com^",
    "||log.byteoversea.com^",
    "||toblog.ctobsnssdk.com^",
    "||hm.baidu.com^",
    "||tracking.vesync.com^",
    "||telemetry.cosori.com^",
    "@@||smart-api.vesync.com^",
    "! --- 🚗 Automotive Driving Telemetry & Essential APIs ---",
    "||telemetry.lexisnexis.com^",
    "||risk.lexisnexis.com^",
    "||telematics.verisk.com^",
    "||api.otonomo.io^",
    "||telemetry.otonomo.io^",
    "@@||owner-api.teslamotors.com^",
    "@@||b2vapi.bmwgroup.com^",
    "! --- 📷 Budget IP Camera Vulnerable P2P Isolation ---",
    "||iotcplatform.com^",
    "||p2pcam.net^",
    "||v380.net^",
    "||xmeye.net^",
    "||cs2-network.com^",
    "! --- 🧒 Youth Safeguard: Anti-Grooming, Deepfake AI Nudify & Predatory Videochats ---",
    "||nudify.online^",
    "||undress.app^",
    "||deepnude.to^",
    "||ome.tv^",
    "||monkey.app^",
    "||chatext.com^",
    "||chatrandom.com^",
    "||csgoempire.com^",
    "! --- 🚗 Automotive Driving Telemetry & Insurance Broker Silencer ---",
    "||telemetry.lexisnexis.com^",
    "||risk.lexisnexis.com^",
    "||telematics.verisk.com^",
    "||api.otonomo.io^",
    "||telemetry.otonomo.io^",
    "! --- 🧸 Smart Toy Audio & Child Microphone Leak Shield ---",
    "||turingos.cn^",
    "||voicecloud.cn^",
    "! --- 📦 Budget AOSP TV Box Badbox Malware C2 ---",
    "||cbty2021.com^",
    "||b2c.aospbox.net^",
    "||mykingbox.com^",
]

# Load additional rules from sources/device_profiles.yaml if present
profiles_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sources", "device_profiles.yaml")
if yaml and os.path.exists(profiles_path):
    with open(profiles_path, "r", encoding="utf-8") as pf:
        profiles_data = yaml.safe_load(pf) or {}
        for dev in profiles_data.get("devices", []):
            dev_name = dev.get("name", "Device")
            for dom in dev.get("control_plane", {}).get("allowed_domains", []):
                rule = f"@@||{dom}^"
                if rule not in NEW_SHIELD_RULES:
                    NEW_SHIELD_RULES.append(rule)
            for dom in dev.get("data_plane", {}).get("blocked_domains", []):
                rule = f"||{dom}^"
                if rule not in NEW_SHIELD_RULES:
                    NEW_SHIELD_RULES.append(rule)

# Append rules that are not already present
added_count = 0
for r in NEW_SHIELD_RULES:
    if r not in current_rules:
        current_rules.append(r)
        added_count += 1

# Post updated rules
update_req = urllib.request.Request(
    f"{ADGUARD_URL}/control/filtering/set_rules",
    data=json.dumps({"rules": current_rules}).encode("utf-8"),
    headers=headers,
    method="POST"
)

with urllib.request.urlopen(update_req) as resp:
    print(f"AdGuard Home updated! Added {added_count} new shield rules. Total active user rules: {len(current_rules)}")
