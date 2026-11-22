import json
import urllib.request
import base64

ADGUARD_URL = "http://127.0.0.1:8080"
USERNAME = "umbette"
PASSWORD = "Agraria86-"

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
    "! --- 🎮 Nintendo Switch 90DNS Local Anti-Ban Shield ---",
    "||receive-lp1.er.srv.nintendo.net^",
    "||receive-lp1.dg.srv.nintendo.net^",
    "||dauth-lp1.ndas.srv.nintendo.net^",
    "||aauth-lp1.ndas.srv.nintendo.net^",
    "||sun.hac.lp1.d4c.srv.nintendo.net^",
    "||ctest.cdn.nintendo.net^",
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
    "||log.dreame.tech^",
    "||tracking.roborock.com^",
    "||api-telemetry.roborock.com^",
    "! --- 🖨️ Bambu Lab 3D Printer IP & Telemetry Shield ---",
    "||log.bambulab.com^",
    "||analytics.bambulab.com^",
    "||crash.bambulab.com^",
    "! --- 🍳 Smart Kitchen Appliance & Air Fryer Profiling Shield ---",
    "||ad.intl.xiaomi.com^",
    "||data.mistat.intl.xiaomi.com^",
    "||log.byteoversea.com^",
    "||toblog.ctobsnssdk.com^",
    "||hm.baidu.com^",
    "||tracking.vesync.com^",
    "||telemetry.cosori.com^",
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
