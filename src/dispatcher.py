import asyncio
import base64
import json
import logging
import datetime
from typing import Optional, List
import aiohttp
from src.config import Settings
from src.storage import StorageEngine

logger = logging.getLogger("ai_hunter.dispatcher")

class Dispatcher:
    def __init__(self, settings: Settings, storage: StorageEngine):
        self.settings = settings
        self.storage = storage
        self._running = False
        self._session: Optional[aiohttp.ClientSession] = None

    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self):
        self._running = False
        if self._session and not self._session.closed:
            await self._session.close()

    # -------------------------------------------------------------
    # 1. Transactional Read-Modify-Write Rule Injection (AdGuard)
    # -------------------------------------------------------------
    async def inject_adguard_rule(self, rule_str: str) -> bool:
        """
        Safely appends a rule to AdGuard Home user_rules using Read-Modify-Write.
        Never overwrites or deletes pre-existing user rules!
        """
        rule_clean = rule_str.strip()
        if not rule_clean.endswith("# ai-hunter"):
            rule_clean = f"{rule_clean} # ai-hunter"

        session = await self.get_session()
        creds = f"{self.settings.adguard.username}:{self.settings.adguard.password}".encode("utf-8")
        auth_header = f"Basic {base64.b64encode(creds).decode('ascii')}"
        headers = {"Authorization": auth_header}
        base_url = self.settings.adguard.base_url

        try:
            # 1. Read existing filtering status & rules
            async with session.get(f"{base_url}/control/filtering/status", headers=headers, timeout=5.0) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to fetch AdGuard rules: HTTP {resp.status}")
                    return False
                data = await resp.json()

            current_rules = data.get("user_rules") or []
            
            # 2. Check if rule is already present
            rule_core = rule_clean.split("#")[0].strip()
            for r in current_rules:
                if r.split("#")[0].strip() == rule_core:
                    logger.info(f"Rule already exists in AdGuard Home: {rule_core}")
                    return True

            # 3. Append rule and write back complete array
            current_rules.append(rule_clean)
            payload = {"rules": current_rules}

            async with session.post(f"{base_url}/control/filtering/set_rules", headers=headers, json=payload, timeout=5.0) as resp:
                if resp.status in (200, 204):
                    logger.info(f"Successfully injected rule into AdGuard Home: {rule_clean}")
                    return True
                else:
                    text = await resp.text()
                    logger.error(f"Failed to post rules to AdGuard Home: HTTP {resp.status} - {text}")
                    return False
        except Exception as e:
            logger.error(f"Error during AdGuard RMW rule injection: {e}")
            return False

    # -------------------------------------------------------------
    # 2. Home Assistant Mobile & Persistent Notification Dispatch
    # -------------------------------------------------------------
    async def send_mobile_alert(self, domain: str, client_ip: str, 
                                classification: str, summary: str, suggested_rule: str) -> bool:
        """
        Sends an actionable mobile push notification to Umbette's smartphone via Home Assistant,
        and creates a persistent notification visible under the Home Assistant UI bell icon (Notifiche).
        """
        session = await self.get_session()
        base_ha_url = self.settings.home_assistant.base_url
        headers = {
            "Authorization": f"Bearer {self.settings.home_assistant.token}",
            "Content-Type": "application/json"
        }

        title = f"🛡️ AI Hunter: {classification.upper()} Rilevato"
        message = f"{summary}\n\n• Dominio: {domain}\n• Dispositivo: {client_ip}"

        # 1. Actionable Mobile Push Notification (Companion App)
        mobile_url = f"{base_ha_url}/api/services/notify/{self.settings.home_assistant.notify_service}"
        payload = {
            "title": title,
            "message": message,
            "data": {
                "tag": f"hunter-{domain}",
                "actions": [
                    {
                        "action": f"BLOCCA_DEVICE::{domain}::{client_ip}",
                        "title": f"Blocca Device ({client_ip})"
                    },
                    {
                        "action": f"BLOCCA_GLOBALE::{domain}",
                        "title": "Blocca per Tutta la Rete"
                    },
                    {
                        "action": f"IGNORA::{domain}",
                        "title": "Ignora (30 giorni)"
                    }
                ]
            }
        }

        notified = False
        try:
            async with session.post(mobile_url, headers=headers, json=payload, timeout=5.0) as resp:
                if resp.status in (200, 201):
                    logger.info(f"Dispatched mobile notification for {domain} to {self.settings.home_assistant.notify_service}")
                    notified = True
                else:
                    text = await resp.text()
                    logger.error(f"Failed to send Home Assistant notification: HTTP {resp.status} - {text}")
        except Exception as e:
            logger.error(f"Error dispatching Home Assistant notification: {e}")

        # 2. Persistent Notification (Visible in Home Assistant UI Bell Icon 🔔)
        clean_id = f"hunter_{domain.replace('.', '_')}"
        persistent_url = f"{base_ha_url}/api/services/persistent_notification/create"
        persistent_payload = {
            "notification_id": clean_id,
            "title": title,
            "message": (
                f"### Anomalia DNS Rilevata da AI Hunter\n\n"
                f"**Diagnosi:** {summary}\n\n"
                f"* **Dominio:** `{domain}`\n"
                f"* **Dispositivo:** `{client_ip}`\n"
                f"* **Classificazione:** `{classification}`\n"
                f"* **Regola Suggerita:** `{suggested_rule}`\n\n"
                f"> *Puoi bloccare o ignorare questo dominio direttamente dalla notifica ricevuta sullo smartphone.*"
            )
        }
        try:
            async with session.post(persistent_url, headers=headers, json=persistent_payload, timeout=5.0) as p_resp:
                if p_resp.status in (200, 201):
                    logger.info(f"Created persistent notification '{clean_id}' in Home Assistant UI")
                else:
                    logger.warning(f"Could not create persistent notification: HTTP {p_resp.status}")
        except Exception as e:
            logger.warning(f"Error creating persistent notification: {e}")

        return notified

    # -------------------------------------------------------------
    # 3. Outbound WebSocket Event Subscription (Zero Inbound Ports)
    # -------------------------------------------------------------
    async def listen_ha_websocket(self):
        """
        Maintains an outbound WebSocket connection to Home Assistant listening for mobile action button taps.
        Eliminates the need for inbound webhooks or exposed container ports!
        """
        self._running = True
        ws_url = self.settings.home_assistant.ws_url

        while self._running:
            session = await self.get_session()
            try:
                logger.info(f"Connecting to Home Assistant WebSocket at {ws_url}...")
                async with session.ws_connect(ws_url, timeout=10.0) as ws:
                    # 1. Receive auth_required
                    msg = await ws.receive_json()
                    if msg.get("type") != "auth_required":
                        logger.error(f"Unexpected initial WS message: {msg}")
                        await asyncio.sleep(5)
                        continue

                    # 2. Authenticate
                    await ws.send_json({
                        "type": "auth",
                        "access_token": self.settings.home_assistant.token
                    })
                    auth_resp = await ws.receive_json()
                    if auth_resp.get("type") != "auth_ok":
                        logger.error(f"Home Assistant WS authentication failed: {auth_resp}")
                        await asyncio.sleep(10)
                        continue

                    logger.info("Home Assistant WebSocket authenticated successfully.")

                    # 3. Subscribe to mobile_app_notification_action events
                    await ws.send_json({
                        "id": 1,
                        "type": "subscribe_events",
                        "event_type": "mobile_app_notification_action"
                    })
                    sub_resp = await ws.receive_json()
                    logger.info(f"Subscribed to mobile_app_notification_action: {sub_resp}")

                    # 4. Event loop
                    async for msg in ws:
                        if not self._running:
                            break
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            data = json.loads(msg.data)
                            if data.get("type") == "event":
                                event_data = data.get("event", {}).get("data", {})
                                action = event_data.get("action", "")
                                await self._handle_notification_action(action)
                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            logger.warning(f"WebSocket closed or encountered error: {msg.type}")
                            break

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"WebSocket listener exception: {e}. Reconnecting in 5s...")
                await asyncio.sleep(5)

    async def _handle_notification_action(self, action_str: str):
        """
        Parses action string: ACTION::domain[::client_ip]
        """
        if not action_str or "::" not in action_str:
            return

        parts = action_str.split("::")
        verb = parts[0]
        domain = parts[1]
        client_ip = parts[2] if len(parts) > 2 else "GLOBAL"

        logger.info(f"Received mobile action: {verb} on domain: {domain} (scope: {client_ip})")

        if verb == "BLOCCA_DEVICE":
            rule = f"||{domain}^$client={client_ip}"
            self.storage.record_decision(domain, client_ip, "BLOCK", notes="Blocked via mobile app (client)")
            await self.inject_adguard_rule(rule)

        elif verb == "BLOCCA_GLOBALE":
            rule = f"||{domain}^"
            self.storage.record_decision(domain, "GLOBAL", "BLOCK", notes="Blocked via mobile app (global)")
            await self.inject_adguard_rule(rule)

        elif verb == "IGNORA":
            # 30-day snooze
            expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).isoformat()
            # Register apex wildcard allow
            apex = ".".join(domain.split(".")[-2:]) if len(domain.split(".")) > 2 else domain
            self.storage.record_decision(f"*.{apex}", "GLOBAL", "ALLOW", expires_at=expires_at, notes="Whitelisted 30 days via mobile app")
            logger.info(f"Recorded 30-day snooze decision for *.{apex} until {expires_at}")

        # Dismiss persistent notification from Home Assistant UI upon resolution
        clean_id = f"hunter_{domain.replace('.', '_')}"
        dismiss_url = f"{self.settings.home_assistant.base_url}/api/services/persistent_notification/dismiss"
        try:
            session = await self.get_session()
            headers = {
                "Authorization": f"Bearer {self.settings.home_assistant.token}",
                "Content-Type": "application/json"
            }
            await session.post(dismiss_url, headers=headers, json={"notification_id": clean_id}, timeout=3.0)
            logger.info(f"Dismissed persistent notification '{clean_id}'")
        except Exception as e:
            logger.warning(f"Error dismissing persistent notification: {e}")
