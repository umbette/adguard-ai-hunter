import asyncio
import ipaddress
import logging
import datetime
from typing import Optional, List, Dict, Any
import aiohttp
from src.config import Settings
from src.storage import StorageEngine
from src.heuristics import HeuristicsEngine
from src.gemini_client import GeminiClassifier
from src.dispatcher import Dispatcher
from src.dynamic_pricing import evaluate_dynamic_pricing_tracker
from src.crypto_shield import ESSENTIAL_TRANSACTION_INFRASTRUCTURE, evaluate_crypto_financial_threat, evaluate_sterile_chamber_domain
from src.device_shield import evaluate_device_shield, is_shield_active
from src.ip_intel import ThreatIPIndex, extract_answer_ips

logger = logging.getLogger("sentinel.ingestion")

class IngestionWorker:
    def __init__(self, settings: Settings, storage: StorageEngine, 
                 heuristics: HeuristicsEngine, gemini: GeminiClassifier, 
                 dispatcher: Dispatcher,
                 ip_intel: Optional[ThreatIPIndex] = None):
        self.settings = settings
        self.storage = storage
        self.heuristics = heuristics
        self.gemini = gemini
        self.dispatcher = dispatcher
        self.ip_intel = ip_intel or ThreatIPIndex()
        self._running = False
        # In-memory recent notification cache: domain -> timestamp to avoid alert storm
        self._notified_cache: Dict[str, float] = {}

    async def run(self):
        self._running = True
        logger.info("Starting IngestionWorker polling loop...")

        auth = aiohttp.BasicAuth(self.settings.adguard.username, self.settings.adguard.password)
        base_url = self.settings.adguard.base_url
        poll_interval = self.settings.adguard.poll_interval_sec
        batch_limit = self.settings.adguard.batch_limit

        # Security check: warn if BasicAuth is transmitted over unencrypted HTTP on non-loopback network
        if base_url.startswith("http://") and not any(h in base_url for h in ("127.0.0.1", "localhost", "[::1]")):
            logger.warning(
                f"[SECURITY WARNING] AdGuard connection ({base_url}) transmits BasicAuth credentials over plain HTTP. "
                f"If AdGuard is hosted on a separate host, use HTTPS to protect credentials from network sniffing."
            )

        # Initialize high-water mark if not set
        checkpoint = self.storage.get_checkpoint("last_query_time")
        if not checkpoint:
            checkpoint = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.storage.set_checkpoint("last_query_time", checkpoint)
            logger.info(f"Initialized high-water mark checkpoint to: {checkpoint}")

        last_cleanup = datetime.datetime.now(datetime.timezone.utc)

        while self._running:
            try:
                session = await self.dispatcher.get_session()
                # Query the latest entries from AdGuard querylog (forward ingestion)
                url = f"{base_url}/control/querylog?limit={batch_limit}"
                async with session.get(url, auth=auth, timeout=10.0) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        entries = data.get("data") or []
                        await self._process_entries(entries)
                    else:
                        logger.warning(f"AdGuard querylog returned HTTP {resp.status}")

                # Periodic maintenance every 10 minutes
                now = datetime.datetime.now(datetime.timezone.utc)
                if (now - last_cleanup).total_seconds() > self.settings.heuristics.cleanup_interval_sec:
                    self.heuristics.cleanup_stale_buckets()
                    pruned = self.storage.cleanup_expired_decisions()
                    logger.info(f"Periodic maintenance executed. Pruned {pruned} expired snooze decisions.")
                    last_cleanup = now

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in ingestion polling cycle: {e}")

            await asyncio.sleep(poll_interval)

    async def _process_entries(self, entries: List[Dict[str, Any]]):
        if not entries:
            return

        current_checkpoint = self.storage.get_checkpoint("last_query_time")
        newest_timestamp = current_checkpoint

        # Sort entries chronologically (oldest to newest)
        valid_entries = []
        for e in entries:
            t = e.get("time")
            if t and (not current_checkpoint or t > current_checkpoint):
                valid_entries.append(e)

        valid_entries.sort(key=lambda x: x.get("time", ""))

        for entry in valid_entries:
            t = entry.get("time")
            if t and (not newest_timestamp or t > newest_timestamp):
                newest_timestamp = t

            # Only inspect queries that weren't already blocked by static lists
            reason = entry.get("reason", "")
            if reason != "NotFilteredNotFound":
                continue

            q = entry.get("question", {})
            domain = q.get("name", "").lower().strip(".")
            client_ip = entry.get("client", "")

            if not domain or not client_ip:
                continue

            # 0. Track device & Zero-Trust admission control (Only for physical LAN clients)
            is_lan = True
            try:
                parsed_ip = ipaddress.ip_address(client_ip)
                if parsed_ip.is_loopback or parsed_ip in ipaddress.ip_network("172.16.0.0/12"):
                    is_lan = False
            except ValueError:
                is_lan = False

            if is_lan:
                default_status = "PENDING" if getattr(self.settings, "admission", None) and self.settings.admission.enabled else "APPROVED"
                is_new, device_record = self.storage.upsert_device(
                    ip=client_ip,
                    default_status=default_status
                )
                if is_new:
                    logger.info(f"🔔 New network device detected: {client_ip}")
                    session = await self.dispatcher.get_session()
                    dev_info = await self.dispatcher.device_resolver.resolve(client_ip, session)
                    self.storage.upsert_device(
                        ip=client_ip,
                        hostname=dev_info.name,
                        category=dev_info.device_type,
                        icon=dev_info.icon
                    )
                    if getattr(self.settings, "admission", None) and self.settings.admission.notify_on_new_device:
                        await self.dispatcher.send_new_device_alert(
                            ip=client_ip,
                            name=dev_info.name,
                            icon=dev_info.icon,
                            category=dev_info.device_type,
                            quarantine=self.settings.admission.quarantine_unapproved
                        )
                    if getattr(self.settings, "admission", None) and self.settings.admission.enabled and self.settings.admission.quarantine_unapproved:
                        await self.dispatcher.inject_adguard_rule(f"||*$client={client_ip}")

            # 1. Check existing decisions (whitelists / blocks)
            decision = self.storage.match_decision(domain, client_ip)
            if decision:
                # Already handled by prior human approval / whitelist
                continue

            # 1.5 Enforce Active Stanza Sterile (SPEC-024): blackhole non-authorized traffic for shielded IP
            sterile_ok, sterile_reason = evaluate_sterile_chamber_domain(client_ip, domain)
            if not sterile_ok:
                await self.dispatcher.inject_adguard_rule(f"||{domain}^$client={client_ip}")
                now_ts = datetime.datetime.now().timestamp()
                if (now_ts - self._notified_cache.get(f"sterile:{client_ip}:{domain}", 0)) >= 300:
                    self._notified_cache[f"sterile:{client_ip}:{domain}"] = now_ts
                    logger.warning(f"🔒 STANZA STERILE BLOCK: {domain} from {client_ip}")
                    await self.dispatcher.send_mobile_alert(
                        domain=domain,
                        client_ip=client_ip,
                        classification="STERILE_CHAMBER_BLOCK",
                        summary=f"🔒 {sterile_reason}",
                        suggested_rule=f"||{domain}^$client={client_ip}"
                    )
                continue

            # 2. Check Crypto Vault & Financial Threat (High Priority)
            crypto_match = evaluate_crypto_financial_threat(domain) if is_shield_active("crypto_vault") else None
            if crypto_match:
                now_ts = datetime.datetime.now().timestamp()
                if (now_ts - self._notified_cache.get(domain, 0)) >= 600:
                    self._notified_cache[domain] = now_ts
                    logger.warning(f"🚨 CRYPTO / FINANCIAL THREAT DETECTED: {domain} from {client_ip} ({crypto_match.threat_type})")
                    await self.dispatcher.send_mobile_alert(
                        domain=domain,
                        client_ip=client_ip,
                        classification="CRYPTO_FINANCIAL_ALERT",
                        summary=f"🚨 {crypto_match.description}",
                        suggested_rule=f"||{domain}^"
                    )
                continue

            # 3. Check Anti-Dynamic Pricing & Cross-App Fingerprinting
            pricing_match = evaluate_dynamic_pricing_tracker(domain) if is_shield_active("dynamic_pricing") else None
            if pricing_match:
                now_ts = datetime.datetime.now().timestamp()
                if (now_ts - self._notified_cache.get(domain, 0)) >= 600:
                    self._notified_cache[domain] = now_ts
                    logger.info(f"🛡️ Dynamic pricing tracker intercepted: {domain} from {client_ip} ({pricing_match.tracker_name})")
                    await self.dispatcher.send_mobile_alert(
                        domain=domain,
                        client_ip=client_ip,
                        classification="DYNAMIC_PRICING",
                        summary=f"🛡️ {pricing_match.tracker_name}: {pricing_match.description}",
                        suggested_rule=f"||{domain}^$client={client_ip}"
                    )
                continue

            # 4. Check Specialized Device Privacy & Diagnostic Shields
            device_match = evaluate_device_shield(domain)
            if device_match:
                now_ts = datetime.datetime.now().timestamp()
                if (now_ts - self._notified_cache.get(domain, 0)) >= 600:
                    self._notified_cache[domain] = now_ts
                    logger.info(f"🛡️ Device Shield alert: {domain} from {client_ip} ({device_match.shield_type})")
                    await self.dispatcher.send_mobile_alert(
                        domain=domain,
                        client_ip=client_ip,
                        classification=device_match.shield_type,
                        summary=f"🛡️ {device_match.description}",
                        suggested_rule=f"||{domain}^$client={client_ip}"
                    )
                continue

            # 4.5 Passive DNS Answer Correlation against High-Confidence Malicious IPs / C2 CIDRs
            if (
                self.ip_intel
                and self.ip_intel.total_entries > 0
                and domain not in ESSENTIAL_TRANSACTION_INFRASTRUCTURE
                and not any(domain.endswith(f".{safe}") for safe in ESSENTIAL_TRANSACTION_INFRASTRUCTURE)
            ):
                resolved_ips = extract_answer_ips(entry)
                matched_ip_threat = None
                for resolved_ip in resolved_ips:
                    candidate_match = self.ip_intel.match_ip(resolved_ip)
                    if candidate_match is not None:
                        matched_ip_threat = candidate_match
                        break

                if matched_ip_threat is not None:
                    now_ts = datetime.datetime.now().timestamp()
                    cache_key = f"ip_correl:{domain}:{matched_ip_threat.ip}"
                    if (now_ts - self._notified_cache.get(cache_key, 0)) >= 600:
                        self._notified_cache[cache_key] = now_ts
                        summary = (
                            f"🚨 Risoluzione DNS verso IP malevolo {matched_ip_threat.ip} "
                            f"(match: {matched_ip_threat.matched_ioc}, feed: {matched_ip_threat.source}, family: {matched_ip_threat.family})."
                        )
                        logger.warning(f"MALICIOUS IP RESOLUTION: {domain} -> {matched_ip_threat.ip} from {client_ip}")
                        self.storage.record_candidate(
                            domain=domain,
                            client_ip=client_ip,
                            entropy=0.0,
                            classification="MALICIOUS_IP_RESOLUTION",
                            summary=summary,
                            status="NOTIFIED",
                        )
                        await self.dispatcher.send_mobile_alert(
                            domain=domain,
                            client_ip=client_ip,
                            classification="MALICIOUS_IP_RESOLUTION",
                            summary=summary,
                            suggested_rule=f"||{domain}^$client={client_ip}",
                        )
                    continue

            # 5. Track rate burst
            is_burst, burst_count = self.heuristics.record_query_and_check_burst(client_ip, domain)

            # 5. Evaluate multi-label entropy
            is_dga, entropy, flagged_label = self.heuristics.evaluate_entropy(domain)

            if is_dga or is_burst:
                # Check persistent SQLite cooldown (e.g. previously evaluated as benign)
                if self.storage.is_in_cooldown(domain, client_ip):
                    continue

                # Debounce notifications (10 minutes per domain)
                now_ts = datetime.datetime.now().timestamp()
                last_alert = self._notified_cache.get(domain, 0)
                if (now_ts - last_alert) < 600:
                    continue
                self._notified_cache[domain] = now_ts

                logger.info(f"Flagged anomaly: domain={domain}, client={client_ip}, DGA={is_dga} (H={entropy}), Burst={is_burst} ({burst_count} req)")

                # Record candidate in SQLite
                candidate_id = self.storage.record_candidate(
                    domain=domain,
                    client_ip=client_ip,
                    entropy=entropy,
                    status="PENDING"
                )

                # Query Gemini classification (with 5s timeout & fallback)
                audit = await self.gemini.classify_domain(
                    domain=domain,
                    client_ip=client_ip,
                    entropy=entropy,
                    burst_count=burst_count,
                    is_dga=is_dga
                )

                # Check classification: if BENIGN or low risk (< 0.40), dismiss candidate with 24h cooldown without creating dangerous wildcard rules
                if audit.classification == "BENIGN" or audit.risk_score < 0.40:
                    logger.info(f"Dismissing benign candidate with 24h cooldown: {domain} (risk={audit.risk_score})")
                    self.storage.update_candidate_status(candidate_id, "DISMISSED", classification=audit.classification, summary=audit.summary)
                    self.storage.set_cooldown(domain, client_ip, duration_seconds=86400, reason="BENIGN")
                    continue

                # Only send interactive Home Assistant push notification for actionable threats / telemetry
                notified = await self.dispatcher.send_mobile_alert(
                    domain=domain,
                    client_ip=client_ip,
                    classification=audit.classification,
                    summary=audit.summary,
                    suggested_rule=audit.suggested_rule
                )

                if notified:
                    self.storage.update_candidate_status(candidate_id, "NOTIFIED", classification=audit.classification, summary=audit.summary)

        # Update high-water mark
        if newest_timestamp and newest_timestamp != current_checkpoint:
            self.storage.set_checkpoint("last_query_time", newest_timestamp)
