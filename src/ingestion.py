import asyncio
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
from src.crypto_shield import evaluate_crypto_financial_threat

logger = logging.getLogger("ai_hunter.ingestion")

class IngestionWorker:
    def __init__(self, settings: Settings, storage: StorageEngine, 
                 heuristics: HeuristicsEngine, gemini: GeminiClassifier, 
                 dispatcher: Dispatcher):
        self.settings = settings
        self.storage = storage
        self.heuristics = heuristics
        self.gemini = gemini
        self.dispatcher = dispatcher
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

            # 1. Check existing decisions (whitelists / blocks)
            decision = self.storage.match_decision(domain, client_ip)
            if decision:
                # Already handled by prior human approval / whitelist
                continue

            # 2. Check Crypto Vault & Financial Threat (High Priority)
            crypto_match = evaluate_crypto_financial_threat(domain)
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
            pricing_match = evaluate_dynamic_pricing_tracker(domain)
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

            # 4. Track rate burst
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
