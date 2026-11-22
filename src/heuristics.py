import os
import math
import time
from pathlib import Path
from collections import Counter
from typing import Tuple, Dict, Set, Optional
import tldextract

# High-traffic popular services and CDN providers to immediately bypass
KNOWN_BENIGN_DOMAINS = {
    "google.com", "googlevideo.com", "youtube.com", "gstatic.com", "googleapis.com",
    "googleusercontent.com", "apple.com", "icloud.com", "mzstatic.com", "aaplimg.com",
    "microsoft.com", "windowsupdate.com", "live.com", "office.com", "bing.com", "azure.com",
    "signalr.net", "amazon.com", "amazonaws.com", "aiv-cdn.net", "media-amazon.com",
    "amazonvideo.com", "netflix.com", "nflxvideo.net", "nflximg.net",
    "cloudflare.com", "cloudflare-dns.com", "akamaihd.net", "akamaized.net",
    "github.com", "githubusercontent.com", "docker.com", "docker.io",
    "spotify.com", "scdn.co", "melcloud.com", "bambulab.com",
    "tuya.com", "tuyaeu.com", "home-assistant.io", "casas.org",
    "iotcplatform.com", "cdn5th.com", "fastly-edge.com", "run.app"
}

INFRASTRUCTURE_SUFFIXES = (
    ".in-addr.arpa", ".ip6.arpa", ".arpa", ".local", ".lan", ".home", ".internal"
)

def calculate_shannon_entropy(text: str) -> float:
    """Calculates byte/character Shannon entropy: H = -sum(p * log2(p))."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

class HeuristicsEngine:
    def __init__(self, entropy_threshold: float = 3.85, 
                 rate_burst_threshold: int = 30, rate_window_sec: int = 60):
        self.entropy_threshold = entropy_threshold
        self.rate_burst_threshold = rate_burst_threshold
        self.rate_window_sec = rate_window_sec
        cache_dir = Path("/app/data/.tld_cache") if Path("/app").is_dir() and os.access("/app", os.W_OK) else Path(__file__).resolve().parent.parent / "data" / ".tld_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.extractor = tldextract.TLDExtract(cache_dir=str(cache_dir))
        # In-memory rate tracker: (client_ip, apex_domain) -> list of timestamps
        self._rate_buckets: Dict[Tuple[str, str], list] = {}

    def is_known_benign(self, apex_domain: str) -> bool:
        return apex_domain.lower() in KNOWN_BENIGN_DOMAINS

    def evaluate_entropy(self, domain: str) -> Tuple[bool, float, str]:
        """
        Evaluates multi-label entropy across both SLD and subdomains.
        Returns: (is_dga_candidate, max_entropy, label_flagged)
        """
        d_lower = domain.lower()
        if d_lower.endswith(INFRASTRUCTURE_SUFFIXES) or d_lower in ("in-addr.arpa", "ip6.arpa", "arpa"):
            return False, 0.0, ""

        ext = self.extractor(domain)
        apex = f"{ext.domain}.{ext.suffix}".lower()
        if self.is_known_benign(apex):
            return False, 0.0, ""

        labels_to_test = []
        if ext.domain:
            labels_to_test.append(("sld", ext.domain))
        if ext.subdomain:
            for sub in ext.subdomain.split("."):
                if len(sub) >= 6:  # Only test non-trivial subdomain labels
                    labels_to_test.append((f"subdomain:{sub}", sub))

        max_entropy = 0.0
        flagged_label = ""
        is_candidate = False

        for label_type, label in labels_to_test:
            # Clean label
            clean = "".join([c for c in label if c.isalnum()])
            if len(clean) < 7:
                continue
            
            ent = calculate_shannon_entropy(clean)
            if ent > max_entropy:
                max_entropy = ent
                flagged_label = label

            # DGA heuristic: 
            # Note on information theory: For len < 15, max possible Shannon entropy is < 3.85 (log2(14) ~ 3.81).
            # We use normalized entropy (H / log2(L) >= 0.96) for 10 <= len < 15, and raw H >= 3.85 for len >= 15.
            clean_len = len(clean)
            if clean_len >= 15 and ent >= self.entropy_threshold:
                is_candidate = True
            elif 10 <= clean_len < 15:
                max_possible = math.log2(clean_len)
                if max_possible > 0 and (ent / max_possible) >= 0.96:
                    is_candidate = True

        return is_candidate, round(max_entropy, 2), flagged_label

    def record_query_and_check_burst(self, client_ip: str, domain: str) -> Tuple[bool, int]:
        """
        Tracks query velocity per (client_ip, apex_domain).
        Returns: (is_burst, current_count)
        """
        d_lower = domain.lower()
        if d_lower.endswith(INFRASTRUCTURE_SUFFIXES) or d_lower in ("in-addr.arpa", "ip6.arpa", "arpa"):
            return False, 0

        ext = self.extractor(domain)
        apex = f"{ext.domain}.{ext.suffix}".lower() if ext.domain else domain.lower()
        if self.is_known_benign(apex):
            return False, 0
        
        now = time.time()
        key = (client_ip, apex)
        
        if key not in self._rate_buckets:
            self._rate_buckets[key] = []
        
        bucket = self._rate_buckets[key]
        bucket.append(now)
        
        # Expire timestamps outside the sliding window
        cutoff = now - self.rate_window_sec
        # In-place prune
        self._rate_buckets[key] = [t for t in bucket if t > cutoff]
        count = len(self._rate_buckets[key])
        
        is_burst = count >= self.rate_burst_threshold
        return is_burst, count

    def cleanup_stale_buckets(self):
        """Prunes tracking buckets inactive for over 2x window period to prevent RAM leaks."""
        now = time.time()
        cutoff = now - (self.rate_window_sec * 2)
        keys_to_delete = []
        for key, bucket in self._rate_buckets.items():
            valid = [t for t in bucket if t > cutoff]
            if not valid:
                keys_to_delete.append(key)
            else:
                self._rate_buckets[key] = valid
        for key in keys_to_delete:
            del self._rate_buckets[key]
