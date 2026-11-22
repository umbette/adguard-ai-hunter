"""
Anti-Dynamic Pricing Shield
===========================
Detects and blocks ad-tech data brokers, cross-app device fingerprinting engines,
and behavioral session recorders used by airlines, hotels, e-commerce, and insurance
companies for dynamic price discrimination (raising prices based on device model,
geolocation, and purchasing history).
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

@dataclass
class DynamicPricingMatch:
    domain: str
    tracker_name: str
    category: str
    risk_score: float
    description: str

# Curated catalog of price discrimination and cross-app tracking networks
DYNAMIC_PRICING_NETWORKS: Dict[str, Tuple[str, str, str]] = {
    # Airlines & Travel Data Brokers (Price Discrimination)
    "criteo.com": ("Criteo Retargeting", "AIRLINE_HOTEL_DISCRIMINATION", "Raccoglie cronologia di ricerca voli e hotel per rincarare i prezzi dinamici."),
    "criteo.net": ("Criteo Network", "AIRLINE_HOTEL_DISCRIMINATION", "Rete di profilazione acquisti per tariffe dinamiche."),
    "appsflyer.com": ("AppsFlyer", "CROSS_APP_FINGERPRINTING", "SDK di attribuzione mobile: correla ricerche su app diverse per stimare il potere d'acquisto."),
    "adjust.com": ("Adjust", "CROSS_APP_FINGERPRINTING", "Piattaforma di analytics cross-device usata per profilazione commerciale."),
    "kochava.com": ("Kochava", "CROSS_APP_FINGERPRINTING", "Broker di identità cross-app per targeting di prezzo."),
    "branch.io": ("Branch Metrics", "DEEP_LINK_TRACKING", "Tracciamento deep-link e fingerprinting hardware del dispositivo."),
    "singular.net": ("Singular Analytics", "CROSS_APP_FINGERPRINTING", "Piattaforma di intelligenza commerciale su abitudini di spesa."),
    "sovrn.com": ("Sovrn Commerce", "COMMERCE_ARBITRAGE", "Broker di affiliazione e monitoraggio carrelli d'acquisto."),

    # Behavioral Session Recorders & Screen Trackers
    "sessioncam.com": ("SessionCam", "BEHAVIORAL_SESSION_RECORDING", "Registra mouse, tocchi e indecisioni sui prezzi prima dell'acquisto."),
    "quantummetric.com": ("Quantum Metric", "BEHAVIORAL_SESSION_RECORDING", "Analizza esitazioni e tempi di sosta sulle tariffe per forzare FOMO."),
    "hotjar.com": ("Hotjar Tracking", "BEHAVIORAL_SESSION_RECORDING", "Mappe di calore e registrazione sessioni d'acquisto."),
    "fullstory.com": ("FullStory", "BEHAVIORAL_SESSION_RECORDING", "Playback visivo delle sessioni di prenotazione e navigazione."),
    "mouseflow.com": ("Mouseflow", "BEHAVIORAL_SESSION_RECORDING", "Registrazione comportamentale durante la consultazione dei preventivi."),
    "decibelinsight.net": ("Decibel Insight", "BEHAVIORAL_SESSION_RECORDING", "Smart analytics delle reazioni ai cambi di prezzo."),

    # Dynamic Pricing & Yield Optimization Enablers
    "everesttech.net": ("Adobe Advertising / Everest", "DYNAMIC_PRICING_ENABLER", "Motore algoritmico di offerta e determinazione del prezzo d'asta."),
    "demdex.net": ("Adobe Audience Manager", "DYNAMIC_PRICING_ENABLER", "DMP che segmenta gli utenti in fasce di reddito stimato."),
    "yieldify.com": ("Yieldify", "DYNAMIC_PRICING_ENABLER", "Ottimizzatore di conversione e tariffe dinamiche d'uscita."),
    "bounceexchange.com": ("Wunderkind / BounceX", "DYNAMIC_PRICING_ENABLER", "Tracciatore di intento d'uscita per forzatura di prezzo."),
    "monetate.net": ("Monetate", "DYNAMIC_PRICING_ENABLER", "Motore di personalizzazione dei prezzi e dei cataloghi in tempo reale.")
}

def evaluate_dynamic_pricing_tracker(hostname: str) -> Optional[DynamicPricingMatch]:
    """
    Checks if a hostname belongs to a known dynamic pricing, fingerprinting,
    or session recording network.
    Returns DynamicPricingMatch if flagged, None otherwise.
    """
    if not hostname:
        return None

    h_lower = hostname.lower().strip()

    for tracker_domain, (name, category, desc) in DYNAMIC_PRICING_NETWORKS.items():
        if h_lower == tracker_domain or h_lower.endswith(f".{tracker_domain}"):
            return DynamicPricingMatch(
                domain=h_lower,
                tracker_name=name,
                category=category,
                risk_score=0.75,
                description=desc
            )

    return None
