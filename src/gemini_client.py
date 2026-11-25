import asyncio
import json
import logging
from typing import Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("sentinel.gemini")

class DomainClassification(BaseModel):
    classification: str = Field(description="TELEMETRY, DGA_MALWARE, BENIGN, or SUSPICIOUS")
    risk_score: float = Field(description="Risk score between 0.0 and 1.0")
    summary: str = Field(description="Brief explanation of the domain purpose and threat")
    suggested_rule: str = Field(description="AdGuard Home filtering rule syntax")

class GeminiClassifier:
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash", timeout_sec: float = 5.0):
        self.api_key = api_key
        self.model = model
        self.timeout_sec = timeout_sec
        self._client = None
        if self.api_key:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Could not initialize google-genai client: {e}")

    async def classify_domain(self, domain: str, client_ip: str, entropy: float, 
                              burst_count: int, is_dga: bool) -> DomainClassification:
        """
        Classifies domain using Gemini API with timeout and robust heuristic fallback.
        """
        prompt = f"""You are a DNS threat intelligence and privacy auditor for a smart home network.
Analyze the following flagged domain observed on the home network:
- Target Domain: {domain}
- Shannon Entropy Score: {entropy}
- Query Velocity: {burst_count} queries in last minute
- Heuristic Trigger: {'High-Entropy DGA' if is_dga else 'Velocity Beacon Burst'}

Classify the domain and return JSON with:
- classification: "TELEMETRY" (OEM TV/app/device tracking), "DGA_MALWARE" (botnet/C2), "BENIGN" (false positive), or "SUSPICIOUS"
- risk_score: float 0.0 to 1.0
- summary: concise description (1-2 sentences in Italian or English)
- suggested_rule: standard AdGuard Home rule syntax (e.g. ||domain.com^ or ||domain.com^$client={client_ip})
"""

        try:
            return await asyncio.wait_for(
                self._call_gemini_api(prompt, domain, client_ip, is_dga),
                timeout=self.timeout_sec
            )
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"Gemini evaluation failed or timed out for {domain}: {e}. Falling back to local heuristics.")
            return self._heuristic_fallback(domain, client_ip, entropy, burst_count, is_dga)

    async def _call_gemini_api(self, prompt: str, domain: str, client_ip: str, is_dga: bool) -> DomainClassification:
        if not self._client:
            raise RuntimeError("Gemini client not initialized")

        from google.genai import types

        # Use native async client to prevent thread pool exhaustion and zombie threads on timeout
        response = await self._client.aio.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=DomainClassification,
                temperature=0.2,
            )
        )
        data = json.loads(response.text)
        return DomainClassification(**data)

    def _heuristic_fallback(self, domain: str, client_ip: str, entropy: float, 
                            burst_count: int, is_dga: bool) -> DomainClassification:
        if is_dga:
            return DomainClassification(
                classification="DGA_MALWARE",
                risk_score=0.85,
                summary=f"Dominio algoritmico sospetto (Entropia H={entropy:.2f}). Possibile DGA / C2.",
                suggested_rule=f"||{domain}^"
            )
        else:
            return DomainClassification(
                classification="TELEMETRY",
                risk_score=0.50,
                summary=f"Raffica di query anomala ({burst_count} query/min) rilevata dal dispositivo {client_ip}.",
                suggested_rule=f"||{domain}^$client={client_ip}"
            )
