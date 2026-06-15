from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from dotenv import load_dotenv


LOGGER = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "Tu es un assistant de diagnostic Android pour un magasin de réparation smartphone. "
    "Tu classes les applications installées selon leur risque publicitaire/arnaque/adware. "
    "Tu ne dois jamais affirmer qu'une app est malveillante avec certitude sans preuve. "
    "Tu dois baser ton analyse uniquement sur les métadonnées fournies. "
    "Tu dois être prudent avec les apps système Samsung/Google. "
    "Réponds uniquement en JSON valide."
)


@dataclass(slots=True)
class AIResult:
    risk_score: int
    category: str
    recommended_action: str
    reason_fr: str
    confidence: str


class AIAnalyzer:
    def __init__(self) -> None:
        load_dotenv()
        self.provider = os.getenv("AI_PROVIDER", "openai").strip().lower()
        if self.provider == "minimax":
            self.api_key = os.getenv("MINIMAX_API_KEY", "").strip()
            self.model = os.getenv("MINIMAX_MODEL", "MiniMax-M3").strip()
            self.base_url = os.getenv("MINIMAX_BASE_URL", "https://api.minimax.io/v1").strip()
        else:
            self.provider = "openai"
            self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
            self.model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()
            self.base_url = os.getenv("OPENAI_BASE_URL", "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    @property
    def provider_label(self) -> str:
        return "MiniMax" if self.provider == "minimax" else "OpenAI"

    def analyze(self, apps: list[dict[str, Any]]) -> dict[str, AIResult]:
        if not self.enabled:
            key_name = "MINIMAX_API_KEY" if self.provider == "minimax" else "OPENAI_API_KEY"
            raise RuntimeError(f"{key_name} absent. Ajoutez une clé dans le fichier .env pour activer l'analyse IA.")
        if not apps:
            return {}

        from openai import OpenAI

        client_kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        client = OpenAI(**client_kwargs)
        payload = {
            "instruction": "Analyse ces applications préfiltrées et retourne un objet JSON avec une clé apps.",
            "format": {
                "apps": [
                    {
                        "package_name": "string",
                        "risk_score": "integer 0-100",
                        "category": "string",
                        "recommended_action": "string",
                        "reason_fr": "string court en français",
                        "confidence": "low|medium|high",
                    }
                ]
            },
            "apps": apps,
        }
        request = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            "temperature": 0.1,
        }
        try:
            response = client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                **request,
            )
        except Exception:  # noqa: BLE001 - some OpenAI-compatible providers reject response_format.
            if self.provider != "minimax":
                raise
            LOGGER.info("MiniMax rejected response_format; retrying with JSON prompt only.")
            response = client.chat.completions.create(model=self.model, **request)
        content = response.choices[0].message.content or "{}"
        return self._parse_response(content)

    def _parse_response(self, content: str) -> dict[str, AIResult]:
        try:
            raw = json.loads(content)
        except json.JSONDecodeError:
            LOGGER.exception("OpenAI response was not valid JSON: %s", content)
            return {}

        entries = raw.get("apps", raw if isinstance(raw, list) else [])
        results: dict[str, AIResult] = {}
        for item in entries:
            if not isinstance(item, dict):
                continue
            package_name = str(item.get("package_name", "")).strip()
            if not package_name:
                continue
            try:
                score = int(item.get("risk_score", 0))
            except (TypeError, ValueError):
                score = 0
            confidence = str(item.get("confidence", "low")).lower()
            if confidence not in {"low", "medium", "high"}:
                confidence = "low"
            results[package_name] = AIResult(
                risk_score=max(0, min(100, score)),
                category=str(item.get("category", "unknown_review_manually")),
                recommended_action=str(item.get("recommended_action", "review")),
                reason_fr=str(item.get("reason_fr", "Analyse IA non détaillée.")),
                confidence=confidence,
            )
        return results


def ai_payload_from_row(row: dict[str, Any]) -> dict[str, Any]:
    app = row["app"]
    risk = row["risk"]
    return {
        "app_name": app.display_name(),
        "app_name_source": app.app_label_source,
        "package_name": app.package_name,
        "installer": app.installer,
        "permissions_sensibles": app.sensitive_permissions,
        "is_system_app": app.is_system_app,
        "has_launcher_entry": app.has_launcher_entry,
        "hidden_audit": app.hidden_audit,
        "notification_audit": app.notification_audit,
        "local_risk_score": risk.score,
        "local_reasons": risk.reasons,
        "version": app.version_name,
        "target_sdk": app.target_sdk,
        "install_date": app.install_date,
    }
