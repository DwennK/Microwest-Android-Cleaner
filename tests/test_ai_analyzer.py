from __future__ import annotations

import unittest
from unittest.mock import patch

from ai_analyzer import AIAnalyzer, AIResult, analyze_in_batches, extract_json_payload


class FakeAnalyzer:
    def __init__(self) -> None:
        self.batch_sizes: list[int] = []

    def analyze(self, apps: list[dict]) -> dict[str, AIResult]:
        self.batch_sizes.append(len(apps))
        return {
            app["package_name"]: AIResult(30, "review", "review", "test", "low")
            for app in apps
        }


class AIAnalyzerTests(unittest.TestCase):
    def test_extract_json_payload_from_markdown_fence(self) -> None:
        content = """```json
{"apps": [{"package_name": "com.test", "risk_score": 42}]}
```"""

        self.assertEqual(extract_json_payload(content), '{"apps": [{"package_name": "com.test", "risk_score": 42}]}')

    def test_parse_response_normalizes_invalid_fields(self) -> None:
        analyzer = AIAnalyzer({})

        result = analyzer._parse_response(
            """
            Voici le JSON:
            {"apps": [{"package_name": "com.test", "risk_score": 140, "recommended_action": "delete",
            "confidence": "certain", "reason_fr": "x"}]}
            """
        )

        self.assertEqual(result["com.test"].risk_score, 100)
        self.assertEqual(result["com.test"].recommended_action, "review")
        self.assertEqual(result["com.test"].confidence, "low")

    def test_analyze_in_batches_keeps_every_candidate(self) -> None:
        analyzer = FakeAnalyzer()
        apps = [{"package_name": f"com.test.app{index}"} for index in range(85)]

        results = analyze_in_batches(analyzer, apps, batch_size=40)

        self.assertEqual(analyzer.batch_sizes, [40, 40, 5])
        self.assertEqual(len(results), 85)

    def test_ui_settings_select_provider_model_and_base_url(self) -> None:
        with patch.dict("os.environ", {"MINIMAX_API_KEY": "test-key"}, clear=True):
            analyzer = AIAnalyzer(
                {
                    "ai_provider": "minimax",
                    "minimax_model": "custom-model",
                    "minimax_base_url": "https://example.test/v1",
                }
            )

        self.assertEqual(analyzer.provider, "minimax")
        self.assertEqual(analyzer.model, "custom-model")
        self.assertEqual(analyzer.base_url, "https://example.test/v1")
        self.assertTrue(analyzer.enabled)


if __name__ == "__main__":
    unittest.main()
