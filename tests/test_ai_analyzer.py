from __future__ import annotations

import unittest

from ai_analyzer import AIAnalyzer, extract_json_payload


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


if __name__ == "__main__":
    unittest.main()
