from __future__ import annotations

import unittest
from unittest.mock import patch

from adb_client import DeviceInfo
from ai_analyzer import AIAnalyzer, AIResult, ai_candidates, analyze_in_batches, apply_ai_result, extract_json_payload
from risk_rules import ReputationLookup, RiskResult
from scanner import AppInfo
from workflow_helpers import build_action_plan, scan_summary


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
    def test_list_response_is_supported_and_invalid_response_is_not_a_success(self) -> None:
        analyzer = AIAnalyzer({})
        self.assertIn("com.test", analyzer._parse_response('[{"package_name":"com.test","risk_score":70}]'))
        for content in ('not JSON', '{}', '{"apps": {}}', 'null'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                analyzer._parse_response(content)

    def test_all_user_apps_are_candidates_even_with_zero_local_score(self) -> None:
        rows = [
            {"app": AppInfo(package_name="test.user", app_label="#GALLERY"),
             "risk": RiskResult(0, "safe", "keep")},
            {"app": AppInfo(package_name="test.system", is_system_app=True),
             "risk": RiskResult(0, "safe", "keep")},
        ]
        self.assertEqual([app["package_name"] for app in ai_candidates(rows)], ["test.user"])

    def test_ai_suggestion_reaches_summary_and_action_plan_without_dangerous_permissions(self) -> None:
        row = {"app": AppInfo(package_name="test.pdf", app_label="PDF READER ALL PRO"),
               "risk": RiskResult(0, "safe", "keep", ["Score local faible."])}
        verdict = AIResult(80, "unwanted", "suggest_uninstall", "Faux utilitaire probable.", "medium")
        apply_ai_result(row, verdict)
        self.assertEqual(row["risk"].recommended_action, "suggest_uninstall")
        self.assertEqual(scan_summary([row])["high"], 1)
        self.assertIn("Faux utilitaire probable", build_action_plan(DeviceInfo(), [row]))
        apply_ai_result(row, verdict)
        self.assertEqual(len(row["risk"].reasons), 2)
        self.assertEqual(ai_candidates([row])[0]["local_risk_score"], 0)
        apply_ai_result(row, AIResult(10, "safe", "keep", "Révision.", "high"))
        self.assertEqual(row["risk"].score, 0)

    def test_low_confidence_cannot_propose_uninstall_and_local_signals_are_preserved(self) -> None:
        row = {"app": AppInfo(package_name="test.user"), "risk": RiskResult(0, "safe", "keep")}
        apply_ai_result(row, AIResult(95, "unwanted", "suggest_uninstall", "Identité incertaine.", "low"))
        self.assertEqual(row["risk"].recommended_action, "review")
        self.assertLess(row["risk"].score, 60)
        row = {"app": AppInfo(package_name="test.user"), "risk": RiskResult(90, "adware", "suggest_uninstall")}
        apply_ai_result(row, AIResult(5, "safe", "keep", "Avis IA.", "high"))
        self.assertEqual(row["risk"].score, 90)

    def test_system_whitelist_and_human_keep_are_preserved(self) -> None:
        verdict = AIResult(95, "unwanted", "suggest_uninstall", "Avis IA.", "high")
        for system, validation, whitelisted in [(True, "unreviewed", False), (False, "keep", False), (False, "unreviewed", True)]:
            row = {"app": AppInfo(package_name="test.app", is_system_app=system),
                   "risk": RiskResult(0, "safe", "keep"), "validation": validation}
            apply_ai_result(row, verdict, ReputationLookup(whitelisted=whitelisted))
            self.assertEqual(row["risk"].recommended_action, "keep")

    def test_missing_verdict_is_retried_and_unrequested_packages_are_ignored(self) -> None:
        analyzer = FakeAnalyzer()
        verdict = AIResult(30, "review", "review", "test", "low")
        with patch.object(analyzer, "analyze", side_effect=[{"unknown": verdict}, {"test.app": verdict}]):
            results = analyze_in_batches(analyzer, [{"package_name": "test.app"}])
        self.assertEqual(list(results), ["test.app"])
        with patch.object(analyzer, "analyze", return_value={}), self.assertRaisesRegex(ValueError, "incomplète"):
            analyze_in_batches(analyzer, [{"package_name": "test.app"}])

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
