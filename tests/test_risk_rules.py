from __future__ import annotations

import unittest

from risk_rules import evaluate_app
from scanner import AppInfo


def app(package: str, installer: str = "", label: str = "") -> AppInfo:
    return AppInfo(
        package_name=package,
        app_label=label,
        app_label_source="apk" if label else "package",
        icon_path="/tmp/icon.png" if label else "",
        installer=installer,
        has_launcher_entry=True,
        sensitive_permissions=[
            "android.permission.READ_CONTACTS",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        has_overlay=True,
        requests_post_notifications=True,
        runs_at_boot=True,
    )


class RiskRuleTests(unittest.TestCase):
    def test_trusted_samsung_app_from_update_center_is_kept(self) -> None:
        samsung = app(
            "com.sec.android.easyMover",
            installer="com.sec.android.app.updatecenter",
            label="Smart Switch",
        )
        samsung.can_install_unknown_apps = True

        risk = evaluate_app(samsung)

        self.assertEqual(risk.recommended_action, "keep")
        self.assertEqual(risk.category, "trusted_official")
        self.assertLess(risk.score, 30)

    def test_trusted_google_app_from_play_store_is_kept(self) -> None:
        google = app(
            "com.google.android.keep",
            installer="com.android.vending",
            label="Keep",
        )

        risk = evaluate_app(google)

        self.assertEqual(risk.recommended_action, "keep")
        self.assertEqual(risk.category, "trusted_official")

    def test_untrusted_official_namespace_still_requires_review(self) -> None:
        fake = app("com.samsung.android.cleaner", label="Cleaner")
        fake.has_launcher_entry = False
        fake.hidden_audit = ["Aucune icône launcher visible"]

        risk = evaluate_app(fake)

        self.assertNotEqual(risk.recommended_action, "keep")
        self.assertIn("Package utilisateur imitant un espace système", " ".join(risk.reasons))

    def test_twint_does_not_match_short_win_scam_keyword(self) -> None:
        twint = app("ch.postfinance.twint.android", installer="com.android.vending", label="TWINT")

        risk = evaluate_app(twint)

        self.assertNotIn("gain, cadeau, crédit ou récompense", " ".join(risk.reasons))
        self.assertNotEqual(risk.recommended_action, "suggest_uninstall")

    def test_visible_play_store_app_without_strong_signal_is_reviewed_not_uninstalled(self) -> None:
        banking = app("ch.postfinance.android", installer="com.android.vending", label="PostFinance")

        risk = evaluate_app(banking)

        self.assertEqual(risk.recommended_action, "review")


if __name__ == "__main__":
    unittest.main()
