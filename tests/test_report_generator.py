from __future__ import annotations

import unittest

from database import RiskChange, ScanAppSnapshot, ScanComparison
from report_generator import comparison_section, validation_label


class ReportGeneratorTests(unittest.TestCase):
    def test_before_after_section_lists_operational_changes(self) -> None:
        comparison = ScanComparison(
            current_scan_id=2,
            previous_scan_id=1,
            new_apps=(ScanAppSnapshot("com.example.new", "New", 10, "safe", "keep", "keep"),),
            removed_apps=(
                ScanAppSnapshot("com.example.removed", "Removed", 70, "adware", "suggest_uninstall", "remove"),
            ),
            risk_changes=(RiskChange("com.example.changed", "Changed", 10, 40, "keep", "review"),),
        )

        content = comparison_section(comparison)

        self.assertIn("Nouvelles apps :</strong> 1", content)
        self.assertIn("Apps retirées :</strong> 1", content)
        self.assertIn("10 → 40", content)
        self.assertEqual(validation_label("remove"), "Retirer")


if __name__ == "__main__":
    unittest.main()
