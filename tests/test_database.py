from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from database import CURRENT_SCHEMA_VERSION, ReputationDatabase


class ReputationDatabaseTests(unittest.TestCase):
    def test_initialize_sets_schema_version_and_default_whitelist(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = ReputationDatabase(Path(temp_dir) / "reputation.sqlite")

            with db.connect() as con:
                version = con.execute("PRAGMA user_version").fetchone()[0]

            self.assertEqual(version, CURRENT_SCHEMA_VERSION)
            self.assertTrue(db.is_whitelisted("com.whatsapp"))


if __name__ == "__main__":
    unittest.main()
