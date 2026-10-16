import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("prepare-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def fixture(self, root):
        (root / "package.json").write_text('{"version":"2.0.3"}', encoding="utf-8")
        bundle = root / "src-tauri/target/release/bundle/nsis"
        bundle.mkdir(parents=True)
        exe = bundle / "App Name_2.0.3_x64-setup.exe"
        exe.write_bytes(b"installer-fixture")
        Path(str(exe) + ".sig").write_text("signature-fixture", encoding="utf-8")

    def test_manifest_points_to_uploaded_exe_and_preserves_signature(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"GITHUB_REF": "refs/tags/v2.0.3"}):
            root = Path(temp)
            self.fixture(root)
            release.prepare(root)
            output = root / "release-output"
            data = json.loads((output / "latest.json").read_text())
            platform = data["platforms"]["windows-x86_64"]
            name = platform["url"].rsplit("/", 1)[1]
            self.assertEqual((output / name).read_bytes(), b"installer-fixture")
            self.assertEqual(platform["signature"], "signature-fixture")
            self.assertIn(name, (output / "SHA256SUMS.txt").read_text())
            self.assertEqual(len(list(output.glob("*.exe"))), 1)
            self.assertFalse(list(output.glob("*.msi")))

    def test_refuses_wrong_tag(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"GITHUB_REF": "refs/tags/v9.0.0"}):
            root = Path(temp)
            self.fixture(root)
            with self.assertRaisesRegex(ValueError, "tag"):
                release.prepare(root)

    def test_refuses_missing_signature(self):
        with self.assertRaisesRegex(ValueError, "signature"):
            release.manifest("2.0.3", "app.exe", " ")


if __name__ == "__main__":
    unittest.main()
