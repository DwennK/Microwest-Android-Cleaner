from __future__ import annotations

import runpy
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from apk_metadata import ApkMetadataExtractor, parse_aapt2_badging

install_aapt2 = runpy.run_path(str(Path(__file__).resolve().parents[1] / "packaging/install_aapt2.py"))["install"]


def test_aapt2_finds_sdk_without_shell_path():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        binary = root / "sdk/build-tools/36.0.0/aapt2"
        binary.parent.mkdir(parents=True)
        binary.touch()
        binary.chmod(0o755)
        with patch.dict("os.environ", {"ANDROID_HOME": str(root / "sdk")}, clear=True), patch("apk_metadata.shutil.which", return_value=None):
            assert ApkMetadataExtractor(root).aapt2_path == str(binary)


def test_real_french_label_is_preserved_including_hash():
    metadata = parse_aapt2_badging("package: name='example.gallery' versionName='1'\napplication-label:'#GALLERY'\napplication-label-fr:'#GALERIE'\nsdkVersion:'21'\n")
    assert metadata.label == "#GALERIE"
    assert metadata.package_name == "example.gallery"


def test_installer_refuses_unverified_archive(tmp_path):
    with patch("urllib.request.urlopen") as request:
        request.return_value.__enter__.return_value.read.return_value = b"corrupt archive"
        with pytest.raises(RuntimeError, match="SHA-256"):
            install_aapt2(tmp_path)
    assert not list(tmp_path.iterdir())
