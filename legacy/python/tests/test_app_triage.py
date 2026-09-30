from __future__ import annotations

import pytest

from ai_analyzer import AIResult, ai_payload_from_row, apply_ai_result
from app_triage import unwanted_profile
from risk_rules import ReputationLookup, evaluate_app
from scanner import AppInfo


def sample(label: str, **kwargs) -> AppInfo:
    return AppInfo(package_name=kwargs.pop("package_name", "example.vendor.utility"), app_label=label,
                   app_label_source="apk", installer="com.android.vending", has_launcher_entry=True, **kwargs)


@pytest.mark.parametrize("label", [
    "Phone Cleaner", "Super Clean", "RAM Booster", "Battery Saver", "CPU Cooler", "Nettoyeur",
    "CCleaner", "SD Maid", "ALL PDF READER", "PDF READER ALL PRO", "QR Scanner Ultra",
    "#GALLERY", "#CONTACT", "Rotate Link", "Gold Miner", "Lucky Cash Miner",
    "AllPDFReader", "PhoneCleaner",
])
def test_unwanted_profiles_are_proposed_even_from_play_without_sensitive_permissions(label):
    app = sample(label)
    risk = evaluate_app(app)
    assert risk.score >= 60
    assert risk.recommended_action == "suggest_uninstall"
    assert risk.category == "unwanted_utility"


@pytest.mark.parametrize("label,package", [
    ("Adobe Acrobat", "com.adobe.reader"), ("Foxit PDF", "com.foxit.mobile.pdf.lite"),
    ("Binary Eye", "de.markusfisch.android.binaryeye"), ("QR Scanner", "org.example.qr"),
    ("Gallery", "org.example.gallery"), ("Contacts", "org.example.contacts"),
    ("Instagram", "com.instagram.android"), ("Telegram", "org.telegram.messenger"),
    ("Battery Monitor", "org.example.battery"), ("Gold Puzzle", "org.example.puzzle"),
])
def test_coherent_apps_are_not_proposed_for_removal_on_role_alone(label, package):
    risk = evaluate_app(sample(label, package_name=package))
    assert risk.recommended_action != "suggest_uninstall"


def test_old_qr_and_disguised_home_are_prioritized_but_normal_home_is_reviewed():
    assert evaluate_app(sample("QR Reader", target_sdk="28")).recommended_action == "suggest_uninstall"
    assert evaluate_app(sample("PDF Reader", is_home_app=True, is_default_home=True)).score >= 80
    assert evaluate_app(sample("Nova Launcher", is_home_app=True, is_default_home=True)).recommended_action == "review"
    launcher = sample("Dedicated Launcher", is_home_app=True, is_default_home=True)
    launcher.has_launcher_entry = False
    launcher.has_overlay = True
    launcher.active_capabilities = ["overlay"]
    assert evaluate_app(launcher).recommended_action == "review"
    assert evaluate_app(launcher).score < 60
    assert unwanted_profile(sample("PDF Reader", is_default_home=None)).score_floor < 60


def test_samsung_maintenance_whitelist_and_blacklist_take_precedence():
    samsung = sample("Device Cleaner", package_name="com.samsung.android.lool", is_system_app=True)
    assert evaluate_app(samsung).recommended_action == "do_not_touch"
    app = sample("Phone Cleaner")
    assert evaluate_app(app, ReputationLookup(whitelisted=True)).recommended_action == "keep"
    plain = sample("Ordinary App", has_overlay=True)
    assert evaluate_app(plain, ReputationLookup(blacklisted=True)).recommended_action == "suggest_uninstall"
    assert evaluate_app(plain, ReputationLookup(blacklisted=True)).score >= 60


def test_package_only_cleaner_and_missing_metadata_are_distinguished():
    app = AppInfo(package_name="com.vendor.cleanmaster")
    assert evaluate_app(app).recommended_action == "suggest_uninstall"
    unknown = AppInfo(package_name="org.example.documents", installer="com.android.vending")
    assert unwanted_profile(unknown).score_floor == 0
    fake_official = sample("Phone Cleaner", package_name="com.google.android.fakecleaner")
    assert evaluate_app(fake_official).recommended_action == "suggest_uninstall"


def test_local_policy_survives_favorable_ai_and_home_context_reaches_ai():
    app = sample("PDF READER ALL PRO", is_home_app=True, is_default_home=True)
    row = {"app": app, "risk": evaluate_app(app)}
    payload = ai_payload_from_row(row)
    assert payload["is_default_home"] is True
    assert "disguised_home" in payload["profil_atelier"]["familles"]
    apply_ai_result(row, AIResult(0, "safe", "keep", "Opinion différente", "high"))
    assert row["risk"].recommended_action == "suggest_uninstall"
