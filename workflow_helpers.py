from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Any

from adb_client import DeviceInfo
from risk_rules import SAFE_INSTALLERS
from scanner import AppInfo


def launcher_text(app: AppInfo) -> str:
    if app.has_launcher_entry is True:
        return "oui"
    if app.has_launcher_entry is False:
        return "non"
    return "non vérifié"


def is_hidden_or_low_visibility(app: AppInfo) -> bool:
    return app.has_launcher_entry is False or "Nom tres generique" in _normalized_audits(app)


def is_sideloaded(app: AppInfo) -> bool:
    return not app.installer or app.installer not in SAFE_INSTALLERS


def priority_text(row: dict[str, Any]) -> str:
    app: AppInfo = row["app"]
    risk = row["risk"]
    if risk.recommended_action == "do_not_touch" or app.is_system_app:
        return "Protégée"
    if risk.score >= 80:
        return "Urgent"
    if risk.score >= 60:
        return "À traiter"
    if risk.recommended_action == "review" or risk.score >= 30:
        return "À vérifier"
    return "OK"


def scan_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(rows),
        "high": len(
            [
                row
                for row in rows
                if row["risk"].score >= 60
                and row["risk"].recommended_action != "do_not_touch"
                and not row["app"].is_system_app
            ]
        ),
        "review": len([row for row in rows if row["risk"].recommended_action == "review"]),
        "hidden": len([row for row in rows if is_hidden_or_low_visibility(row["app"])]),
        "sideload": len([row for row in rows if is_sideloaded(row["app"])]),
    }


def build_action_plan(
    device: DeviceInfo,
    rows: list[dict[str, Any]],
    selected_rows: list[dict[str, Any]] | None = None,
) -> str:
    selected_rows = selected_rows or []
    candidates = selected_rows or [
        row
        for row in rows
        if row["risk"].score >= 60 and row["risk"].recommended_action != "do_not_touch" and not row["app"].is_system_app
    ]
    review_rows = [row for row in rows if row["risk"].recommended_action == "review" and row not in candidates]
    summary = scan_summary(rows)
    lines = [
        "Microwest Android Cleaner - Plan d'action",
        f"Date : {datetime.now().strftime('%d.%m.%Y %H:%M')}",
        f"Téléphone : {device.manufacturer} {device.model}".strip(),
        f"Android : {device.android_version or '-'}",
        f"ADB : {device.serial or '-'}",
        "",
        "Synthèse",
        f"- Apps scannées : {summary['total']}",
        f"- À traiter : {summary['high']}",
        f"- À vérifier : {summary['review']}",
        f"- Apps cachées/faible visibilité : {summary['hidden']}",
        f"- Sideload/installateur inconnu : {summary['sideload']}",
        "",
        "Applications proposées pour validation humaine",
    ]
    if not candidates:
        lines.append("- Aucune application à traiter automatiquement sélectionnée.")
    for row in candidates:
        app: AppInfo = row["app"]
        risk = row["risk"]
        lines.extend(
            [
                f"- {app.display_name()} ({app.package_name})",
                f"  Score : {risk.score} - {risk.category}",
                f"  Validation technicien : {row.get('validation', 'unreviewed')}",
                f"  Raisons : {'; '.join(risk.reasons[:4])}",
                f"  Commande après validation : adb shell pm uninstall --user 0 {app.package_name}",
            ]
        )
        if row.get("note"):
            lines.append(f"  Note : {row['note']}")
    lines.extend(["", "Applications à vérifier manuellement"])
    if not review_rows:
        lines.append("- Aucune.")
    for row in review_rows[:20]:
        app = row["app"]
        risk = row["risk"]
        lines.append(f"- {app.display_name()} ({app.package_name}) - score {risk.score} - {'; '.join(risk.reasons[:3])}")
    lines.extend(
        [
            "",
            "Rappel sécurité",
            "- Ne pas désinstaller sans validation humaine.",
            "- Ne pas utiliser adb root, su, rm ou commandes destructrices.",
            "- Vérifier l'écran du téléphone si ADB passe en unauthorized/offline.",
        ]
    )
    return "\n".join(lines)


def permission_matches(app: AppInfo, query: str) -> bool:
    requested = app.requested_permissions or app.sensitive_permissions
    haystack = " ".join(requested + app.granted_permissions + app.active_capabilities + app.notification_audit + app.hidden_audit).upper()
    flags = {
        "ACCESSIBILITY": app.has_accessibility,
        "NOTIFICATION": app.has_notification_listener or app.requests_post_notifications,
        "OVERLAY": app.has_overlay,
        "DEVICE_ADMIN": app.has_device_admin,
        "VPN": app.has_vpn_service,
    }
    if query in flags:
        return flags[query] or query in haystack
    return query in haystack


def hidden_summary(app: AppInfo) -> str:
    if app.has_launcher_entry is False:
        return "Sans launcher"
    if "Nom tres generique" in _normalized_audits(app):
        return "Nom générique"
    if app.hidden_audit:
        return "À vérifier"
    return "-"


def notification_summary(app: AppInfo) -> str:
    if not app.notification_audit:
        return "-"
    return ", ".join(app.notification_audit[:2])


def _normalized_audits(app: AppInfo) -> set[str]:
    return {_ascii_fold(value) for value in app.hidden_audit}


def _ascii_fold(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(char for char in normalized if not unicodedata.combining(char))
