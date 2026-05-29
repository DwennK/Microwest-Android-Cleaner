from __future__ import annotations

import re
from dataclasses import dataclass, field

from scanner import AppInfo, installed_recently


SAFE_INSTALLERS = {
    "com.android.vending": "Google Play",
    "com.sec.android.app.samsungapps": "Galaxy Store",
}

OFFICIAL_PREFIXES = (
    "com.google.",
    "com.android.",
    "com.samsung.",
    "com.sec.",
    "com.microsoft.",
)

KNOWN_SYSTEM_SAFE_PREFIXES = (
    "android",
    "com.android.",
    "com.google.",
    "com.google.android.",
    "com.samsung.",
    "com.sec.",
    "com.sec.android.",
    "com.microsoft.",
)

SUSPICIOUS_WORDS = (
    "cleaner",
    "clean",
    "nettoyeur",
    "nettoyage",
    "optimiseur",
    "optimisation",
    "booster",
    "boost",
    "speed",
    "ram",
    "cpu cooler",
    "cooler",
    "antivirus",
    "virus",
    "malware",
    "security",
    "secure",
    "safe",
    "privacy",
    "lock",
    "applock",
    "vpn",
    "proxy",
    "weather",
    "meteo",
    "météo",
    "forecast",
    "battery",
    "saver",
    "phone",
    "call",
    "contacts",
    "pdf",
    "scanner",
    "qr",
    "file manager",
    "filemanager",
    "launcher",
    "horoscope",
    "wallpaper",
    "flashlight",
    "torch",
    "keyboard",
    "emoji",
    "photo recovery",
    "wifi",
    "update",
    "service",
)

CLEANER_BAIT_WORDS = (
    "cleaner",
    "clean",
    "nettoyeur",
    "nettoyage",
    "booster",
    "boost",
    "speed",
    "ram",
    "cpu cooler",
    "cooler",
    "battery",
    "saver",
    "optimizer",
    "optimiseur",
    "optimisation",
)

SCAM_BAIT_WORDS = (
    "cash",
    "loan",
    "credit",
    "win",
    "winner",
    "lucky",
    "reward",
    "earn",
    "money",
    "gift",
    "cadeau",
    "prix",
    "gratuit",
    "free",
    "lottery",
    "casino",
    "bonus",
)

GENERIC_SYSTEM_NAMES = (
    "contacts",
    "phone",
    "cleaner",
    "weather",
    "security",
    "update",
    "system service",
    "android service",
    "google service",
    "samsung service",
    "software update",
    "phone service",
    "contact service",
)

HIGH_RISK_PERMISSION_MARKERS = (
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
    "BIND_DEVICE_ADMIN",
    "POST_NOTIFICATIONS",
)

OFFICIAL_IMPERSONATION_PREFIXES = (
    "android.",
    "com.android.",
    "com.google.",
    "com.samsung.",
    "com.sec.",
    "com.microsoft.",
)


@dataclass(slots=True)
class ReputationLookup:
    whitelisted: bool = False
    blacklisted: bool = False
    blacklist_severity: int = 50
    reason: str = ""


@dataclass(slots=True)
class RiskResult:
    score: int
    category: str
    recommended_action: str
    reasons: list[str] = field(default_factory=list)


def evaluate_app(app: AppInfo, reputation: ReputationLookup | None = None) -> RiskResult:
    reputation = reputation or ReputationLookup()
    score = 0
    reasons: list[str] = []

    if app.is_system_app and is_known_system_package(app.package_name):
        return RiskResult(
            score=0,
            category="do_not_touch_system",
            recommended_action="do_not_touch",
            reasons=["Application système officielle Samsung/Google/Microsoft : ne pas supprimer."],
        )

    if reputation.blacklisted:
        score += max(50, reputation.blacklist_severity)
        reasons.append(f"Présent dans la blacklist locale. {reputation.reason}".strip())

    if reputation.whitelisted:
        score -= 80
        reasons.append("Présent dans la whitelist locale.")

    sensitive_count = len(app.sensitive_permissions)
    has_suspicious_name = contains_any(label_and_package(app), SUSPICIOUS_WORDS)
    has_cleaner_bait = contains_any(label_and_package(app), CLEANER_BAIT_WORDS)
    has_scam_bait = contains_any(label_and_package(app), SCAM_BAIT_WORDS)
    has_unknown_installer = not app.installer or app.installer not in SAFE_INSTALLERS
    has_hidden_profile = bool(app.hidden_audit) and app.has_launcher_entry is False
    has_notification_profile = bool(app.notification_audit)

    if app.has_accessibility:
        score += 35
        reasons.append("Service d'accessibilité détecté.")

    if app.has_overlay or _has_permission(app, "SYSTEM_ALERT_WINDOW"):
        score += 30
        reasons.append("Permission overlay SYSTEM_ALERT_WINDOW détectée.")

    dangerous = [p for p in app.sensitive_permissions if any(marker in p for marker in HIGH_RISK_PERMISSION_MARKERS)]
    if dangerous:
        score += 25
        reasons.append("Permissions sensibles SMS/appels/contacts/admin/notifications détectées.")

    if sensitive_count >= 5:
        score += 20
        reasons.append("Nombre élevé de permissions sensibles.")

    if not app.installer:
        score += 20
        reasons.append("Installateur inconnu ou vide.")
    elif app.installer in SAFE_INSTALLERS:
        score -= 20
        reasons.append(f"Installé via {SAFE_INSTALLERS[app.installer]}.")

    if has_suspicious_name:
        score += 20
        reasons.append("Nom ou package contenant un mot souvent associé à adware/scam.")

    if has_scam_bait:
        score += 20
        reasons.append("Nom évoquant gain, cadeau, crédit ou récompense : signal courant d'arnaque.")

    normalized_label = app.display_name().strip().lower()
    if any(name == normalized_label or name in label_and_package(app) for name in GENERIC_SYSTEM_NAMES):
        score += 15
        reasons.append("Nom générique pouvant imiter une application système.")

    if installed_recently(app.install_date):
        score += 15
        reasons.append("Application installée récemment.")

    if app.has_accessibility and not reputation.whitelisted:
        score += 30
        reasons.append("Accessibilité demandée sans whitelist locale.")

    if app.has_device_admin:
        score += 30
        reasons.append("Fonction administrateur de l'appareil détectée.")

    if app.has_notification_listener:
        score += 35
        reasons.append("Accès aux notifications détecté.")

    if app.requests_post_notifications and has_suspicious_name:
        score += 15
        reasons.append("Demande notifications avec nom suspect.")

    if has_notification_profile and len(app.notification_audit) >= 3 and not reputation.whitelisted:
        score += 20
        reasons.append("Profil notification/spam potentiel : " + ", ".join(app.notification_audit[:4]) + ".")

    if app.can_install_unknown_apps:
        score += 25
        reasons.append("Peut demander l'installation d'apps inconnues.")

    if app.has_usage_stats:
        score += 20
        reasons.append("Accès aux statistiques d'utilisation détecté.")

    if app.has_vpn_service and has_unknown_installer:
        score += 20
        reasons.append("Service VPN/proxy hors installateur de confiance.")

    if app.runs_at_boot and has_suspicious_name:
        score += 15
        reasons.append("Se lance au démarrage et porte un nom suspect.")

    if app.has_launcher_entry is False and not app.is_system_app:
        score += 20
        reasons.append("Application utilisateur sans icône visible dans le launcher.")

    if has_hidden_profile and (has_unknown_installer or has_suspicious_name):
        score += 25
        reasons.append("Profil peu visible combiné à installateur inconnu ou nom suspect.")

    if app.has_launcher_entry is False and (app.has_notification_listener or app.requests_post_notifications or app.has_overlay):
        score += 25
        reasons.append("App peu visible avec accès notifications ou overlay.")

    if looks_generic_identity(app) and (has_unknown_installer or app.has_launcher_entry is False):
        score += 15
        reasons.append("Nom ou icône générique avec visibilité faible.")

    if has_cleaner_bait and (app.has_overlay or app.has_accessibility or app.has_notification_listener):
        score += 30
        reasons.append("Combinaison cleaner/booster avec overlay, accessibilité ou notifications.")

    if has_unknown_installer and has_suspicious_name and dangerous:
        score += 25
        reasons.append("Installateur non fiable + nom suspect + permissions sensibles.")

    if target_sdk_is_old(app.target_sdk):
        score += 15
        reasons.append("Application ciblant une ancienne version Android.")

    if looks_random_or_generic(app.package_name):
        score += 20
        reasons.append("Package très générique ou semblant aléatoire.")

    if impersonates_official_namespace(app):
        score += 35
        reasons.append("Package utilisateur imitant un espace système Google/Samsung/Android.")

    if is_official_package(app):
        score -= 50
        reasons.append("Package officiel connu Google/Samsung/Microsoft.")

    score = max(0, min(100, score))
    category, action = classify(score, app, reputation)
    if not reasons:
        reasons.append("Aucun signal de risque notable détecté.")
    return RiskResult(score=score, category=category, recommended_action=action, reasons=reasons)


def classify(score: int, app: AppInfo, reputation: ReputationLookup) -> tuple[str, str]:
    if app.is_system_app and is_known_system_package(app.package_name):
        return "do_not_touch_system", "do_not_touch"
    if reputation.whitelisted or score < 15:
        return "safe", "keep"
    if score < 30:
        return "probably_safe", "keep"
    if app.is_system_app:
        return "do_not_touch_system", "do_not_touch"
    if score < 60:
        return "unknown_review_manually", "review"
    if app.has_accessibility or app.has_device_admin:
        return "spyware_suspect", "suggest_uninstall"
    if app.can_install_unknown_apps or contains_any(label_and_package(app), SCAM_BAIT_WORDS):
        return "scam_suspect", "suggest_uninstall"
    if app.has_launcher_entry is False or app.notification_audit:
        return "adware_suspect", "suggest_uninstall"
    if any(word in label_and_package(app) for word in ("clean", "boost", "weather", "battery", "security", "vpn", "proxy")):
        return "adware_suspect", "suggest_uninstall"
    return "scam_suspect", "suggest_uninstall"


def _has_permission(app: AppInfo, marker: str) -> bool:
    return any(marker in permission for permission in app.sensitive_permissions)


def label_and_package(app: AppInfo) -> str:
    return f"{app.display_name()} {app.package_name}".lower()


def contains_any(text: str, words: tuple[str, ...]) -> bool:
    return any(word in text for word in words)


def is_official_package(app: AppInfo) -> bool:
    return app.is_system_app and app.package_name.startswith(OFFICIAL_PREFIXES)


def impersonates_official_namespace(app: AppInfo) -> bool:
    if app.is_system_app:
        return False
    return app.package_name.startswith(OFFICIAL_IMPERSONATION_PREFIXES)


def target_sdk_is_old(target_sdk: str) -> bool:
    try:
        return int(target_sdk) <= 26
    except (TypeError, ValueError):
        return False


def looks_generic_identity(app: AppInfo) -> bool:
    generic_labels = {
        "app",
        "service",
        "system",
        "update",
        "android",
        "tools",
        "manager",
        "phone",
        "contacts",
        "security",
        "cleaner",
        "weather",
    }
    label = app.display_name().strip().lower()
    return label in generic_labels or not app.icon_path or app.app_label_source != "apk"


def is_known_system_package(package_name: str) -> bool:
    return package_name == "android" or package_name.startswith(KNOWN_SYSTEM_SAFE_PREFIXES)


def looks_random_or_generic(package_name: str) -> bool:
    parts = package_name.split(".")
    if len(parts) < 2:
        return True
    tail = parts[-1]
    if tail in {"app", "service", "update", "system", "android", "tools", "manager"}:
        return True
    if re.fullmatch(r"[a-z]{1,3}\d{2,}[a-z0-9]*", tail):
        return True
    if re.fullmatch(r"[a-z0-9]{12,}", tail) and not re.search(r"[aeiou]{2}", tail):
        return True
    return False
