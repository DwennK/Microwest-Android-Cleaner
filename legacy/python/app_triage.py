"""Repair-shop unwanted-app policy, distinct from verified malware reputation."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from scanner import AppInfo


@dataclass
class TriageProfile:
    score_floor: int = 0
    reasons: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)

    def add(self, family: str, score: int, reason: str) -> None:
        self.score_floor = max(self.score_floor, score)
        self.families.append(family)
        self.reasons.append(reason)


def normalized_words(value: str) -> set[str]:
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    value = unicodedata.normalize("NFKD", value.casefold())
    return set(re.findall(r"[a-z0-9]+", "".join(c for c in value if not unicodedata.combining(c))))


def unwanted_profile(app: AppInfo) -> TriageProfile:
    profile = TriageProfile()
    words = normalized_words(f"{app.display_name()} {app.package_name}")
    label_words = normalized_words(app.app_label) if app.app_label_source == "apk" else set()
    cleaner = bool(words & {
        "cleaner", "cleaners", "nettoyeur", "nettoyage", "booster", "boosters", "optimizer",
        "optimiseur", "optimisation", "cleanmaster", "superclean", "phoneclean", "junkclean",
        "rambooster", "speedbooster", "batterydoctor", "ccleaner", "phonecleaner", "junkcleaner",
    }) or any(pair <= words for pair in (
        {"cpu", "cooler"}, {"battery", "saver"}, {"super", "clean"}, {"sd", "maid"}, {"junk", "removal"},
    )) or (
        bool(words & {"clean", "cleaning", "boost", "cooler"})
        and bool(words & {"phone", "ram", "memory", "junk", "cache", "battery", "storage"})
    )
    if cleaner:
        profile.add("cleaner", 75, "Cleaner/booster tiers : suppression proposée selon la politique de nettoyage de l'atelier, même sans permission dangereuse.")

    # These are operator-reported display names, never a package malware blacklist.
    reported = label_words in ({"rotate", "link"}, {"gold", "miner"})
    hash_clone = app.app_label_source == "apk" and app.app_label.strip().startswith("#") and bool(
        label_words & {"gallery", "galerie", "contact", "contacts"}
    )
    if reported or hash_clone:
        profile.add("reported_name", 70, "Nom correspondant aux applications indésirables signalées par l'atelier ; vérifier l'identité avant suppression (homonymes possibles).")

    pdf = bool(words & {"pdf", "pdfreader", "allpdfreader", "pdfviewer"})
    qr = bool(words & {"qr", "qrcode", "barcode", "qrscanner", "qrreader", "qrcodescanner"})
    clone = bool(label_words) and label_words <= {"gallery", "galerie", "contact", "contacts", "pro", "all"}
    utility = pdf or qr or clone
    if utility:
        profile.add("utility", 35, "Utilitaire PDF/QR ou doublon galerie/contacts tiers : vérifier son utilité et son identité.")
        hype = words & {"all", "super", "ultra", "max", "ultimate", "boost", "cleaner"}
        if hype:
            profile.add("promoted_utility", 65, "Utilitaire au nom racoleur (« all/super/ultra/max ») : indésirable probable selon le tri atelier.")
        try:
            old_qr = qr and 0 < int(app.target_sdk) <= 28
        except (ValueError, TypeError):
            old_qr = False
        if old_qr:
            profile.add("old_qr", 65, "Ancien lecteur QR tiers ciblant Android 9 ou antérieur : suppression proposée si devenu inutile.")
        intrusive = bool(set(app.active_capabilities) & {"overlay", "accessibility", "notification_listener", "install_unknown_apps"})
        if app.has_launcher_entry is False or intrusive:
            profile.add("intrusive_utility", 80, "Utilitaire peu visible ou doté d'accès intrusifs actifs : profil prioritaire de publicité indésirable.")

    if app.is_home_app:
        profile.add("home", 40, "Application capable de remplacer l'écran d'accueil.")
    if app.is_default_home:
        profile.add("default_home", 50, "Cette application est actuellement l'écran d'accueil par défaut : vérifier ce remplacement avec le client.")
        if utility or cleaner or reported or hash_clone:
            profile.add("disguised_home", 90, "Un utilitaire ou une application signalée occupe le rôle d'écran d'accueil : rétablir l'accueil souhaité puis proposer sa suppression.")
    reward = bool(words & {"cash", "reward", "rewards", "earn", "money", "payout", "jackpot"})
    if reward:
        profile.add("reward", 40, "Promesse de gains/récompenses : examiner le risque de publicité et d'arnaque.")
        if words & {"miner", "mining", "gold", "lucky", "win", "spin"}:
            profile.add("reward_bait", 70, "Jeu/minage combiné à une promesse de gains : application indésirable probable selon le tri atelier.")
    return profile
