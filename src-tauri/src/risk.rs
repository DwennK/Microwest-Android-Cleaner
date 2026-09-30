use crate::model::{AppInfo, Reputation, Risk};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, sync::LazyLock};
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

pub static CONSTANTS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../reference/constants.json"))
        .expect("checked reference constants")
});
fn words(key: &str) -> Vec<&'static str> {
    CONSTANTS[key]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect()
}
pub fn safe_installer(s: &str) -> bool {
    CONSTANTS["SAFE_INSTALLERS"].get(s).is_some()
}
fn starts(s: &str, key: &str) -> bool {
    words(key).iter().any(|p| s.starts_with(p))
}
fn known_system(s: &str) -> bool {
    s == "android" || starts(s, "KNOWN_SYSTEM_SAFE_PREFIXES")
}
pub fn trusted(a: &AppInfo) -> bool {
    a.is_system_app && known_system(&a.package_name)
        || words("TRUSTED_OFFICIAL_PACKAGES").contains(&a.package_name.as_str())
            && safe_installer(&a.installer)
}
fn impersonates(a: &AppInfo) -> bool {
    !a.is_system_app && !trusted(a) && starts(&a.package_name, "OFFICIAL_IMPERSONATION_PREFIXES")
}
fn text(a: &AppInfo) -> String {
    format!("{} {}", a.display_name(), a.package_name).to_lowercase()
}
pub fn active(a: &AppInfo, cap: &str) -> bool {
    a.active_capabilities.iter().any(|v| v == cap)
}
fn any_active(a: &AppInfo, caps: &[&str]) -> bool {
    caps.iter().any(|c| active(a, c))
}
fn requested(a: &AppInfo) -> &[String] {
    if a.requested_permissions.is_empty() {
        &a.sensitive_permissions
    } else {
        &a.requested_permissions
    }
}
fn boundary(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        (i == 0 || !alnum(text.as_bytes()[i - 1]))
            && (i + word.len() == text.len() || !alnum(text.as_bytes()[i + word.len()]))
    })
}
fn contains(text: &str, key: &str) -> bool {
    words(key).iter().any(|w| boundary(text, w))
}
fn scam(text: &str) -> bool {
    words("SCAM_BAIT_WORDS").iter().any(|w| {
        if w.len() <= 3 {
            boundary(text, w)
        } else {
            text.contains(w)
        }
    })
}
fn dangerous(p: &str) -> bool {
    words("HIGH_RISK_PERMISSION_MARKERS")
        .iter()
        .any(|m| p.contains(m))
}
fn cleaner_profile(a: &AppInfo) -> bool {
    contains(&text(a), "CLEANER_BAIT_WORDS")
        && any_active(a, &["overlay", "accessibility", "notification_listener"])
}
fn strong(a: &AppInfo) -> bool {
    any_active(
        a,
        &[
            "accessibility",
            "device_admin",
            "notification_listener",
            "install_unknown_apps",
        ],
    ) || a.has_launcher_entry == Some(false) && any_active(a, &["overlay", "notifications"])
        || cleaner_profile(a)
}
fn distribution(a: &AppInfo) -> bool {
    let t = text(a);
    !safe_installer(&a.installer)
        || a.has_launcher_entry == Some(false)
        || a.can_install_unknown_apps
        || scam(&t)
        || cleaner_profile(a)
        || impersonates(a)
        || contains(&t, "SUSPICIOUS_WORDS")
            && (a.has_overlay || a.has_notification_listener || a.requests_post_notifications)
}
fn random_package(p: &str) -> bool {
    if !p.contains('.') {
        return true;
    }
    let tail = p.rsplit('.').next().unwrap_or("");
    [
        "app", "service", "update", "system", "android", "tools", "manager",
    ]
    .contains(&tail)
        || Regex::new(r"^[a-z]{1,3}\d{2,}[a-z0-9]*$")
            .unwrap()
            .is_match(tail)
        || Regex::new(r"^[a-z0-9]{12,}$").unwrap().is_match(tail)
            && !Regex::new(r"[aeiou]{2}").unwrap().is_match(tail)
}
pub fn generic_label(s: &str) -> bool {
    [
        "app", "service", "system", "update", "android", "tools", "manager", "phone", "contacts",
        "security", "cleaner", "weather",
    ]
    .contains(&s.trim().to_lowercase().as_str())
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub score_floor: i32,
    pub reasons: Vec<String>,
    pub families: Vec<String>,
}
impl Profile {
    fn add(&mut self, family: &str, score: i32, reason: &str) {
        self.score_floor = self.score_floor.max(score);
        self.families.push(family.into());
        self.reasons.push(reason.into());
    }
}
fn normalized_words(s: &str) -> HashSet<String> {
    let split = Regex::new(r"([a-z])([A-Z])")
        .unwrap()
        .replace_all(s, "$1 $2");
    let folded: String = split
        .to_lowercase()
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .collect();
    Regex::new(r"[a-z0-9]+")
        .unwrap()
        .find_iter(&folded)
        .map(|m| m.as_str().into())
        .collect()
}
pub fn profile(a: &AppInfo) -> Profile {
    let mut p = Profile::default();
    let w = normalized_words(&format!("{} {}", a.display_name(), a.package_name));
    let l = if a.app_label_source == "apk" {
        normalized_words(&a.app_label)
    } else {
        HashSet::new()
    };
    let has = |list: &[&str]| list.iter().any(|s| w.contains(*s));
    let cleaner = has(&[
        "cleaner",
        "cleaners",
        "nettoyeur",
        "nettoyage",
        "booster",
        "boosters",
        "optimizer",
        "optimiseur",
        "optimisation",
        "cleanmaster",
        "superclean",
        "phoneclean",
        "junkclean",
        "rambooster",
        "speedbooster",
        "batterydoctor",
        "ccleaner",
        "phonecleaner",
        "junkcleaner",
    ]) || [
        ["cpu", "cooler"],
        ["battery", "saver"],
        ["super", "clean"],
        ["sd", "maid"],
        ["junk", "removal"],
    ]
    .iter()
    .any(|pair| pair.iter().all(|s| w.contains(*s)))
        || has(&["clean", "cleaning", "boost", "cooler"])
            && has(&[
                "phone", "ram", "memory", "junk", "cache", "battery", "storage",
            ]);
    if cleaner {
        p.add("cleaner",75,"Cleaner/booster tiers : suppression proposée selon la politique de nettoyage de l'atelier, même sans permission dangereuse.");
    }
    let reported = l == normalized_words("rotate link") || l == normalized_words("gold miner");
    let hash = a.app_label_source == "apk"
        && a.app_label.trim().starts_with('#')
        && ["gallery", "galerie", "contact", "contacts"]
            .iter()
            .any(|s| l.contains(*s));
    if reported || hash {
        p.add("reported_name",70,"Nom correspondant aux applications indésirables signalées par l'atelier ; vérifier l'identité avant suppression (homonymes possibles).");
    }
    let pdf = has(&["pdf", "pdfreader", "allpdfreader", "pdfviewer"]);
    let qr = has(&[
        "qr",
        "qrcode",
        "barcode",
        "qrscanner",
        "qrreader",
        "qrcodescanner",
    ]);
    let clone = !l.is_empty()
        && l.iter().all(|s| {
            ["gallery", "galerie", "contact", "contacts", "pro", "all"].contains(&s.as_str())
        });
    let utility = pdf || qr || clone;
    if utility {
        p.add("utility",35,"Utilitaire PDF/QR ou doublon galerie/contacts tiers : vérifier son utilité et son identité.");
        if has(&[
            "all", "super", "ultra", "max", "ultimate", "boost", "cleaner",
        ]) {
            p.add("promoted_utility",65,"Utilitaire au nom racoleur (« all/super/ultra/max ») : indésirable probable selon le tri atelier.");
        }
        if qr && a.target_sdk.parse::<u32>().is_ok_and(|v| v > 0 && v <= 28) {
            p.add("old_qr",65,"Ancien lecteur QR tiers ciblant Android 9 ou antérieur : suppression proposée si devenu inutile.");
        }
        if a.has_launcher_entry == Some(false)
            || any_active(
                a,
                &[
                    "overlay",
                    "accessibility",
                    "notification_listener",
                    "install_unknown_apps",
                ],
            )
        {
            p.add("intrusive_utility",80,"Utilitaire peu visible ou doté d'accès intrusifs actifs : profil prioritaire de publicité indésirable.");
        }
    }
    if a.is_home_app == Some(true) {
        p.add(
            "home",
            40,
            "Application capable de remplacer l'écran d'accueil.",
        );
    }
    if a.is_default_home == Some(true) {
        p.add("default_home",50,"Cette application est actuellement l'écran d'accueil par défaut : vérifier ce remplacement avec le client.");
        if utility || cleaner || reported || hash {
            p.add("disguised_home",90,"Un utilitaire ou une application signalée occupe le rôle d'écran d'accueil : rétablir l'accueil souhaité puis proposer sa suppression.");
        }
    }
    if has(&[
        "cash", "reward", "rewards", "earn", "money", "payout", "jackpot",
    ]) {
        p.add(
            "reward",
            40,
            "Promesse de gains/récompenses : examiner le risque de publicité et d'arnaque.",
        );
        if has(&["miner", "mining", "gold", "lucky", "win", "spin"]) {
            p.add("reward_bait",70,"Jeu/minage combiné à une promesse de gains : application indésirable probable selon le tri atelier.");
        }
    }
    p
}
pub fn evaluate(a: &AppInfo, rep: &Reputation) -> Risk {
    let mut score: i32 = 0;
    let mut reasons = Vec::new();
    let official = trusted(a);
    let t = text(a);
    macro_rules! add {
        ($n:expr,$s:expr) => {{
            score += $n;
            reasons.push(($s).to_string());
        }};
    }
    if a.is_system_app && known_system(&a.package_name) {
        return Risk {
            score: 0,
            category: "do_not_touch_system".into(),
            recommended_action: "do_not_touch".into(),
            reasons: vec![
                "Application système officielle Samsung/Google/Microsoft : ne pas supprimer."
                    .into(),
            ],
        };
    }
    if rep.blacklisted {
        add!(
            50.max(rep.blacklist_severity),
            format!("Présent dans la blacklist locale. {}", rep.reason).trim()
        );
    }
    if rep.whitelisted {
        add!(-80, "Présent dans la whitelist locale.");
    }
    let req = requested(a);
    let suspicious = contains(&t, "SUSPICIOUS_WORDS");
    let cleaner = contains(&t, "CLEANER_BAIT_WORDS");
    let unknown = !safe_installer(&a.installer);
    let hidden = a.has_launcher_entry == Some(false);
    if active(a, "accessibility") {
        add!(35, "Service d'accessibilité actif.");
    } else if a.has_accessibility {
        add!(
            10,
            "Service d'accessibilité déclaré mais non confirmé actif."
        );
    }
    if active(a, "overlay") && !official {
        add!(30, "Permission overlay SYSTEM_ALERT_WINDOW active.");
    } else if (a.has_overlay || req.iter().any(|p| p.contains("SYSTEM_ALERT_WINDOW"))) && !official
    {
        add!(
            8,
            "Permission overlay SYSTEM_ALERT_WINDOW demandée mais non confirmée active."
        );
    }
    let dg = a.granted_permissions.iter().any(|p| dangerous(p));
    let dr = req.iter().any(|p| dangerous(p));
    if dg && !official {
        add!(25, "Permissions sensibles SMS/appels/contacts accordées.");
    } else if dr && !official {
        add!(
            8,
            "Permissions sensibles SMS/appels/contacts demandées mais non confirmées accordées."
        );
    }
    if a.granted_permissions.len() >= 5 && !official {
        add!(20, "Nombre élevé de permissions sensibles accordées.");
    } else if req.len() >= 5 && !official {
        add!(5, "Nombre élevé de permissions sensibles demandées.");
    }
    if a.installer.is_empty() {
        add!(20, "Installateur inconnu ou vide.");
    } else if safe_installer(&a.installer) {
        add!(
            -20,
            format!(
                "Installé via {}.",
                CONSTANTS["SAFE_INSTALLERS"][&a.installer].as_str().unwrap()
            )
        );
    }
    if suspicious && !official {
        add!(
            20,
            "Nom ou package contenant un mot souvent associé à adware/scam."
        );
    }
    if scam(&t) && !official {
        add!(
            20,
            "Nom évoquant gain, cadeau, crédit ou récompense : signal courant d'arnaque."
        );
    }
    if !official
        && words("GENERIC_SYSTEM_NAMES")
            .iter()
            .any(|n| a.display_name().trim().to_lowercase() == *n || t.contains(n))
    {
        add!(15, "Nom générique pouvant imiter une application système.");
    }
    if crate::scanner::installed_recently(&a.install_date) {
        add!(15, "Application installée récemment.");
    }
    if active(a, "device_admin") {
        add!(30, "Administrateur de l'appareil actif.");
    } else if a.has_device_admin {
        add!(
            10,
            "Fonction administrateur déclarée mais non confirmée active."
        );
    }
    if active(a, "notification_listener") {
        add!(35, "Accès aux notifications actif.");
    } else if a.has_notification_listener {
        add!(
            10,
            "Accès aux notifications déclaré mais non confirmé actif."
        );
    }
    if a.requests_post_notifications && suspicious && !official {
        if active(a, "notifications") {
            add!(15, "Notifications actives avec nom suspect.");
        } else {
            add!(5, "Notifications demandées avec nom suspect.");
        }
    }
    if a.notification_audit.len() >= 3 && !rep.whitelisted && !official {
        add!(
            if any_active(a, &["notifications", "notification_listener"]) {
                20
            } else {
                5
            },
            format!(
                "Profil notification/spam potentiel : {}.",
                a.notification_audit
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        );
    }
    if active(a, "install_unknown_apps") && !official {
        add!(25, "Installation d'apps inconnues autorisée.");
    } else if a.can_install_unknown_apps && !official {
        add!(
            8,
            "Installation d'apps inconnues demandée mais non confirmée autorisée."
        );
    }
    if active(a, "usage_stats") {
        add!(20, "Accès aux statistiques d'utilisation actif.");
    } else if a.has_usage_stats {
        add!(
            5,
            "Accès aux statistiques d'utilisation demandé mais non confirmé actif."
        );
    }
    if a.has_vpn_service && unknown {
        add!(
            8,
            "Service VPN/proxy déclaré hors installateur de confiance."
        );
    }
    if a.runs_at_boot && suspicious && !official {
        add!(15, "Se lance au démarrage et porte un nom suspect.");
    }
    if hidden && !a.is_system_app && !official {
        add!(
            20,
            "Application utilisateur sans icône visible dans le launcher."
        );
    }
    if !a.hidden_audit.is_empty() && hidden && (unknown || suspicious) && !official {
        add!(
            25,
            "Profil peu visible combiné à installateur inconnu ou nom suspect."
        );
    }
    if hidden && !official {
        if any_active(a, &["notification_listener", "notifications", "overlay"]) {
            add!(
                25,
                "App peu visible avec accès notifications ou overlay actif."
            );
        } else if a.has_notification_listener || a.requests_post_notifications || a.has_overlay {
            add!(
                8,
                "App peu visible avec accès notifications ou overlay demandé."
            );
        }
    }
    if (generic_label(&a.display_name()) || a.icon_path.is_empty() || a.app_label_source != "apk")
        && (unknown || hidden)
        && !official
    {
        add!(15, "Nom ou icône générique avec visibilité faible.");
    }
    if cleaner {
        if any_active(a, &["overlay", "accessibility", "notification_listener"]) {
            add!(
                30,
                "Combinaison cleaner/booster avec overlay, accessibilité ou notifications actifs."
            );
        } else if a.has_overlay || a.has_accessibility || a.has_notification_listener {
            add!(
                10,
                "Combinaison cleaner/booster avec accès sensibles demandés."
            );
        }
    }
    if unknown && suspicious && dg {
        add!(
            25,
            "Installateur non fiable + nom suspect + permissions sensibles accordées."
        );
    } else if unknown && suspicious && dr {
        add!(
            8,
            "Installateur non fiable + nom suspect + permissions sensibles demandées."
        );
    }
    if a.target_sdk.parse::<i32>().is_ok_and(|v| v <= 26) && !official {
        add!(15, "Application ciblant une ancienne version Android.");
    }
    if random_package(&a.package_name) && !official {
        add!(20, "Package très générique ou semblant aléatoire.");
    }
    if impersonates(a) {
        add!(
            35,
            "Package utilisateur imitant un espace système Google/Samsung/Android."
        );
    }
    if official && !rep.blacklisted {
        add!(-80, "Namespace officiel installé via une source fiable.");
    }
    let p = profile(a);
    if !a.is_system_app && !official && !rep.whitelisted {
        score = score.max(p.score_floor);
        reasons.extend(p.reasons);
        if a.is_home_app == Some(true) && p.score_floor < 60 && !rep.blacklisted {
            score = score.min(59);
        }
    }
    if rep.blacklisted && !rep.whitelisted {
        score = score.max(60);
    }
    score = score.clamp(0, 100);
    let (category, action) = classify(score, a, rep);
    if reasons.is_empty() {
        reasons.push("Aucun signal de risque notable détecté.".into());
    }
    Risk {
        score,
        category: category.into(),
        recommended_action: action.into(),
        reasons,
    }
}
fn classify(score: i32, a: &AppInfo, r: &Reputation) -> (&'static str, &'static str) {
    if a.is_system_app {
        return ("do_not_touch_system", "do_not_touch");
    }
    if r.whitelisted {
        return ("safe", "keep");
    }
    if r.blacklisted {
        return ("local_blacklist", "suggest_uninstall");
    }
    if trusted(a) {
        return if a.has_accessibility
            || a.has_device_admin
            || a.has_notification_listener
            || score >= 50
        {
            ("trusted_official_review", "review")
        } else {
            ("trusted_official", "keep")
        };
    }
    if profile(a).score_floor >= 60 {
        return ("unwanted_utility", "suggest_uninstall");
    }
    if a.is_home_app == Some(true)
        || safe_installer(&a.installer)
            && (a.has_accessibility
                || a.has_device_admin
                || a.has_notification_listener
                || a.has_overlay
                || requested(a).iter().filter(|p| dangerous(p)).count() >= 2)
    {
        return ("unknown_review_manually", "review");
    }
    if score < 15 {
        return ("safe", "keep");
    }
    if score < 30 {
        return ("probably_safe", "keep");
    }
    if score < 60 || safe_installer(&a.installer) && (!distribution(a) || !strong(a)) {
        return ("unknown_review_manually", "review");
    }
    if any_active(a, &["accessibility", "device_admin"]) {
        return ("spyware_suspect", "suggest_uninstall");
    }
    if active(a, "install_unknown_apps") || scam(&text(a)) {
        return ("scam_suspect", "suggest_uninstall");
    }
    if a.has_launcher_entry == Some(false)
        || !a.notification_audit.is_empty()
        || [
            "clean", "boost", "weather", "battery", "security", "vpn", "proxy",
        ]
        .iter()
        .any(|w| text(a).contains(w))
    {
        return ("adware_suspect", "suggest_uninstall");
    }
    ("scam_suspect", "suggest_uninstall")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_python_tests_parity() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../reference/python-test-cases.json")).unwrap();
        for (i, c) in cases.iter().enumerate() {
            let mut a: AppInfo = serde_json::from_value(c["app"].clone()).unwrap();
            if !a.install_date.is_empty() {
                a.install_date = if c["recent_install"] == true {
                    chrono::Utc::now().to_rfc3339()
                } else {
                    "2000-01-01".into()
                };
            }
            let r = serde_json::from_value(c["reputation"].clone()).unwrap();
            assert_eq!(
                serde_json::to_value(evaluate(&a, &r)).unwrap(),
                c["risk"],
                "legacy test evaluation {i}"
            );
        }
    }
    #[test]
    fn python_parity_600_cases() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../reference/risk-cases.json")).unwrap();
        for (i, c) in cases.iter().enumerate() {
            let a = serde_json::from_value(c["app"].clone()).unwrap();
            let r = serde_json::from_value(c["reputation"].clone()).unwrap();
            assert_eq!(
                serde_json::to_value(evaluate(&a, &r)).unwrap(),
                c["risk"],
                "risk case {i}"
            );
            assert_eq!(
                serde_json::to_value(profile(&a)).unwrap(),
                c["profile"],
                "profile case {i}"
            );
        }
    }
}
