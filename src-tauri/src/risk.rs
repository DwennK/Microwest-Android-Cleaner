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
fn text(a: &AppInfo) -> String {
    format!("{} {}", a.display_name(), a.package_name).to_lowercase()
}
pub fn active(a: &AppInfo, cap: &str) -> bool {
    a.active_capabilities.iter().any(|v| v == cap)
}
fn any_active(a: &AppInfo, caps: &[&str]) -> bool {
    caps.iter().any(|c| active(a, c))
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
        p.add("reported_name",40,"Nom correspondant aux applications indésirables signalées par l'atelier ; vérifier l'identité avant suppression (homonymes possibles).");
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
        p.add(
            "utility",
            0,
            "Rôle PDF/QR/galerie/contacts : cette fonction seule ne constitue pas un risque.",
        );
        if has(&[
            "all", "super", "ultra", "max", "ultimate", "boost", "cleaner",
        ]) {
            p.add("promoted_utility",35,"Nom promotionnel d’un utilitaire : vérifier son identité, sans conclure à une application malveillante.");
        }
        if qr && a.target_sdk.parse::<u32>().is_ok_and(|v| v > 0 && v <= 28) {
            p.add("old_qr",15,"Ancien lecteur QR : compatibilité vieillissante, pas une preuve de comportement indésirable.");
        }
        if a.has_launcher_entry == Some(false)
            && any_active(
                a,
                &[
                    "overlay",
                    "accessibility",
                    "notification_listener",
                    "install_unknown_apps",
                ],
            )
        {
            p.add("intrusive_utility",80,"Utilitaire peu visible et doté d'accès intrusifs actifs : profil prioritaire de publicité indésirable.");
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
            p.add("reward_bait",40,"Jeu/minage combiné à une promesse de gains : application à vérifier avec le client.");
        }
    }
    p
}
// The score is a triage priority, not a probability of infection. Store identity,
// permission declarations and missing metadata are not evidence of abuse.
pub fn evaluate(a: &AppInfo, rep: &Reputation) -> Risk {
    if a.is_system_app {
        return Risk {
            score: 0,
            category: "do_not_touch_system".into(),
            recommended_action: "do_not_touch".into(),
            reasons: vec!["Composant système : protégé contre la suppression.".into()],
        };
    }
    if rep.whitelisted {
        return Risk {
            score: 0,
            category: "safe".into(),
            recommended_action: "keep".into(),
            reasons: vec!["Application conservée selon la liste blanche locale.".into()],
        };
    }
    if rep.blacklisted {
        return Risk {
            score: rep.blacklist_severity.clamp(60, 100),
            category: "local_blacklist".into(),
            recommended_action: "suggest_uninstall".into(),
            reasons: vec![format!("Présente dans la blacklist locale. {}", rep.reason)],
        };
    }

    let mut score: i32 = 0;
    let mut reasons = Vec::new();
    let unknown = !safe_installer(&a.installer);
    let hidden = a.has_launcher_entry == Some(false);
    let p = profile(a);
    let mut privileged = 0;
    let deceptive_utility = crate::evidence::deceptive_utility(a);
    if deceptive_utility {
        score = 65;
        reasons.push("Utilitaire combinant une bibliothèque publicitaire et des ressources alarmistes : faux utilitaire publicitaire possible. L’affichage effectif reste à vérifier.".into());
    }
    for (cap, weight, reason) in [
        (
            "accessibility",
            35,
            "Service d'accessibilité activé : peut agir sur les autres applications.",
        ),
        (
            "overlay",
            20,
            "Superposition autorisée : peut afficher du contenu au-dessus des autres applications.",
        ),
        ("device_admin", 30, "Administrateur de l'appareil activé."),
        (
            "notification_listener",
            25,
            "Lecture des notifications des autres applications activée.",
        ),
        (
            "install_unknown_apps",
            20,
            "Installation d'applications de sources inconnues autorisée.",
        ),
    ] {
        if active(a, cap) {
            privileged += 1;
            score += weight;
            reasons.push(reason.into());
        }
    }
    if active(a, "usage_stats") {
        score += 10;
        reasons.push("Accès aux statistiques d'utilisation activé.".into());
    }
    // Count data access once; ordinary notifications, vibration, boot and
    // foreground services do not imply SMS access, surveillance or spam.
    if a.granted_permissions.iter().any(|p| {
        matches!(
            p.as_str(),
            "android.permission.READ_SMS"
                | "android.permission.SEND_SMS"
                | "android.permission.RECEIVE_SMS"
                | "android.permission.READ_CALL_LOG"
                | "android.permission.WRITE_CALL_LOG"
                | "android.permission.READ_CONTACTS"
                | "android.permission.WRITE_CONTACTS"
        )
    }) {
        score += 10;
        reasons.push("Accès SMS, journal d'appels ou contacts accordé : à rapprocher de la fonction de l'application, sans présumer un abus.".into());
    }
    if unknown {
        score += 10;
        reasons.push(
            "Provenance non vérifiée ; ce seul constat ne justifie pas une suppression.".into(),
        );
    } else {
        reasons.push(format!("Installée via {} ; cette provenance ne garantit pas l'absence de comportement indésirable.", CONSTANTS["SAFE_INSTALLERS"][&a.installer].as_str().unwrap()));
    }
    if hidden {
        score += 20;
        reasons.push(
            "Aucune entrée dans le lanceur : vérifier si c'est un compagnon ou un service attendu."
                .into(),
        );
    }
    let hidden_access = hidden && (privileged > 0 || active(a, "notifications"));
    if hidden_access {
        score += 25;
        reasons.push("Faible visibilité combinée à un accès spécial ou aux notifications autorisé : vérifier l'usage avec le client.".into());
    }
    let multiple_unknown_access = unknown && privileged >= 2;
    if multiple_unknown_access {
        score += 15;
        reasons.push("Provenance non vérifiée combinée à plusieurs accès spéciaux activés.".into());
    }
    let corroborated = hidden_access || multiple_unknown_access || deceptive_utility;
    if corroborated && contains(&text(a), "SUSPICIOUS_WORDS") {
        score += 10;
        reasons.push(
            "Le rôle annoncé doit être vérifié au regard des accès et de la visibilité constatés."
                .into(),
        );
    }
    if corroborated && crate::scanner::installed_recently(&a.install_date) {
        score += 5;
        reasons
            .push("Installation récente : comparer sa date à l'apparition des symptômes.".into());
    }
    score = score.max(p.score_floor);
    reasons.extend(p.reasons);
    if privileged > 0 {
        // Even one special access deserves review, but it is not proof of malware.
        score = score.max(30);
    }
    if !corroborated && p.score_floor < 60 {
        score = score.min(59);
    }
    if !a.dumpsys_error.is_empty() {
        score = score.clamp(30, 59);
        reasons.push("Collecte incomplète : vérifier les métadonnées avant toute décision.".into());
    }
    score = score.clamp(0, 100);
    let (category, action) = if score >= 60 && p.score_floor >= 60 {
        ("unwanted_utility", "suggest_uninstall")
    } else if score >= 60 && corroborated {
        ("combined_signals", "suggest_uninstall")
    } else if score >= 30 {
        ("unknown_review_manually", "review")
    } else {
        reasons.push("Aucun faisceau d'indices local ne justifie un retrait. Les permissions seulement déclarées ne sont pas considérées comme actives.".into());
        ("probably_safe", "keep")
    };
    Risk {
        score,
        category: category.into(),
        recommended_action: action.into(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordinary() -> AppInfo {
        AppInfo {
            package_name: "org.example.dailycompanion".into(),
            app_label: "Daily Companion".into(),
            app_label_source: "apk".into(),
            installer: "com.android.vending".into(),
            has_launcher_entry: Some(true),
            target_sdk: "36".into(),
            ..Default::default()
        }
    }

    #[test]
    fn ordinary_phone_apps_do_not_need_a_whitelist() {
        let apps: Vec<AppInfo> =
            serde_json::from_str(include_str!("../reference/ordinary-apps.json")).unwrap();
        for mut app in apps {
            let result = evaluate(&app, &Reputation::default());
            println!(
                "{}: {} -> {}",
                app.package_name, result.score, result.recommended_action
            );
            assert_eq!(
                result.recommended_action, "keep",
                "{}: {:?}",
                app.package_name, result
            );
            assert_eq!(result.score, 0, "{}", app.package_name);
            // Identical metadata must work for an unknown publisher too.
            app.package_name = "org.independent.dailycompanion".into();
            app.app_label = "Daily Companion".into();
            let renamed = evaluate(&app, &Reputation::default());
            assert_eq!(renamed.score, result.score);
            assert_eq!(renamed.recommended_action, result.recommended_action);
        }
    }

    #[test]
    fn declarations_and_missing_icons_do_not_prove_abuse() {
        let mut a = ordinary();
        a.has_accessibility = true;
        a.has_overlay = true;
        a.has_notification_listener = true;
        a.has_device_admin = true;
        a.can_install_unknown_apps = true;
        a.requests_post_notifications = true;
        a.runs_at_boot = true;
        a.install_date = chrono::Utc::now().to_rfc3339();
        a.granted_permissions = [
            "FOREGROUND_SERVICE",
            "POST_NOTIFICATIONS",
            "VIBRATE",
            "RECEIVE_BOOT_COMPLETED",
            "FOREGROUND_SERVICE_DATA_SYNC",
        ]
        .map(|s| format!("android.permission.{s}"))
        .to_vec();
        a.requested_permissions = a.granted_permissions.clone();
        a.notification_audit = vec![
            "Notifications".into(),
            "Vibration".into(),
            "Démarrage".into(),
        ];
        a.active_capabilities = vec!["notifications".into()];
        let result = evaluate(&a, &Reputation::default());
        assert_eq!(result.score, 0);
        assert_eq!(result.recommended_action, "keep");
        a.app_label_source = "package".into();
        a.installer.clear();
        let result = evaluate(&a, &Reputation::default());
        assert_eq!(result.recommended_action, "keep");
    }

    #[test]
    fn contacts_and_special_access_are_not_malware_verdicts() {
        let mut a = ordinary();
        a.granted_permissions = vec![
            "android.permission.READ_CONTACTS".into(),
            "android.permission.READ_SMS".into(),
        ];
        assert_eq!(
            evaluate(&a, &Reputation::default()).recommended_action,
            "keep"
        );
        a.active_capabilities = vec![
            "accessibility".into(),
            "overlay".into(),
            "notification_listener".into(),
        ];
        let risk = evaluate(&a, &Reputation::default());
        assert_eq!(risk.recommended_action, "review");
        assert!(risk.score < 60);
    }

    #[test]
    fn hidden_intrusive_apps_remain_prioritized_even_from_a_store() {
        for installer in ["com.android.vending", "unverified", ""] {
            let mut a = ordinary();
            a.installer = installer.into();
            a.package_name = "com.google.android.apps.photos".into();
            a.has_launcher_entry = Some(false);
            a.active_capabilities = vec!["overlay".into(), "accessibility".into()];
            let risk = evaluate(&a, &Reputation::default());
            assert_eq!(risk.recommended_action, "suggest_uninstall");
            assert!(risk.score >= 60);
        }
    }

    #[test]
    fn unknown_source_with_multiple_active_privileges_needs_attention() {
        let mut a = ordinary();
        a.installer.clear();
        a.active_capabilities = vec!["accessibility".into(), "install_unknown_apps".into()];
        assert_eq!(
            evaluate(&a, &Reputation::default()).recommended_action,
            "suggest_uninstall"
        );
        a.dumpsys_error = "Incomplete collection".into();
        assert_eq!(
            evaluate(&a, &Reputation::default()).recommended_action,
            "review"
        );
    }

    #[test]
    fn utilities_are_judged_by_context_and_cleaner_policy_is_explicit() {
        let mut a = ordinary();
        for name in ["PDF Reader", "QR Reader", "Gallery", "Contacts"] {
            a.app_label = name.into();
            assert_eq!(
                evaluate(&a, &Reputation::default()).recommended_action,
                "keep",
                "{name}"
            );
        }
        a.app_label = "PDF Reader".into();
        a.is_default_home = Some(true);
        a.is_home_app = Some(true);
        assert_eq!(
            evaluate(&a, &Reputation::default()).recommended_action,
            "suggest_uninstall"
        );
        a = ordinary();
        a.app_label = "Phone Cleaner".into();
        let risk = evaluate(&a, &Reputation::default());
        assert_eq!(risk.recommended_action, "suggest_uninstall");
        assert!(risk.reasons.iter().any(|r| r.contains("politique")));
    }

    #[test]
    fn legacy_corpus_preserves_protections_not_obsolete_false_positive_scores() {
        // Migration equality snapshots encoded the old false positives. Reuse their
        // varied inputs to retain protection coverage under the corrected policy.
        for source in [
            include_str!("../reference/risk-cases.json"),
            include_str!("../reference/python-test-cases.json"),
        ] {
            let cases: Vec<Value> = serde_json::from_str(source).unwrap();
            for c in cases {
                let a: AppInfo = serde_json::from_value(c["app"].clone()).unwrap();
                let rep: Reputation = serde_json::from_value(c["reputation"].clone()).unwrap();
                let risk = evaluate(&a, &rep);
                assert!((0..=100).contains(&risk.score));
                if a.is_system_app {
                    assert_eq!(risk.recommended_action, "do_not_touch");
                } else if rep.whitelisted {
                    assert_eq!(risk.recommended_action, "keep");
                } else if rep.blacklisted {
                    assert_eq!(risk.recommended_action, "suggest_uninstall");
                }
                if risk.recommended_action == "suggest_uninstall" {
                    assert!(risk.score >= 60);
                }
            }
        }
    }
}
