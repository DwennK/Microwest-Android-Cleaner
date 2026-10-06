use crate::{model::AppInfo, process, risk};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path};
use tokio_util::sync::CancellationToken;

pub const RULES_VERSION: u32 = 3;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApkAnalysis {
    pub inspected: bool,
    pub partial: bool,
    pub sha256: String,
    pub ad_libraries: Vec<String>,
    pub warning_strings: Vec<String>,
    pub components: Vec<String>,
    pub signer_sha256: Vec<String>,
    pub signature_verified: bool,
    pub publisher: String,
    pub limitations: Vec<String>,
}

/// Bounded static inspection, never execute APK code or treat resources as observed behaviour.
pub fn inspect_archive(path: &Path) -> Result<ApkAnalysis, String> {
    let mut result = ApkAnalysis::default();
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    result.sha256 = format!("{:x}", hash.finalize());
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut budget = 64 * 1024 * 1024;
    for i in 0..zip.len().min(4096) {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        if !entry.name().ends_with(".dex") {
            continue;
        }
        if entry.size() > budget as u64 || entry.size() > 32 * 1024 * 1024 {
            result.partial = true;
            continue;
        }
        let mut bytes = Vec::new();
        (&mut entry)
            .take(budget as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > budget {
            result.partial = true;
            break;
        }
        budget -= bytes.len();
        static MATCHERS: std::sync::LazyLock<regex::bytes::RegexSet> =
            std::sync::LazyLock::new(|| {
                regex::bytes::RegexSetBuilder::new([
                    "Lcom/google/android/gms/ads/",
                    "Lcom/facebook/ads/",
                    "Lcom/applovin/",
                    "Lcom/ironsource/",
                    "Lcom/unity3d/ads/",
                    "Lcom/bytedance/sdk/openadsdk/",
                    "Lcom/mbridge/msdk/",
                ])
                .unicode(false)
                .build()
                .unwrap()
            });
        let labels = [
            "Google Mobile Ads",
            "Meta Audience Network",
            "AppLovin",
            "ironSource",
            "Unity Ads",
            "Pangle",
            "Mintegral",
        ];
        for hit in MATCHERS.matches(&bytes).iter() {
            result.ad_libraries.push(labels[hit].into());
        }
    }
    result.ad_libraries.sort();
    result.ad_libraries.dedup();
    result.inspected = true;
    result.partial |= zip.len() > 4096;
    if result.partial {
        result
            .limitations
            .push("Inspection DEX partielle (limite de taille).".into());
    }
    Ok(result)
}

pub fn inspect_resources(raw: &str) -> Vec<String> {
    // Only fixed matching labels are retained, never arbitrary application text.
    let text = raw.to_lowercase();
    let mut found = Vec::new();
    for (needles, label) in [
        (
            &[
                "your phone is infected",
                "virus detected",
                "votre téléphone est infecté",
                "virus détecté",
            ][..],
            "Ressource annonçant une infection",
        ),
        (
            &[
                "storage is full",
                "storage full",
                "stockage plein",
                "mémoire pleine",
            ][..],
            "Ressource annonçant un stockage plein",
        ),
        (
            &[
                "clean now",
                "clean immediately",
                "nettoyer maintenant",
                "remove viruses",
            ][..],
            "Ressource incitant à un nettoyage immédiat",
        ),
    ] {
        if needles.iter().any(|s| text.contains(s)) {
            found.push(label.into());
        }
    }
    found
}

pub async fn enrich(
    path: &Path,
    tool: &Path,
    root: &Path,
    cancel: &CancellationToken,
) -> ApkAnalysis {
    let mut a = match inspect_archive(path) {
        Ok(a) => a,
        Err(_) => ApkAnalysis {
            limitations: vec!["Inspection statique APK indisponible.".into()],
            ..Default::default()
        },
    };
    let apk = path.to_string_lossy();
    match process::run(tool, &process::args(&["dump", "strings", &apk]), 15, cancel).await {
        Ok(s) => a.warning_strings = inspect_resources(&s),
        Err(_) => {
            a.partial = true;
            a.limitations
                .push("Ressources textuelles non inspectées.".into());
        }
    }
    match process::run(
        tool,
        &process::args(&["dump", "xmltree", &apk, "--file", "AndroidManifest.xml"]),
        15,
        cancel,
    )
    .await
    {
        Ok(s) => {
            let re = regex::Regex::new(r#"android:name[^=]*=\"([^\"]+)\""#).unwrap();
            let mut component = false;
            for line in s.lines() {
                if line.trim_start().starts_with("E:") {
                    component = [
                        "E: activity ",
                        "E: activity-alias ",
                        "E: service ",
                        "E: receiver ",
                    ]
                    .iter()
                    .any(|tag| line.contains(tag));
                }
                if component {
                    if let Some(c) = re.captures(line) {
                        a.components.push(c[1].chars().take(200).collect());
                        component = false;
                    }
                }
            }
            a.components.sort();
            a.components.dedup();
            if a.components.len() > 100 {
                a.partial = true;
                a.limitations
                    .push("Liste des composants limitée aux 100 premières entrées.".into());
            }
            a.components.truncate(100);
        }
        Err(_) => {
            a.partial = true;
            a.limitations
                .push("Composants du manifeste non inspectés.".into());
        }
    }
    // Official Android verifier. No shell invocation, no invented certificate trust.
    let jar = std::env::var_os("APKSIGNER_JAR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let sibling = tool.parent().unwrap_or(root).join("apksigner.jar");
            if sibling.is_file() {
                sibling
            } else {
                root.join("tools/apksigner.jar")
            }
        });
    if jar.is_file() {
        let java = std::env::var_os("JAVA_HOME")
            .map(std::path::PathBuf::from)
            .map(|p| {
                p.join(if cfg!(windows) {
                    "bin/java.exe"
                } else {
                    "bin/java"
                })
            })
            .unwrap_or_else(|| {
                let bundled = jar.parent().unwrap_or(root).join(if cfg!(windows) {
                    "jre/bin/java.exe"
                } else {
                    "jre/bin/java"
                });
                if bundled.is_file() {
                    bundled
                } else {
                    "java".into()
                }
            });
        match process::run(
            &java,
            &process::args(&[
                "-jar",
                &jar.to_string_lossy(),
                "verify",
                "--print-certs",
                &apk,
            ]),
            20,
            cancel,
        )
        .await
        {
            Ok(s) => {
                for line in s.lines() {
                    // Source-stamp certificates identify distribution, not the APK publisher.
                    if !line.starts_with("Signer #") {
                        continue;
                    }
                    if let Some((_, digest)) = line.split_once("certificate SHA-256 digest:") {
                        let digest = digest.trim().to_lowercase();
                        if digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()) {
                            a.signer_sha256.push(digest);
                        }
                    }
                }
                a.signer_sha256.sort();
                a.signer_sha256.dedup();
                a.signature_verified = !a.signer_sha256.is_empty();
            }
            Err(_) => a.limitations.push(
                "Signature non vérifiée : outil indisponible ou vérification refusée.".into(),
            ),
        }
    } else {
        a.limitations
            .push("Vérification de signature indisponible (apksigner non installé).".into());
    }
    a
}

/// Each conclusion references identifiers generated here, not free-form model claims.
pub fn facts(a: &AppInfo) -> BTreeMap<String, String> {
    let mut f = BTreeMap::new();
    f.insert(
        "identity:unverified".into(),
        "Identité de l'éditeur non vérifiée par une référence de signature.".into(),
    );
    if !a.apk_analysis.publisher.is_empty() {
        f.remove("identity:unverified");
        f.insert(
            "identity:verified".into(),
            format!(
                "Signature correspondant à la référence éditeur : {}",
                a.apk_analysis.publisher
            ),
        );
    }
    if risk::safe_installer(&a.installer) {
        f.insert(
            "source:store".into(),
            "Installation via une boutique connue, sans garantie d'innocuité.".into(),
        );
    } else {
        f.insert(
            "source:unknown".into(),
            "Source d'installation non vérifiée.".into(),
        );
    }
    if let Some(visible) = a.has_launcher_entry {
        f.insert(
            if visible {
                "launcher:visible"
            } else {
                "launcher:hidden"
            }
            .into(),
            if visible {
                "Entrée visible dans le lanceur."
            } else {
                "Absence d'entrée dans le lanceur."
            }
            .into(),
        );
    }
    if a.is_default_home == Some(true) {
        f.insert(
            "role:home".into(),
            "Occupe actuellement le rôle d'écran d'accueil.".into(),
        );
    }
    for p in &a.requested_permissions {
        f.insert(
            format!("requested:{p}"),
            format!("Permission déclarée, pas nécessairement accordée : {p}"),
        );
    }
    for p in &a.granted_permissions {
        f.insert(format!("granted:{p}"), format!("Permission accordée : {p}"));
    }
    for p in &a.active_capabilities {
        f.insert(format!("active:{p}"), format!("Accès confirmé actif : {p}"));
    }
    for p in &a.apk_analysis.ad_libraries {
        f.insert(
            format!("ads:{p}"),
            format!(
                "Bibliothèque publicitaire présente dans le DEX : {p}. Usage effectif non observé."
            ),
        );
    }
    for (i, p) in a.apk_analysis.warning_strings.iter().enumerate() {
        f.insert(
            format!("resource:{i}"),
            format!("{p}. Présence statique, affichage non observé."),
        );
    }
    let profile = risk::profile(a);
    for (family, reason) in profile.families.iter().zip(profile.reasons.iter()) {
        f.insert(format!("profile:{family}"), reason.clone());
    }
    if !a.dumpsys_error.is_empty() {
        f.insert(
            "collection:incomplete".into(),
            "Métadonnées Android incomplètes.".into(),
        );
    }
    if !a.apk_analysis.inspected {
        f.insert(
            "apk:unavailable".into(),
            "APK non inspecté : comportement publicitaire non établi.".into(),
        );
    }
    f
}

pub fn supports_removal(a: &AppInfo, ids: &[String]) -> bool {
    let has = |id: &str| ids.iter().any(|s| s == id);
    let profile = risk::profile(a);
    if (has("profile:cleaner") && profile.families.iter().any(|s| s == "cleaner"))
        || (has("profile:disguised_home") && a.is_default_home == Some(true))
    {
        return true;
    }
    let active = [
        "overlay",
        "accessibility",
        "notification_listener",
        "device_admin",
        "install_unknown_apps",
    ]
    .iter()
    .filter(|cap| risk::active(a, cap) && has(&format!("active:{cap}")))
    .count();
    if has("launcher:hidden") && a.has_launcher_entry == Some(false) && active > 0 {
        return true;
    }
    if has("source:unknown") && !risk::safe_installer(&a.installer) && active >= 2 {
        return true;
    }
    has("profile:utility")
        && deceptive_utility(a)
        && ids.iter().any(|s| s.starts_with("ads:"))
        && !a.apk_analysis.ad_libraries.is_empty()
        && ids.iter().any(|s| s.starts_with("resource:"))
        && ids
            .iter()
            .filter(|s| s.starts_with("resource:"))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            >= 2
}

pub fn deceptive_utility(a: &AppInfo) -> bool {
    let p = risk::profile(a);
    p.families.iter().any(|s| s == "utility")
        && !a.apk_analysis.ad_libraries.is_empty()
        && a.apk_analysis.warning_strings.len() >= 2
        && (a
            .apk_analysis
            .warning_strings
            .iter()
            .any(|s| s.contains("infection"))
            || p.families.iter().any(|s| s == "promoted_utility"))
}

pub fn resolve_publisher(root: &Path, a: &mut AppInfo) {
    #[derive(Deserialize)]
    struct Reference {
        package: String,
        publisher: String,
        signer_sha256: Vec<String>,
        source: String,
    }
    a.apk_analysis.publisher.clear();
    if !a.apk_analysis.signature_verified || a.apk_analysis.signer_sha256.is_empty() {
        return;
    }
    let path = root.join("data/publisher_certificates.json");
    let references = std::fs::read(path)
        .ok()
        .filter(|v| v.len() < 1024 * 1024)
        .and_then(|b| serde_json::from_slice::<Vec<Reference>>(&b).ok())
        .unwrap_or_default();
    for r in references {
        // Require exact package plus every signer; a namespace match never establishes identity.
        if r.package == a.package_name
            && !r.source.trim().is_empty()
            && !r.publisher.trim().is_empty()
            && a.apk_analysis
                .signer_sha256
                .iter()
                .all(|s| r.signer_sha256.iter().any(|v| v.eq_ignore_ascii_case(s)))
        {
            a.apk_analysis.publisher = format!("{} — {}", r.publisher, r.source);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn static_indicators_need_context_and_do_not_require_overlay() {
        let mut a = AppInfo {
            app_label: "PDF Reader".into(),
            app_label_source: "apk".into(),
            package_name: "org.example.reader".into(),
            installer: "com.android.vending".into(),
            has_launcher_entry: Some(true),
            ..Default::default()
        };
        a.apk_analysis.ad_libraries = vec!["Google Mobile Ads".into()];
        a.apk_analysis.warning_strings = inspect_resources("Storage full");
        assert_eq!(
            risk::evaluate(&a, &Default::default()).recommended_action,
            "keep"
        );
        a.apk_analysis.warning_strings = inspect_resources("Your phone is infected! Clean now!");
        assert!(a.active_capabilities.is_empty());
        assert_eq!(
            risk::evaluate(&a, &Default::default()).recommended_action,
            "suggest_uninstall"
        );
        let ids = vec![
            "profile:utility".into(),
            "ads:Google Mobile Ads".into(),
            "resource:0".into(),
            "resource:1".into(),
        ];
        assert!(supports_removal(&a, &ids));
        assert!(!supports_removal(&a, &ids[..3]));
    }
    #[test]
    fn inspect_dex_archive_and_corrupt_apk() {
        use std::io::Write;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("base.apk");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        zip.start_file("classes.dex", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(
            b"dex\n035\0Lcom/google/android/gms/ads/AdActivity;Lcom/applovin/sdk/AppLovinSdk;",
        )
        .unwrap();
        zip.finish().unwrap();
        let a = inspect_archive(&path).unwrap();
        assert_eq!(a.ad_libraries.len(), 2);
        assert_eq!(a.sha256.len(), 64);
        assert!(a.inspected);
        std::fs::write(&path, b"not an apk").unwrap();
        assert!(inspect_archive(&path).is_err());
    }
    #[test]
    fn publisher_reference_requires_exact_package_and_all_verified_signers() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("data")).unwrap();
        std::fs::write(temp.path().join("data/publisher_certificates.json"), br#"[{"package":"org.example.reader","publisher":"Example","signer_sha256":["aaaa"],"source":"validated test reference"}]"#).unwrap();
        let mut a = AppInfo {
            package_name: "org.example.reader".into(),
            ..Default::default()
        };
        a.apk_analysis.signer_sha256 = vec!["aaaa".into()];
        resolve_publisher(temp.path(), &mut a);
        assert!(a.apk_analysis.publisher.is_empty());
        a.apk_analysis.signature_verified = true;
        resolve_publisher(temp.path(), &mut a);
        assert!(!a.apk_analysis.publisher.is_empty());
        a.apk_analysis.signer_sha256.push("bbbb".into());
        resolve_publisher(temp.path(), &mut a);
        assert!(a.apk_analysis.publisher.is_empty());
    }
}
