use crate::{
    adb::Adb,
    model::{AppInfo, Result},
    process, risk,
};
use base64::Engine;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;
use std::{collections::BTreeSet, path::Path};

pub fn extract(s: &str, p: &str) -> String {
    Regex::new(p)
        .unwrap()
        .captures(s)
        .map(|c| c[1].trim().into())
        .unwrap_or_default()
}
pub fn package_to_label(p: &str) -> String {
    let label = p
        .rsplit('.')
        .next()
        .unwrap_or(p)
        .replace(['_', '-'], " ")
        .split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(c) => format!("{}{}", c.to_uppercase(), chars.as_str().to_lowercase()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if label.is_empty() {
        p.into()
    } else {
        label
    }
}
pub fn installed_recently(s: &str) -> bool {
    let parsed = DateTime::parse_from_rfc3339(s)
        .map(|v| v.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f%:z")
                .ok()
                .map(|v| v.with_timezone(&Utc))
        })
        .or_else(|| {
            ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
                .iter()
                .find_map(|format| {
                    NaiveDateTime::parse_from_str(s, format)
                        .ok()
                        .map(|v| v.and_utc())
                })
        })
        .or_else(|| {
            NaiveDate::parse_from_str(s.split_whitespace().next().unwrap_or(""), "%Y-%m-%d")
                .ok()
                .and_then(|v| v.and_hms_opt(0, 0, 0))
                .map(|v| v.and_utc())
        });
    parsed.is_some_and(|v| Utc::now().signed_duration_since(v).num_days() <= 10)
}
pub fn enrich(a: &mut AppInfo, s: &str) {
    a.app_label = package_to_label(&a.package_name);
    a.version_name = extract(s, r"versionName=([^\s]+)");
    a.target_sdk = extract(s, r"targetSdk=([0-9]+)");
    a.install_date = extract(s, r"firstInstallTime=([^\n\r]+)");
    a.enabled = extract(s, r"enabled=([^\s]+)");
    if a.enabled.is_empty() {
        a.enabled = extract(s, r"enabledComponents:([^\n\r]+)");
    }
    a.is_system_app = s
        .lines()
        .filter(|l| l.contains("flags=[") || l.contains("pkgFlags=["))
        .any(|l| {
            l.contains(" SYSTEM")
                || l.contains(" PRIVILEGED")
                || l.contains("[SYSTEM")
                || l.contains("[PRIVILEGED")
        });
    let markers: Vec<_> = risk::CONSTANTS["SENSITIVE_PERMISSION_KEYWORDS"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let mut perms = BTreeSet::new();
    for k in &markers {
        if s.contains(k) {
            perms.insert(if k.starts_with("BIND_") {
                k.to_string()
            } else {
                format!("android.permission.{k}")
            });
        }
    }
    for c in Regex::new(r"android\.permission\.([A-Z0-9_]+)")
        .unwrap()
        .captures_iter(s)
    {
        if markers.iter().any(|m| c[0].contains(m)) {
            perms.insert(c[0].to_owned());
        }
    }
    a.requested_permissions = perms.into_iter().collect();
    a.sensitive_permissions = a.requested_permissions.clone();
    a.granted_permissions =
        Regex::new(r"(?m)^\s*(android\.permission\.([A-Z0-9_]+)):\s+granted=true\b")
            .unwrap()
            .captures_iter(s)
            .filter(|c| markers.iter().any(|m| c[2].contains(m)))
            .map(|c| c[1].to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    a.has_accessibility =
        s.contains("BIND_ACCESSIBILITY_SERVICE") || s.contains("AccessibilityService");
    a.has_overlay = s.contains("SYSTEM_ALERT_WINDOW");
    a.has_device_admin = s.contains("BIND_DEVICE_ADMIN") || s.contains("android.app.device_admin");
    a.has_notification_listener = s.contains("BIND_NOTIFICATION_LISTENER_SERVICE");
    a.requests_post_notifications = s.contains("POST_NOTIFICATIONS");
    a.uses_exact_alarm = s.contains("SCHEDULE_EXACT_ALARM") || s.contains("USE_EXACT_ALARM");
    a.uses_vibration = s.contains("VIBRATE");
    a.can_install_unknown_apps = s.contains("REQUEST_INSTALL_PACKAGES");
    a.has_usage_stats = s.contains("PACKAGE_USAGE_STATS");
    a.runs_at_boot = s.contains("RECEIVE_BOOT_COMPLETED");
    a.has_vpn_service = s.contains("BIND_VPN_SERVICE") || s.contains("VpnService");
}

/// Absence of flags is unknown, never permission to remove a package.
pub fn system_status(raw: &str) -> Option<bool> {
    let flags: Vec<_> = raw
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with("flags=[") || s.starts_with("pkgFlags=["))
        .collect();
    if flags.is_empty() {
        return None;
    }
    Some(flags.iter().any(|line| {
        line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|token| token == "SYSTEM" || token == "PRIVILEGED")
    }))
}
pub fn audits(a: &mut AppInfo) {
    a.hidden_audit.clear();
    a.notification_audit.clear();
    if a.has_launcher_entry == Some(false) && !a.is_system_app {
        a.hidden_audit.push("Aucune icône launcher visible".into());
    }
    if a.app_label_source != "apk" {
        a.hidden_audit.push("Nom affiché réel non récupéré".into());
    }
    if a.icon_path.is_empty() {
        a.hidden_audit
            .push("Icône non récupérée ou adaptive XML".into());
    }
    if risk::generic_label(&a.display_name())
        || a.display_name().trim().to_lowercase()
            == package_to_label(&a.package_name).to_lowercase()
    {
        a.hidden_audit.push("Nom très générique".into());
    }
    if a.has_notification_listener {
        a.notification_audit.push(format!(
            "Accès notifications {}",
            if risk::active(a, "notification_listener") {
                "actif"
            } else {
                "demandé"
            }
        ));
    }
    if a.requests_post_notifications {
        a.notification_audit.push(format!(
            "POST_NOTIFICATIONS {}",
            if risk::active(a, "notifications")
                || a.granted_permissions
                    .iter()
                    .any(|p| p.contains("POST_NOTIFICATIONS"))
            {
                "accordé/actif"
            } else {
                "demandé"
            }
        ));
    }
    if a.runs_at_boot {
        a.notification_audit
            .push("Réception du démarrage déclarée".into());
    }
    if a.uses_exact_alarm {
        a.notification_audit.push(format!(
            "Alarme exacte {}",
            if risk::active(a, "exact_alarm") {
                "active"
            } else {
                "demandée"
            }
        ));
    }
    if a.uses_vibration {
        a.notification_audit.push(format!(
            "Vibration {}",
            if a.granted_permissions.iter().any(|p| p.contains("VIBRATE")) {
                "accordée"
            } else {
                "demandée"
            }
        ));
    }
}
pub async fn appops(adb: &Adb, serial: &str, a: &mut AppInfo) {
    for (requested, op, cap) in [
        (a.has_overlay, "SYSTEM_ALERT_WINDOW", "overlay"),
        (a.has_usage_stats, "GET_USAGE_STATS", "usage_stats"),
        (
            a.can_install_unknown_apps,
            "REQUEST_INSTALL_PACKAGES",
            "install_unknown_apps",
        ),
        (
            a.requests_post_notifications,
            "POST_NOTIFICATION",
            "notifications",
        ),
        (a.uses_exact_alarm, "SCHEDULE_EXACT_ALARM", "exact_alarm"),
    ] {
        if requested
            && ["allow", "foreground"]
                .contains(&adb.appop(serial, &a.package_name, op).await.as_str())
        {
            a.active_capabilities.push(cap.into());
        }
    }
    a.active_capabilities.sort();
    a.active_capabilities.dedup();
}
#[derive(Debug, Default)]
pub struct Metadata {
    pub label: String,
    pub package: String,
    pub version: String,
    pub target: String,
    pub icons: Vec<String>,
}
pub fn badging(s: &str) -> Metadata {
    let label = [
        r"application-label-fr:'([^']+)'",
        r"application-label-fr-CA:'([^']+)'",
        r"application-label-fr-FR:'([^']+)'",
        r"application-label:'([^']+)'",
    ]
    .iter()
    .map(|p| extract(s, p))
    .find(|s| !s.is_empty())
    .unwrap_or_default();
    Metadata {
        label,
        package: extract(s, r"package: name='([^']+)'"),
        version: extract(s, r"versionName='([^']+)'"),
        target: extract(s, r"targetSdkVersion:'([^']+)'"),
        icons: s
            .lines()
            .filter(|l| l.starts_with("application-icon"))
            .map(|l| extract(l, r":'([^']+)'"))
            .filter(|s| !s.is_empty())
            .collect(),
    }
}
pub fn best_icon(paths: &[String]) -> Option<&String> {
    paths
        .iter()
        .filter(|p| {
            ["png", "webp", "jpg", "jpeg"].contains(
                &Path::new(p)
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase()
                    .as_str(),
            )
        })
        .max_by_key(|p| {
            if p.contains("xxxhdpi") {
                640
            } else if p.contains("xxhdpi") {
                480
            } else if p.contains("xhdpi") {
                320
            } else if p.contains("hdpi") {
                240
            } else if p.contains("mdpi") {
                160
            } else {
                0
            }
        })
}
pub async fn apk(
    adb: &Adb,
    tool: &Path,
    cache: &Path,
    serial: &str,
    a: &mut AppInfo,
) -> Result<()> {
    let raw = adb
        .shell(serial, &["pm", "path", &a.package_name], 10)
        .await?;
    let paths: Vec<_> = raw
        .lines()
        .filter_map(|s| s.trim().strip_prefix("package:"))
        .collect();
    let Some(remote) = paths
        .iter()
        .find(|p| p.ends_with("/base.apk"))
        .or(paths.first())
    else {
        return Ok(());
    };
    if !remote.starts_with('/') || !remote.ends_with(".apk") || remote.contains(['\n', '\r']) {
        return Err("Chemin APK invalide".into());
    }
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let local = dir.path().join("base.apk");
    adb.run(
        &["-s", serial, "pull", remote, &local.to_string_lossy()],
        45,
    )
    .await?;
    let raw = process::run(
        tool,
        &process::args(&["dump", "badging", &local.to_string_lossy()]),
        20,
        &adb.cancel,
    )
    .await?;
    let meta = badging(&raw);
    if !meta.package.is_empty() && meta.package != a.package_name {
        return Err("Identité APK différente du package demandé".into());
    }
    if !meta.label.is_empty() {
        a.app_label = meta.label;
        a.app_label_source = "apk".into();
    }
    if a.version_name.is_empty() {
        a.version_name = meta.version;
    }
    if a.target_sdk.is_empty() {
        a.target_sdk = meta.target;
    }
    if let Some(icon) = best_icon(&meta.icons) {
        let file = std::fs::File::open(&local).map_err(|e| e.to_string())?;
        if let Ok(mut archive) = zip::ZipArchive::new(file) {
            if let Ok(mut entry) = archive.by_name(icon) {
                if entry.size() <= 4 * 1024 * 1024 {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    entry
                        .by_ref()
                        .take(4 * 1024 * 1024 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|e| e.to_string())?;
                    if bytes.len() <= 4 * 1024 * 1024 {
                        std::fs::create_dir_all(cache).map_err(|e| e.to_string())?;
                        let ext = Path::new(icon).extension().unwrap().to_string_lossy();
                        let dest = cache.join(format!("{}.{}", a.package_name, ext));
                        std::fs::write(&dest, &bytes).map_err(|e| e.to_string())?;
                        a.icon_path = dest.to_string_lossy().into();
                        a.icon_source = "apk".into();
                    }
                }
            }
        }
    }
    Ok(())
}
pub fn icon_data(cache: &Path, package: &str) -> Result<String> {
    crate::adb::validate_package(package)?;
    for ext in ["png", "webp", "jpg", "jpeg"] {
        let p = cache.join(format!("{package}.{ext}"));
        if p.is_file() {
            let bytes = std::fs::read(p).map_err(|e| e.to_string())?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err("Icône trop volumineuse".into());
            }
            return Ok(format!(
                "data:image/{};base64,{}",
                if ext == "jpg" { "jpeg" } else { ext },
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ));
        }
    }
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permissions_distinguish_grants() {
        let mut a = AppInfo {
            package_name: "com.example.app".into(),
            ..Default::default()
        };
        enrich(&mut a,"versionName=1.0\ntargetSdk=35\npkgFlags=[ HAS_CODE ]\nandroid.permission.READ_SMS: granted=false\nandroid.permission.POST_NOTIFICATIONS: granted=true\nandroid.permission.SYSTEM_ALERT_WINDOW\nBIND_ACCESSIBILITY_SERVICE");
        assert_eq!(
            a.granted_permissions,
            vec!["android.permission.POST_NOTIFICATIONS"]
        );
        assert!(a.has_accessibility);
        assert!(a.active_capabilities.is_empty());
        assert!(!a.is_system_app);
        audits(&mut a);
        assert!(a.notification_audit.iter().any(|s| s.contains("accordé")));
    }
    #[test]
    fn apk_labels_and_raster() {
        let m=badging("package: name='org.test.app' versionName='2'\napplication-label:'Name'\napplication-label-fr:'Nom'\ntargetSdkVersion:'33'\napplication-icon-160:'res/mipmap-mdpi/icon.png'\napplication-icon-640:'res/mipmap-xxxhdpi/icon.png'\napplication-icon-65534:'res/icon.xml'");
        assert_eq!(m.label, "Nom");
        assert_eq!(best_icon(&m.icons).unwrap(), "res/mipmap-xxxhdpi/icon.png");
        assert_eq!(m.target, "33");
    }
}
