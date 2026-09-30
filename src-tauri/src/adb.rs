use crate::{
    model::{Device, Result},
    process,
};
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Adb {
    pub path: PathBuf,
    pub cancel: CancellationToken,
}
impl Adb {
    pub async fn run(&self, values: &[&str], timeout: u64) -> Result<String> {
        process::run(&self.path, &process::args(values), timeout, &self.cancel).await
    }
    pub async fn shell(&self, serial: &str, values: &[&str], timeout: u64) -> Result<String> {
        if serial.is_empty() || serial.starts_with('-') || serial.chars().any(char::is_control) {
            return Err("Numéro ADB invalide".into());
        }
        let mut args = vec!["-s", serial, "shell"];
        args.extend_from_slice(values);
        self.run(&args, timeout).await
    }
    pub async fn devices(&self) -> Result<Vec<Device>> {
        Ok(parse_devices(&self.run(&["devices", "-l"], 10).await?))
    }
    pub async fn detect(&self, serial: &str) -> Result<(Vec<Device>, Device)> {
        let devices = self.devices().await?;
        let selected = if serial.is_empty() {
            devices
                .iter()
                .find(|d| d.state == "device")
                .or(devices.first())
        } else {
            devices.iter().find(|d| d.serial == serial)
        };
        let mut d = selected.cloned().unwrap_or(Device {
            serial: serial.into(),
            state: "disconnected".into(),
            message: "Aucun appareil détecté. Vérifiez le câble USB et le débogage USB.".into(),
            ..Default::default()
        });
        if d.state == "device" {
            d.manufacturer = self
                .shell(&d.serial, &["getprop", "ro.product.manufacturer"], 8)
                .await
                .unwrap_or_default();
            d.model = self
                .shell(&d.serial, &["getprop", "ro.product.model"], 8)
                .await
                .unwrap_or_default();
            d.android_version = self
                .shell(&d.serial, &["getprop", "ro.build.version.release"], 8)
                .await
                .unwrap_or_default();
            d.message = if devices.len() > 1 {
                "Plusieurs appareils connectés : vérifiez la sélection."
            } else {
                "Téléphone connecté et autorisé"
            }
            .into();
        } else if d.state == "unauthorized" {
            d.message = "Acceptez l’autorisation RSA sur le téléphone déverrouillé.".into();
        } else if d.state == "offline" {
            d.message =
                "Téléphone hors ligne : rebranchez le câble ou réparez la connexion.".into();
        }
        Ok((devices, d))
    }
    pub async fn require_connected(&self, serial: &str) -> Result<()> {
        if self
            .devices()
            .await?
            .iter()
            .any(|d| d.serial == serial && d.state == "device")
        {
            Ok(())
        } else {
            Err("Téléphone déconnecté, hors ligne ou non autorisé. Le scan est incomplet.".into())
        }
    }
    pub async fn packages(
        &self,
        serial: &str,
        include_system: bool,
    ) -> Result<BTreeMap<String, String>> {
        let mut args = vec!["pm", "list", "packages", "-i"];
        if !include_system {
            args.push("-3");
        }
        let raw = self.shell(serial, &args, 45).await?;
        if raw.contains("Error:") || raw.contains("Exception") {
            return Err(raw);
        }
        Ok(parse_packages(&raw))
    }
    pub async fn launcher(&self, serial: &str) -> Option<BTreeSet<String>> {
        for brief in [true, false] {
            let mut args = vec!["cmd", "package", "query-activities"];
            if brief {
                args.push("--brief");
            }
            args.extend([
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.LAUNCHER",
            ]);
            if let Ok(raw) = self.shell(serial, &args, 20).await {
                let p = parse_launcher(&raw);
                if !p.is_empty() {
                    return Some(p);
                }
            }
        }
        None
    }
    pub async fn home(&self, serial: &str) -> (Option<BTreeSet<String>>, Option<String>) {
        let mut args = vec![
            "cmd",
            "package",
            "query-activities",
            "--brief",
            "--user",
            "current",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.HOME",
        ];
        let homes = self.shell(serial, &args, 15).await.ok().and_then(|s| {
            let p = parse_launcher(&s);
            if !p.is_empty() || s.contains("No activities found") {
                Some(p)
            } else {
                None
            }
        });
        args[2] = "resolve-activity";
        let default = self
            .shell(serial, &args, 15)
            .await
            .ok()
            .and_then(|s| parse_default_home(&s));
        (homes, default)
    }
    pub async fn services(&self, serial: &str) -> BTreeMap<String, Vec<String>> {
        let mut caps: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (setting, cap) in [
            ("enabled_accessibility_services", "accessibility"),
            ("enabled_notification_listeners", "notification_listener"),
        ] {
            if let Ok(raw) = self
                .shell(serial, &["settings", "get", "secure", setting], 8)
                .await
            {
                for package in parse_components(&raw) {
                    caps.entry(package).or_default().push(cap.into());
                }
            }
        }
        if let Ok(raw) = self.shell(serial, &["dumpsys", "device_policy"], 12).await {
            for p in parse_admins(&raw) {
                caps.entry(p).or_default().push("device_admin".into());
            }
        }
        caps
    }
    pub async fn dumpsys(&self, serial: &str, package: &str) -> Result<String> {
        validate_package(package)?;
        let s = self
            .shell(serial, &["dumpsys", "package", package], 15)
            .await?;
        if s.is_empty() || s.contains("Unable to find package") || s.contains("Can't find service")
        {
            return Err("Métadonnées du package indisponibles".into());
        }
        Ok(s)
    }
    pub async fn appop(&self, serial: &str, package: &str, operation: &str) -> String {
        self.shell(serial, &["cmd", "appops", "get", package, operation], 8)
            .await
            .map(|s| parse_appop(&s, operation))
            .unwrap_or_default()
    }
    pub async fn open_settings(&self, serial: &str, package: &str) -> Result<String> {
        validate_package(package)?;
        self.shell(
            serial,
            &[
                "am",
                "start",
                "-a",
                "android.settings.APPLICATION_DETAILS_SETTINGS",
                "-d",
                &format!("package:{package}"),
            ],
            10,
        )
        .await
    }
    /// Only called after backend validation and native human confirmation.
    pub(crate) async fn uninstall(&self, serial: &str, package: &str) -> Result<String> {
        validate_package(package)?;
        self.shell(serial, &uninstall_args(package)?, 60).await
    }
}
pub fn validate_package(p: &str) -> Result<()> {
    if Regex::new(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
        .unwrap()
        .is_match(p)
    {
        Ok(())
    } else {
        Err("Package invalide".into())
    }
}
pub fn uninstall_args(package: &str) -> Result<Vec<&str>> {
    validate_package(package)?;
    Ok(vec!["pm", "uninstall", "--user", "0", package])
}
pub fn parse_devices(raw: &str) -> Vec<Device> {
    raw.lines()
        .filter_map(|s| {
            let parts: Vec<_> = s.split_whitespace().collect();
            if parts.len() < 2
                || s.starts_with("List of devices")
                || s.starts_with('*')
                || s.starts_with("adb:")
            {
                return None;
            }
            Some(Device {
                serial: parts[0].into(),
                state: parts[1].into(),
                details: parts[2..].join(" "),
                ..Default::default()
            })
        })
        .collect()
}
pub fn parse_packages(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter_map(|s| {
            let rest = s.trim().strip_prefix("package:")?;
            let p = rest.split_whitespace().next()?;
            if p != "android" && validate_package(p).is_err() {
                return None;
            }
            let i = rest
                .split_whitespace()
                .find_map(|v| v.strip_prefix("installer="))
                .unwrap_or("");
            Some((
                p.into(),
                if i == "null" || i == "None" {
                    String::new()
                } else {
                    i.into()
                },
            ))
        })
        .collect()
}
pub fn parse_launcher(raw: &str) -> BTreeSet<String> {
    let patterns = [
        r"(?:^|\s)([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/",
        r"packageName=([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)",
    ];
    raw.lines()
        .filter_map(|s| {
            patterns
                .iter()
                .find_map(|p| Regex::new(p).unwrap().captures(s).map(|c| c[1].to_owned()))
                .filter(|s| !s.starts_with("android.intent."))
        })
        .collect()
}
pub fn parse_default_home(raw: &str) -> Option<String> {
    let re = Regex::new(r"^([\w]+(?:\.[\w]+)+)/([\w.$]+)$").unwrap();
    raw.lines().find_map(|s| {
        re.captures(s.trim())
            .filter(|c| !c[2].ends_with("ResolverActivity") && !c[2].ends_with("ChooserActivity"))
            .map(|c| c[1].to_owned())
    })
}
pub fn parse_components(raw: &str) -> BTreeSet<String> {
    raw.split([':', ','])
        .filter_map(|s| {
            let p = s.trim().split('/').next()?;
            validate_package(p).ok().map(|_| p.into())
        })
        .collect()
}
pub fn parse_admins(raw: &str) -> BTreeSet<String> {
    Regex::new(r"(?:AdminInfo|ComponentInfo)\{([^/\s}]+)/")
        .unwrap()
        .captures_iter(raw)
        .filter_map(|c| validate_package(&c[1]).ok().map(|_| c[1].into()))
        .collect()
}
pub fn parse_appop(raw: &str, operation: &str) -> String {
    raw.lines()
        .filter(|s| s.contains(operation))
        .find_map(|s| {
            Regex::new(r"(?i)\b(allow|foreground|deny|ignore|default)\b")
                .unwrap()
                .find(s)
                .map(|v| v.as_str().to_lowercase())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parsers_and_protections() {
        let d=parse_devices("* daemon started successfully *\nList of devices attached\nABC device model:SM_G960F\nDEF unauthorized\nE offline\n");
        assert_eq!(d.len(), 3);
        assert_eq!(d[1].state, "unauthorized");
        assert_eq!(
            parse_packages("package:com.test.app installer=null")["com.test.app"],
            ""
        );
        assert_eq!(
            parse_launcher("priority=0\ncom.test.app/.Main\npackageName=com.other.app").len(),
            2
        );
        assert_eq!(
            parse_default_home("android/com.android.internal.app.ResolverActivity"),
            None
        );
        assert_eq!(
            parse_default_home("com.test.app/.Home"),
            Some("com.test.app".into())
        );
        assert_eq!(parse_components("com.a.b/.A:com.c.d/.C").len(), 2);
        assert_eq!(parse_admins("AdminInfo{com.a.b/.Admin}").len(), 1);
        assert_eq!(
            parse_appop("SYSTEM_ALERT_WINDOW: allow; time=0", "SYSTEM_ALERT_WINDOW"),
            "allow"
        );
        assert_eq!(
            uninstall_args("com.test.app").unwrap(),
            vec!["pm", "uninstall", "--user", "0", "com.test.app"]
        );
        for p in [
            "foo;rm -rf /",
            "--user",
            "com.app\nreboot",
            "com.app/other",
            "com.app$(x)",
        ] {
            assert!(uninstall_args(p).is_err());
        }
    }
}
