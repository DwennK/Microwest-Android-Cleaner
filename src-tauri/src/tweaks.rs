//! Explicit workshop actions only; no arbitrary shell command or package from the UI.
use crate::{adb::Adb, model::*};
use serde::{Deserialize, Serialize};

pub const CHROME: &str = "com.android.chrome";
pub const SAMSUNG: &str = "com.sec.android.app.sbrowser";
pub const ONE_UI: &str = "com.sec.android.app.launcher";
const ADGUARD: &str = "dns.adguard-dns.com";

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    DnsAdguard,
    DnsRestore,
    ChromeDisable,
    ChromeEnable,
    SamsungEnable,
    SamsungStore,
    BrowserSettings,
    SamsungOpen,
    AdblockStore,
    HomeRestore,
    HomeSettings,
    PlayStore,
    ConfirmAdblock,
    ConfirmUpdates,
}
impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::DnsAdguard => "Configurer le DNS AdGuard",
            Self::DnsRestore => "Restaurer le DNS précédent",
            Self::ChromeDisable => "Désactiver Chrome",
            Self::ChromeEnable => "Réactiver Chrome",
            Self::SamsungEnable => "Activer Samsung Browser",
            Self::SamsungStore => "Ouvrir la fiche Samsung Browser",
            Self::BrowserSettings => "Choisir le navigateur par défaut",
            Self::SamsungOpen => "Ouvrir Samsung Browser",
            Self::AdblockStore => "Ouvrir la fiche AdGuard Content Blocker",
            Self::HomeRestore => "Rétablir One UI Home",
            Self::HomeSettings => "Choisir l’écran d’accueil",
            Self::PlayStore => "Ouvrir le Play Store",
            Self::ConfirmAdblock => "Activation du bloqueur dans Samsung Browser",
            Self::ConfirmUpdates => "Mises à jour Play Store",
        }
    }
    pub fn changes_device(self) -> bool {
        matches!(
            self,
            Self::DnsAdguard
                | Self::DnsRestore
                | Self::ChromeDisable
                | Self::ChromeEnable
                | Self::SamsungEnable
                | Self::HomeRestore
        )
    }
    pub fn manual(self) -> bool {
        matches!(self, Self::ConfirmAdblock | Self::ConfirmUpdates)
    }
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub dns: Option<DnsSettings>,
    pub chrome: Option<bool>,
    pub samsung: Option<bool>,
    pub default_browser: Option<String>,
    pub home: Option<String>,
    pub one_ui_available: bool,
    pub warnings: Vec<String>,
}

pub fn validate_scan(scan: &Scan, serial: &str, scan_id: i64) -> Result<()> {
    if scan.demo
        || scan.cancelled
        || scan.device.state != "device"
        || scan.scan_id != Some(scan_id)
        || serial.is_empty()
        || scan.device.serial != serial
    {
        return Err(
            "Un scan réel complet du téléphone sélectionné est requis pour les Tweaks.".into(),
        );
    }
    Ok(())
}

fn checked(raw: String) -> Result<String> {
    let lower = raw.to_lowercase();
    if [
        "error:",
        "exception",
        "permission denial",
        "permission denied",
        "not allowed",
        "unknown command",
        "failed",
        "no activity found",
        "unable to resolve",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        Err(raw)
    } else {
        Ok(raw)
    }
}
async fn shell(adb: &Adb, serial: &str, args: &[&str]) -> Result<String> {
    checked(adb.shell(serial, args, 15).await?)
}
pub async fn require_owner(adb: &Adb, serial: &str) -> Result<()> {
    adb.require_connected(serial).await?;
    if shell(adb, serial, &["am", "get-current-user"])
        .await?
        .trim()
        != "0"
    {
        return Err("Les Tweaks sont disponibles uniquement dans le profil principal Android (utilisateur 0).".into());
    }
    Ok(())
}
fn setting_value(s: String) -> Option<String> {
    if s.trim() == "null" {
        None
    } else {
        Some(s.trim().into())
    }
}
pub async fn read_dns(adb: &Adb, serial: &str) -> Result<DnsSettings> {
    let api = shell(adb, serial, &["getprop", "ro.build.version.sdk"]).await?;
    if api.trim().parse::<u32>().unwrap_or(0) < 28 {
        return Err("Le DNS privé nécessite Android 9 ou plus récent.".into());
    }
    let mode = setting_value(
        shell(
            adb,
            serial,
            &["settings", "get", "global", "private_dns_mode"],
        )
        .await?,
    );
    let hostname = setting_value(
        shell(
            adb,
            serial,
            &["settings", "get", "global", "private_dns_specifier"],
        )
        .await?,
    );
    let dns = DnsSettings { mode, hostname };
    validate_dns(&dns)?;
    Ok(dns)
}
fn validate_dns(dns: &DnsSettings) -> Result<()> {
    if !matches!(
        dns.mode.as_deref(),
        None | Some("" | "off" | "opportunistic" | "hostname")
    ) {
        return Err("Mode DNS non reconnu : aucune modification automatique.".into());
    }
    if dns.hostname.as_ref().is_some_and(|s| {
        s.len() > 253
            || !s
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
    }) {
        return Err("Nom d’hôte DNS non pris en charge : aucune modification automatique.".into());
    }
    Ok(())
}
async fn write_setting(adb: &Adb, serial: &str, key: &str, value: &Option<String>) -> Result<()> {
    match value {
        Some(v) => {
            shell(
                adb,
                serial,
                &[
                    "settings",
                    "put",
                    "global",
                    key,
                    if v.is_empty() { "''" } else { v },
                ],
            )
            .await?;
        }
        None => {
            shell(adb, serial, &["settings", "delete", "global", key]).await?;
        }
    }
    Ok(())
}
async fn write_dns(adb: &Adb, serial: &str, dns: &DnsSettings) -> Result<()> {
    validate_dns(dns)?;
    let api = shell(adb, serial, &["getprop", "ro.build.version.sdk"]).await?;
    if api.trim().parse::<u32>().unwrap_or(0) < 28 {
        return Err("Le DNS privé nécessite Android 9 ou plus récent.".into());
    }
    write_setting(adb, serial, "private_dns_specifier", &dns.hostname).await?;
    write_setting(adb, serial, "private_dns_mode", &dns.mode).await?;
    if read_dns(adb, serial).await? != *dns {
        return Err("Le réglage DNS relu ne correspond pas à la demande. Utilisez Restaurer le DNS précédent.".into());
    }
    Ok(())
}
async fn packages(
    adb: &Adb,
    serial: &str,
    flag: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let raw = shell(
        adb,
        serial,
        &["pm", "list", "packages", "--user", "0", flag],
    )
    .await?;
    Ok(raw
        .lines()
        .filter_map(|s| s.trim().strip_prefix("package:").map(str::to_owned))
        .collect())
}
async fn resolve(adb: &Adb, serial: &str, browser: bool) -> Result<Option<String>> {
    let mut args = vec![
        "cmd",
        "package",
        "resolve-activity",
        "--brief",
        "--user",
        "0",
        "-a",
    ];
    if browser {
        args.extend([
            "android.intent.action.VIEW",
            "-c",
            "android.intent.category.BROWSABLE",
            "-d",
            "https://example.com",
        ]);
    } else {
        args.extend([
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.HOME",
        ]);
    }
    let raw = shell(adb, serial, &args).await?;
    Ok(crate::adb::parse_default_home(&raw))
}
pub async fn status(adb: &Adb, serial: &str) -> Result<Status> {
    require_owner(adb, serial).await?;
    let enabled = packages(adb, serial, "-e").await?;
    let disabled = packages(adb, serial, "-d").await?;
    if enabled.is_empty() {
        return Err("Liste des applications actives indisponible.".into());
    }
    let app_state = |p: &str| {
        if enabled.contains(p) {
            Some(true)
        } else if disabled.contains(p) {
            Some(false)
        } else {
            None
        }
    };
    let mut warnings = Vec::new();
    let dns = match read_dns(adb, serial).await {
        Ok(v) => Some(v),
        Err(e) => {
            warnings.push(e);
            None
        }
    };
    let mut home = None;
    let mut default_browser = None;
    match resolve(adb, serial, false).await {
        Ok(v) => home = v,
        Err(e) => warnings.push(e),
    }
    match resolve(adb, serial, true).await {
        Ok(v) => default_browser = v,
        Err(e) => warnings.push(e),
    }
    Ok(Status {
        dns,
        chrome: app_state(CHROME),
        samsung: app_state(SAMSUNG),
        default_browser,
        home,
        one_ui_available: enabled.contains(ONE_UI),
        warnings,
    })
}
async fn set_enabled(adb: &Adb, serial: &str, package: &str, enabled: bool) -> Result<()> {
    shell(
        adb,
        serial,
        &[
            "pm",
            if enabled { "enable" } else { "disable-user" },
            "--user",
            "0",
            package,
        ],
    )
    .await?;
    if !packages(adb, serial, if enabled { "-e" } else { "-d" })
        .await?
        .contains(package)
    {
        return Err("Le nouvel état de l’application n’a pas pu être vérifié.".into());
    }
    Ok(())
}
async fn open(adb: &Adb, serial: &str, args: &[&str]) -> Result<()> {
    let mut cmd = vec!["am", "start", "--user", "0"];
    cmd.extend_from_slice(args);
    let result = shell(adb, serial, &cmd).await?;
    if !result.contains("Starting:") {
        return Err("Android n’a pas confirmé l’ouverture de l’écran.".into());
    }
    Ok(())
}
pub fn manual_detail(action: Action, note: &str) -> Result<String> {
    let note = note.trim();
    if matches!(action, Action::ConfirmUpdates) {
        let count = note
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0 && *n <= 10000)
            .ok_or("Indiquez le nombre d’applications effectivement mises à jour (1 à 10 000).")?;
        Ok(format!("{count} application(s) mises à jour ; déclaration du technicien, non vérifiée par ADB."))
    } else if matches!(action, Action::ConfirmAdblock)
        && !note.is_empty()
        && note.chars().count() <= 500
    {
        Ok(format!("Bloqueur installé et activé selon le technicien : {note}. Activation non vérifiée par ADB."))
    } else {
        Err("Indiquez le nom du bloqueur activé (500 caractères maximum).".into())
    }
}

pub async fn execute(
    adb: &Adb,
    serial: &str,
    action: Action,
    backup: Option<&DnsSettings>,
) -> Result<String> {
    require_owner(adb, serial).await?;
    match action {
        Action::DnsAdguard => {
            write_dns(
                adb,
                serial,
                &DnsSettings {
                    mode: Some("hostname".into()),
                    hostname: Some(ADGUARD.into()),
                },
            )
            .await?;
            return Ok(format!("DNS privé configuré : {ADGUARD}. Réglage relu ; connectivité et filtrage à vérifier sur le téléphone."));
        }
        Action::DnsRestore => {
            write_dns(
                adb,
                serial,
                backup.ok_or("Aucune sauvegarde DNS pour cette intervention.")?,
            )
            .await?;
            return Ok("Réglages DNS précédents restaurés et relus.".into());
        }
        Action::ChromeDisable => {
            if !packages(adb, serial, "-e").await?.contains(SAMSUNG)
                || resolve(adb, serial, true).await?.as_deref() != Some(SAMSUNG)
            {
                return Err("Activez Samsung Browser et choisissez-le comme navigateur par défaut avant de désactiver Chrome.".into());
            }
            set_enabled(adb, serial, CHROME, false).await?;
        }
        Action::ChromeEnable => set_enabled(adb, serial, CHROME, true).await?,
        Action::SamsungEnable => set_enabled(adb, serial, SAMSUNG, true).await?,
        Action::HomeRestore => {
            let raw = shell(
                adb,
                serial,
                &[
                    "cmd",
                    "package",
                    "query-activities",
                    "--brief",
                    "--user",
                    "0",
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.HOME",
                ],
            )
            .await?;
            if !crate::adb::parse_launcher(&raw).contains(ONE_UI) {
                return Err(
                    "One UI Home n’est pas disponible comme écran d’accueil sur ce téléphone."
                        .into(),
                );
            }
            shell(
                adb,
                serial,
                &["cmd", "package", "set-home-activity", "--user", "0", ONE_UI],
            )
            .await?;
            if resolve(adb, serial, false).await?.as_deref() != Some(ONE_UI) {
                return Err("Le retour à One UI Home n’a pas pu être vérifié. Ouvrez le choix de l’écran d’accueil.".into());
            }
        }
        Action::BrowserSettings => {
            open(
                adb,
                serial,
                &["-a", "android.settings.MANAGE_DEFAULT_APPS_SETTINGS"],
            )
            .await?
        }
        Action::HomeSettings => {
            open(adb, serial, &["-a", "android.settings.HOME_SETTINGS"]).await?
        }
        Action::SamsungOpen => {
            open(
                adb,
                serial,
                &[
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "-p",
                    SAMSUNG,
                ],
            )
            .await?
        }
        Action::SamsungStore | Action::AdblockStore => {
            let uri = format!(
                "market://details?id={}",
                if matches!(action, Action::SamsungStore) {
                    SAMSUNG
                } else {
                    "com.adguard.android.contentblocker"
                }
            );
            open(
                adb,
                serial,
                &[
                    "-a",
                    "android.intent.action.VIEW",
                    "-d",
                    &uri,
                    "-p",
                    "com.android.vending",
                ],
            )
            .await?;
        }
        Action::PlayStore => {
            open(
                adb,
                serial,
                &[
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "-p",
                    "com.android.vending",
                ],
            )
            .await?
        }
        Action::ConfirmAdblock | Action::ConfirmUpdates => {
            return Err("Confirmation manuelle attendue.".into())
        }
    }
    Ok(if action.changes_device() { "Modification effectuée ; état relu sur le téléphone." } else { "Ouverture demandée à Android. Terminez l’action sur le téléphone ; cette ouverture ne confirme pas sa réalisation." }.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuse_untrusted_dns_and_actions() {
        for host in ["a;reboot", "$(id)", "dns name", "a/b", "'x'"] {
            assert!(validate_dns(&DnsSettings {
                mode: Some("hostname".into()),
                hostname: Some(host.into())
            })
            .is_err());
        }
        assert!(serde_json::from_str::<Action>("\"shell\"").is_err());
        assert!(checked("Error: Activity not started".into()).is_err());
        assert!(checked("java.lang.SecurityException".into()).is_err());
    }
    #[test]
    fn require_same_live_complete_scan() {
        let mut scan = Scan {
            scan_id: Some(1),
            device: Device {
                serial: "phone".into(),
                state: "device".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_scan(&scan, "phone", 1).is_ok());
        assert!(validate_scan(&scan, "other", 1).is_err());
        assert!(validate_scan(&scan, "phone", 2).is_err());
        scan.demo = true;
        assert!(validate_scan(&scan, "phone", 1).is_err());
        scan.demo = false;
        scan.cancelled = true;
        assert!(validate_scan(&scan, "phone", 1).is_err());
        scan.cancelled = false;
        scan.device.state = "historical".into();
        assert!(validate_scan(&scan, "phone", 1).is_err());
    }
    #[test]
    fn manual_confirmations_are_explicit_and_bounded() {
        assert!(manual_detail(Action::ConfirmUpdates, "7")
            .unwrap()
            .contains("7 application"));
        for value in ["0", "-1", "1.5", "10001", ""] {
            assert!(manual_detail(Action::ConfirmUpdates, value).is_err());
        }
        assert!(manual_detail(Action::ConfirmAdblock, "").is_err());
        assert!(manual_detail(Action::ConfirmAdblock, "AdGuard")
            .unwrap()
            .contains("non vérifiée"));
    }
}
