use crate::{adb::Adb, database::Database, model::*, risk, scanner};
use std::path::Path;

/// Complete domain workflow, independent from Tauri and React.
pub async fn scan_device(
    adb: &Adb,
    device: Device,
    include_system: bool,
    tool: Option<&Path>,
    cache: &Path,
    db_path: &Path,
    notify: impl Fn(usize, usize, &str),
) -> Result<Scan> {
    let cancel = &adb.cancel;
    let serial = device.serial.clone();
    notify(0, 0, "Lecture de l’inventaire Android…");
    let packages = adb.packages(&serial, include_system).await?;
    let launcher = adb.launcher(&serial).await;
    let (homes, home) = adb.home(&serial).await;
    let services = adb.services(&serial).await;
    let mut scan = Scan {
        rules_version: crate::evidence::RULES_VERSION,
        device,
        total: packages.len(),
        ..Default::default()
    };
    for (index, (package, installer)) in packages.into_iter().enumerate() {
        if cancel.is_cancelled() {
            scan.cancelled = true;
            break;
        }
        if let Err(e) = adb.require_connected(&serial).await {
            scan.errors.push(e);
            scan.cancelled = true;
            break;
        }
        notify(index, scan.total, &package);
        let mut a = AppInfo {
            package_name: package.clone(),
            installer,
            is_system_app: include_system,
            has_launcher_entry: launcher.as_ref().map(|l| l.contains(&package)),
            is_home_app: homes.as_ref().map(|h| h.contains(&package)),
            is_default_home: home.as_ref().map(|h| h == &package),
            ..Default::default()
        };
        if a.is_default_home == Some(true) {
            a.is_home_app = Some(true);
        }
        match adb.dumpsys(&serial, &package).await {
            Ok(raw) => {
                scanner::enrich(&mut a, &raw);
                a.active_capabilities = services.get(&package).cloned().unwrap_or_default();
                scanner::appops(adb, &serial, &mut a).await;
                if let Some(tool) = &tool {
                    if let Err(e) = scanner::apk(adb, tool, cache, &serial, &mut a).await {
                        a.apk_analysis
                            .limitations
                            .push("APK non inspecté : récupération ou lecture impossible.".into());
                        scan.errors
                            .push(format!("{package} : métadonnées APK indisponibles : {e}"));
                    }
                } else {
                    a.apk_analysis
                        .limitations
                        .push("APK non inspecté : aapt2 indisponible.".into());
                }
                scanner::audits(&mut a);
            }
            Err(e) => {
                a.dumpsys_error = e.clone();
                scan.errors.push(format!("{package} : {e}"));
            }
        }
        let db = Database::open(db_path)?;
        let reputation = db.reputation(&package)?;
        let risk = risk::evaluate(&a, &reputation);
        let note = db.note(&package)?;
        scan.rows.push(Row {
            app: a,
            risk: risk.clone(),
            local_risk: risk,
            ai: None,
            ai_text: String::new(),
            note,
            validation: "unreviewed".into(),
        });
    }
    if cancel.is_cancelled() {
        scan.cancelled = true;
    }
    if !scan.cancelled {
        if let Err(e) = adb.require_connected(&serial).await {
            scan.cancelled = true;
            scan.errors.push(e);
        }
    }
    scan.rows.sort_by_key(|r| std::cmp::Reverse(r.risk.score));
    if !scan.cancelled {
        Database::open(db_path)?.record(&mut scan)?;
    }
    notify(
        scan.rows.len(),
        scan.total,
        if scan.cancelled {
            "Scan interrompu — aucune désinstallation autorisée"
        } else {
            "Scan terminé"
        },
    );
    Ok(scan)
}
