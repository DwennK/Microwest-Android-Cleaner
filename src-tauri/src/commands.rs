use crate::{
    adb::{self, Adb},
    ai, config,
    database::Database,
    model::*,
    process, reports, risk, scanner,
};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

pub struct Engine {
    root: PathBuf,
    resources: PathBuf,
    scan: Mutex<Option<Scan>>,
    operation: Arc<Semaphore>,
    cancel: Mutex<CancellationToken>,
    backup: Option<PathBuf>,
    diagnostic: Mutex<String>,
}
impl Engine {
    pub fn new(app: &tauri::AppHandle) -> Result<Self> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let dir = exe.parent().ok_or("Dossier exécutable absent")?;
        let root = if let Some(p) = std::env::var_os("MICROWEST_DATA_DIR") {
            PathBuf::from(p)
        } else if cfg!(debug_assertions) {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .to_owned()
        } else if dir.join("portable.flag").is_file()
            || dir.join("data/app_reputation.sqlite").is_file()
        {
            dir.to_owned()
        } else {
            app.path().app_local_data_dir().map_err(|e| e.to_string())?
        };
        for name in ["data", "cache/app_icons", "logs", "reports"] {
            std::fs::create_dir_all(root.join(name))
                .map_err(|e| format!("Dossier {} inaccessible : {e}", root.display()))?;
        }
        let backup = Database::initialize(&root.join("data/app_reputation.sqlite"))?;
        let resources = if cfg!(debug_assertions) {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .to_owned()
        } else {
            app.path().resource_dir().map_err(|e| e.to_string())?
        };
        Ok(Self {
            root,
            resources,
            scan: Mutex::new(None),
            operation: Arc::new(Semaphore::new(1)),
            cancel: Mutex::new(CancellationToken::new()),
            backup,
            diagnostic: Mutex::new(String::new()),
        })
    }
    fn db(&self) -> Result<Database> {
        Database::open(&self.root.join("data/app_reputation.sqlite"))
    }
    fn tool(&self, name: &str) -> Option<PathBuf> {
        process::discover(name, &[self.resources.clone(), self.root.clone()])
    }
    fn adb(&self, cancel: CancellationToken) -> Result<Adb> {
        Ok(Adb {
            path: self.tool("adb").ok_or(
                "ADB introuvable. Installez Android Platform Tools ou configurez ADB_PATH.",
            )?,
            cancel,
        })
    }
    fn begin(&self) -> Result<(OwnedSemaphorePermit, CancellationToken)> {
        let permit = self
            .operation
            .clone()
            .try_acquire_owned()
            .map_err(|_| "Une opération est déjà en cours")?;
        let cancel = CancellationToken::new();
        *self.cancel.lock().map_err(|e| e.to_string())? = cancel.clone();
        Ok((permit, cancel))
    }
    fn current(&self) -> Result<Scan> {
        self.scan
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or("Aucun scan disponible".into())
    }
    fn store(&self, scan: Scan) -> Result<Scan> {
        *self.scan.lock().map_err(|e| e.to_string())? = Some(scan.clone());
        Ok(scan)
    }
    fn log(&self, message: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("logs/app.log"))
        {
            let _ = writeln!(f, "{} {}", chrono::Utc::now().to_rfc3339(), message);
        }
    }
}
fn progress(app: &tauri::AppHandle, operation: &str, current: usize, total: usize, message: &str) {
    let _ = app.emit(
        "operation-progress",
        Progress {
            operation: operation.into(),
            current,
            total,
            message: message.into(),
        },
    );
}

#[tauri::command]
pub async fn bootstrap(state: State<'_, Engine>) -> Result<Value> {
    let (settings, settings_error) = match config::read(&state.root) {
        Ok(settings) => (settings, None),
        Err(error) => (config::defaults(&state.root), Some(error)),
    };
    Ok(
        json!({"root":state.root,"settings":settings,"settings_error":settings_error,"adb_path":state.tool("adb"),"aapt2_path":state.tool("aapt2"),"migration_backup":state.backup,"scan":state.scan.lock().map_err(|e|e.to_string())?.clone()}),
    )
}
#[tauri::command]
pub async fn detect_devices(state: State<'_, Engine>, serial: String) -> Result<Value> {
    let adb = state.adb(CancellationToken::new())?;
    let (devices, device) = adb.detect(&serial).await?;
    Ok(json!({"devices":devices,"device":device,"adb_path":adb.path}))
}
#[tauri::command]
pub async fn daemon_action(state: State<'_, Engine>, action: String) -> Result<String> {
    let (_permit, cancel) = state.begin()?;
    let adb = state.adb(cancel)?;
    match action.as_str() {
        "start" => adb.run(&["start-server"], 15).await,
        "kill" => adb.run(&["kill-server"], 15).await,
        "restart" | "repair" => {
            adb.run(&["kill-server"], 15).await?;
            adb.run(&["start-server"], 15).await
        }
        _ => Err("Action ADB inconnue".into()),
    }
}
#[tauri::command]
pub async fn diagnostic(state: State<'_, Engine>, serial: String) -> Result<String> {
    let mut s = format!(
        "Microwest Android Cleaner 2 · Rust/Tauri\nSystème : {} {}\nDonnées : {}\n",
        std::env::consts::OS,
        std::env::consts::ARCH,
        state.root.display()
    );
    for name in ["data", "logs", "cache", "reports"] {
        let path = state.root.join(name);
        let status = tempfile::NamedTempFile::new_in(&path)
            .map(|_| "OK écriture".to_owned())
            .unwrap_or_else(|e| e.to_string());
        s.push_str(&format!("{name} : {} — {status}\n", path.display()));
    }
    s.push_str(&format!(
        "aapt2 : {}\n",
        state
            .tool("aapt2")
            .map(|p| p.display().to_string())
            .unwrap_or("absent (optionnel)".into())
    ));
    match state.adb(CancellationToken::new()) {
        Err(e) => s.push_str(&e),
        Ok(adb) => {
            s.push_str(&format!("ADB : {}\n", adb.path.display()));
            for args in [&["version"][..], &["devices", "-l"][..]] {
                s.push_str(&adb.run(args, 10).await.unwrap_or_else(|e| e));
                s.push('\n');
            }
            if let Ok((_, d)) = adb.detect(&serial).await {
                s.push_str(&format!(
                    "Appareil sélectionné : {} {} {}\n{}",
                    d.serial, d.model, d.state, d.message
                ));
            }
        }
    }
    *state.diagnostic.lock().map_err(|e| e.to_string())? = s.clone();
    Ok(s)
}
#[tauri::command]
pub async fn export_diagnostic(state: State<'_, Engine>) -> Result<String> {
    let s = state.diagnostic.lock().map_err(|e| e.to_string())?.clone();
    if s.is_empty() {
        return Err("Exécutez d'abord le diagnostic".into());
    }
    let path = state.root.join("reports").join(format!(
        "diagnostic_adb_{}.txt",
        chrono::Utc::now().format("%Y%m%d_%H%M%S_%f")
    ));
    config::atomic_write(&path, s.as_bytes())?;
    Ok(path.to_string_lossy().into())
}
#[tauri::command]
pub async fn cancel_operation(state: State<'_, Engine>) -> Result<()> {
    state.cancel.lock().map_err(|e| e.to_string())?.cancel();
    Ok(())
}

#[tauri::command]
pub async fn start_scan(
    app: tauri::AppHandle,
    state: State<'_, Engine>,
    serial: String,
    include_system: bool,
) -> Result<Scan> {
    let (_permit, cancel) = state.begin()?;
    let adb = state.adb(cancel)?;
    *state.scan.lock().map_err(|e| e.to_string())? = None;
    let (_, device) = adb.detect(&serial).await?;
    if device.state != "device" {
        return Err(device.message);
    }
    let tool = state.tool("aapt2");
    let scan = crate::workflow::scan_device(
        &adb,
        device,
        include_system,
        tool.as_deref(),
        &state.root.join("cache/app_icons"),
        &state.root.join("data/app_reputation.sqlite"),
        |n, total, message| progress(&app, "scan", n, total, message),
    )
    .await?;
    state.log(&format!(
        "scan terminé : {} apps ; incomplet={}",
        scan.rows.len(),
        scan.cancelled
    ));
    state.store(scan)
}
#[tauri::command]
pub async fn analyze_ai(app: tauri::AppHandle, state: State<'_, Engine>) -> Result<Scan> {
    let (_permit, cancel) = state.begin()?;
    let mut scan = state.current()?;
    if scan.demo || scan.cancelled || scan.device.state == "historical" || scan.rows.is_empty() {
        return Err("Un scan réel complet est requis".into());
    }
    reevaluate(&mut scan, &state.db()?)?;
    let results = ai::analyze(&state.root, &scan.rows, &cancel, |n, total| {
        progress(&app, "ai", n, total, "Analyse IA des métadonnées…")
    })
    .await?;
    if cancel.is_cancelled() {
        return Err("Analyse IA annulée".into());
    }
    let mut db = state.db()?;
    let mut applied = 0;
    let mut changed = 0;
    for row in &mut scan.rows {
        if let Some(result) = results.get(&row.app.package_name) {
            let previous = (row.risk.score, row.risk.recommended_action.clone());
            if ai::apply(row, result.clone(), &db.reputation(&row.app.package_name)?) {
                applied += 1;
            }
            if previous != (row.risk.score, row.risk.recommended_action.clone()) {
                changed += 1;
            }
        }
    }
    scan.analysis_notice = format!("IA : {} avis reçus, {applied} intégrés, {changed} décisions ou scores modifiés. Les autres avis sont non étayés ou concernent une décision protégée.", results.len());
    scan.rows.sort_by_key(|r| std::cmp::Reverse(r.risk.score));
    db.persist_analysis(&scan)?;
    if let Some(id) = scan.scan_id {
        scan.comparison = Some(db.comparison(id)?);
    }
    state.store(scan)
}
#[tauri::command]
pub async fn update_note(state: State<'_, Engine>, package: String, note: String) -> Result<Scan> {
    let (_permit, _) = state.begin()?;
    let mut scan = state.current()?;
    let row = scan
        .rows
        .iter_mut()
        .find(|r| r.app.package_name == package)
        .ok_or("Application absente du scan")?;
    if !scan.demo {
        state.db()?.set_note(&package, &note)?;
    }
    row.note = note.trim().into();
    state.db()?.persist_analysis(&scan)?;
    state.store(scan)
}
#[tauri::command]
pub async fn update_validation(
    state: State<'_, Engine>,
    package: String,
    status: String,
) -> Result<Scan> {
    let (_permit, _) = state.begin()?;
    if !["unreviewed", "keep", "review", "remove"].contains(&status.as_str()) {
        return Err("Validation invalide".into());
    }
    let mut scan = state.current()?;
    let id = scan.scan_id.ok_or("Scan complet requis")?;
    let row = scan
        .rows
        .iter_mut()
        .find(|r| r.app.package_name == package)
        .ok_or("Application absente")?;
    if row.validation == "removed" {
        return Err(
            "Une désinstallation enregistrée ne peut pas être annulée par une validation".into(),
        );
    }
    if status == "remove"
        && (row.app.is_system_app || row.risk.recommended_action == "do_not_touch")
    {
        return Err("Application protégée".into());
    }
    state.db()?.set_validation(id, &package, &status)?;
    row.validation = status;
    state.db()?.persist_analysis(&scan)?;
    state.store(scan)
}
#[tauri::command]
pub async fn update_reputation(
    state: State<'_, Engine>,
    package: String,
    kind: String,
    reason: String,
) -> Result<Scan> {
    let (_permit, _) = state.begin()?;
    let mut scan = state.current()?;
    if scan.demo {
        return Err("Réputation désactivée en démonstration".into());
    }
    let row = scan
        .rows
        .iter()
        .find(|r| r.app.package_name == package)
        .ok_or("Application absente")?;
    let mut db = state.db()?;
    db.set_reputation(&package, &row.app.display_name(), &kind, &reason)?;
    reevaluate(&mut scan, &db)?;
    db.persist_analysis(&scan)?;
    state.store(scan)
}
fn reevaluate(scan: &mut Scan, db: &Database) -> Result<()> {
    for row in &mut scan.rows {
        if scan.device.state == "historical" && !row.app.dumpsys_error.is_empty() {
            continue;
        }
        let rep = db.reputation(&row.app.package_name)?;
        row.local_risk = risk::evaluate(&row.app, &rep);
        row.risk = row.local_risk.clone();
        if let Some(ai) = row.ai.clone() {
            ai::apply(row, ai, &rep);
        }
    }
    scan.rows.sort_by_key(|r| std::cmp::Reverse(r.risk.score));
    scan.rules_version = crate::evidence::RULES_VERSION;
    Ok(())
}
#[tauri::command]
pub async fn reload_reputation(state: State<'_, Engine>) -> Result<Scan> {
    let (_permit, _) = state.begin()?;
    let mut scan = state.current()?;
    let mut db = state.db()?;
    reevaluate(&mut scan, &db)?;
    db.persist_analysis(&scan)?;
    state.store(scan)
}
#[tauri::command]
pub async fn app_settings(state: State<'_, Engine>, package: String) -> Result<String> {
    let (_permit, cancel) = state.begin()?;
    let scan = state.current()?;
    if scan.demo
        || scan.device.serial.is_empty()
        || !scan.rows.iter().any(|r| r.app.package_name == package)
    {
        return Err("Application réelle du téléphone courant requise".into());
    }
    state
        .adb(cancel)?
        .open_settings(&scan.device.serial, &package)
        .await
}

pub fn removal_candidates(scan: &Scan, packages: &[String]) -> Result<Vec<Row>> {
    if scan.demo
        || scan.cancelled
        || scan.scan_id.is_none()
        || scan.device.serial.is_empty()
        || scan.device.state != "device"
    {
        return Err("Un scan complet du téléphone connecté est obligatoire".into());
    }
    if packages.is_empty() {
        return Err("Sélection vide".into());
    }
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for p in packages {
        adb::validate_package(p)?;
        if !seen.insert(p) {
            continue;
        }
        let row = scan
            .rows
            .iter()
            .find(|r| &r.app.package_name == p)
            .ok_or("Package absent du scan")?;
        if row.app.is_system_app
            || row.risk.recommended_action == "do_not_touch"
            || ["keep", "removed"].contains(&row.validation.as_str())
            || !row.app.dumpsys_error.is_empty()
        {
            return Err(format!(
                "Application protégée, conservée ou non vérifiée : {p}"
            ));
        }
        rows.push(row.clone());
    }
    Ok(rows)
}
#[tauri::command]
pub async fn uninstall_selected(
    app: tauri::AppHandle,
    state: State<'_, Engine>,
    packages: Vec<String>,
) -> Result<Scan> {
    let (_permit, cancel) = state.begin()?;
    let mut scan = state.current()?;
    let candidates = removal_candidates(&scan, &packages)?;
    let adb = state.adb(cancel.clone())?;
    adb.require_connected(&scan.device.serial).await?;
    let list = candidates
        .iter()
        .map(|r| {
            format!(
                "• {} ({})",
                r.app.display_name().replace(['\n', '\r'], " "),
                r.app.package_name
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let home = if candidates
        .iter()
        .any(|r| r.app.is_default_home == Some(true))
    {
        "\nCette sélection contient l’écran d’accueil actuel. Rétablissez l’accueil souhaité avant suppression."
    } else {
        ""
    };
    let (send, recv) = tokio::sync::oneshot::channel();
    app.dialog().message(format!("Téléphone : {} — {}\n\nDésinstaller pour l’utilisateur Android 0 ?\n\n{list}{home}\n\nSeule la commande pm uninstall --user 0 sera utilisée.",scan.device.model,scan.device.serial)).title("Microwest · Confirmation humaine obligatoire").kind(MessageDialogKind::Warning).buttons(MessageDialogButtons::OkCancelCustom("Confirmer la désinstallation".into(),"Annuler".into())).show(move |yes|{let _=send.send(yes);});
    if !recv.await.map_err(|_| "Confirmation interrompue")? || cancel.is_cancelled() {
        return Ok(scan);
    }
    for (i, row) in candidates.iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        adb.require_connected(&scan.device.serial).await?;
        // Re-read system flags immediately before deletion; never trust frontend app metadata.
        let raw = adb
            .dumpsys(&scan.device.serial, &row.app.package_name)
            .await?;
        let mut current = row.app.clone();
        scanner::enrich(&mut current, &raw);
        if scanner::system_status(&raw) != Some(false) || current.is_system_app {
            return Err(format!(
                "Suppression refusée : {} est système ou ses flags ne sont pas vérifiables",
                current.package_name
            ));
        }
        {
            let mut db = state.db()?;
            db.set_validation(scan.scan_id.unwrap(), &row.app.package_name, "remove")?;
        }
        progress(
            &app,
            "uninstall",
            i,
            candidates.len(),
            &row.app.package_name,
        );
        let output = adb
            .uninstall(&scan.device.serial, &row.app.package_name)
            .await
            .unwrap_or_else(|e| e);
        let success = output.lines().any(|s| s.trim() == "Success");
        let result = UninstallResult {
            package: row.app.package_name.clone(),
            label: row.app.display_name(),
            result: output,
            success,
        };
        {
            let mut db = state.db()?;
            db.record_uninstall(&result)?;
            if success {
                db.set_validation(scan.scan_id.unwrap(), &row.app.package_name, "removed")?;
            }
        }
        if let Some(r) = scan
            .rows
            .iter_mut()
            .find(|r| r.app.package_name == row.app.package_name)
        {
            r.validation = if success { "removed" } else { "remove" }.into();
        }
        scan.uninstalled.push(result);
        state.db()?.persist_analysis(&scan)?;
        state.store(scan.clone())?;
    }
    state.store(scan)
}

#[tauri::command]
pub async fn history(state: State<'_, Engine>) -> Result<Vec<Value>> {
    state.db()?.history()
}
#[tauri::command]
pub async fn load_history(state: State<'_, Engine>, id: i64) -> Result<Scan> {
    let (_permit, _) = state.begin()?;
    let mut db = state.db()?;
    let mut scan = db.load(id)?;
    if scan.rules_version != crate::evidence::RULES_VERSION {
        reevaluate(&mut scan, &db)?;
        scan.analysis_notice = "Analyse recalculée avec les règles actuelles. Les anciens verdicts sont archivés. Les anciennes métadonnées ne remplacent pas un nouveau scan APK ; les avis IA sans références doivent être relancés sur un scan réel.".into();
        db.persist_analysis(&scan)?;
        scan.comparison = Some(db.comparison(id)?);
    }
    state.store(scan)
}

#[tauri::command]
pub async fn observe_foreground(state: State<'_, Engine>) -> Result<String> {
    let (_permit, cancel) = state.begin()?;
    let scan = state.current()?;
    if scan.demo || scan.cancelled || scan.device.state != "device" {
        return Err("Connectez le téléphone et lancez un scan réel.".into());
    }
    let adb = state.adb(cancel)?;
    adb.require_connected(&scan.device.serial).await?;
    let raw = adb
        .shell(
            &scan.device.serial,
            &["dumpsys", "activity", "activities"],
            10,
        )
        .await?;
    foreground_package(&raw).ok_or_else(|| "Application au premier plan non identifiable sur cet Android. Aucune attribution n’a été faite.".into())
}

fn foreground_package(raw: &str) -> Option<String> {
    let re = regex::Regex::new(r"\b([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/[A-Za-z0-9_.$]+").unwrap();
    raw.lines()
        .filter(|l| l.contains("mResumedActivity") || l.contains("topResumedActivity"))
        .find_map(|l| re.captures(l).map(|c| c[1].to_string()))
}
#[tauri::command]
pub async fn export_scan(
    state: State<'_, Engine>,
    kind: String,
    selected: Vec<String>,
) -> Result<String> {
    reports::export(&state.root, &state.current()?, &kind, &selected)
}
#[tauri::command]
pub async fn action_plan(state: State<'_, Engine>, selected: Vec<String>) -> Result<String> {
    Ok(reports::plan(&state.current()?, &selected))
}
#[tauri::command]
pub async fn save_settings(
    state: State<'_, Engine>,
    settings: Value,
    api_key: Option<String>,
) -> Result<Value> {
    let (_permit, _) = state.begin()?;
    config::save(&state.root, settings, api_key)
}
#[tauri::command]
pub async fn app_icon(state: State<'_, Engine>, package: String) -> Result<String> {
    scanner::icon_data(&state.root.join("cache/app_icons"), &package)
}
#[tauri::command]
pub async fn open_folder(state: State<'_, Engine>, folder: String) -> Result<()> {
    if !["data", "logs", "reports"].contains(&folder.as_str()) {
        return Err("Dossier non autorisé".into());
    }
    open::that_detached(state.root.join(folder)).map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn open_report(state: State<'_, Engine>, path: String) -> Result<()> {
    let p = PathBuf::from(path)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let reports = state
        .root
        .join("reports")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if p.parent() != Some(reports.as_path())
        || !p.is_file()
        || !["html", "csv", "txt"].contains(&p.extension().and_then(|s| s.to_str()).unwrap_or(""))
    {
        return Err("Rapport non autorisé".into());
    }
    open::that_detached(p).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn demo_scan(state: State<'_, Engine>) -> Result<Scan> {
    let (_permit, _) = state.begin()?;
    let mut scan = Scan {
        device: Device {
            state: "demo".into(),
            model: "Téléphone fictif".into(),
            android_version: "14".into(),
            message: "DÉMONSTRATION — aucune connexion réelle".into(),
            ..Default::default()
        },
        demo: true,
        ..Default::default()
    };
    for (p, label, installer, home) in [
        ("demo.phone.cleaner", "Phone Cleaner", "", false),
        (
            "demo.pdf.reader",
            "PDF READER ALL PRO",
            "com.android.vending",
            true,
        ),
        ("com.whatsapp", "WhatsApp", "com.android.vending", false),
    ] {
        let mut a = AppInfo {
            package_name: p.into(),
            app_label: label.into(),
            app_label_source: "apk".into(),
            installer: installer.into(),
            has_launcher_entry: Some(true),
            is_home_app: Some(home),
            is_default_home: Some(home),
            target_sdk: "34".into(),
            ..Default::default()
        };
        scanner::audits(&mut a);
        let risk = risk::evaluate(&a, &state.db()?.reputation(p)?);
        scan.rows.push(Row {
            app: a,
            risk: risk.clone(),
            local_risk: risk,
            ai: None,
            ai_text: String::new(),
            note: String::new(),
            validation: "unreviewed".into(),
        });
    }
    scan.total = scan.rows.len();
    state.store(scan)
}

#[tauri::command]
pub async fn import_legacy(app: tauri::AppHandle, state: State<'_, Engine>) -> Result<Value> {
    let (_permit, _) = state.begin()?;
    let (send, recv) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Dossier de l’ancienne application (contient data et .env)")
        .pick_folder(move |p| {
            let _ = send.send(p);
        });
    let Some(folder) = recv.await.map_err(|_| "Sélection interrompue")? else {
        return Ok(json!({"cancelled":true}));
    };
    let source = folder.into_path().map_err(|e| e.to_string())?;
    if source.canonicalize().map_err(|e| e.to_string())?
        == state.root.canonicalize().map_err(|e| e.to_string())?
    {
        return Err("Ce dossier est déjà le dossier actif".into());
    }
    if !source.join("data/app_reputation.sqlite").is_file() {
        return Err("Base historique introuvable dans ce dossier".into());
    }
    // Prepare and validate the entire import before asking to replace the active data.
    let root = state.root.clone();
    let prepared = tauri::async_runtime::spawn_blocking(move || -> Result<_> {
        let staging = tempfile::tempdir_in(&root).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(staging.path().join("data")).map_err(|e| e.to_string())?;
        let src = rusqlite::Connection::open_with_flags(
            source.join("data/app_reputation.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| e.to_string())?;
        src.backup(
            rusqlite::DatabaseName::Main,
            staging.path().join("data/app_reputation.sqlite"),
            None,
        )
        .map_err(|e| e.to_string())?;
        Database::initialize(&staging.path().join("data/app_reputation.sqlite"))?;
        for name in ["data/ui_settings.json", ".env"] {
            if source.join(name).is_file() {
                std::fs::copy(source.join(name), staging.path().join(name))
                    .map_err(|e| e.to_string())?;
            }
        }
        config::read(staging.path())?;
        Ok(staging)
    })
    .await
    .map_err(|e| e.to_string())??;
    let (send, recv) = tokio::sync::oneshot::channel();
    app.dialog().message("La base et les réglages du dossier sélectionné ont été vérifiés. Remplacer les données actives ? Une sauvegarde des données actuelles sera conservée. Le dossier source restera intact.").title("Importer les données Python").buttons(MessageDialogButtons::OkCancelCustom("Importer avec sauvegarde".into(),"Annuler".into())).show(move|yes|{let _=send.send(yes);});
    if !recv.await.map_err(|_| "Confirmation interrompue")? {
        return Ok(json!({"cancelled":true}));
    }
    let backup = state.root.join(format!(
        "backup-import-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S%f")
    ));
    std::fs::create_dir_all(backup.join("data")).map_err(|e| e.to_string())?;
    let current = rusqlite::Connection::open(state.root.join("data/app_reputation.sqlite"))
        .map_err(|e| e.to_string())?;
    current
        .backup(
            rusqlite::DatabaseName::Main,
            backup.join("data/app_reputation.sqlite"),
            None,
        )
        .map_err(|e| e.to_string())?;
    drop(current);
    for name in ["data/ui_settings.json", ".env"] {
        if state.root.join(name).is_file() {
            std::fs::copy(state.root.join(name), backup.join(name)).map_err(|e| e.to_string())?;
        }
    }
    let mut replaced = Vec::new();
    let replacement = (|| -> Result<()> {
        for name in [
            "data/ui_settings.json",
            ".env",
            "data/app_reputation.sqlite",
        ] {
            if prepared.path().join(name).is_file() {
                config::atomic_write(
                    &state.root.join(name),
                    &std::fs::read(prepared.path().join(name)).map_err(|e| e.to_string())?,
                )?;
                replaced.push(name);
            }
        }
        Ok(())
    })();
    if let Err(failure) = replacement {
        let mut recovery_errors = Vec::new();
        for name in replaced {
            let result = if backup.join(name).is_file() {
                std::fs::read(backup.join(name))
                    .map_err(|e| e.to_string())
                    .and_then(|bytes| config::atomic_write(&state.root.join(name), &bytes))
            } else {
                std::fs::remove_file(state.root.join(name)).map_err(|e| e.to_string())
            };
            if let Err(e) = result {
                recovery_errors.push(e);
            }
        }
        return Err(format!(
            "Import interrompu : {failure}. Sauvegarde : {}. Erreurs de restauration : {}",
            backup.display(),
            recovery_errors.join("; ")
        ));
    }
    *state.scan.lock().map_err(|e| e.to_string())? = None;
    state.log("Import historique effectué avec sauvegarde");
    Ok(json!({"backup":backup,"settings":config::read(&state.root)?}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_delete_without_real_complete_scan() {
        let mut s = Scan::default();
        assert!(removal_candidates(&s, &["com.test.app".into()]).is_err());
        s.scan_id = Some(1);
        s.device.serial = "A".into();
        s.device.state = "device".into();
        let a = AppInfo {
            package_name: "com.test.app".into(),
            is_system_app: true,
            ..Default::default()
        };
        let risk = risk::evaluate(&a, &Reputation::default());
        s.rows.push(Row {
            app: a,
            risk: risk.clone(),
            local_risk: risk,
            ai: None,
            ai_text: String::new(),
            note: String::new(),
            validation: "unreviewed".into(),
        });
        assert!(removal_candidates(&s, &["com.test.app".into()]).is_err());
        s.rows[0].app.is_system_app = false;
        s.rows[0].risk.recommended_action = "review".into();
        assert!(removal_candidates(&s, &["com.test.app".into()]).is_ok());
        s.demo = true;
        assert!(removal_candidates(&s, &["com.test.app".into()]).is_err());
        s.demo = false;
        s.cancelled = true;
        assert!(removal_candidates(&s, &["com.test.app".into()]).is_err());
    }
}
