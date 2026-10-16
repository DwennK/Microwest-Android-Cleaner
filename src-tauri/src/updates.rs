use crate::{commands::Engine, model::Result};
use serde::Serialize;
use std::{sync::Mutex, time::Duration};
use tauri::State;
use tauri_plugin_updater::{Update, UpdaterExt};

#[derive(Default)]
pub struct PendingUpdate(Mutex<Option<Update>>);

#[derive(Serialize)]
pub struct UpdateInfo {
    version: String,
    notes: String,
}

#[tauri::command]
pub async fn check_update(
    app: tauri::AppHandle,
    pending: State<'_, PendingUpdate>,
) -> Result<Option<UpdateInfo>> {
    if cfg!(debug_assertions) {
        return Err("Les mises à jour sont disponibles dans la version installée.".into());
    }
    let update = app
        .updater_builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;
    let update = tokio::time::timeout(Duration::from_secs(20), update.check())
        .await
        .map_err(|_| "GitHub ne répond pas. Réessayez plus tard.".to_owned())?
        .map_err(|e| format!("Vérification de mise à jour impossible : {e}"))?;
    let info = update.as_ref().map(|u| UpdateInfo {
        version: u.version.clone(),
        notes: u.body.clone().unwrap_or_default(),
    });
    *pending.0.lock().map_err(|e| e.to_string())? = update;
    Ok(info)
}

#[tauri::command]
pub async fn install_update(
    engine: State<'_, Engine>,
    pending: State<'_, PendingUpdate>,
    version: String,
) -> Result<()> {
    if cfg!(debug_assertions) {
        return Err("Installez une release pour utiliser les mises à jour.".into());
    }
    // The same backend lock protects scans, AI, imports and uninstallations.
    // Hold it until the installer exits this application, including the download.
    let (_permit, cancel) = engine.begin()?;
    let update = pending
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or("Vérifiez à nouveau les mises à jour.")?;
    if update.version != version {
        return Err("La version disponible a changé. Vérifiez à nouveau les mises à jour.".into());
    }
    // download() verifies the updater signature before returning the bytes.
    let bytes = tokio::select! {
        result = update.download(|_, _| {}, || {}) => result.map_err(|e| format!("Téléchargement ou signature invalide : {e}"))?,
        _ = cancel.cancelled() => return Err("Mise à jour annulée.".into()),
    };
    if cancel.is_cancelled() {
        return Err("Mise à jour annulée.".into());
    }
    update
        .install(bytes)
        .map_err(|e| format!("Installation impossible : {e}"))
}
