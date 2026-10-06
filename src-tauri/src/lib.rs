pub mod adb;
pub mod ai;
mod app_info;
pub mod commands;
pub mod config;
pub mod database;
pub mod evidence;
pub mod model;
pub mod process;
pub mod reports;
pub mod risk;
pub mod scanner;
pub mod workflow;
use tauri::Manager;
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let engine = commands::Engine::new(app.handle()).map_err(std::io::Error::other)?;
            app.manage(engine);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::detect_devices,
            commands::daemon_action,
            commands::diagnostic,
            commands::export_diagnostic,
            commands::cancel_operation,
            commands::start_scan,
            commands::analyze_ai,
            commands::update_note,
            commands::update_validation,
            commands::update_reputation,
            commands::reload_reputation,
            commands::app_settings,
            commands::uninstall_selected,
            commands::history,
            commands::load_history,
            commands::observe_foreground,
            commands::export_scan,
            commands::action_plan,
            commands::save_settings,
            commands::app_icon,
            commands::open_folder,
            commands::open_report,
            commands::demo_scan,
            commands::import_legacy
        ])
        .run(tauri::generate_context!())
        .expect("Application Tauri");
}
