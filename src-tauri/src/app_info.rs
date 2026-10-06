use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppInfo {
    pub apk_analysis: crate::evidence::ApkAnalysis,
    pub package_name: String,
    pub app_label: String,
    pub app_label_source: String,
    pub icon_path: String,
    pub icon_source: String,
    pub has_launcher_entry: Option<bool>,
    pub is_home_app: Option<bool>,
    pub is_default_home: Option<bool>,
    pub hidden_audit: Vec<String>,
    pub notification_audit: Vec<String>,
    pub installer: String,
    pub is_system_app: bool,
    pub sensitive_permissions: Vec<String>,
    pub requested_permissions: Vec<String>,
    pub granted_permissions: Vec<String>,
    pub active_capabilities: Vec<String>,
    pub enabled: String,
    pub install_date: String,
    pub version_name: String,
    pub target_sdk: String,
    pub has_accessibility: bool,
    pub has_overlay: bool,
    pub has_device_admin: bool,
    pub has_notification_listener: bool,
    pub requests_post_notifications: bool,
    pub uses_exact_alarm: bool,
    pub uses_vibration: bool,
    pub can_install_unknown_apps: bool,
    pub has_usage_stats: bool,
    pub runs_at_boot: bool,
    pub has_vpn_service: bool,
    pub dumpsys_error: String,
}
impl Default for AppInfo {
    fn default() -> Self {
        Self {
            apk_analysis: Default::default(),
            package_name: String::new(),
            app_label: "".into(),
            app_label_source: "package".into(),
            icon_path: "".into(),
            icon_source: "".into(),
            has_launcher_entry: None,
            is_home_app: None,
            is_default_home: None,
            hidden_audit: Vec::new(),
            notification_audit: Vec::new(),
            installer: "".into(),
            is_system_app: false,
            sensitive_permissions: Vec::new(),
            requested_permissions: Vec::new(),
            granted_permissions: Vec::new(),
            active_capabilities: Vec::new(),
            enabled: "".into(),
            install_date: "".into(),
            version_name: "".into(),
            target_sdk: "".into(),
            has_accessibility: false,
            has_overlay: false,
            has_device_admin: false,
            has_notification_listener: false,
            requests_post_notifications: false,
            uses_exact_alarm: false,
            uses_vibration: false,
            can_install_unknown_apps: false,
            has_usage_stats: false,
            runs_at_boot: false,
            has_vpn_service: false,
            dumpsys_error: "".into(),
        }
    }
}
impl AppInfo {
    pub fn display_name(&self) -> String {
        if self.app_label.is_empty() {
            crate::scanner::package_to_label(&self.package_name)
        } else {
            self.app_label.clone()
        }
    }
}
