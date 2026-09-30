pub use crate::app_info::AppInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Device {
    pub serial: String,
    pub state: String,
    pub details: String,
    pub manufacturer: String,
    pub model: String,
    pub android_version: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub score: i32,
    pub category: String,
    pub recommended_action: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Reputation {
    pub whitelisted: bool,
    pub blacklisted: bool,
    pub blacklist_severity: i32,
    pub reason: String,
}
impl Default for Reputation {
    fn default() -> Self {
        Self {
            whitelisted: false,
            blacklisted: false,
            blacklist_severity: 50,
            reason: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiResult {
    pub risk_score: i32,
    pub category: String,
    pub recommended_action: String,
    pub reason_fr: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub app: AppInfo,
    pub risk: Risk,
    pub local_risk: Risk,
    pub ai: Option<AiResult>,
    pub ai_text: String,
    pub note: String,
    pub validation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub package: String,
    pub app_label: String,
    pub score: i32,
    pub category: String,
    pub action: String,
    pub validation_status: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskChange {
    pub package: String,
    pub app_label: String,
    pub previous_score: i32,
    pub current_score: i32,
    pub previous_action: String,
    pub current_action: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Comparison {
    pub current_scan_id: i64,
    pub previous_scan_id: Option<i64>,
    pub new_apps: Vec<Snapshot>,
    pub removed_apps: Vec<Snapshot>,
    pub unchanged_count: usize,
    pub risk_changes: Vec<RiskChange>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UninstallResult {
    pub package: String,
    pub label: String,
    pub result: String,
    pub success: bool,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scan {
    pub device: Device,
    pub rows: Vec<Row>,
    pub errors: Vec<String>,
    pub cancelled: bool,
    pub demo: bool,
    pub total: usize,
    pub scan_id: Option<i64>,
    pub comparison: Option<Comparison>,
    pub uninstalled: Vec<UninstallResult>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub operation: String,
    pub current: usize,
    pub total: usize,
    pub message: String,
}
pub type Result<T> = std::result::Result<T, String>;
