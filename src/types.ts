export interface Device {
  serial: string;
  state: string;
  details: string;
  manufacturer: string;
  model: string;
  android_version: string;
  message: string;
}
export interface AppInfo {
  package_name: string;
  app_label: string;
  app_label_source: string;
  icon_path: string;
  icon_source: string;
  installer: string;
  is_system_app: boolean;
  has_launcher_entry: boolean | null;
  is_home_app: boolean | null;
  is_default_home: boolean | null;
  requested_permissions: string[];
  granted_permissions: string[];
  sensitive_permissions: string[];
  active_capabilities: string[];
  hidden_audit: string[];
  notification_audit: string[];
  enabled: string;
  install_date: string;
  version_name: string;
  target_sdk: string;
  dumpsys_error: string;
  has_accessibility: boolean;
  has_overlay: boolean;
  has_device_admin: boolean;
  has_notification_listener: boolean;
  requests_post_notifications: boolean;
  uses_exact_alarm: boolean;
  uses_vibration: boolean;
  can_install_unknown_apps: boolean;
  has_usage_stats: boolean;
  runs_at_boot: boolean;
  has_vpn_service: boolean;
}
export interface Risk {
  score: number;
  category: string;
  recommended_action: string;
  reasons: string[];
}
export interface Row {
  app: AppInfo;
  risk: Risk;
  local_risk: Risk;
  ai: {
    risk_score: number;
    category: string;
    recommended_action: string;
    reason_fr: string;
    confidence: string;
  } | null;
  ai_text: string;
  note: string;
  validation: string;
}
export interface Snapshot {
  package: string;
  app_label: string;
  score: number;
  category: string;
  action: string;
  validation_status: string;
}
export interface Comparison {
  current_scan_id: number;
  previous_scan_id: number | null;
  new_apps: Snapshot[];
  removed_apps: Snapshot[];
  unchanged_count: number;
  risk_changes: {
    package: string;
    app_label: string;
    previous_score: number;
    current_score: number;
    previous_action: string;
    current_action: string;
  }[];
}
export interface Scan {
  device: Device;
  rows: Row[];
  errors: string[];
  cancelled: boolean;
  demo: boolean;
  total: number;
  scan_id: number | null;
  comparison: Comparison | null;
  uninstalled: {
    package: string;
    label: string;
    result: string;
    success: boolean;
  }[];
}
export interface Settings {
  ai_provider: "openai" | "minimax";
  openai_model: string;
  openai_base_url: string;
  minimax_model: string;
  minimax_base_url: string;
  openai_key_configured: boolean;
  minimax_key_configured: boolean;
}
export interface Boot {
  settings_error?: string | null;
  root: string;
  settings: Settings;
  adb_path: string | null;
  aapt2_path: string | null;
  migration_backup: string | null;
  scan: Scan | null;
}
export interface Detection {
  devices: Device[];
  device: Device;
  adb_path: string;
}
export interface Progress {
  operation: string;
  current: number;
  total: number;
  message: string;
}
export interface HistoryEntry {
  id: number;
  date: string;
  device_model: string;
  android_version: string;
  scanned_count: number;
  suspicious_count: number;
}
