use crate::model::Result;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const FIELDS: [&str; 5] = [
    "ai_provider",
    "openai_model",
    "openai_base_url",
    "minimax_model",
    "minimax_base_url",
];
pub fn env(root: &Path) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    if let Ok(iter) = dotenvy::from_path_iter(root.join(".env")) {
        for (k, v) in iter.flatten() {
            values.insert(k, v);
        }
    }
    for k in [
        "AI_PROVIDER",
        "OPENAI_MODEL",
        "OPENAI_BASE_URL",
        "MINIMAX_MODEL",
        "MINIMAX_BASE_URL",
        "OPENAI_API_KEY",
        "MINIMAX_API_KEY",
    ] {
        if let Ok(v) = std::env::var(k) {
            values.insert(k.into(), v);
        }
    }
    values
}
pub fn read(root: &Path) -> Result<Value> {
    let path = root.join("data/ui_settings.json");
    let v = if path.is_file() {
        serde_json::from_slice::<Value>(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("Réglages illisibles (fichier conservé) : {e}"))?
    } else {
        json!({})
    };
    if !v.is_object() {
        return Err("ui_settings.json doit contenir un objet".into());
    }
    Ok(resolve(root, v))
}
pub fn defaults(root: &Path) -> Value {
    resolve(root, json!({}))
}
fn resolve(root: &Path, mut v: Value) -> Value {
    let e = env(root);
    for (key, default) in [
        ("ai_provider", "openai"),
        ("openai_model", "gpt-4.1-mini"),
        ("openai_base_url", ""),
        ("minimax_model", "MiniMax-M3"),
        ("minimax_base_url", "https://api.minimax.io/v1"),
    ] {
        if v[key].as_str().unwrap_or("").is_empty() {
            v[key] = json!(e
                .get(&key.to_uppercase())
                .map(String::as_str)
                .unwrap_or(default));
        }
    }
    // Never expose arbitrary old fields or credentials to the webview.
    let provider = v["ai_provider"]
        .as_str()
        .unwrap_or("openai")
        .trim()
        .to_lowercase();
    v["ai_provider"] = json!(if provider == "minimax" {
        "minimax"
    } else {
        "openai"
    });
    let mut public = json!({});
    for key in FIELDS {
        public[key] = v[key].clone();
    }
    public["openai_key_configured"] = json!(e.get("OPENAI_API_KEY").is_some_and(|s| !s.is_empty()));
    public["minimax_key_configured"] =
        json!(e.get("MINIMAX_API_KEY").is_some_and(|s| !s.is_empty()));
    public
}
pub fn save(root: &Path, settings: Value, key: Option<String>) -> Result<Value> {
    let provider = settings["ai_provider"]
        .as_str()
        .ok_or("Provider manquant")?;
    if !["openai", "minimax"].contains(&provider) {
        return Err("Provider inconnu".into());
    }
    for name in ["openai_base_url", "minimax_base_url"] {
        let value = settings[name].as_str().unwrap_or("");
        if !value.is_empty() {
            validate_url(value)?;
        }
    }
    let path = root.join("data/ui_settings.json");
    let mut saved = if path.exists() {
        match serde_json::from_slice::<Value>(&std::fs::read(&path).map_err(|e| e.to_string())?) {
            Ok(v) if v.is_object() => v,
            _ => {
                backup_file(&path)?;
                json!({})
            }
        }
    } else {
        json!({})
    };
    for name in FIELDS {
        saved[name] = json!(settings[name].as_str().unwrap_or("").trim());
    }
    if let Some(key) = key.filter(|v| !v.trim().is_empty()) {
        if key.contains(['\n', '\r', '"']) {
            return Err("Clé API invalide".into());
        }
        let envpath = root.join(".env");
        let old = std::fs::read_to_string(&envpath).unwrap_or_default();
        let key_name = if provider == "minimax" {
            "MINIMAX_API_KEY"
        } else {
            "OPENAI_API_KEY"
        };
        let mut lines: Vec<_> = old
            .lines()
            .filter(|l| !l.starts_with(&format!("{key_name}=")))
            .map(String::from)
            .collect();
        lines.push(format!("{key_name}=\"{}\"", key.trim()));
        atomic_write(&envpath, lines.join("\n").as_bytes())?;
    }
    atomic_write(
        &path,
        &serde_json::to_vec_pretty(&saved).map_err(|e| e.to_string())?,
    )?;
    read(root)
}
pub fn validate_url(s: &str) -> Result<()> {
    let url = reqwest::Url::parse(s).map_err(|_| "URL IA invalide")?;
    if url.scheme() != "https"
        && !((url.host_str() == Some("localhost") || url.host_str() == Some("127.0.0.1"))
            && url.scheme() == "http")
    {
        return Err("Utilisez HTTPS (HTTP accepté uniquement pour localhost).".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("URL IA : identifiants, paramètres et fragments interdits".into());
    }
    Ok(())
}
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("Chemin invalide")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    use std::io::Write;
    temp.write_all(data).map_err(|e| e.to_string())?;
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    temp.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn backup_file(path: &Path) -> Result<Option<PathBuf>> {
    if !path.is_file() {
        return Ok(None);
    }
    let dest = path.with_extension(format!(
        "backup-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S%f")
    ));
    std::fs::copy(path, &dest).map_err(|e| e.to_string())?;
    Ok(Some(dest))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_settings_remain_compatible_and_secrets_are_not_returned() {
        let t = tempfile::tempdir().unwrap();
        atomic_write(&t.path().join("data/ui_settings.json"),br#"{"ai_provider":"minimax","minimax_model":"custom-model","other_setting":42,"OPENAI_API_KEY":"must-not-return"}"#).unwrap();
        let s = read(t.path()).unwrap();
        assert_eq!(s["minimax_model"], "custom-model");
        assert!(s.get("OPENAI_API_KEY").is_none());
        assert!(s.get("other_setting").is_none());
        save(t.path(), s, None).unwrap();
        let saved: Value =
            serde_json::from_slice(&std::fs::read(t.path().join("data/ui_settings.json")).unwrap())
                .unwrap();
        assert_eq!(saved["other_setting"], 42);
        atomic_write(&t.path().join("data/ui_settings.json"), b"broken json").unwrap();
        assert!(read(t.path()).is_err());
        save(t.path(), defaults(t.path()), None).unwrap();
        assert!(std::fs::read_dir(t.path().join("data"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("backup-")));
    }
}
