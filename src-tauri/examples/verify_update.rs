//! Verify the actual distribution without launching the installer or touching a phone.
use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("src-tauri/tauri.conf.json"))?)?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("release-output/latest.json"))?)?;
    assert_eq!(manifest["version"], config["version"]);
    let platform = &manifest["platforms"]["windows-x86_64"];
    let url = platform["url"].as_str().ok_or("Missing download URL")?;
    let prefix = format!(
        "https://github.com/DwennK/Microwest-Android-Cleaner/releases/download/v{}/",
        env!("CARGO_PKG_VERSION")
    );
    let name = url.strip_prefix(&prefix).ok_or("Wrong release URL")?;
    if name.contains(['/', '\\']) || !name.ends_with("-setup.exe") {
        return Err("Unexpected installer name".into());
    }
    let decode = |value: &str| -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(
            base64::engine::general_purpose::STANDARD.decode(value.trim())?,
        )?)
    };
    let key = PublicKey::decode(&decode(
        config["plugins"]["updater"]["pubkey"]
            .as_str()
            .ok_or("Missing public key")?,
    )?)?;
    let signature = Signature::decode(&decode(
        platform["signature"].as_str().ok_or("Missing signature")?,
    )?)?;
    let mut bytes = std::fs::read(root.join("release-output").join(name))?;
    key.verify(&bytes, &signature, false)?;
    *bytes.first_mut().ok_or("Empty installer")? ^= 1;
    if key.verify(&bytes, &signature, false).is_ok() {
        return Err("Modified installer was accepted".into());
    }
    println!("Release manifest and EXE signature verified; modified EXE rejected.");
    Ok(())
}
