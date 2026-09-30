use crate::model::Result;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};
use tokio_util::sync::CancellationToken;

/// No shell. Drain both pipes concurrently, cap output, kill and reap on timeout/cancel.
pub async fn run(
    program: &Path,
    args: &[String],
    seconds: u64,
    cancel: &CancellationToken,
) -> Result<String> {
    if cancel.is_cancelled() {
        return Err("Opération annulée".into());
    }
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Impossible de lancer {} : {e}", program.display()))?;
    let stdout = child.stdout.take().ok_or("Sortie processus absente")?;
    let stderr = child.stderr.take().ok_or("Erreur processus absente")?;
    async fn read<R: tokio::io::AsyncRead + Unpin>(mut pipe: R) -> std::io::Result<Vec<u8>> {
        let mut kept = Vec::new();
        let mut overflow = false;
        let mut buf = [0u8; 8192];
        loop {
            let n = pipe.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if kept.len() + n <= 16 * 1024 * 1024 {
                kept.extend_from_slice(&buf[..n]);
            } else {
                overflow = true;
            }
        }
        if overflow {
            Err(std::io::Error::other(
                "Sortie de commande trop volumineuse ; résultat non utilisé",
            ))
        } else {
            Ok(kept)
        }
    }
    let mut out = tokio::spawn(read(stdout));
    let mut err = tokio::spawn(read(stderr));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let status = tokio::select! {
        status = child.wait() => status.map_err(|e|e.to_string()),
        _ = tokio::time::sleep_until(deadline) => Err("Délai de la commande dépassé".into()),
        _ = cancel.cancelled() => Err("Opération annulée".into()),
    };
    if let Err(error) = status {
        let _ = child.kill().await;
        let _ = child.wait().await;
        out.abort();
        err.abort();
        return Err(error);
    }
    // A subprocess may leave inherited pipes open after the direct child exits.
    // The original deadline and cancellation also cover draining those pipes.
    let drained = tokio::select! {
        result = async { tokio::join!(&mut out, &mut err) } => Ok(result),
        _ = tokio::time::sleep_until(deadline) => Err("Délai de lecture de la commande dépassé"),
        _ = cancel.cancelled() => Err("Opération annulée"),
    };
    let (output, errors) = match drained {
        Ok(values) => values,
        Err(error) => {
            out.abort();
            err.abort();
            return Err(error.into());
        }
    };
    let output = output
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let errors = errors
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let output = String::from_utf8_lossy(&output).trim().to_owned();
    let errors = String::from_utf8_lossy(&errors).trim().to_owned();
    if !status.unwrap().success() {
        return Err(if errors.is_empty() { output } else { errors });
    }
    Ok(if output.is_empty() { errors } else { output })
}
pub fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}

pub fn discover(name: &str, roots: &[PathBuf]) -> Option<PathBuf> {
    let executable = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.into()
    };
    let mut candidates = Vec::new();
    for root in roots {
        candidates.push(
            root.join(if name == "adb" { "adb" } else { "tools" })
                .join(&executable),
        );
        if name == "aapt2" {
            candidates.push(root.join("adb").join(&executable));
        }
    }
    if let Ok(path) = std::env::var(if name == "adb" {
        "ADB_PATH"
    } else {
        "AAPT2_PATH"
    }) {
        candidates.push(PathBuf::from(path));
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_default();
    let mut sdks: Vec<PathBuf> = ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        sdks.push(PathBuf::from(local).join("Android/sdk"));
    }
    sdks.extend([home.join("Library/Android/sdk"), home.join("Android/Sdk")]);
    if name == "adb" {
        for sdk in &sdks {
            candidates.push(sdk.join("platform-tools").join(&executable));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|p| p.join(&executable)));
    }
    for p in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        candidates.push(Path::new(p).join(&executable));
    }
    if name == "aapt2" {
        for sdk in sdks {
            if let Ok(entries) = std::fs::read_dir(sdk.join("build-tools")) {
                let mut paths: Vec<_> = entries
                    .flatten()
                    .map(|e| e.path().join(&executable))
                    .collect();
                paths.sort();
                paths.reverse();
                candidates.extend(paths);
            }
        }
    }
    candidates.into_iter().find(|p| {
        if !p.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            p.metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            true
        }
    })
}
