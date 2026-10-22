#![cfg(feature = "test-support")]
use microwest_cleaner::{
    adb::Adb,
    database::Database,
    model::*,
    reports,
    tweaks::{self, Action},
};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

fn fixture(overrides: Value) -> (tempfile::TempDir, Adb) {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir
        .path()
        .join(if cfg!(windows) { "adb.exe" } else { "adb" });
    std::fs::copy(env!("CARGO_BIN_EXE_tweaks-fixture"), &exe).unwrap();
    let mut state = json!({
        "user":"0", "api":34, "enabled":[tweaks::CHROME,tweaks::SAMSUNG,tweaks::ONE_UI],
        "disabled":[], "browser":tweaks::SAMSUNG, "home":"com.fake.launcher",
        "private_dns_mode":"opportunistic", "private_dns_specifier":null, "commands":[]
    });
    for (key, value) in overrides.as_object().unwrap() {
        state[key] = value.clone();
    }
    std::fs::write(
        dir.path().join("state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    (
        dir,
        Adb {
            path: exe,
            cancel: CancellationToken::new(),
        },
    )
}
fn state(dir: &tempfile::TempDir) -> Value {
    serde_json::from_slice(&std::fs::read(dir.path().join("state.json")).unwrap()).unwrap()
}

#[tokio::test]
async fn applies_and_verifies_dns_browser_home_and_restores_absent_dns_key() {
    let (dir, adb) = fixture(json!({}));
    let original = tweaks::read_dns(&adb, "ready").await.unwrap();
    tweaks::execute(&adb, "ready", Action::DnsAdguard, Some(&original))
        .await
        .unwrap();
    assert_eq!(
        tweaks::read_dns(&adb, "ready")
            .await
            .unwrap()
            .hostname
            .as_deref(),
        Some("dns.adguard-dns.com")
    );
    tweaks::execute(&adb, "ready", Action::DnsRestore, Some(&original))
        .await
        .unwrap();
    assert_eq!(tweaks::read_dns(&adb, "ready").await.unwrap(), original);
    tweaks::execute(&adb, "ready", Action::ChromeDisable, None)
        .await
        .unwrap();
    assert_eq!(
        tweaks::status(&adb, "ready").await.unwrap().chrome,
        Some(false)
    );
    tweaks::execute(&adb, "ready", Action::ChromeEnable, None)
        .await
        .unwrap();
    tweaks::execute(&adb, "ready", Action::HomeRestore, None)
        .await
        .unwrap();
    let status = tweaks::status(&adb, "ready").await.unwrap();
    assert_eq!(status.home.as_deref(), Some(tweaks::ONE_UI));
    assert_eq!(status.chrome, Some(true));
    assert!(state(&dir)["private_dns_specifier"].is_null());
}

#[tokio::test]
async fn rejects_unsafe_context_and_detects_silent_android_failures() {
    let (dir, adb) = fixture(json!({"browser":tweaks::CHROME}));
    assert!(tweaks::execute(&adb, "ready", Action::ChromeDisable, None)
        .await
        .is_err());
    assert!(!state(&dir)["commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c[1] == "disable-user"));
    let (_dir, adb) = fixture(json!({"user":"10"}));
    assert!(tweaks::execute(&adb, "ready", Action::HomeRestore, None)
        .await
        .is_err());
    let (_dir, adb) = fixture(json!({"deny":true}));
    assert!(tweaks::execute(&adb, "ready", Action::DnsAdguard, None)
        .await
        .unwrap_err()
        .contains("permission"));
    let (_dir, adb) = fixture(json!({"ignore_write":true}));
    assert!(tweaks::execute(&adb, "ready", Action::DnsAdguard, None)
        .await
        .is_err());
    let (_dir, adb) = fixture(json!({"open_error":true}));
    assert!(tweaks::execute(&adb, "ready", Action::PlayStore, None)
        .await
        .is_err());
}

#[tokio::test]
async fn restores_after_partial_dns_failure_and_preserves_empty_and_absent_settings() {
    let (dir, adb) =
        fixture(json!({"private_dns_mode":null, "private_dns_specifier":"", "fail_mode":true}));
    let original = tweaks::read_dns(&adb, "ready").await.unwrap();
    assert!(
        tweaks::execute(&adb, "ready", Action::DnsAdguard, Some(&original))
            .await
            .is_err()
    );
    assert_eq!(state(&dir)["private_dns_specifier"], "dns.adguard-dns.com");
    let mut value = state(&dir);
    value["fail_mode"] = json!(false);
    std::fs::write(
        dir.path().join("state.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    tweaks::execute(&adb, "ready", Action::DnsRestore, Some(&original))
        .await
        .unwrap();
    assert_eq!(tweaks::read_dns(&adb, "ready").await.unwrap(), original);
}

#[tokio::test]
async fn opens_guided_flows_without_claiming_completion_and_handles_old_android() {
    let (_dir, adb) = fixture(json!({"api":27}));
    assert!(tweaks::status(&adb, "ready").await.unwrap().dns.is_none());
    // A denied/old DNS setting does not hide browser and home tools.
    for action in [
        Action::SamsungStore,
        Action::AdblockStore,
        Action::SamsungOpen,
        Action::PlayStore,
        Action::BrowserSettings,
        Action::HomeSettings,
    ] {
        assert!(tweaks::execute(&adb, "ready", action, None)
            .await
            .unwrap()
            .contains("ne confirme pas"));
    }
}

#[test]
fn journal_and_dns_backup_survive_history_and_are_escaped_in_reports() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    Database::initialize(&path).unwrap();
    let mut db = Database::open(&path).unwrap();
    let mut scan = Scan {
        device: Device {
            serial: "private-serial".into(),
            state: "device".into(),
            ..Default::default()
        },
        dns_backup: Some(DnsSettings {
            mode: None,
            hostname: Some(String::new()),
        }),
        interventions: vec![Intervention {
            date: "2026-10-20T12:00:00Z".into(),
            action: "<script>alert(1)</script>".into(),
            status: "manual".into(),
            detail: "7 applications mises à jour & vérifiées par le technicien".into(),
        }],
        ..Default::default()
    };
    db.record(&mut scan).unwrap();
    scan.interventions.push(Intervention {
        date: "2026-10-20T13:00:00Z".into(),
        action: "DNS".into(),
        status: "pending".into(),
        detail: "Résultat non confirmé".into(),
    });
    db.persist_analysis(&scan).unwrap();
    let loaded = db.load(scan.scan_id.unwrap()).unwrap();
    assert_eq!(loaded.interventions.len(), 2);
    assert_eq!(loaded.dns_backup, scan.dns_backup);
    assert!(loaded.device.serial.is_empty());
    let html = reports::html(&loaded);
    assert!(html.contains("Confirmé par le technicien"));
    assert!(html.contains("résultat non confirmé"));
    assert!(!html.contains("<script>"));
    assert!(reports::plan(&loaded, &[]).contains("7 applications mises à jour"));
    let mut old = serde_json::to_value(&loaded).unwrap();
    old.as_object_mut().unwrap().remove("interventions");
    old.as_object_mut().unwrap().remove("dns_backup");
    let old: Scan = serde_json::from_value(old).unwrap();
    assert!(old.interventions.is_empty());
    assert!(old.dns_backup.is_none());
}

#[tokio::test]
async fn mupdf_installation_is_guided_and_missing_apps_cannot_be_verified() {
    let (dir, adb) = fixture(json!({}));
    let status = tweaks::status(&adb, "ready").await.unwrap();
    assert_eq!(status.mupdf, None);
    assert_eq!(status.pdf_handler, None);
    assert!(status.warnings.is_empty());
    assert!(tweaks::execute(&adb, "ready", Action::MupdfStore, None)
        .await
        .unwrap()
        .contains("ne confirme pas"));
    assert!(!Action::MupdfStore.verifies_state());
    for action in [Action::PdfChoose, Action::PdfVerify, Action::MupdfEnable] {
        assert!(tweaks::execute(&adb, "ready", action, None).await.is_err());
    }
    let value = state(&dir);
    let starts: Vec<_> = value["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c[0] == "am" && c[1] == "start")
        .collect();
    assert_eq!(starts.len(), 1);
    assert!(starts[0]
        .as_array()
        .unwrap()
        .contains(&json!("market://details?id=com.artifex.mupdf.viewer.app")));
    assert!(starts[0]
        .as_array()
        .unwrap()
        .contains(&json!("com.android.vending")));
}

#[tokio::test]
async fn mupdf_enable_choose_and_verify_only_the_observed_pdf_handler() {
    let (dir, adb) = fixture(json!({"disabled":[tweaks::MUPDF], "pdf":"com.old.reader"}));
    assert_eq!(
        tweaks::status(&adb, "ready").await.unwrap().mupdf,
        Some(false)
    );
    tweaks::execute(&adb, "ready", Action::MupdfEnable, None)
        .await
        .unwrap();
    assert_eq!(
        tweaks::status(&adb, "ready").await.unwrap().mupdf,
        Some(true)
    );
    let message = tweaks::execute(&adb, "ready", Action::PdfChoose, None)
        .await
        .unwrap();
    assert!(message.contains("Aucun choix n’a été forcé ni vérifié"));
    assert!(!Action::PdfChoose.verifies_state());
    tweaks::execute(&adb, "ready", Action::PdfPreviousSettings, None)
        .await
        .unwrap();
    assert!(tweaks::execute(&adb, "ready", Action::PdfVerify, None)
        .await
        .is_err());
    let mut value = state(&dir);
    assert!(value["commands"].as_array().unwrap().iter().any(|c| c
        .as_array()
        .unwrap()
        .contains(&json!("package:com.old.reader"))));
    assert!(value["commands"].as_array().unwrap().iter().any(|c| c
        .as_array()
        .unwrap()
        .contains(&json!("android.intent.action.VIEW_DOWNLOADS"))));
    value["pdf"] = json!(tweaks::MUPDF);
    std::fs::write(
        dir.path().join("state.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    let verified = tweaks::execute(&adb, "ready", Action::PdfVerify, None)
        .await
        .unwrap();
    assert!(verified.contains("sans choix Toujours enregistré"));
    assert!(Action::PdfVerify.verifies_state());
    assert!(!Action::PdfVerify.changes_device());
    assert!(
        tweaks::execute(&adb, "ready", Action::PdfPreviousSettings, None)
            .await
            .is_err()
    );
    assert_eq!(
        tweaks::status(&adb, "ready")
            .await
            .unwrap()
            .pdf_handler
            .as_deref(),
        Some(tweaks::MUPDF)
    );
}

#[tokio::test]
async fn unsupported_pdf_resolution_does_not_hide_other_tweaks_or_claim_success() {
    let (_dir, adb) = fixture(
        json!({"pdf_error":true, "enabled":[tweaks::MUPDF,tweaks::CHROME,tweaks::SAMSUNG]}),
    );
    let status = tweaks::status(&adb, "ready").await.unwrap();
    assert_eq!(status.pdf_handler, None);
    assert_eq!(status.chrome, Some(true));
    assert_eq!(status.mupdf, Some(true));
    assert!(status
        .warnings
        .iter()
        .any(|s| s.contains("Lecteur PDF non vérifié")));
    assert!(tweaks::execute(&adb, "ready", Action::PdfVerify, None)
        .await
        .is_err());
    let (_dir, adb) = fixture(json!({"open_error":true}));
    assert!(tweaks::execute(&adb, "ready", Action::MupdfStore, None)
        .await
        .is_err());
}
