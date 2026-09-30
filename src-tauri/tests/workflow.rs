#![cfg(feature = "test-support")]
use microwest_cleaner::{adb::Adb, database::Database, model::Device, process, workflow};
use std::{path::Path, time::Duration};
use tokio_util::sync::CancellationToken;
fn adb() -> Adb {
    Adb {
        path: env!("CARGO_BIN_EXE_process-fixture").into(),
        cancel: CancellationToken::new(),
    }
}
fn device(serial: &str) -> Device {
    Device {
        serial: serial.into(),
        state: "device".into(),
        model: "Fixture".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn detection_and_real_workflow_with_simulated_transport() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("db.sqlite");
    Database::initialize(&db).unwrap();
    let adb = adb();
    let (devices, selected) = adb.detect("").await.unwrap();
    assert_eq!(devices.len(), 3);
    assert_eq!(selected.serial, "ready");
    assert_eq!(selected.model, "Test Phone");
    assert_eq!(
        adb.detect("unapproved").await.unwrap().1.state,
        "unauthorized"
    );
    assert_eq!(adb.detect("sleeping").await.unwrap().1.state, "offline");
    assert_eq!(adb.detect("missing").await.unwrap().1.state, "disconnected");
    let scan = workflow::scan_device(&adb, selected, true, None, temp.path(), &db, |_, _, _| {})
        .await
        .unwrap();
    assert!(!scan.cancelled);
    assert!(scan.scan_id.is_some());
    assert_eq!(scan.rows.len(), 3);
    let bad = scan
        .rows
        .iter()
        .find(|r| r.app.package_name == "com.test.cleanmaster")
        .unwrap();
    assert!(bad.app.active_capabilities.contains(&"overlay".into()));
    assert!(bad
        .app
        .active_capabilities
        .contains(&"accessibility".into()));
    assert_eq!(bad.risk.recommended_action, "suggest_uninstall");
    let system = scan
        .rows
        .iter()
        .find(|r| r.app.package_name == "com.android.settings")
        .unwrap();
    assert_eq!(system.risk.recommended_action, "do_not_touch");
    let saved = Database::open(&db)
        .unwrap()
        .load(scan.scan_id.unwrap())
        .unwrap();
    assert_eq!(saved.rows.len(), 3);
    assert_eq!(saved.rows[0].risk.score, scan.rows[0].risk.score);
}
#[tokio::test]
async fn interrupted_and_disconnected_scans_never_become_reference() {
    let t = tempfile::tempdir().unwrap();
    let db = t.path().join("db.sqlite");
    Database::initialize(&db).unwrap();
    let adb = adb();
    let scan = workflow::scan_device(
        &adb,
        device("gone"),
        false,
        None,
        t.path(),
        &db,
        |_, _, _| {},
    )
    .await
    .unwrap();
    assert!(scan.cancelled);
    assert!(scan.scan_id.is_none());
    let token = adb.cancel.clone();
    let scan = workflow::scan_device(
        &adb,
        device("ready"),
        false,
        None,
        t.path(),
        &db,
        |_, total, _| {
            if total > 0 {
                token.cancel();
            }
        },
    )
    .await
    .unwrap();
    assert!(scan.cancelled);
    assert!(scan.scan_id.is_none());
    assert!(Database::open(&db).unwrap().history().unwrap().is_empty());
}
#[tokio::test]
async fn timeout_and_cancellation_kill_processes_and_drain_pipes() {
    let t = tempfile::tempdir().unwrap();
    let exe = Path::new(env!("CARGO_BIN_EXE_process-fixture"));
    let marker = t.path().join("timeout");
    let token = CancellationToken::new();
    let e = process::run(
        exe,
        &["sleep-marker".into(), marker.to_string_lossy().into()],
        1,
        &token,
    )
    .await
    .unwrap_err();
    assert!(e.contains("Délai"));
    let marker2 = t.path().join("cancel");
    let cancel = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
    });
    let e = process::run(
        exe,
        &["sleep-marker".into(), marker2.to_string_lossy().into()],
        10,
        &token,
    )
    .await
    .unwrap_err();
    assert!(e.contains("annulée"));
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(!marker.exists());
    assert!(!marker2.exists());
    let out = process::run(exe, &["pipes".into()], 10, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(out.len(), 256 * 1024);
    let start = std::time::Instant::now();
    let error = process::run(
        exe,
        &["inherited-pipes".into()],
        1,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(error.contains("Délai"));
    assert!(start.elapsed() < Duration::from_millis(2500));
}
