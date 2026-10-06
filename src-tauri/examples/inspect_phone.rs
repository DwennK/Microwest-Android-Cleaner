//! Read-only APK collection smoke check. No AI calls or database writes.
use microwest_cleaner::{adb::Adb, model::AppInfo, process, scanner};
#[tokio::main]
async fn main() -> Result<(), String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let package = std::env::args()
        .nth(1)
        .ok_or("Usage: inspect_phone <package>")?;
    microwest_cleaner::adb::validate_package(&package)?;
    let adb = Adb {
        path: process::discover("adb", &[root.into()]).ok_or("ADB absent")?,
        cancel: Default::default(),
    };
    let (_, device) = adb.detect("").await?;
    adb.require_connected(&device.serial).await?;
    let mut app = AppInfo {
        package_name: package,
        ..Default::default()
    };
    let dump = adb.dumpsys(&device.serial, &app.package_name).await?;
    scanner::enrich(&mut app, &dump);
    let tool = process::discover("aapt2", &[root.into()]).ok_or("aapt2 absent")?;
    scanner::apk(
        &adb,
        &tool,
        &root.join("cache/app_icons"),
        &device.serial,
        &mut app,
    )
    .await?;
    println!("{}: inspected={}, partial={}, signature_verified={}, signers={}, components={}, ad_libraries={}, resource_signals={}", app.display_name(), app.apk_analysis.inspected, app.apk_analysis.partial, app.apk_analysis.signature_verified, app.apk_analysis.signer_sha256.len(), app.apk_analysis.components.len(), app.apk_analysis.ad_libraries.len(), app.apk_analysis.warning_strings.len());
    for limitation in app.apk_analysis.limitations {
        println!("{limitation}");
    }
    Ok(())
}
