//! Render a saved Scan JSON without a phone or a running desktop application.
//! cargo run --manifest-path src-tauri/Cargo.toml --example report_preview -- scan.json report.html
use microwest_cleaner::{model::Scan, reports};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("Usage: report_preview <scan.json> <report.html>".into());
    }
    let scan: Scan = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    std::fs::write(&args[1], reports::html(&scan))?;
    Ok(())
}
