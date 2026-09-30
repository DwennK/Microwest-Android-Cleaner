//! Deterministic subprocess for tests. Not included in production builds/installers.
use std::{io::Write, time::Duration};
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if args.first() == Some(&"hold-pipes") {
        std::thread::sleep(Duration::from_secs(3));
        return;
    }
    if args.first() == Some(&"inherited-pipes") {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.arg("hold-pipes");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        // Intentionally leave a short-lived descendant holding both output pipes.
        #[allow(clippy::zombie_processes)]
        let _child = command.spawn().unwrap();
        return;
    }
    if args.first() == Some(&"sleep-marker") {
        std::thread::sleep(Duration::from_secs(2));
        std::fs::write(args[1], "process survived").unwrap();
        return;
    }
    if args.first() == Some(&"pipes") {
        let block = "x".repeat(1024);
        for _ in 0..256 {
            std::io::stdout().write_all(block.as_bytes()).unwrap();
            std::io::stderr().write_all(block.as_bytes()).unwrap();
        }
        return;
    }
    if args.as_slice() == ["devices", "-l"] {
        println!("List of devices attached\nready device model:Test_Phone\nunapproved unauthorized\nsleeping offline");
        return;
    }
    if args.as_slice() == ["version"] {
        println!("Android Debug Bridge TEST FIXTURE");
        return;
    }
    let shell = if args.len() > 3 && args[0] == "-s" && args[2] == "shell" {
        &args[3..]
    } else {
        &args[..]
    };
    match shell {
        ["getprop", "ro.product.manufacturer"] => println!("Fixture"),
        ["getprop", "ro.product.model"] => println!("Test Phone"),
        ["getprop", "ro.build.version.release"] => println!("14"),
        ["pm", "list", "packages", "-i", tail @ ..] => {
            println!("package:com.test.cleanmaster installer=null\npackage:com.whatsapp installer=com.android.vending");
            if tail.is_empty() {
                println!("package:com.android.settings installer=null");
            }
        }
        ["cmd", "package", "query-activities", rest @ ..] => {
            if rest.contains(&"android.intent.category.HOME") {
                println!("No activities found")
            } else {
                println!("com.test.cleanmaster/.Main\ncom.whatsapp/.Main")
            }
        }
        ["cmd", "package", "resolve-activity", ..] => {
            println!("android/com.android.internal.app.ResolverActivity")
        }
        ["settings", "get", "secure", "enabled_accessibility_services"] => {
            println!("com.test.cleanmaster/.Accessibility")
        }
        ["settings", "get", "secure", _] => println!("null"),
        ["dumpsys", "device_policy"] => println!("No active administrators"),
        ["dumpsys", "package", p] => {
            println!("Package [{p}]\nversionName=1.0\ntargetSdk=34\nfirstInstallTime=2000-01-01\nenabled=0");
            if *p == "com.android.settings" {
                println!("pkgFlags=[ SYSTEM HAS_CODE ]")
            } else {
                println!("pkgFlags=[ HAS_CODE ]")
            }
            if *p == "com.test.cleanmaster" {
                println!("android.permission.SYSTEM_ALERT_WINDOW\nandroid.permission.POST_NOTIFICATIONS: granted=true\nBIND_ACCESSIBILITY_SERVICE");
            }
        }
        ["cmd", "appops", "get", _, op] => println!("{op}: allow"),
        _ => {
            eprintln!("Unsupported fixture arguments: {args:?}");
            std::process::exit(42);
        }
    }
}
