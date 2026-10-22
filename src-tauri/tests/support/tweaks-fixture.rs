//! Stateful Android simulator. Each test copies this executable into its own temporary directory.
use serde_json::{json, Value};
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("state.json");
    let mut state: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    if args == ["devices", "-l"] {
        println!("List of devices attached\nready device model:Test");
        return;
    }
    let shell = match args.as_slice() {
        ["-s", "ready", "shell", tail @ ..] => tail,
        _ => panic!("Unexpected arguments: {args:?}"),
    };
    state["commands"].as_array_mut().unwrap().push(json!(shell));
    match shell {
        ["am", "get-current-user"] => println!("{}", state["user"].as_str().unwrap()),
        ["getprop", "ro.build.version.sdk"] => println!("{}", state["api"]),
        ["pm", "list", "packages", "--user", "0", flag] => {
            for package in state[if *flag == "-e" { "enabled" } else { "disabled" }]
                .as_array()
                .unwrap()
            {
                println!("package:{}", package.as_str().unwrap());
            }
        }
        ["settings", "get", "global", key] => {
            println!("{}", state[*key].as_str().unwrap_or("null"));
        }
        ["settings", "put", "global", key, value] => {
            if state["deny"].as_bool().unwrap_or(false)
                || (*key == "private_dns_mode" && state["fail_mode"].as_bool().unwrap_or(false))
            {
                println!("SecurityException: permission denied");
            } else if !state["ignore_write"].as_bool().unwrap_or(false) {
                state[*key] = json!(if *value == "''" { "" } else { *value });
            }
        }
        ["settings", "delete", "global", key] => {
            state[*key] = Value::Null;
        }
        ["pm", op @ ("enable" | "disable-user"), "--user", "0", package] => {
            let (target, source) = if *op == "enable" {
                ("enabled", "disabled")
            } else {
                ("disabled", "enabled")
            };
            state[source]
                .as_array_mut()
                .unwrap()
                .retain(|p| p != package);
            state[target].as_array_mut().unwrap().push(json!(package));
            println!("Package {package} new state: {op}");
        }
        ["cmd", "package", "resolve-activity", rest @ ..] => {
            let key = if rest.contains(&"android.intent.category.HOME") {
                "home"
            } else if rest.contains(&"application/pdf") {
                "pdf"
            } else {
                "browser"
            };
            if key == "pdf" && state["pdf_error"].as_bool().unwrap_or(false) {
                println!("Error: PDF resolution unavailable");
            } else if let Some(package) = state[key].as_str() {
                println!("{package}/.Main");
            } else {
                println!("No activity found");
            }
        }
        ["cmd", "package", "query-activities", ..] => {
            println!("com.sec.android.app.launcher/.Main")
        }
        ["cmd", "package", "set-home-activity", "--user", "0", package] => {
            state["home"] = json!(package);
            println!("Success");
        }
        ["am", "start", ..] => {
            if state["open_error"].as_bool().unwrap_or(false) {
                println!("Error: Activity not started, unable to resolve Intent");
            } else {
                println!("Starting: Intent {{ fixture }}");
            }
        }
        _ => panic!("Unsupported fixture arguments: {shell:?}"),
    }
    std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
}
