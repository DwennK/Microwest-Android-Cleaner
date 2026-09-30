use microwest_cleaner::{ai, config, model::*, risk};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn minimax_format_fallback_and_missing_verdict_retry_are_atomic() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let mut bodies = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        for index in 0..3 {
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "test server timed out");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            let (body_start, length) = loop {
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(i) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..i]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap();
                    break (i + 4, length);
                }
            };
            while bytes.len() < body_start + length {
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
            }
            bodies.push(
                serde_json::from_slice::<Value>(&bytes[body_start..body_start + length]).unwrap(),
            );
            let (status, response) = if index == 0 {
                (
                    "400 Bad Request",
                    json!({"error":"response_format unsupported"}).to_string(),
                )
            } else {
                let verdict = if index == 1 {
                    json!({"apps":[{"package_name":"not.requested","risk_score":100}]})
                } else {
                    json!({"apps":[{"package_name":"org.test.reader","risk_score":55,"recommended_action":"review","confidence":"medium","reason_fr":"Vérification du produit"}]})
                };
                (
                    "200 OK",
                    json!({"choices":[{"message":{"content":verdict.to_string()}}]}).to_string(),
                )
            };
            write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
        }
        bodies
    });
    let temp = tempfile::tempdir().unwrap();
    config::atomic_write(
        &temp.path().join(".env"),
        b"MINIMAX_API_KEY=test-only-placeholder\n",
    )
    .unwrap();
    config::atomic_write(&temp.path().join("data/ui_settings.json"),json!({"ai_provider":"minimax","minimax_model":"test-model","minimax_base_url":format!("http://127.0.0.1:{port}/v1")}).to_string().as_bytes()).unwrap();
    let app = AppInfo {
        package_name: "org.test.reader".into(),
        ..Default::default()
    };
    let risk = risk::evaluate(&app, &Reputation::default());
    let row = Row {
        app,
        risk: risk.clone(),
        local_risk: risk,
        ai: None,
        ai_text: String::new(),
        note: "Private technician note".into(),
        validation: "unreviewed".into(),
    };
    let result = ai::analyze(temp.path(), &[row], &CancellationToken::new(), |_, _| {})
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result["org.test.reader"].risk_score, 55);
    let requests = server.join().unwrap();
    assert!(requests[0].get("response_format").is_some());
    assert!(requests[1].get("response_format").is_none());
    for request in requests {
        assert!(!request.to_string().contains("Private technician note"));
        assert_eq!(request["model"], "test-model");
    }
}
