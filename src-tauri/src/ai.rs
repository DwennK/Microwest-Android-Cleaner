use crate::{config, model::*, risk};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub fn payload(row: &Row) -> Value {
    let a = &row.app;
    let p = risk::profile(a);
    json!({"app_name":a.display_name(),"app_name_source":a.app_label_source,"package_name":a.package_name,"installer":a.installer,"permissions_demandees":if a.requested_permissions.is_empty(){&a.sensitive_permissions}else{&a.requested_permissions},"permissions_accordees":a.granted_permissions,"capacites_actives":a.active_capabilities,"is_system_app":a.is_system_app,"has_launcher_entry":a.has_launcher_entry,"is_home_app":a.is_home_app,"is_default_home":a.is_default_home,"profil_atelier":{"familles":p.families,"raisons":p.reasons},"hidden_audit":a.hidden_audit,"notification_audit":a.notification_audit,"local_risk_score":row.local_risk.score,"local_reasons":row.local_risk.reasons,"version":a.version_name,"target_sdk":a.target_sdk,"install_date":a.install_date,"metadata_error":!a.dumpsys_error.is_empty()})
}
pub fn parse(content: &str) -> Result<BTreeMap<String, AiResult>> {
    let mut s = content.trim().trim_matches('`').trim();
    if s.starts_with("json") {
        s = s[4..].trim();
    }
    if !s.starts_with(['{', '[']) {
        if let (Some(i), Some(j)) = (s.find('{'), s.rfind('}')) {
            s = &s[i..=j];
        } else if let (Some(i), Some(j)) = (s.find('['), s.rfind(']')) {
            s = &s[i..=j];
        }
    }
    let raw: Value = serde_json::from_str(s).map_err(|_| "Réponse IA illisible : JSON invalide")?;
    let entries = raw
        .as_array()
        .or_else(|| raw["apps"].as_array())
        .ok_or("Réponse IA incomplète : liste apps absente")?;
    let mut results = BTreeMap::new();
    for item in entries {
        let p = item["package_name"].as_str().unwrap_or("").trim();
        if p.is_empty() {
            continue;
        }
        let score = item["risk_score"]
            .as_i64()
            .or_else(|| item["risk_score"].as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0)
            .clamp(0, 100) as i32;
        let norm = |key: &str, allowed: &[&str], fallback: &str| {
            let s = item[key].as_str().unwrap_or("").trim().to_lowercase();
            if allowed.contains(&s.as_str()) {
                s
            } else {
                fallback.into()
            }
        };
        let reason = item["reason_fr"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("Analyse IA non détaillée.")
            .trim()
            .chars()
            .take(500)
            .collect();
        results.insert(
            p.into(),
            AiResult {
                risk_score: score,
                category: item["category"]
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or("unknown_review_manually")
                    .trim()
                    .into(),
                recommended_action: norm(
                    "recommended_action",
                    &["keep", "review", "suggest_uninstall", "do_not_touch"],
                    "review",
                ),
                reason_fr: reason,
                confidence: norm("confidence", &["low", "medium", "high"], "low"),
            },
        );
    }
    Ok(results)
}
pub fn apply(row: &mut Row, result: AiResult, rep: &Reputation) {
    row.ai_text = format!(
        "{}/100 {} ({}) - {}",
        result.risk_score, result.category, result.confidence, result.reason_fr
    );
    row.ai = Some(result.clone());
    row.risk = row.local_risk.clone();
    if row.app.is_system_app
        || row.local_risk.recommended_action == "do_not_touch"
        || rep.whitelisted
        || ["keep", "removed"].contains(&row.validation.as_str())
        || !["review", "suggest_uninstall"].contains(&result.recommended_action.as_str())
    {
        return;
    }
    let suggest = result.recommended_action == "suggest_uninstall"
        && ["medium", "high"].contains(&result.confidence.as_str())
        && result.risk_score >= 60;
    row.risk.score = row.local_risk.score.max(if suggest {
        30.max(result.risk_score)
    } else {
        result.risk_score.clamp(30, 59)
    });
    row.risk.recommended_action =
        if suggest || row.local_risk.recommended_action == "suggest_uninstall" {
            "suggest_uninstall"
        } else {
            "review"
        }
        .into();
    row.risk.category = if suggest {
        "ai_unwanted_suspect".into()
    } else if row.local_risk.score >= 30 {
        row.local_risk.category.clone()
    } else {
        "unknown_review_manually".into()
    };
    row.risk.reasons.push(format!(
        "Avis IA ({}) : {}",
        result.confidence, result.reason_fr
    ));
}
pub async fn analyze(
    root: &Path,
    rows: &[Row],
    cancel: &CancellationToken,
    progress: impl Fn(usize, usize),
) -> Result<BTreeMap<String, AiResult>> {
    let settings = config::read(root)?;
    let env = config::env(root);
    let provider = settings["ai_provider"].as_str().unwrap_or("openai");
    let key_name = if provider == "minimax" {
        "MINIMAX_API_KEY"
    } else {
        "OPENAI_API_KEY"
    };
    let key = env
        .get(key_name)
        .filter(|s| !s.is_empty())
        .ok_or("Clé API absente. Configurez-la dans les réglages.")?;
    let base = settings[format!("{provider}_base_url")]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("https://api.openai.com/v1");
    config::validate_url(base)?;
    let model = settings[format!("{provider}_model")]
        .as_str()
        .unwrap_or("gpt-4.1-mini");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let inventory:Vec<_>=rows.iter().map(|r|json!({"package_name":r.app.package_name,"app_name":r.app.display_name(),"app_name_source":r.app.app_label_source,"is_system_app":r.app.is_system_app})).collect();
    let apps: Vec<_> = rows
        .iter()
        .filter(|r| !r.app.is_system_app && r.risk.recommended_action != "do_not_touch")
        .map(payload)
        .collect();
    let mut results = BTreeMap::new();
    for (batch_index, batch) in apps.chunks(20).enumerate() {
        progress(batch_index * 20, apps.len());
        let mut missing = batch.to_vec();
        for _ in 0..2 {
            let expected: BTreeSet<_> = missing
                .iter()
                .filter_map(|a| a["package_name"].as_str())
                .collect();
            let data = json!({"instruction":"Retourne un objet JSON contenant apps, un verdict par package demandé.","format":{"apps":[{"package_name":"string","risk_score":"integer 0-100","category":"string","recommended_action":"keep|review|suggest_uninstall|do_not_touch","reason_fr":"français","confidence":"low|medium|high"}]},"apps":missing,"inventaire_pour_comparaison_uniquement":inventory});
            let mut body = json!({"model":model,"temperature":0.1,"response_format":{"type":"json_object"},"messages":[{"role":"system","content":risk::CONSTANTS["SYSTEM_PROMPT"]},{"role":"user","content":data.to_string()}]});
            let mut transient_retries = 0;
            let received = loop {
                let sent = tokio::select! {r=client.post(format!("{}/chat/completions",base.trim_end_matches('/'))).bearer_auth(key).json(&body).send()=>r,_=cancel.cancelled()=>return Err("Analyse IA annulée".into())};
                let response =
                    match sent {
                        Ok(response) => response,
                        Err(_) if transient_retries == 0 => {
                            transient_retries += 1;
                            retry_pause(cancel).await?;
                            continue;
                        }
                        Err(_) => return Err(
                            "Connexion au fournisseur IA impossible après une nouvelle tentative"
                                .into(),
                        ),
                    };
                let status = response.status();
                let mut response = response;
                let mut bytes = Vec::new();
                loop {
                    let chunk = tokio::select! {r=response.chunk()=>r.map_err(|_|"Lecture de la réponse IA impossible")?,_=cancel.cancelled()=>return Err("Analyse IA annulée".into())};
                    let Some(chunk) = chunk else {
                        break;
                    };
                    if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
                        return Err("Réponse IA trop volumineuse".into());
                    }
                    bytes.extend(chunk);
                }
                if status.as_u16() == 400
                    && provider == "minimax"
                    && body.get("response_format").is_some()
                    && String::from_utf8_lossy(&bytes).contains("response_format")
                {
                    body.as_object_mut().unwrap().remove("response_format");
                    continue;
                }
                if !status.is_success() {
                    if transient_retries == 0
                        && (status.as_u16() == 429
                            || status.is_server_error()
                            || status.as_u16() == 408)
                    {
                        transient_retries += 1;
                        retry_pause(cancel).await?;
                        continue;
                    }
                    return Err(format!("Le fournisseur IA a répondu HTTP {}. Vérifiez la clé, le modèle et le quota.",status.as_u16()));
                }
                let raw: Value =
                    serde_json::from_slice(&bytes).map_err(|_| "Réponse HTTP IA invalide")?;
                break parse(
                    raw["choices"][0]["message"]["content"]
                        .as_str()
                        .ok_or("Réponse IA sans contenu")?,
                )?;
            };
            results.extend(
                received
                    .into_iter()
                    .filter(|(p, _)| expected.contains(p.as_str())),
            );
            missing = batch
                .iter()
                .filter(|a| !results.contains_key(a["package_name"].as_str().unwrap_or("")))
                .cloned()
                .collect();
            if missing.is_empty() {
                break;
            }
        }
        if !missing.is_empty() {
            return Err(format!(
                "Analyse IA incomplète : {} verdict(s) manquant(s). Aucun résultat appliqué.",
                missing.len()
            ));
        }
        progress(((batch_index + 1) * 20).min(apps.len()), apps.len());
    }
    Ok(results)
}

async fn retry_pause(cancel: &CancellationToken) -> Result<()> {
    tokio::select! { _ = tokio::time::sleep(Duration::from_millis(500)) => Ok(()), _ = cancel.cancelled() => Err("Analyse IA annulée".into()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_json_is_normalized() {
        let r=parse("```json\n{\"apps\":[{\"package_name\":\"com.test.app\",\"risk_score\":900,\"recommended_action\":\"delete\",\"confidence\":\"certain\"}]}\n```").unwrap();
        assert_eq!(r["com.test.app"].risk_score, 100);
        assert_eq!(r["com.test.app"].recommended_action, "review");
        assert_eq!(r["com.test.app"].confidence, "low");
        assert!(parse("not JSON").is_err());
    }
    #[test]
    fn ai_never_overrides_human_or_system() {
        let a = AppInfo {
            package_name: "org.test.app".into(),
            ..Default::default()
        };
        let risk = risk::evaluate(&a, &Reputation::default());
        let mut row = Row {
            app: a,
            risk: risk.clone(),
            local_risk: risk.clone(),
            ai: None,
            ai_text: String::new(),
            note: String::new(),
            validation: "keep".into(),
        };
        let ai = AiResult {
            risk_score: 100,
            category: "spyware".into(),
            recommended_action: "suggest_uninstall".into(),
            reason_fr: "test".into(),
            confidence: "high".into(),
        };
        apply(&mut row, ai.clone(), &Reputation::default());
        assert_eq!(row.risk.score, risk.score);
        row.validation = "unreviewed".into();
        row.app.is_system_app = true;
        apply(&mut row, ai, &Reputation::default());
        assert_eq!(row.risk.score, risk.score);
    }
}
