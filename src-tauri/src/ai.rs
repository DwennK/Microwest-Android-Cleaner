use crate::{config, model::*};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub fn payload(row: &Row) -> Value {
    let a = &row.app;
    json!({"app_name":a.display_name(),"app_name_source":a.app_label_source,"package_name":a.package_name,"version":a.version_name,"target_sdk":a.target_sdk,"facts":crate::evidence::facts(a),"apk_limitations":a.apk_analysis.limitations})
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
                evidence_ids: string_list(&item["evidence_ids"]),
                counter_evidence_ids: string_list(&item["counter_evidence_ids"]),
                missing_information: string_list(&item["missing_information"]),
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
fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .take(32)
                .map(|s| s.chars().take(250).collect())
                .collect()
        })
        .unwrap_or_default()
}

/// Returns true only when a supported opinion was incorporated in the final decision.
pub fn apply(row: &mut Row, result: AiResult, rep: &Reputation) -> bool {
    row.ai = Some(result.clone());
    row.risk = row.local_risk.clone();
    let facts = crate::evidence::facts(&row.app);
    let ids: Vec<_> = result
        .evidence_ids
        .iter()
        .chain(&result.counter_evidence_ids)
        .collect();
    let grounded = !ids.is_empty() && ids.iter().all(|id| facts.contains_key(id.as_str()));
    let confident = ["medium", "high"].contains(&result.confidence.as_str());
    // The model's prose is retained in ai.reason_fr for auditing. User-facing
    // justification is reconstructed from actual facts so invented permissions
    // or publisher identities never appear as established evidence.
    row.ai_text = if grounded {
        format!(
            "Avis IA : {} ({}/100, confiance {}). Faits cités : {}",
            result.recommended_action,
            result.risk_score,
            result.confidence,
            ids.iter()
                .filter_map(|id| facts.get(id.as_str()))
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
        )
    } else {
        "Avis IA non appliqué : références absentes, anciennes ou non présentes dans les observations. Relancer l’analyse IA.".into()
    };
    if row.app.is_system_app
        || row.local_risk.recommended_action == "do_not_touch"
        || rep.whitelisted
        || rep.blacklisted
        || row.validation != "unreviewed"
    {
        row.ai_text
            .push_str(" Décision humaine, réputation explicite ou protection système conservée.");
        return false;
    }
    if !grounded || !confident {
        if grounded {
            row.ai_text
                .push_str(" Confiance insuffisante : décision locale conservée.");
        }
        return false;
    }
    let strong_local = row.local_risk.recommended_action == "suggest_uninstall";
    let incomplete = !row.app.dumpsys_error.is_empty();
    let (action, score, category, explanation) = match result.recommended_action.as_str() {
        "keep" if strong_local => ("review", row.local_risk.score.min(59), "conflicting_evidence", "Désaccord : l’IA conseille de conserver malgré des indices locaux forts. Vérification humaine requise."),
        "keep" if incomplete => ("review", 30, "incomplete_evidence", "L’IA conseille de conserver mais la collecte Android est incomplète."),
        "keep" if !result.counter_evidence_ids.is_empty() => ("keep", result.risk_score.clamp(0, 29), "ai_keep", "L’avis IA corrige la suspicion locale ; aucun indice local fort ne s’y oppose."),
        "suggest_uninstall" if !incomplete && crate::evidence::supports_removal(&row.app, &result.evidence_ids) => ("suggest_uninstall", result.risk_score.clamp(60, 100), "ai_unwanted_suspect", "Retrait proposé par l’IA sur un faisceau d’indices vérifiables, à confirmer par le technicien."),
        "review" | "suggest_uninstall" | "keep" => ("review", result.risk_score.clamp(30, 59), "unknown_review_manually", "Avis IA à vérifier : les éléments cités ne suffisent pas à confirmer un retrait ou une conservation."),
        _ => { row.ai_text.push_str(" Action non applicable : décision locale conservée."); return false; }
    };
    row.risk = Risk {
        score,
        recommended_action: action.into(),
        category: category.into(),
        reasons: vec![explanation.into()],
    };
    row.risk
        .reasons
        .extend(ids.iter().filter_map(|id| facts.get(id.as_str())).cloned());
    true
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
            let data = json!({"instruction":"Retourne un objet JSON contenant apps, un verdict par package demandé.","format":{"apps":[{"package_name":"string","risk_score":"integer 0-100","category":"string","recommended_action":"keep|review|suggest_uninstall|do_not_touch","reason_fr":"français","confidence":"low|medium|high","evidence_ids":["identifiants exacts des faits motivant une suspicion"],"counter_evidence_ids":["identifiants exacts des faits rassurants"],"missing_information":["incertitudes"]}]},"apps":missing,"inventaire_pour_comparaison_uniquement":inventory});
            let mut body = json!({"model":model,"temperature":0.1,"response_format":{"type":"json_object"},"messages":[{"role":"system","content":include_str!("ai_prompt.txt")},{"role":"user","content":data.to_string()}]});
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
                    if status.as_u16() == 402 {
                        return Err(if provider == "minimax" {
                            "MiniMax refuse la requête pour un problème de facturation ou de crédits (HTTP 402). Vérifiez le solde et les droits associés à cette clé dans la console MiniMax. Un abonnement Token/Coding Plan utilise une clé d’abonnement distincte de la clé API facturée à l’usage."
                        } else {
                            "Le fournisseur IA refuse la requête pour un problème de facturation ou de crédits (HTTP 402). Vérifiez le solde et les droits associés à votre clé dans sa console."
                        }.into());
                    }
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
                if provider == "minimax" {
                    // MiniMax can also report a provider error inside an HTTP 200 response.
                    if let Some(code) = raw["base_resp"]["status_code"].as_i64().filter(|c| *c != 0)
                    {
                        let help = match code {
                            1008 => "Solde insuffisant. Vérifiez les crédits associés à votre clé MiniMax ; les clés d’abonnement et API à l’usage sont distinctes.",
                            2056 => "Limite d’utilisation atteinte. Consultez le quota et sa prochaine réinitialisation dans la console MiniMax.",
                            1004 | 2049 => "Clé API refusée. Vérifiez qu’elle est active et correspond au compte MiniMax utilisé.",
                            _ => "La requête a été refusée. Consultez la console MiniMax pour vérifier les droits et limites de votre compte.",
                        };
                        return Err(format!("MiniMax · erreur {code}. {help}"));
                    }
                }
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
    use crate::risk;
    fn review_row() -> Row {
        let app = AppInfo {
            package_name: "org.example.reader".into(),
            app_label: "Document Viewer".into(),
            app_label_source: "apk".into(),
            installer: "com.android.vending".into(),
            has_launcher_entry: Some(true),
            ..Default::default()
        };
        let risk = Risk {
            score: 68,
            category: "unknown_review_manually".into(),
            recommended_action: "review".into(),
            reasons: vec!["Ancienne suspicion faible".into()],
        };
        Row {
            app,
            risk: risk.clone(),
            local_risk: risk,
            ai: None,
            ai_text: String::new(),
            note: String::new(),
            validation: "unreviewed".into(),
        }
    }
    fn keep_opinion() -> AiResult {
        AiResult {
            risk_score: 10,
            recommended_action: "keep".into(),
            confidence: "high".into(),
            counter_evidence_ids: vec!["source:store".into(), "launcher:visible".into()],
            reason_fr: "Unsupported prose must never become evidence".into(),
            ..Default::default()
        }
    }
    #[test]
    fn grounded_ai_can_lower_a_weak_local_score_without_invented_prose() {
        let mut row = review_row();
        assert!(apply(&mut row, keep_opinion(), &Reputation::default()));
        assert_eq!(row.risk.score, 10);
        assert_eq!(row.risk.recommended_action, "keep");
        assert_eq!(row.local_risk.score, 68);
        assert!(!row.ai_text.contains("Unsupported prose"));
        let mut invented = keep_opinion();
        invented.evidence_ids = vec!["granted:android.permission.READ_SMS".into()];
        assert!(!apply(&mut row, invented, &Reputation::default()));
        assert_eq!(row.risk.score, 68);
    }
    #[test]
    fn contradictory_ai_requires_review_and_manual_decisions_win() {
        let mut row = review_row();
        row.local_risk.recommended_action = "suggest_uninstall".into();
        assert!(apply(&mut row, keep_opinion(), &Reputation::default()));
        assert_eq!(row.risk.category, "conflicting_evidence");
        assert_eq!(row.risk.recommended_action, "review");
        for status in ["keep", "remove", "review", "removed"] {
            row.validation = status.into();
            assert!(!apply(&mut row, keep_opinion(), &Reputation::default()));
        }
    }
    #[test]
    fn ai_cannot_propose_removal_for_a_library_alone() {
        let mut row = review_row();
        row.app.apk_analysis.ad_libraries = vec!["Google Mobile Ads".into()];
        let mut opinion = keep_opinion();
        opinion.recommended_action = "suggest_uninstall".into();
        opinion.risk_score = 90;
        opinion.evidence_ids = vec!["ads:Google Mobile Ads".into()];
        assert!(apply(&mut row, opinion, &Reputation::default()));
        assert_eq!(row.risk.recommended_action, "review");
        assert!(row.risk.score < 60);
    }
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
            evidence_ids: vec![],
            counter_evidence_ids: vec![],
            missing_information: vec![],
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
