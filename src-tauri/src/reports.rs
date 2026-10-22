use crate::model::*;
use std::path::Path;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn priority(r: &Row) -> &'static str {
    if r.app.is_system_app || r.risk.recommended_action == "do_not_touch" {
        "Protégée"
    } else if r.risk.recommended_action == "suggest_uninstall" && r.risk.score >= 80 {
        "Urgent"
    } else if r.risk.recommended_action == "suggest_uninstall" {
        "À traiter"
    } else if r.risk.recommended_action == "review" {
        "À vérifier"
    } else {
        "OK"
    }
}
fn boolean_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "oui",
        Some(false) => "non",
        None => "non vérifié",
    }
}
pub fn plan(scan: &Scan, selected: &[String]) -> String {
    let high = scan
        .rows
        .iter()
        .filter(|r| r.risk.recommended_action == "suggest_uninstall" && !r.app.is_system_app)
        .count();
    let review = scan
        .rows
        .iter()
        .filter(|r| r.risk.recommended_action == "review")
        .count();
    let hidden = scan
        .rows
        .iter()
        .filter(|r| {
            r.app.has_launcher_entry == Some(false)
                || r.app.hidden_audit.iter().any(|s| {
                    s.nfd()
                        .filter(|c| !is_combining_mark(*c))
                        .collect::<String>()
                        == "Nom tres generique"
                })
        })
        .count();
    let sideload = scan
        .rows
        .iter()
        .filter(|r| !crate::risk::safe_installer(&r.app.installer))
        .count();
    let mut s=format!("Microwest Android Cleaner — Plan d'action\nDate : {}\nTéléphone : {} {}\nAndroid : {}\nADB : {}\n\nSynthèse\nApplications : {}\nÀ traiter : {high}\nÀ vérifier : {review}\nApps cachées/faible visibilité : {hidden}\nSideload/installateur inconnu : {sideload}\n\nApplications proposées pour validation humaine\n",chrono::Local::now().format("%d.%m.%Y %H:%M"),scan.device.manufacturer,scan.device.model,scan.device.android_version,scan.device.serial,scan.rows.len());
    if scan.cancelled || scan.demo {
        s.push_str("SCAN INCOMPLET / DÉMONSTRATION : aucune désinstallation autorisée.\n");
    }
    for r in &scan.rows {
        if r.app.is_system_app || r.risk.recommended_action == "do_not_touch" {
            continue;
        }
        if (!selected.is_empty() && selected.contains(&r.app.package_name))
            || (selected.is_empty() && r.risk.recommended_action == "suggest_uninstall")
        {
            s.push_str(&format!("- {} ({})\n  Score : {} — {}\n  Validation technicien : {}\n  Raisons : {}\n  Note : {}\n",r.app.display_name(),r.app.package_name,r.risk.score,r.risk.category,r.validation,r.risk.reasons.iter().take(4).cloned().collect::<Vec<_>>().join("; "),r.note));
            if !scan.cancelled
                && !scan.demo
                && scan.scan_id.is_some()
                && crate::adb::validate_package(&r.app.package_name).is_ok()
            {
                s.push_str(&format!(
                    "  Commande après validation : adb shell pm uninstall --user 0 {}\n",
                    r.app.package_name
                ));
            }
            if r.app.is_default_home == Some(true) {
                s.push_str(
                    "  Écran d'accueil actuel : rétablir l'accueil souhaité avant suppression.\n",
                );
            }
        }
    }
    s.push_str("\nApplications à vérifier manuellement\n");
    for r in scan
        .rows
        .iter()
        .filter(|r| r.risk.recommended_action == "review")
        .take(20)
    {
        s.push_str(&format!(
            "- {} ({}) — score {} — {}\n",
            r.app.display_name(),
            r.app.package_name,
            r.risk.score,
            r.risk
                .reasons
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    s.push_str("\nJournal d’intervention · Tweaks\n");
    if scan.interventions.is_empty() {
        s.push_str("Aucune intervention enregistrée.\n");
    }
    for entry in &scan.interventions {
        s.push_str(&format!(
            "- {} · {} · {}\n  {}\n",
            entry.date,
            intervention_status(&entry.status),
            entry.action,
            entry.detail
        ));
    }
    s.push_str("\nRappel sécurité\nNe pas désinstaller sans validation humaine. Aucune suppression automatique. Vérifier le téléphone si ADB devient unauthorized/offline.\n");
    s
}
pub fn csv(scan: &Scan) -> Result<String> {
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record([
        "score",
        "priority",
        "category",
        "recommended_action",
        "technician_validation",
        "app_name",
        "package",
        "installer",
        "system",
        "launcher_visible",
        "permissions_requested",
        "permissions_granted",
        "capabilities_active",
        "risk_reasons",
        "technician_note",
        "metadata_error",
        "version",
        "target_sdk",
        "install_date",
        "home",
        "default_home",
        "ai",
        "local_score",
        "ai_score",
        "rules_version",
        "apk_sha256",
        "ad_libraries",
        "warning_resources",
        "apk_limitations",
        "signature_verified",
        "publisher",
    ])
    .map_err(|e| e.to_string())?;
    for r in &scan.rows {
        let a = &r.app;
        let cells = vec![
            r.risk.score.to_string(),
            priority(r).into(),
            r.risk.category.clone(),
            r.risk.recommended_action.clone(),
            r.validation.clone(),
            a.display_name(),
            a.package_name.clone(),
            if a.installer.is_empty() {
                "inconnu".into()
            } else {
                a.installer.clone()
            },
            if a.is_system_app { "oui" } else { "non" }.into(),
            match a.has_launcher_entry {
                Some(true) => "oui",
                Some(false) => "non",
                None => "non vérifié",
            }
            .into(),
            a.requested_permissions.join("; "),
            a.granted_permissions.join("; "),
            a.active_capabilities.join("; "),
            r.risk.reasons.join("; "),
            r.note.clone(),
            a.dumpsys_error.clone(),
            a.version_name.clone(),
            a.target_sdk.clone(),
            a.install_date.clone(),
            boolean_label(a.is_home_app).into(),
            boolean_label(a.is_default_home).into(),
            r.ai_text.clone(),
            r.local_risk.score.to_string(),
            r.ai.as_ref()
                .map(|v| v.risk_score.to_string())
                .unwrap_or_default(),
            scan.rules_version.to_string(),
            a.apk_analysis.sha256.clone(),
            a.apk_analysis.ad_libraries.join("; "),
            a.apk_analysis.warning_strings.join("; "),
            a.apk_analysis.limitations.join("; "),
            a.apk_analysis.signature_verified.to_string(),
            a.apk_analysis.publisher.clone(),
        ];
        w.write_record(cells.iter().map(|s| csv_cell(s)))
            .map_err(|e| e.to_string())?;
    }
    String::from_utf8(w.into_inner().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
fn csv_cell(s: &str) -> String {
    if s.trim_start().starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.into()
    }
}
fn action_label(value: &str) -> &str {
    match value {
        "keep" => "Conserver",
        "review" => "À vérifier",
        "suggest_uninstall" => "Retrait proposé",
        "do_not_touch" => "Protégée",
        _ => value,
    }
}
fn validation_label(value: &str) -> &str {
    match value {
        "unreviewed" => "Non validée",
        "keep" => "Conserver",
        "review" => "À vérifier",
        "remove" => "Retirer",
        "removed" => "Retirée",
        _ => value,
    }
}
fn html_field(title: &str, value: &str) -> String {
    format!(
        "<div class=\"fact\"><dt>{}</dt><dd>{}</dd></div>",
        escape(title),
        if value.trim().is_empty() {
            "—".into()
        } else {
            escape(value)
        }
    )
}
fn excerpt(value: &str, limit: usize) -> String {
    let mut chars = value.chars();
    let mut text: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        text.push('…');
    }
    text
}

fn html_inventory(scan: &Scan) -> String {
    if scan.rows.is_empty() {
        return "<p>Aucune application dans ce scan.</p>".into();
    }
    let mut s = String::from("<table class=\"inventory\"><caption>Inventaire complet · motifs abrégés, détails techniques consultables dans le HTML.</caption><thead><tr><th scope=\"col\">Application</th><th scope=\"col\">Analyse</th><th scope=\"col\">Motif principal</th><th scope=\"col\">Validation / note</th></tr></thead><tbody>");
    for row in &scan.rows {
        let reason = if matches!(
            row.risk.recommended_action.as_str(),
            "review" | "suggest_uninstall"
        ) {
            row.risk
                .reasons
                .iter()
                .find(|reason| !reason.starts_with("Installée via "))
                .map(|reason| excerpt(reason, 180))
                .unwrap_or_default()
        } else {
            String::new()
        };
        s.push_str(&format!(
            "<tr><td><strong>{}</strong><div class=\"package\">{}</div></td><td><strong>{}</strong><br>{}/100</td><td>{}</td><td>{}",
            escape(&row.app.display_name()), escape(&row.app.package_name),
            escape(action_label(&row.risk.recommended_action)), row.risk.score,
            escape(&reason), escape(validation_label(&row.validation)),
        ));
        if !row.note.trim().is_empty() {
            s.push_str(&format!("<p class=\"note\">{}</p>", escape(&row.note)));
        }
        s.push_str("</td></tr>");
    }
    s.push_str("</tbody></table>");
    s
}

fn html_application(row: &Row) -> String {
    let a = &row.app;
    let tone = match priority(row) {
        "Urgent" | "À traiter" => "bad",
        "À vérifier" => "warn",
        "OK" => "good",
        _ => "neutral",
    };
    let mut s = format!(
        "<article class=\"application\"><header class=\"application-header\"><span class=\"priority priority-{tone}\">{} · {}/100</span><h3>{}</h3><div class=\"package\">{}</div><p class=\"muted\">Application {} · {}</p></header><div class=\"application-body\"><h3>Analyse</h3><dl class=\"facts\">{}{}</dl><ul>",
        priority(row), row.risk.score, escape(&a.display_name()), escape(&a.package_name),
        if a.is_system_app { "système" } else { "utilisateur" },
        escape(action_label(&row.risk.recommended_action)),
        html_field("Catégorie", &row.risk.category),
        html_field("Action proposée", action_label(&row.risk.recommended_action)),
    );
    for reason in &row.risk.reasons {
        s.push_str(&format!("<li>{}</li>", escape(reason)));
    }
    s.push_str("</ul>");
    s.push_str(&format!(
        "<p>Score local : {} · Score IA : {} · Décision finale : {}/100</p>",
        row.local_risk.score,
        row.ai
            .as_ref()
            .map(|v| v.risk_score.to_string())
            .unwrap_or_else(|| "non analysée".into()),
        row.risk.score
    ));
    if !row.ai_text.is_empty() {
        s.push_str(&format!(
            "<h3>Avis IA</h3><p class=\"note\">{}</p>",
            escape(&row.ai_text)
        ));
    }
    s.push_str("<h3>Métadonnées et accès</h3><dl class=\"facts\">");
    for (label, value) in [
        ("Installateur", a.installer.clone()),
        ("Version", a.version_name.clone()),
        ("SDK cible", a.target_sdk.clone()),
        ("Installation", a.install_date.clone()),
        ("Permissions demandées", a.requested_permissions.join(", ")),
        ("Permissions accordées", a.granted_permissions.join(", ")),
        ("Capacités actives", a.active_capabilities.join(", ")),
        ("Visibilité", a.hidden_audit.join("; ")),
        ("Notifications", a.notification_audit.join("; ")),
        ("Rôle HOME", boolean_label(a.is_home_app).into()),
        (
            "Accueil par défaut",
            boolean_label(a.is_default_home).into(),
        ),
        ("Erreur de collecte", a.dumpsys_error.clone()),
        (
            "Bibliothèques publicitaires (présence statique)",
            a.apk_analysis.ad_libraries.join(", "),
        ),
        (
            "Ressources alarmistes (affichage non observé)",
            a.apk_analysis.warning_strings.join("; "),
        ),
        ("Composants APK", a.apk_analysis.components.join(", ")),
        ("APK SHA-256", a.apk_analysis.sha256.clone()),
        (
            "Signataires SHA-256",
            a.apk_analysis.signer_sha256.join(", "),
        ),
        (
            "Signature APK",
            if a.apk_analysis.signature_verified {
                "Vérifiée"
            } else {
                "Non vérifiée"
            }
            .into(),
        ),
        (
            "Éditeur",
            if a.apk_analysis.publisher.is_empty() {
                "Identité non vérifiée".into()
            } else {
                a.apk_analysis.publisher.clone()
            },
        ),
        (
            "Limites de l’inspection APK",
            a.apk_analysis.limitations.join("; "),
        ),
    ] {
        if !value.trim().is_empty() {
            s.push_str(&html_field(label, &value));
        }
    }
    s.push_str(&format!("</dl><div class=\"technician\"><h3>Validation technicien : {}</h3><p class=\"note\">{}</p></div></div></article>", escape(validation_label(&row.validation)), if row.note.trim().is_empty() { "Aucune note.".into() } else { escape(&row.note) }));
    s
}
pub fn intervention_status(status: &str) -> &str {
    match status {
        "verified" => "Vérifié par l’application",
        "manual" => "Confirmé par le technicien",
        "opened" => "Écran ouvert · réalisation à confirmer",
        "failed" => "Échec / résultat non confirmé",
        _ => "Interrompu ou en cours · résultat non confirmé",
    }
}

pub fn html(scan: &Scan) -> String {
    let mut s = format!(
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Rapport Microwest Android Cleaner</title><style>{}</style></head><body><main><header class=\"report-header\"><p class=\"brand\">Microwest</p><p class=\"eyebrow\">Shopy Phone Sàrl · Android Cleaner</p><h1>Rapport de diagnostic Android</h1><dl class=\"identity\"><div><dt>Date d’édition</dt><dd>{}</dd></div><div><dt>Téléphone</dt><dd>{} {}</dd></div><div><dt>Version Android</dt><dd>{}</dd></div><div><dt>Numéro ADB</dt><dd>{}</dd></div><div><dt>Applications analysées</dt><dd>{}</dd></div></dl></header><p class=\"notice\">Ce rapport est une aide au diagnostic, pas une certification d’infection. Seules les métadonnées des applications sont analysées. Aucune donnée personnelle du client n’est lue.</p>",
        include_str!("report.css"), chrono::Local::now().format("%d.%m.%Y %H:%M"),
        escape(&scan.device.manufacturer), escape(&scan.device.model), escape(&scan.device.android_version),
        escape(&scan.device.serial), scan.rows.len()
    );
    s.push_str(&format!(
        "<p class=\"muted\">Version des règles : {}. {}</p>",
        scan.rules_version,
        escape(&scan.analysis_notice)
    ));
    if scan.demo || scan.cancelled {
        s.push_str("<p class=\"notice warning\">DÉMONSTRATION / SCAN INCOMPLET — aucune désinstallation autorisée.</p>");
    }
    let count = |action: &str| {
        scan.rows
            .iter()
            .filter(|r| r.risk.recommended_action == action)
            .count()
    };
    s.push_str(&format!(
        "<p class=\"scan-summary\"><strong>{} retraits proposés</strong> · {} à vérifier · {} à conserver · {} protégées</p>",
        count("suggest_uninstall"), count("review"), count("keep"), count("do_not_touch"),
    ));
    if scan.comparison.is_some() {
        s.push_str("<h2>Évolution depuis le scan précédent</h2>");
    }
    match &scan.comparison {
        None => s.push_str("<p class=\"screen-only\">Comparaison indisponible pour ce scan.</p>"),
        Some(c) if c.previous_scan_id.is_none() => s.push_str(
            "<p>Premier scan complet de ce téléphone : référence initiale enregistrée.</p>",
        ),
        Some(c) => {
            s.push_str(&format!("<p>Nouvelles applications : {} · Retirées : {} · Inchangées : {} · Risque modifié : {}</p>", c.new_apps.len(), c.removed_apps.len(), c.unchanged_count, c.risk_changes.len()));
            s.push_str("<details class=\"screen-only\"><summary>Détail des changements</summary>");
            for (title, apps) in [
                ("Nouvelles applications", &c.new_apps),
                (
                    "Applications retirées depuis le dernier scan",
                    &c.removed_apps,
                ),
            ] {
                s.push_str(&format!("<h3>{title}</h3>"));
                if apps.is_empty() {
                    s.push_str("<p>Aucune.</p>");
                    continue;
                }
                s.push_str("<ul>");
                for a in apps {
                    s.push_str(&format!(
                        "<li>{} ({}) — score {} — validation : {}</li>",
                        escape(&a.app_label),
                        escape(&a.package),
                        a.score,
                        escape(validation_label(&a.validation_status))
                    ));
                }
                s.push_str("</ul>");
            }
            for r in &c.risk_changes {
                s.push_str(&format!(
                    "<p>{} ({}) : {} → {}, {} → {}</p>",
                    escape(&r.app_label),
                    escape(&r.package),
                    r.previous_score,
                    r.current_score,
                    escape(action_label(&r.previous_action)),
                    escape(action_label(&r.current_action))
                ));
            }
            s.push_str("</details>");
        }
    }
    if !scan.interventions.is_empty() {
        s.push_str("<h2>Journal d’intervention · Tweaks</h2>");
    }
    for entry in &scan.interventions {
        s.push_str(&format!(
            "<section class=\"intervention\"><h3>{}</h3><p>{} · {}</p><p>{}</p></section>",
            escape(&entry.action),
            escape(&entry.date),
            escape(intervention_status(&entry.status)),
            escape(&entry.detail)
        ));
    }
    if !scan.uninstalled.is_empty() {
        s.push_str("<h2>Résultats des désinstallations</h2>");
    }
    for u in &scan.uninstalled {
        s.push_str(&format!(
            "<p><strong>{}</strong> · {} ({}) : {}</p>",
            if u.success { "Retirée" } else { "Échec" },
            escape(&u.label),
            escape(&u.package),
            escape(&u.result)
        ));
    }
    s.push_str("<h2>Résultats du scan</h2>");
    s.push_str(&html_inventory(scan));
    if !scan.rows.is_empty() {
        s.push_str("<details class=\"technical-details screen-only\"><summary>Détails techniques complets des applications (hors impression)</summary><p>Permissions, indices, analyse IA et métadonnées restent disponibles ici. L’impression contient la synthèse, l’inventaire, les notes et les résultats d’intervention.</p>");
        for row in &scan.rows {
            s.push_str(&html_application(row));
        }
        s.push_str("</details>");
    }
    s.push_str("<footer class=\"report-footer\">Microwest · Diagnostic atelier · Décisions humaines · Données locales</footer></main></body></html>");
    s
}

pub fn export(root: &Path, scan: &Scan, kind: &str, selected: &[String]) -> Result<String> {
    let (name, ext, content) = match kind {
        "html" => ("rapport_android_cleaner", "html", html(scan)),
        "csv" => ("apps_android_cleaner", "csv", csv(scan)?),
        "plan" => ("plan_action_android_cleaner", "txt", plan(scan, selected)),
        _ => return Err("Format inconnu".into()),
    };
    let path = root.join("reports").join(format!(
        "{name}_{}.{}",
        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S_%f"),
        ext
    ));
    crate::config::atomic_write(&path, content.as_bytes())?;
    Ok(path.to_string_lossy().into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_escapes_untrusted_content() {
        let s = Scan {
            device: Device {
                model: "<script>alert(1)</script>".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let h = html(&s);
        assert!(!h.contains("<script>"));
        assert!(h.contains("&lt;script&gt;"));
        assert!(h.contains("Comparaison indisponible"));
        assert_eq!(csv_cell("=cmd()"), "'=cmd()");
        assert!(csv(&s).unwrap().contains("permissions_granted"));
    }

    #[test]
    fn compact_inventory_keeps_every_app_and_full_notes_outside_the_technical_annex() {
        let risk = Risk {
            score: 35,
            category: "review".into(),
            recommended_action: "review".into(),
            reasons: vec!["Installée via Google Play".into(), "é".repeat(250)],
        };
        let mut scan = Scan::default();
        for i in 0..60 {
            scan.rows.push(Row {
                app: AppInfo {
                    package_name: format!("org.example.app{i:02}"),
                    requested_permissions: vec!["android.permission.TECHNICAL_ONLY".into()],
                    ..Default::default()
                },
                risk: risk.clone(),
                local_risk: risk.clone(),
                ai: None,
                ai_text: String::new(),
                note: format!("Note complète {i}: {}", "à".repeat(300)),
                validation: "review".into(),
            });
        }
        let rendered = html(&scan);
        let (summary, annex) = rendered
            .split_once("<details class=\"technical-details screen-only\">")
            .unwrap();
        let inventory = summary.split_once("<tbody>").unwrap().1;
        assert_eq!(inventory.matches("<tr>").count(), 60);
        assert!(!inventory.contains("TECHNICAL_ONLY"));
        assert!(inventory.contains(&format!("{}…", "é".repeat(180))));
        assert!(!inventory.contains(&"é".repeat(181)));
        for row in &scan.rows {
            assert!(inventory.contains(&row.app.package_name));
            assert!(inventory.contains(&row.note));
        }
        assert!(annex.contains("android.permission.TECHNICAL_ONLY"));
        assert!(annex.contains(&"é".repeat(250)));
        assert!(summary.contains("60 à vérifier"));
    }

    #[test]
    fn detailed_report_preserves_and_escapes_application_data() {
        let app = AppInfo {
            package_name: "com.test.<package>".into(),
            app_label: "<img src=x onerror=alert(1)>".into(),
            installer: "store & source".into(),
            requested_permissions: vec!["permission.<requested>".into()],
            granted_permissions: vec!["permission.<granted>".into()],
            active_capabilities: vec!["<overlay>".into()],
            dumpsys_error: "<collection error>".into(),
            ..Default::default()
        };
        let risk = Risk {
            score: 75,
            category: "<category>".into(),
            recommended_action: "suggest_uninstall".into(),
            reasons: vec!["<reason>".into()],
        };
        let scan = Scan {
            cancelled: true,
            rows: vec![Row {
                app,
                local_risk: risk.clone(),
                risk,
                ai: None,
                ai_text: "<AI text>".into(),
                note: "Première ligne\n<script>note</script>".into(),
                validation: "review".into(),
            }],
            uninstalled: vec![UninstallResult {
                package: "<removed package>".into(),
                label: "<removed label>".into(),
                result: "<failure>".into(),
                success: false,
            }],
            ..Default::default()
        };
        let html = html(&scan);
        for text in [
            "&lt;img src=x onerror=alert(1)&gt;",
            "com.test.&lt;package&gt;",
            "store &amp; source",
            "permission.&lt;requested&gt;",
            "permission.&lt;granted&gt;",
            "&lt;overlay&gt;",
            "&lt;collection error&gt;",
            "&lt;category&gt;",
            "&lt;reason&gt;",
            "&lt;AI text&gt;",
            "Première ligne\n&lt;script&gt;note&lt;/script&gt;",
            "&lt;removed package&gt;",
            "&lt;removed label&gt;",
            "&lt;failure&gt;",
            "<strong>Échec</strong>",
            "Retrait proposé",
            "Validation technicien : À vérifier",
            "SCAN INCOMPLET",
            "aucune désinstallation autorisée",
        ] {
            assert!(html.contains(text), "Missing report content: {text}");
        }
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img"));
        assert!(html.ends_with("</main></body></html>"));
    }
}
