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
    } else if r.risk.score >= 80 {
        "Urgent"
    } else if r.risk.score >= 60 {
        "À traiter"
    } else if r.risk.score >= 30 || r.risk.recommended_action == "review" {
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
        .filter(|r| {
            r.risk.score >= 60
                && r.risk.recommended_action != "do_not_touch"
                && !r.app.is_system_app
        })
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
            || (selected.is_empty() && r.risk.score >= 60)
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
pub fn html(scan: &Scan) -> String {
    let mut s=format!("<!doctype html><html lang=\"fr\"><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Rapport Microwest Android Cleaner</title><style>body{{font:14px Segoe UI,Arial;color:#183249;margin:36px}}h1{{color:#0b2a4a}}table{{border-collapse:collapse;width:100%;margin:20px 0;font-size:12px}}th,td{{border:1px solid #dbe3e9;padding:9px;vertical-align:top;text-align:left}}th{{background:#edf3f6}}.notice{{padding:15px;background:#edf3f6;border-left:4px solid #008e80}}@media print{{body{{margin:12px}}thead{{display:table-header-group}}tr{{break-inside:avoid}}}}</style><h1>Microwest</h1><p>Shopy Phone Sàrl · Android Cleaner</p><h2>Rapport de diagnostic Android</h2><p>Date : {}<br>Téléphone : {} {}<br>Android : {}<br>Numéro ADB : {}<br>Applications : {}</p><p class=notice>Ce rapport est une aide au diagnostic, pas une certification d'infection. Seules les métadonnées des applications sont analysées. Aucune donnée personnelle du client n'est lue.</p>",chrono::Local::now().format("%d.%m.%Y %H:%M"),escape(&scan.device.manufacturer),escape(&scan.device.model),escape(&scan.device.android_version),escape(&scan.device.serial),scan.rows.len());
    if scan.demo || scan.cancelled {
        s.push_str("<p class=notice>DÉMONSTRATION / SCAN INCOMPLET — aucune désinstallation autorisée.</p>");
    }
    s.push_str("<h2>Évolution depuis le scan précédent</h2>");
    match &scan.comparison {
        None => s.push_str("<p>Comparaison indisponible pour ce scan.</p>"),
        Some(c) if c.previous_scan_id.is_none() => s.push_str(
            "<p>Premier scan complet de ce téléphone : référence initiale enregistrée.</p>",
        ),
        Some(c) => {
            s.push_str(&format!("<p>Nouvelles apps : {} · Apps retirées : {} · Inchangées : {} · Risque modifié : {}</p>",c.new_apps.len(),c.removed_apps.len(),c.unchanged_count,c.risk_changes.len()));
            for (title, apps) in [
                ("Nouvelles applications", &c.new_apps),
                (
                    "Applications retirées depuis le dernier scan",
                    &c.removed_apps,
                ),
            ] {
                s.push_str(&format!("<h3>{title}</h3><ul>"));
                for a in apps {
                    s.push_str(&format!(
                        "<li>{} ({}) — score {} — validation {}</li>",
                        escape(&a.app_label),
                        escape(&a.package),
                        a.score,
                        escape(&a.validation_status)
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
                    escape(&r.previous_action),
                    escape(&r.current_action)
                ));
            }
        }
    }
    s.push_str("<h2>Résultats du scan</h2><table><thead><tr><th>Priorité / score</th><th>Application</th><th>Analyse</th><th>Métadonnées / accès</th><th>Validation / note</th></tr></thead><tbody>");
    for r in &scan.rows {
        let a = &r.app;
        s.push_str(&format!("<tr><td>{} · {}/100</td><td>{}<br>{}<br>{}</td><td>{}<br>{}<br>{}<br>{}</td><td>Installateur : {}<br>Version : {} · SDK {}<br>Installation : {}<br>Demandées : {}<br>Accordées : {}<br>Actives : {}<br>Visibilité : {}<br>Notifications : {}<br>HOME : {} · Défaut : {}<br>Erreur : {}</td><td>{}<br>{}</td></tr>",priority(r),r.risk.score,escape(&a.display_name()),escape(&a.package_name),if a.is_system_app{"Système"}else{"Utilisateur"},escape(&r.risk.category),escape(&r.risk.recommended_action),escape(&r.risk.reasons.join("; ")),escape(&r.ai_text),escape(&a.installer),escape(&a.version_name),escape(&a.target_sdk),escape(&a.install_date),escape(&a.requested_permissions.join(", ")),escape(&a.granted_permissions.join(", ")),escape(&a.active_capabilities.join(", ")),escape(&a.hidden_audit.join(", ")),escape(&a.notification_audit.join(", ")),boolean_label(a.is_home_app),boolean_label(a.is_default_home),escape(&a.dumpsys_error),escape(&r.validation),escape(&r.note)));
    }
    s.push_str("</tbody></table><h2>Apps désinstallées</h2>");
    if scan.uninstalled.is_empty() {
        s.push_str("<p>Aucune.</p>");
    }
    for u in &scan.uninstalled {
        s.push_str(&format!(
            "<p>{} ({}) : {}</p>",
            escape(&u.label),
            escape(&u.package),
            escape(&u.result)
        ));
    }
    s.push_str("</html>");
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
}
