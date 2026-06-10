from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_DIR / "reports"


def export_html_report(device: Any, rows: list[dict[str, Any]], uninstalled: list[dict[str, str]]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    path = REPORTS_DIR / f"rapport_android_cleaner_{timestamp}.html"

    suspicious = [r for r in rows if r["risk"].score >= 60 and r["risk"].recommended_action != "do_not_touch"]
    review = [r for r in rows if r["risk"].recommended_action == "review"]

    content = f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Rapport Android Cleaner</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #1f2933; }}
    .brand {{ display: flex; align-items: center; gap: 16px; border-bottom: 2px solid #d8dee8; padding-bottom: 18px; margin-bottom: 22px; }}
    .brand-mark {{ width: 72px; height: 72px; border-radius: 16px; background: #0b2a4a; color: white; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 800; letter-spacing: 0; }}
    .brand-title {{ font-size: 28px; font-weight: 800; color: #0b2a4a; line-height: 1.05; }}
    .brand-subtitle {{ font-size: 14px; color: #5f6b7a; margin-top: 6px; }}
    h1 {{ margin-bottom: 0; }}
    .muted {{ color: #5f6b7a; }}
    table {{ border-collapse: collapse; width: 100%; margin: 18px 0 28px; }}
    th, td {{ border: 1px solid #d8dee8; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    .risk-high {{ color: #b42318; font-weight: 700; }}
    .risk-medium {{ color: #b54708; font-weight: 700; }}
    .risk-low {{ color: #027a48; font-weight: 700; }}
    .notice {{ background: #f8fafc; border-left: 4px solid #3b82f6; padding: 12px 14px; }}
  </style>
</head>
<body>
  <div class="brand">
    <div class="brand-mark">MW</div>
    <div>
      <div class="brand-title">Microwest</div>
      <div class="brand-subtitle">Shopy Phone Sàrl · Android Cleaner</div>
    </div>
  </div>
  <h1>Rapport Android Cleaner</h1>
  <p><strong>Date :</strong> {html.escape(datetime.now().strftime("%d.%m.%Y %H:%M"))}</p>
  <p><strong>Téléphone :</strong> {html.escape(getattr(device, "manufacturer", ""))} {html.escape(getattr(device, "model", ""))}</p>
  <p><strong>Android :</strong> {html.escape(getattr(device, "android_version", ""))}</p>
  <p><strong>Numéro ADB :</strong> {html.escape(getattr(device, "serial", ""))}</p>
  <p><strong>Nombre d'apps scannées :</strong> {len(rows)}</p>
  <p><strong>Apps suspectes détectées :</strong> {len(suspicious)}</p>

  <div class="notice">
    Ce rapport est une aide au diagnostic. Les applications ont été classées selon leurs métadonnées,
    permissions et signaux de risque. Aucune donnée personnelle du client n'a été lue.
  </div>

  <h2>Apps suspectes détectées</h2>
  {table_for_rows(suspicious)}

  <h2>Apps laissées en vérification</h2>
  {table_for_rows(review)}

  <h2>Apps désinstallées</h2>
  {table_for_uninstalls(uninstalled)}
</body>
</html>
"""
    path.write_text(content, encoding="utf-8")
    return path


def table_for_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<p class=\"muted\">Aucune.</p>"
    lines = [
        "<table>",
        "<tr><th>Priorité</th><th>Score</th><th>Catégorie</th><th>Action</th><th>Nom</th><th>Package</th><th>Visibilité</th><th>Notifications</th><th>Raisons</th><th>Note</th><th>IA</th></tr>",
    ]
    for row in rows:
        app = row["app"]
        risk = row["risk"]
        ai_text = row.get("ai_text", "")
        css = "risk-high" if risk.score >= 60 else "risk-medium" if risk.score >= 30 else "risk-low"
        lines.append(
            "<tr>"
            f"<td>{html.escape(report_priority(row))}</td>"
            f"<td class=\"{css}\">{risk.score}</td>"
            f"<td>{html.escape(risk.category)}</td>"
            f"<td>{html.escape(risk.recommended_action)}</td>"
            f"<td>{html.escape(app.display_name())}</td>"
            f"<td>{html.escape(app.package_name)}</td>"
            f"<td>{html.escape(report_hidden_summary(app))}</td>"
            f"<td>{html.escape(', '.join(app.notification_audit) or '-')}</td>"
            f"<td>{html.escape('; '.join(risk.reasons))}</td>"
            f"<td>{html.escape(row.get('note', ''))}</td>"
            f"<td>{html.escape(ai_text)}</td>"
            "</tr>"
        )
    lines.append("</table>")
    return "\n".join(lines)


def report_hidden_summary(app: Any) -> str:
    if getattr(app, "has_launcher_entry", None) is False:
        return "Sans icône launcher"
    hidden_audit = getattr(app, "hidden_audit", [])
    if hidden_audit:
        return ", ".join(hidden_audit)
    return "-"


def report_priority(row: dict[str, Any]) -> str:
    app = row["app"]
    risk = row["risk"]
    if risk.recommended_action == "do_not_touch" or getattr(app, "is_system_app", False):
        return "Protégée"
    if risk.score >= 80:
        return "Urgent"
    if risk.score >= 60:
        return "À traiter"
    if risk.recommended_action == "review" or risk.score >= 30:
        return "À vérifier"
    return "OK"


def table_for_uninstalls(uninstalled: list[dict[str, str]]) -> str:
    if not uninstalled:
        return "<p class=\"muted\">Aucune.</p>"
    lines = ["<table>", "<tr><th>Nom</th><th>Package</th><th>Résultat</th></tr>"]
    for item in uninstalled:
        lines.append(
            "<tr>"
            f"<td>{html.escape(item.get('label', ''))}</td>"
            f"<td>{html.escape(item.get('package', ''))}</td>"
            f"<td>{html.escape(item.get('result', ''))}</td>"
            "</tr>"
        )
    lines.append("</table>")
    return "\n".join(lines)
