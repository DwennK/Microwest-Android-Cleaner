"""Development only: freeze Python behavior as JSON consumed by Rust tests.

Run with the legacy development environment, never from the shipped application.
"""
import ast
import dataclasses
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / 'legacy/python'
sys.path.insert(0, str(LEGACY))
from scanner import AppInfo
from risk_rules import evaluate_app, ReputationLookup
from app_triage import unwanted_profile

out = ROOT / 'src-tauri' / 'reference'
out.mkdir(parents=True, exist_ok=True)
constants = {}
for filename in ('risk_rules.py', 'database.py', 'scanner.py', 'ai_analyzer.py'):
    tree = ast.parse((LEGACY / filename).read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            try:
                value = ast.literal_eval(node.value)
                if isinstance(value, set):
                    value = sorted(value)
                constants[node.targets[0].id] = value
            except (ValueError, TypeError):
                pass
(out / 'constants.json').write_text(json.dumps(constants, ensure_ascii=False, indent=2), encoding='utf-8')

# Cover combinations deterministically; dates deliberately fixed outside the recent window.
rng = random.Random(481)
labels = ['Phone Cleaner', 'PDF READER ALL PRO', '#GALLERY', '#CONTACT', 'Rotate Link', 'Gold Miner', 'Nova Launcher', 'QR Reader', 'Battery Monitor', 'Adobe Acrobat', 'Ordinary App', 'Super Clean', 'Gold Cash Rewards', 'Contacts', 'Nettoyeur Téléphone']
packages = ['org.example.reader', 'com.google.android.fakecleaner', 'com.google.android.contacts', 'com.vendor.cleanmaster', 'org.example.ab123', 'com.samsung.android.lool', 'com.whatsapp', 'org.example.service']
flags = ['has_accessibility','has_overlay','has_device_admin','has_notification_listener','requests_post_notifications','uses_exact_alarm','uses_vibration','can_install_unknown_apps','has_usage_stats','runs_at_boot','has_vpn_service']
cases = []
for i in range(600):
    app = AppInfo(package_name=rng.choice(packages), app_label=rng.choice(labels), app_label_source=rng.choice(['apk','package']), icon_path=rng.choice(['','icon.png']), installer=rng.choice(['','com.android.vending','unknown','com.sec.android.app.samsungapps']), is_system_app=i % 11 == 0, has_launcher_entry=rng.choice([True,False,None]), is_home_app=rng.choice([True,False,None]), is_default_home=rng.choice([True,False,None]), target_sdk=rng.choice(['','23','28','35']), install_date='2000-01-01')
    for flag in flags:
        setattr(app, flag, rng.choice([True,False]))
    app.active_capabilities = [v for v in ['accessibility','overlay','device_admin','notification_listener','notifications','install_unknown_apps','usage_stats','exact_alarm'] if rng.random()<.2]
    app.requested_permissions = rng.sample(['android.permission.READ_SMS','android.permission.POST_NOTIFICATIONS','android.permission.READ_CONTACTS','android.permission.VIBRATE','android.permission.SEND_SMS','android.permission.SYSTEM_ALERT_WINDOW'], rng.randrange(7))
    app.granted_permissions = app.requested_permissions[:rng.randrange(len(app.requested_permissions)+1)]
    app.hidden_audit = ['Nom très générique'] if i % 2 else []
    app.notification_audit = ['Accès notifications demandé','Vibration demandée','Alarme exacte demandée'] if i % 3 else []
    rep = ReputationLookup(whitelisted=i%17==0, blacklisted=i%19==0, blacklist_severity=70, reason='Test')
    cases.append({'app':dataclasses.asdict(app),'reputation':dataclasses.asdict(rep),'risk':dataclasses.asdict(evaluate_app(app, rep)), 'profile':dataclasses.asdict(unwanted_profile(app))})
(out / 'risk-cases.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2),encoding='utf-8')

# Match all model fields; generated declarations are ordinary compiled Rust.
lines = ['use serde::{Serialize, Deserialize};', '#[derive(Debug, Clone, Serialize, Deserialize)]', '#[serde(default)]', 'pub struct AppInfo {']
types = {'str':'String','bool':'bool','bool | None':'Option<bool>','list[str]':'Vec<String>'}
for f in dataclasses.fields(AppInfo):
    lines.append(f'    pub {f.name}: {types[f.type]},')
lines += ['}', 'impl Default for AppInfo {', '    fn default() -> Self { Self {']
for f in dataclasses.fields(AppInfo):
    default = f.default
    if isinstance(default,str): expr = json.dumps(default)+'.into()'
    elif default is False: expr='false'
    elif default is None: expr='None'
    elif f.type == 'str': expr='String::new()'
    else: expr='Vec::new()'
    lines.append(f'        {f.name}: {expr},')
lines += ['    }}','}', 'impl AppInfo { pub fn display_name(&self) -> String { if self.app_label.is_empty() { crate::scanner::package_to_label(&self.package_name) } else { self.app_label.clone() } } }']
(ROOT / 'src-tauri/src/app_info.rs').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(f'Generated {len(cases)} parity cases, constants and AppInfo.')

# Reuse the existing Python tests themselves as a second, independent corpus.
import pytest
import risk_rules
from scanner import installed_recently
original_evaluate = risk_rules.evaluate_app
reference_cases = []
def capture(app, reputation=None):
    result = original_evaluate(app, reputation)
    reference_cases.append({
        'app': dataclasses.asdict(app),
        'reputation': dataclasses.asdict(reputation or ReputationLookup()),
        'risk': dataclasses.asdict(result),
        'recent_install': installed_recently(app.install_date),
    })
    return result
risk_rules.evaluate_app = capture
code = pytest.main(['-q', str(LEGACY / 'tests/test_risk_rules.py'), str(LEGACY / 'tests/test_app_triage.py')])
if code:
    raise SystemExit(code)
(out / 'python-test-cases.json').write_text(json.dumps(reference_cases,ensure_ascii=False,indent=2),encoding='utf-8')
print(f'Captured {len(reference_cases)} evaluations from existing tests.')
