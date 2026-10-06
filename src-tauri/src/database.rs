use crate::{model::*, risk::CONSTANTS};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Database {
    con: Connection,
}
fn err(e: rusqlite::Error) -> String {
    e.to_string()
}
pub fn device_key(serial: &str, model: &str) -> String {
    let id = if serial.trim().is_empty() {
        format!("model:{}", model.trim().to_lowercase())
    } else {
        serial.trim().into()
    };
    format!("{:x}", Sha256::digest(id.as_bytes()))[..24].into()
}
impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let con = Connection::open(path).map_err(err)?;
        con.busy_timeout(Duration::from_secs(5)).map_err(err)?;
        con.execute_batch("PRAGMA foreign_keys=ON;").map_err(err)?;
        Ok(Self { con })
    }
    pub fn initialize(path: &Path) -> Result<Option<PathBuf>> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let mut db = Self::open(path)?;
        let version: i64 = db
            .con
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(err)?;
        if version > 4 {
            return Err(format!("Base version {version} plus récente que cette application : aucun changement effectué."));
        }
        let count: i64 = db
            .con
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        let backup = if count > 0 && version < 4 {
            let dest = path.with_file_name(format!(
                "app_reputation.schema{version}_backup_{}.sqlite",
                chrono::Utc::now().format("%Y%m%d_%H%M%S_%f")
            ));
            db.con
                .backup(rusqlite::DatabaseName::Main, &dest, None)
                .map_err(err)?;
            Some(dest)
        } else {
            None
        };
        let tx = db.con.transaction().map_err(err)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS whitelist(package TEXT PRIMARY KEY,label TEXT,reason TEXT);
        CREATE TABLE IF NOT EXISTS blacklist(package TEXT PRIMARY KEY,label TEXT,reason TEXT,severity INTEGER);
        CREATE TABLE IF NOT EXISTS scan_history(id INTEGER PRIMARY KEY,date TEXT,device_model TEXT,android_version TEXT,scanned_count INTEGER,suspicious_count INTEGER,device_key TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS uninstall_history(id INTEGER PRIMARY KEY,date TEXT,package TEXT,app_label TEXT,result TEXT);
        CREATE TABLE IF NOT EXISTS app_notes(package TEXT PRIMARY KEY,note TEXT,updated_at TEXT);
        CREATE TABLE IF NOT EXISTS scan_apps(scan_id INTEGER NOT NULL,package TEXT NOT NULL,app_label TEXT,score INTEGER NOT NULL,category TEXT,action TEXT,validation_status TEXT NOT NULL DEFAULT 'unreviewed',PRIMARY KEY(scan_id,package),FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE CASCADE);").map_err(err)?;
        let columns = |table: &str| -> Result<Vec<String>> {
            let mut s = tx
                .prepare(&format!("PRAGMA table_info({table})"))
                .map_err(err)?;
            let values = s
                .query_map([], |r| r.get(1))
                .map_err(err)?
                .collect::<std::result::Result<Vec<String>, _>>()
                .map_err(err)?;
            Ok(values)
        };
        if !columns("scan_history")?.iter().any(|s| s == "device_key") {
            tx.execute_batch(
                "ALTER TABLE scan_history ADD COLUMN device_key TEXT NOT NULL DEFAULT '';",
            )
            .map_err(err)?;
        }
        let old = columns("app_validations")?;
        if !old.is_empty() && !old.iter().any(|s| s == "scan_id") {
            tx.execute_batch("ALTER TABLE app_validations RENAME TO app_validations_v2;")
                .map_err(err)?;
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS app_validations(scan_id INTEGER NOT NULL,package TEXT NOT NULL,status TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(scan_id,package),FOREIGN KEY(scan_id,package) REFERENCES scan_apps(scan_id,package) ON DELETE CASCADE);
        CREATE INDEX IF NOT EXISTS idx_scan_history_device ON scan_history(device_key,id DESC);
        CREATE TABLE IF NOT EXISTS scan_payloads(scan_id INTEGER PRIMARY KEY,payload TEXT NOT NULL,FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE CASCADE);").map_err(err)?;
        let legacy:i64=tx.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='app_validations_v2'",[],|r|r.get(0)).map_err(err)?;
        if legacy > 0 {
            tx.execute_batch("INSERT OR REPLACE INTO app_validations(scan_id,package,status,updated_at) SELECT scan_apps.scan_id,scan_apps.package,scan_apps.validation_status,COALESCE(app_validations_v2.updated_at,scan_history.date,'') FROM scan_apps JOIN scan_history ON scan_history.id=scan_apps.scan_id LEFT JOIN app_validations_v2 ON app_validations_v2.package=scan_apps.package WHERE scan_apps.validation_status IN ('keep','review','remove','removed'); DROP TABLE app_validations_v2;").map_err(err)?;
        }
        for value in CONSTANTS["DEFAULT_WHITELIST"].as_array().unwrap() {
            tx.execute(
                "INSERT OR IGNORE INTO whitelist(package,label,reason) VALUES(?1,?2,?3)",
                params![value[0].as_str(), value[1].as_str(), value[2].as_str()],
            )
            .map_err(err)?;
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS analysis_revisions(id INTEGER PRIMARY KEY,scan_id INTEGER NOT NULL,payload TEXT NOT NULL,archived_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reputation_overrides(package TEXT PRIMARY KEY);
        PRAGMA user_version=4;").map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(backup)
    }
    pub fn reputation(&self, p: &str) -> Result<Reputation> {
        let white: Option<String> = self
            .con
            .query_row(
                "SELECT COALESCE(reason,'') FROM whitelist WHERE package=?",
                [p],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let black: Option<(String, i32)> = self
            .con
            .query_row(
                "SELECT COALESCE(reason,''),COALESCE(severity,50) FROM blacklist WHERE package=?",
                [p],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        Ok(Reputation {
            whitelisted: white.as_ref().is_some_and(|reason| {
                let seeded = CONSTANTS["DEFAULT_WHITELIST"]
                    .as_array()
                    .is_some_and(|items| {
                        items.iter().any(|item| {
                            item[0].as_str() == Some(p) && item[2].as_str() == Some(reason.as_str())
                        })
                    });
                !seeded
                    || self
                        .con
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM reputation_overrides WHERE package=?)",
                            [p],
                            |r| r.get::<_, bool>(0),
                        )
                        .unwrap_or(false)
            }),
            blacklisted: black.is_some(),
            blacklist_severity: black.as_ref().map(|v| v.1).unwrap_or(50),
            reason: black.map(|v| v.0).or(white).unwrap_or_default(),
        })
    }
    pub fn set_reputation(&self, p: &str, label: &str, kind: &str, reason: &str) -> Result<()> {
        match kind {
            "whitelist" => {
                self.con
                    .execute(
                        "INSERT OR REPLACE INTO whitelist(package,label,reason) VALUES(?,?,?)",
                        params![p, label, reason],
                    )
                    .map_err(err)?;
            }
            "blacklist" => {
                self.con.execute("INSERT OR REPLACE INTO blacklist(package,label,reason,severity) VALUES(?,?,?,70)",params![p,label,reason]).map_err(err)?;
            }
            _ => return Err("Liste inconnue".into()),
        };
        self.con
            .execute(
                "INSERT OR IGNORE INTO reputation_overrides(package) VALUES(?)",
                [p],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn note(&self, p: &str) -> Result<String> {
        Ok(self
            .con
            .query_row(
                "SELECT COALESCE(note,'') FROM app_notes WHERE package=?",
                [p],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?
            .unwrap_or_default())
    }
    pub fn set_note(&self, p: &str, note: &str) -> Result<()> {
        self.con
            .execute(
                "INSERT OR REPLACE INTO app_notes(package,note,updated_at) VALUES(?,?,?)",
                params![p, note.trim(), chrono::Utc::now().to_rfc3339()],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn record(&mut self, scan: &mut Scan) -> Result<()> {
        if scan.cancelled || scan.demo {
            return Err("Un scan incomplet ou fictif ne peut pas être enregistré".into());
        }
        let tx = self.con.transaction().map_err(err)?;
        tx.execute("INSERT INTO scan_history(date,device_model,android_version,scanned_count,suspicious_count,device_key) VALUES(?,?,?,?,?,?)",params![chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string(),scan.device.model,scan.device.android_version,scan.rows.len(),scan.rows.iter().filter(|r|r.risk.recommended_action=="suggest_uninstall"&&!r.app.is_system_app).count(),device_key(&scan.device.serial,&scan.device.model)]).map_err(err)?;
        let id = tx.last_insert_rowid();
        for r in &scan.rows {
            tx.execute("INSERT INTO scan_apps(scan_id,package,app_label,score,category,action,validation_status) VALUES(?,?,?,?,?,?,?)",params![id,r.app.package_name,r.app.display_name(),r.risk.score,r.risk.category,r.risk.recommended_action,"unreviewed"]).map_err(err)?;
        }
        scan.scan_id = Some(id);
        let mut saved = scan.clone();
        saved.device.serial.clear();
        tx.execute(
            "INSERT INTO scan_payloads(scan_id,payload) VALUES(?,?)",
            params![
                id,
                serde_json::to_string(&saved).map_err(|e| e.to_string())?
            ],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        scan.comparison = Some(self.comparison(id)?);
        Ok(())
    }
    pub fn persist_analysis(&mut self, scan: &Scan) -> Result<()> {
        let Some(id) = scan.scan_id else {
            return Ok(());
        };
        let tx = self.con.transaction().map_err(err)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT payload FROM scan_payloads WHERE scan_id=?",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(payload) = previous {
            let old_version = serde_json::from_str::<serde_json::Value>(&payload)
                .ok()
                .and_then(|v| v["rules_version"].as_u64())
                .unwrap_or(0);
            if old_version != u64::from(scan.rules_version) {
                tx.execute(
                    "INSERT INTO analysis_revisions(scan_id,payload,archived_at) VALUES(?,?,?)",
                    params![id, payload, chrono::Utc::now().to_rfc3339()],
                )
                .map_err(err)?;
            }
        }
        for r in &scan.rows {
            tx.execute(
                "UPDATE scan_apps SET score=?,category=?,action=? WHERE scan_id=? AND package=?",
                params![
                    r.risk.score,
                    r.risk.category,
                    r.risk.recommended_action,
                    id,
                    r.app.package_name
                ],
            )
            .map_err(err)?;
        }
        tx.execute("UPDATE scan_history SET suspicious_count=(SELECT count(*) FROM scan_apps WHERE scan_id=? AND action='suggest_uninstall') WHERE id=?",params![id,id]).map_err(err)?;
        let mut saved = scan.clone();
        saved.device.serial.clear();
        tx.execute(
            "INSERT OR REPLACE INTO scan_payloads(scan_id,payload) VALUES(?,?)",
            params![
                id,
                serde_json::to_string(&saved).map_err(|e| e.to_string())?
            ],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(())
    }
    pub fn validation(&self, id: i64, p: &str) -> Result<String> {
        Ok(self
            .con
            .query_row(
                "SELECT COALESCE(v.status,a.validation_status) FROM scan_apps a LEFT JOIN app_validations v ON v.scan_id=a.scan_id AND v.package=a.package WHERE a.scan_id=? AND a.package=?",
                params![id, p],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?
            .unwrap_or_else(|| "unreviewed".into()))
    }
    pub fn set_validation(&mut self, id: i64, p: &str, status: &str) -> Result<()> {
        if !["unreviewed", "keep", "review", "remove", "removed"].contains(&status) {
            return Err("Validation inconnue".into());
        }
        let tx = self.con.transaction().map_err(err)?;
        if tx
            .execute(
                "UPDATE scan_apps SET validation_status=? WHERE scan_id=? AND package=?",
                params![status, id, p],
            )
            .map_err(err)?
            != 1
        {
            return Err("Application absente de ce scan".into());
        }
        tx.execute("INSERT OR REPLACE INTO app_validations(scan_id,package,status,updated_at) VALUES(?,?,?,?)",params![id,p,status,chrono::Utc::now().to_rfc3339()]).map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(())
    }
    pub fn record_uninstall(&self, r: &UninstallResult) -> Result<()> {
        self.con
            .execute(
                "INSERT INTO uninstall_history(date,package,app_label,result) VALUES(?,?,?,?)",
                params![
                    chrono::Utc::now().to_rfc3339(),
                    r.package,
                    r.label,
                    r.result
                ],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn snapshots(&self, id: i64) -> Result<BTreeMap<String, Snapshot>> {
        let mut s=self.con.prepare("SELECT package,COALESCE(app_label,package),score,COALESCE(category,''),COALESCE(action,''),validation_status FROM scan_apps WHERE scan_id=? ORDER BY package").map_err(err)?;
        let rows = s
            .query_map([id], |r| {
                Ok(Snapshot {
                    package: r.get(0)?,
                    app_label: r.get(1)?,
                    score: r.get(2)?,
                    category: r.get(3)?,
                    action: r.get(4)?,
                    validation_status: r.get(5)?,
                })
            })
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(rows.into_iter().map(|v| (v.package.clone(), v)).collect())
    }
    pub fn comparison(&self, id: i64) -> Result<Comparison> {
        let key: Option<String> = self
            .con
            .query_row(
                "SELECT device_key FROM scan_history WHERE id=?",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        // Old scans without an identity cannot safely be compared across customers.
        let prev = if let Some(key) = key.filter(|k| !k.is_empty()) {
            self.con.query_row("SELECT id FROM scan_history WHERE device_key=? AND id<? ORDER BY id DESC LIMIT 1",params![key,id],|r|r.get::<_,i64>(0)).optional().map_err(err)?
        } else {
            None
        };
        let now = self.snapshots(id)?;
        let old = match prev {
            Some(p) => self.snapshots(p)?,
            None => BTreeMap::new(),
        };
        let mut c = Comparison {
            current_scan_id: id,
            previous_scan_id: prev,
            ..Default::default()
        };
        for (p, n) in &now {
            if let Some(o) = old.get(p) {
                if o.score != n.score || o.action != n.action {
                    c.risk_changes.push(RiskChange {
                        package: p.clone(),
                        app_label: n.app_label.clone(),
                        previous_score: o.score,
                        current_score: n.score,
                        previous_action: o.action.clone(),
                        current_action: n.action.clone(),
                    });
                } else {
                    c.unchanged_count += 1;
                }
            } else {
                c.new_apps.push(n.clone());
            }
        }
        c.removed_apps = old
            .into_iter()
            .filter(|(p, _)| !now.contains_key(p))
            .map(|(_, v)| v)
            .collect();
        Ok(c)
    }
    pub fn history(&self) -> Result<Vec<serde_json::Value>> {
        let mut s=self.con.prepare("SELECT id,date,device_model,android_version,scanned_count,suspicious_count FROM scan_history ORDER BY id DESC LIMIT 100").map_err(err)?;
        let v=s.query_map([],|r|Ok(serde_json::json!({"id":r.get::<_,i64>(0)?,"date":r.get::<_,String>(1)?,"device_model":r.get::<_,String>(2)?,"android_version":r.get::<_,String>(3)?,"scanned_count":r.get::<_,i64>(4)?,"suspicious_count":r.get::<_,i64>(5)?}))).map_err(err)?.collect::<std::result::Result<Vec<_>,_>>().map_err(err)?;
        Ok(v)
    }
    pub fn load(&self, id: i64) -> Result<Scan> {
        let payload: Option<String> = self
            .con
            .query_row(
                "SELECT payload FROM scan_payloads WHERE scan_id=?",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let mut scan = if let Some(p) = payload {
            serde_json::from_str(&p).map_err(|e| e.to_string())?
        } else {
            let device = self
                .con
                .query_row(
                    "SELECT device_model,android_version FROM scan_history WHERE id=?",
                    [id],
                    |r| {
                        Ok(Device {
                            model: r.get(0)?,
                            android_version: r.get(1)?,
                            state: "historical".into(),
                            ..Default::default()
                        })
                    },
                )
                .map_err(err)?;
            let rows = self.snapshots(id)?.into_values().map(|s| {
                let risk = Risk { score: s.score, category: s.category, recommended_action: s.action, reasons: vec!["Ancien snapshot : les métadonnées détaillées n'étaient pas conservées.".into()] };
                Row { app: AppInfo { package_name: s.package, app_label: s.app_label, dumpsys_error: "Ancien snapshot : métadonnées détaillées non conservées".into(), ..Default::default() }, local_risk: risk.clone(), risk, ai: None, ai_text: String::new(), note: String::new(), validation: s.validation_status }
            }).collect();
            Scan {
                device,
                rows,
                scan_id: Some(id),
                ..Default::default()
            }
        };
        for row in &mut scan.rows {
            row.validation = self.validation(id, &row.app.package_name)?;
            row.note = self.note(&row.app.package_name)?;
        }
        scan.device.serial.clear();
        scan.device.state = "historical".into();
        scan.comparison = Some(self.comparison(id)?);
        Ok(scan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_v2_validations_do_not_propagate() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("db.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("PRAGMA user_version=2;
        CREATE TABLE scan_history(id INTEGER PRIMARY KEY,date TEXT,device_model TEXT,android_version TEXT,scanned_count INTEGER,suspicious_count INTEGER,device_key TEXT NOT NULL DEFAULT '');
        CREATE TABLE scan_apps(scan_id INTEGER NOT NULL,package TEXT NOT NULL,app_label TEXT,score INTEGER NOT NULL,category TEXT,action TEXT,validation_status TEXT NOT NULL DEFAULT 'unreviewed',PRIMARY KEY(scan_id,package));
        CREATE TABLE app_validations(package TEXT PRIMARY KEY,status TEXT NOT NULL,updated_at TEXT NOT NULL);
        INSERT INTO scan_history VALUES(1,'2026','A','14',1,1,'a'); INSERT INTO scan_history VALUES(2,'2026','B','14',1,1,'b');
        INSERT INTO scan_apps VALUES(1,'com.example.app','Example',70,'test','suggest_uninstall','remove');
        INSERT INTO scan_apps VALUES(2,'com.example.app','Example',70,'test','suggest_uninstall','unreviewed');
        INSERT INTO app_validations VALUES('com.example.app','remove','2026');").unwrap();
        }
        let backup = Database::initialize(&path).unwrap().unwrap();
        assert!(backup.exists());
        let mut db = Database::open(&path).unwrap();
        assert_eq!(db.validation(1, "com.example.app").unwrap(), "remove");
        assert_eq!(db.validation(2, "com.example.app").unwrap(), "unreviewed");
        db.set_note("com.example.app", "Note de test").unwrap();
        assert_eq!(db.note("com.example.app").unwrap(), "Note de test");
        let mut scan = db.load(1).unwrap();
        scan.rows[0].risk.score = 85;
        db.persist_analysis(&scan).unwrap();
        assert_eq!(db.validation(1, "com.example.app").unwrap(), "remove");
        assert_eq!(db.snapshots(2).unwrap()["com.example.app"].score, 70);
    }
    fn row(p: &str, score: i32) -> Row {
        let a = AppInfo {
            package_name: p.into(),
            ..Default::default()
        };
        let risk = Risk {
            score,
            category: "test".into(),
            recommended_action: "review".into(),
            reasons: vec![],
        };
        Row {
            app: a,
            risk: risk.clone(),
            local_risk: risk,
            ai: None,
            ai_text: String::new(),
            note: String::new(),
            validation: "unreviewed".into(),
        }
    }
    #[test]
    fn scans_are_atomic_and_validations_scoped() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("db.sqlite");
        Database::initialize(&path).unwrap();
        let mut db = Database::open(&path).unwrap();
        assert!(!db.reputation("com.whatsapp").unwrap().whitelisted);
        db.set_reputation(
            "com.whatsapp",
            "WhatsApp",
            "whitelist",
            "Application courante connue",
        )
        .unwrap();
        assert!(db.reputation("com.whatsapp").unwrap().whitelisted);
        let mut a = Scan {
            device: Device {
                serial: "A".into(),
                ..Default::default()
            },
            rows: vec![row("test.one", 70)],
            ..Default::default()
        };
        db.record(&mut a).unwrap();
        db.set_validation(a.scan_id.unwrap(), "test.one", "remove")
            .unwrap();
        let mut b = a.clone();
        b.rows.push(row("test.two", 0));
        db.record(&mut b).unwrap();
        assert_eq!(
            db.validation(b.scan_id.unwrap(), "test.one").unwrap(),
            "unreviewed"
        );
        assert_eq!(b.comparison.as_ref().unwrap().new_apps.len(), 1);
        assert_eq!(b.comparison.as_ref().unwrap().unchanged_count, 1);
        let mut other = b.clone();
        other.device.serial = "B".into();
        db.record(&mut other).unwrap();
        assert!(other.comparison.unwrap().previous_scan_id.is_none());
        b.cancelled = true;
        assert!(db.record(&mut b).is_err());
        assert!(db
            .load(a.scan_id.unwrap())
            .unwrap()
            .device
            .serial
            .is_empty());
    }
    #[test]
    fn new_rules_archive_the_old_payload_and_preserve_validation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("db.sqlite");
        Database::initialize(&path).unwrap();
        let mut db = Database::open(&path).unwrap();
        let mut scan = Scan {
            rows: vec![row("org.test.reader", 68)],
            ..Default::default()
        };
        db.record(&mut scan).unwrap();
        let id = scan.scan_id.unwrap();
        db.set_validation(id, "org.test.reader", "keep").unwrap();
        let mut updated = db.load(id).unwrap();
        updated.rules_version = crate::evidence::RULES_VERSION;
        updated.rows[0].risk.score = 10;
        updated.rows[0].risk.recommended_action = "keep".into();
        db.persist_analysis(&updated).unwrap();
        let old: String = db
            .con
            .query_row(
                "SELECT payload FROM analysis_revisions WHERE scan_id=?",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        let old: Scan = serde_json::from_str(&old).unwrap();
        assert_eq!(old.rows[0].risk.score, 68);
        let loaded = db.load(id).unwrap();
        assert_eq!(loaded.rows[0].risk.score, 10);
        assert_eq!(loaded.rows[0].validation, "keep");
        assert_eq!(loaded.rules_version, crate::evidence::RULES_VERSION);
        assert_eq!(db.history().unwrap()[0]["suspicious_count"], 0);
        db.persist_analysis(&loaded).unwrap();
        assert_eq!(
            db.con
                .query_row("SELECT COUNT(*) FROM analysis_revisions", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn legacy_migration_backs_up_and_preserves_data() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("db.sqlite");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE scan_history(id INTEGER PRIMARY KEY,date TEXT,device_model TEXT,android_version TEXT,scanned_count INTEGER,suspicious_count INTEGER); INSERT INTO scan_history VALUES(1,'2026','Phone','14',1,0); PRAGMA user_version=1;").unwrap();
        }
        let backup = Database::initialize(&path).unwrap().unwrap();
        assert!(backup.is_file());
        let db = Database::open(&path).unwrap();
        assert_eq!(db.history().unwrap().len(), 1);
        assert_eq!(
            db.con
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i32>(0))
                .unwrap(),
            4
        );
        assert!(Database::initialize(&path).unwrap().is_none());
    }
}
