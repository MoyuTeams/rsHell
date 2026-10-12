use rshell_core::{KeyBinding, KeyCode, KeyModifiers, TerminalSettingsV1};
use rusqlite::{Connection, params};
use std::{fs, path::PathBuf};
use tempfile::TempDir;

pub const CONNECTION: &str = "abcdefab-cdef-abcd-efab-cdefabcdef10";
pub const GROUP: &str = "abcdefab-cdef-abcd-efab-cdefabcdef04";
pub const REFERENCED: &str = "00000000-0000-0000-0000-000000000002";
pub const EXPLICIT: &str = "00000000-0000-0000-0000-000000000003";

pub struct Fixture {
    pub directory: TempDir,
    pub path: PathBuf,
}

impl Fixture {
    pub fn new(page: u32, encoding: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("raw 汉字😀.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(&format!(
            "PRAGMA page_size={page}; PRAGMA encoding='{encoding}';"
        ))
        .unwrap();
        db.execute_batch(include_str!("../../migrations/0001_initial.sql"))
            .unwrap();
        db.execute_batch(include_str!(
            "../../migrations/0003_configuration_revision.sql"
        ))
        .unwrap();
        let binding = KeyBinding {
            code: KeyCode::F(6),
            modifiers: KeyModifiers {
                control: true,
                ..KeyModifiers::default()
            },
            action: "new_tab".into(),
        };
        let settings = TerminalSettingsV1 {
            terminal_type: "  screen-256color  ".into(),
            font_family: "  Cascadia Mono  ".into(),
            key_bindings: vec![binding.clone()],
            extensions: std::collections::BTreeMap::from([
                (
                    "future.namespace".into(),
                    serde_json::json!({"version":99,"values":[null,true,"甲\0乙😀",{"nested":[1,2,3]}]}),
                ),
                (
                    "second".into(),
                    serde_json::json!({"opaque":{"not_known":"保留"}}),
                ),
            ]),
            ..TerminalSettingsV1::default()
        };
        let json = serde_json::to_string_pretty(&settings).unwrap();
        db.execute(
            "UPDATE terminal_profiles SET name='默认',settings_json=?1",
            [&json],
        )
        .unwrap();
        for (id, name) in [(REFERENCED, "引用"), (EXPLICIT, "显式")] {
            db.execute(
                "INSERT INTO terminal_profiles VALUES(?1,?2,?3)",
                params![id, name, json],
            )
            .unwrap();
        }
        db.execute(
            "UPDATE app_settings SET color_scheme='nord',key_bindings_json=?1",
            [serde_json::json!({"version":1,"key_bindings":[binding],"future_app":{"namespace":"保留","nested":[0,false,null]}}).to_string()],
        )
        .unwrap();
        db.execute("INSERT INTO connections VALUES(?1,NULL,?5,'example.invalid',65535,'','native_ssh','password',NULL,NULL,'strict','',?2,0,?3,?4)",
            params![CONNECTION, "甲\0乙😀SHSELFD2SHSELFN2", REFERENCED,
                r#"{ "version": 1, "initial_cols": 132, "answerback": "\u0000尾", "future_override": {"v": 9} }"#,
                "示例\0尾"]).unwrap();
        for tag in ["z", "", "标签\0尾", "a", "😀"] {
            db.execute(
                "INSERT INTO connection_tags VALUES(?1,?2)",
                params![CONNECTION, tag],
            )
            .unwrap();
        }
        db.execute("UPDATE configuration_revision SET revision=7", [])
            .unwrap();
        db.close().unwrap();
        Self { directory, path }
    }

    pub fn open(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }

    pub fn group(&self, stored: &str, reference: &str) {
        let db = self.open();
        // 旧 reader 按二进制 UUID 解释 alias；SQLite FK 仅按原始文本比较。
        db.pragma_update(None, "foreign_keys", false).unwrap();
        db.execute(
            "INSERT INTO connection_groups VALUES(?1,NULL,'分组',0)",
            [stored],
        )
        .unwrap();
        db.execute(
            "UPDATE connections SET group_id=?1 WHERE id=?2",
            params![reference, CONNECTION],
        )
        .unwrap();
    }

    pub fn bytes(&self) -> Vec<u8> {
        fs::read(&self.path).unwrap()
    }

    pub fn sidecars(&self) -> Vec<std::ffi::OsString> {
        let mut names: Vec<_> = fs::read_dir(self.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    }

    pub fn unrelated(&self) {
        let mut db = self.open();
        let tx = db.transaction().unwrap();
        for n in 100..2100 {
            tx.execute("INSERT INTO connections SELECT ?1,NULL,'无关','unrelated.invalid',22,'','native_ssh','agent',NULL,NULL,'strict',NULL,'',0,NULL,'{\"version\":1}'",
                [uuid::Uuid::from_u128(n).to_string()]).unwrap();
        }
        tx.execute(
            "INSERT INTO terminal_profiles VALUES(?1,'无关',?2)",
            params![
                uuid::Uuid::from_u128(4096).to_string(),
                "x".repeat(17 * 1024 * 1024)
            ],
        )
        .unwrap();
        tx.commit().unwrap();
    }
}
