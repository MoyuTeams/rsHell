use rusqlite::{Connection, params};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

pub const CONNECTION: &str = "00000000-0000-0000-0000-000000000010";
pub const REFERENCED: &str = "00000000-0000-0000-0000-000000000002";
pub const EXPLICIT: &str = "00000000-0000-0000-0000-000000000003";

pub struct Fixture {
    pub dir: TempDir,
    pub path: PathBuf,
}
impl Fixture {
    pub fn new(page: u32, encoding: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.sqlite");
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
        db.execute(
            "UPDATE terminal_profiles SET name='默认',settings_json='{}'",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE app_settings SET color_scheme='',key_bindings_json='{}'",
            [],
        )
        .unwrap();
        for (id, name) in [(REFERENCED, "引用"), (EXPLICIT, "显式")] {
            db.execute(
                "INSERT INTO terminal_profiles VALUES(?1,?2,'{}')",
                params![id, name],
            )
            .unwrap();
        }
        db.execute("INSERT INTO connections VALUES(?1,NULL,'示例','host',22,'user','ssh','password',NULL,NULL,'strict',NULL,?2,0,?3,'{}')",params![CONNECTION,"甲\0乙😀",REFERENCED]).unwrap();
        db.execute(
            "INSERT INTO connection_tags VALUES(?1,?2)",
            params![CONNECTION, "标签\0尾"],
        )
        .unwrap();
        db.execute("UPDATE configuration_revision SET revision=7", [])
            .unwrap();
        db.close().unwrap();
        Self { dir, path }
    }
    pub fn open(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
    pub fn bytes(&self) -> Vec<u8> {
        fs::read(&self.path).unwrap()
    }
    pub fn sidecars(&self) -> Vec<String> {
        let mut names = fs::read_dir(self.dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }
    pub fn logical(&self) -> (i64, String, String) {
        let db = self.open();
        (
            db.query_row("SELECT revision FROM configuration_revision", [], |r| {
                r.get(0)
            })
            .unwrap(),
            db.query_row(
                "SELECT hex(note) FROM connections WHERE id=?1",
                [CONNECTION],
                |r| r.get(0),
            )
            .unwrap(),
            db.query_row(
                "SELECT hex(tag) FROM connection_tags WHERE connection_id=?1",
                [CONNECTION],
                |r| r.get(0),
            )
            .unwrap(),
        )
    }
    pub fn unrelated(&self) {
        let mut db = self.open();
        let tx = db.transaction().unwrap();
        for i in 100..2100 {
            let id = uuid::Uuid::from_u128(i).to_string();
            tx.execute("INSERT INTO connections SELECT ?1,NULL,'unrelated','other',22,'user','ssh','password',NULL,NULL,'strict',NULL,'note',0,NULL,'{}'",[id]).unwrap();
        }
        tx.execute(
            "INSERT INTO terminal_profiles VALUES('unrelated','large',?1)",
            ["x".repeat(17 * 1024 * 1024)],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    pub fn giant_tag(&self) {
        let db = self.open();
        db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        db.execute(
            "INSERT INTO connection_tags VALUES(?1,?2)",
            params![
                "00000000-0000-0000-0000-000000000009",
                "x".repeat(16 * 1024 * 1024)
            ],
        )
        .unwrap();
    }
    pub fn large_schema(&self, n: usize) {
        let mut db = self.open();
        let tx = db.transaction().unwrap();
        for i in 0..n {
            tx.execute_batch(&format!("CREATE TABLE extra_{i}(a TEXT,b TEXT,c TEXT,d TEXT,e TEXT,f TEXT,g TEXT,h TEXT,i TEXT,j TEXT,k TEXT,l TEXT,m TEXT,n TEXT,o TEXT,p TEXT,q TEXT,r TEXT,s TEXT,t TEXT);")).unwrap();
        }
        tx.commit().unwrap();
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
