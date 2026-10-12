//! 仅测试 launcher 消费父显式提供的来源记录；不认证 app controller，也不改正常 helper。

use crate::helper::rust_budget::source::BuildEvidence;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    schema_version: u32,
    recipe_sha256: String,
    upstream_root: PathBuf,
    actual_git_head_baseline: String,
    sources: serde_json::Value,
    compiler: Compiler,
    compiler_verbose_version: String,
    target: String,
    actual_target_cfg: serde_json::Value,
    dependencies: Vec<Dependency>,
    embedded_build_evidence: BTreeMap<String, String>,
    inherited_compiler_flags: serde_json::Value,
    artifact: Artifact,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Compiler {
    full_commit: String,
    release: String,
    host: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Dependency {
    name: String,
    version: String,
    enabled_features: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
    features: Vec<String>,
    profile: serde_json::Value,
}

struct HeldFile {
    file: File,
    digest: String,
    size: u64,
}

fn held_file(path: &Path) -> HeldFile {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // 源码、record 与 exe 在 child 生存及 drain 期间不可写入或替换。
        options.share_mode(1);
    }
    let mut file = options.open(path).expect("受信来源文件不可读取");
    let size = file.metadata().unwrap().len();
    let digest = hash(&mut file);
    HeldFile { file, digest, size }
}

fn hash(file: &mut File) -> String {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    format!("{:x}", digest.finalize())
}

pub struct Candidate {
    record: Record,
    files: Vec<HeldFile>,
    executable_file: usize,
    pub record_digest: String,
}

impl Candidate {
    pub fn load() -> Self {
        let path = std::env::var_os("RSHELL_HELPER_NORMAL_TEST_RECORD")
            .expect("normal-v2 验收必须由父显式提供 actual artifact record；不能使用 Cargo shadow 或自填证据");
        let path = PathBuf::from(path);
        assert!(path.is_absolute());
        let mut record_file = held_file(&path);
        let record_digest = record_file.digest.clone();
        record_file.file.seek(SeekFrom::Start(0)).unwrap();
        let record: Record = serde_json::from_reader(&record_file.file).unwrap();
        assert_eq!(record.schema_version, 1);
        let mut recipe_file = held_file(&path.parent().unwrap().join("build_recipe.json"));
        assert!(recipe_file.digest == record.recipe_sha256);
        recipe_file.file.seek(SeekFrom::Start(0)).unwrap();
        let recipe: serde_json::Value = serde_json::from_reader(&recipe_file.file).unwrap();
        assert!(recipe["sources"] == record.sources);
        assert!(
            recipe["embeddedBuildEvidence"]
                == serde_json::to_value(&record.embedded_build_evidence).unwrap()
        );
        assert!(
            recipe["actualGitHeadBaseline"].as_str()
                == Some(record.actual_git_head_baseline.as_str())
        );
        assert!(recipe["target"].as_str() == Some(record.target.as_str()));
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        assert!(record.upstream_root.canonicalize().unwrap() == root);
        assert!(
            Path::new(recipe["upstreamRoot"].as_str().unwrap())
                .canonicalize()
                .unwrap()
                == root
        );
        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(head.status.success());
        assert!(
            std::str::from_utf8(&head.stdout).unwrap().trim() == record.actual_git_head_baseline
        );
        assert!(!record.artifact.profile["test"].as_bool().unwrap());
        assert_eq!(record.artifact.profile["opt_level"], "0");
        assert_eq!(record.artifact.profile["debuginfo"], 2);
        assert_eq!(record.artifact.profile["debug_assertions"], true);
        assert_eq!(record.artifact.profile["overflow_checks"], true);
        assert!(record.artifact.features.is_empty());
        let cfg = &record.actual_target_cfg;
        for (name, value) in [
            ("target_arch", "x86_64"),
            ("target_os", "windows"),
            ("target_env", "msvc"),
            ("target_vendor", "pc"),
            ("target_pointer_width", "64"),
            ("target_endian", "little"),
            ("panic", "unwind"),
        ] {
            assert_eq!(cfg["values"][name], value);
        }
        assert!(
            !cfg["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flag| flag == "test")
        );
        for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
            assert!(record.inherited_compiler_flags.get(name).unwrap().is_null());
            assert!(
                recipe["inheritedCompilerFlags"]
                    .get(name)
                    .unwrap()
                    .is_null()
            );
        }
        let env = &record.embedded_build_evidence;
        assert_eq!(env.len(), 7);
        let value = |key: &str| env.get(key).unwrap().as_str();
        assert!(value("RSHELL_HELPER_BUILD_COMPILER_COMMIT") == record.compiler.full_commit);
        assert!(value("RSHELL_HELPER_BUILD_COMPILER_RELEASE") == record.compiler.release);
        assert!(value("RSHELL_HELPER_BUILD_TARGET") == record.target);
        assert!(record.compiler.host == record.target);
        for (prefix, expected) in [
            ("commit-hash: ", record.compiler.full_commit.as_str()),
            ("release: ", record.compiler.release.as_str()),
            ("host: ", record.compiler.host.as_str()),
        ] {
            assert!(
                record
                    .compiler_verbose_version
                    .lines()
                    .find_map(|line| line.strip_prefix(prefix))
                    == Some(expected)
            );
        }
        assert_eq!(value("RSHELL_HELPER_BUILD_CFG"), "normal");
        assert_eq!(value("RSHELL_HELPER_BUILD_ENVIRONMENT"), "inherited");
        assert_eq!(value("RSHELL_HELPER_BUILD_STDIO"), "synchronous-pipes");
        assert_eq!(record.dependencies.len(), 3);
        let mut dependency_names = BTreeSet::new();
        let mut features = Vec::new();
        for name in ["rusqlite", "libsqlite3-sys", "uuid"] {
            let dependency = record.dependencies.iter().find(|d| d.name == name).unwrap();
            assert!(dependency_names.insert(&dependency.name));
            assert!(
                dependency
                    .enabled_features
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            features.push(format!(
                "{}={}:{}",
                name,
                dependency.version,
                dependency.enabled_features.join(",")
            ));
        }
        assert!(features.join(";") == value("RSHELL_HELPER_BUILD_RESOLVED_FEATURES"));
        let mut files = vec![record_file, recipe_file];
        let mut previous = None;
        let mut canonical = Sha256::new();
        let mut paths = BTreeSet::new();
        for source in record.sources["files"].as_array().unwrap() {
            let relative = source["relativePath"].as_str().unwrap();
            assert!(previous.is_none_or(|previous| previous < relative));
            previous = Some(relative);
            assert!(paths.insert(relative));
            let relative_path = Path::new(relative);
            assert!(
                relative_path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
            );
            assert!(
                matches!(
                    relative,
                    "Cargo.toml" | "Cargo.lock" | "crates/rshell-storage/Cargo.toml"
                ) || (relative.starts_with("crates/rshell-storage/src/")
                    && relative.ends_with(".rs"))
            );
            let actual = root.join(relative).canonicalize().unwrap();
            assert!(actual.starts_with(&root));
            let file = held_file(&actual);
            assert!(source["sha256"].as_str() == Some(file.digest.as_str()));
            assert_eq!(source["sizeBytes"].as_u64().unwrap(), file.size);
            canonical.update(format!("{relative}\n{}\n{}\n", file.digest, file.size));
            if relative == "Cargo.lock" {
                assert!(
                    record.sources["cargoLock"]["sha256"].as_str() == Some(file.digest.as_str())
                );
                assert_eq!(
                    record.sources["cargoLock"]["sizeBytes"].as_u64().unwrap(),
                    file.size
                );
            }
            files.push(file);
        }
        for required in [
            "Cargo.toml",
            "Cargo.lock",
            "crates/rshell-storage/Cargo.toml",
            "crates/rshell-storage/src/bin/selected-read-helper.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/mod.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/normal_v2.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/producer.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/preflight.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/envelope.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/production_protocol.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/protocol.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/rust_budget/mod.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/rust_budget/source.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/rust_budget/launch.rs",
            "crates/rshell-storage/src/bin/selected_read_helper/rust_budget/capacity.rs",
        ] {
            assert!(paths.contains(required));
        }
        assert!(
            format!("{:x}", canonical.finalize())
                == record.sources["sourceFilesSha256"].as_str().unwrap()
        );
        let expected = path
            .parent()
            .unwrap()
            .join("cargo/x86_64-pc-windows-msvc/debug/selected-read-helper.exe")
            .canonicalize()
            .unwrap();
        assert!(record.artifact.path.is_absolute());
        assert!(record.artifact.path.canonicalize().unwrap() == expected);
        let file = held_file(&record.artifact.path);
        assert!(file.digest == record.artifact.sha256);
        assert_eq!(file.size, record.artifact.size_bytes);
        let executable_file = files.len();
        files.push(file);
        let candidate = Self {
            record,
            files,
            executable_file,
            record_digest,
        };
        candidate.evidence().verify_artifact().unwrap();
        candidate
    }

    pub fn executable(&self) -> &Path {
        &self.record.artifact.path
    }
    pub fn executable_digest(&self) -> &str {
        &self.record.artifact.sha256
    }
    pub fn source_digest(&self) -> &str {
        self.record.sources["sourceFilesSha256"].as_str().unwrap()
    }
    pub fn evidence(&self) -> BuildEvidence<'_> {
        let env = &self.record.embedded_build_evidence;
        BuildEvidence {
            compiler_commit: &env["RSHELL_HELPER_BUILD_COMPILER_COMMIT"],
            release: &env["RSHELL_HELPER_BUILD_COMPILER_RELEASE"],
            target: &env["RSHELL_HELPER_BUILD_TARGET"],
            sqlite_features: &env["RSHELL_HELPER_BUILD_RESOLVED_FEATURES"],
            normal_helper_cfg: env["RSHELL_HELPER_BUILD_CFG"] == "normal",
            inherited_environment: env["RSHELL_HELPER_BUILD_ENVIRONMENT"] == "inherited",
            synchronous_pipe_handles: env["RSHELL_HELPER_BUILD_STDIO"] == "synchronous-pipes",
        }
    }
    pub fn verify_unchanged(&mut self) {
        for held in &mut self.files {
            assert_eq!(held.file.metadata().unwrap().len(), held.size);
            assert!(hash(&mut held.file) == held.digest);
        }
        assert!(self.files[self.executable_file].digest == self.record.artifact.sha256);
    }
}

/// 仅证明 fixture caller 在 spawn 前实际占额；不是生产 controller ledger。
pub struct Ledger {
    limit: usize,
    held: AtomicUsize,
}
impl Ledger {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            held: AtomicUsize::new(0),
        })
    }
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Grant> {
        self.held
            .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .ok()?;
        Some(Grant {
            ledger: Arc::clone(self),
            bytes,
        })
    }
}
pub struct Grant {
    ledger: Arc<Ledger>,
    bytes: usize,
}
impl Drop for Grant {
    fn drop(&mut self) {
        assert!(self.ledger.held.fetch_sub(self.bytes, Ordering::AcqRel) >= self.bytes);
    }
}
