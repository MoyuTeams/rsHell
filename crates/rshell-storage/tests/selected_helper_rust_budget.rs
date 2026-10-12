//! 精确 W1-H target；只消费新模型与生产 codec，不 include 三份受保护资产。

#[path = "../src/bin/selected_read_helper/production_protocol.rs"]
pub mod production_protocol;
#[path = "../src/bin/selected_read_helper/rust_budget/mod.rs"]
pub mod rust_budget;

#[cfg(all(target_os = "windows", target_env = "msvc", target_arch = "x86_64"))]
mod actual_msvc {
    use super::{production_protocol, rust_budget};
    use rust_budget::{source::*, *};
    use std::{ffi::OsStr, process::Command};

    fn build() -> VerifiedBuild {
        let output = Command::new("rustc")
            .env("RUSTUP_AUTO_INSTALL", "0")
            .arg("-vV")
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = std::str::from_utf8(&output.stdout).unwrap();
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap()
        };
        BuildEvidence {
            compiler_commit: field("commit-hash: "),
            release: field("release: "),
            target: field("host: "),
            sqlite_features: SQLITE_FEATURES,
            normal_helper_cfg: true,
            inherited_environment: true,
            synchronous_pipe_handles: true,
        }
        .verify()
        .unwrap()
    }

    fn certificate(executable: &OsStr, database: &OsStr, route: SqlRoute) -> HelperRustCertificate {
        HelperRustCertificate::calculate(
            build(),
            HelperLaunchShape::from_paths(executable, database).unwrap(),
            FixedLimits::default(),
            route,
        )
        .unwrap()
    }

    fn request(
        certificate: HelperRustCertificate,
        grant: u64,
    ) -> production_protocol::WireValidatedRequest {
        production_protocol::Request {
            c_max: certificate.c_backing().size() as u64,
            field_max: 65536,
            total_max: 1048576,
            tags_max: 256,
            connection: Some([1; 16]),
            profile: None,
            wire_max: production_protocol::wire_upper(278, 1048576, 10).unwrap(),
            helper_rust_max: grant,
            frame_count_max: 278,
            nonce: [7; 16],
        }
        .validate()
        .unwrap()
    }

    #[test]
    fn exact_compiler_public_layouts_and_private_source_upper() {
        let certificate = certificate(
            OsStr::new(r"C:\trusted\selected-read-helper.exe"),
            OsStr::new(r"C:\catalog\selected.sqlite"),
            SqlRoute::LegacyBuilder,
        );
        let layouts = certificate.layouts();
        assert_eq!(layouts, PublicLayouts::current().unwrap());
        assert_eq!(
            (layouts.os_string.size(), layouts.os_string.align()),
            (32, 8)
        );
        assert_eq!((layouts.path_buf.size(), layouts.path_buf.align()), (32, 8));
        assert_eq!((layouts.c_string.size(), layouts.c_string.align()), (16, 8));
        assert_eq!((layouts.string.size(), layouts.string.align()), (24, 8));
        assert_eq!(
            (
                layouts.reader_buffer_control_upper.size(),
                layouts.reader_buffer_control_upper.align()
            ),
            (40, 8)
        );
        assert_eq!(certificate.costs().stdio_globals, 13312);
        assert_eq!(
            (
                layouts.wtf8_control_upper.size(),
                layouts.wtf8_control_upper.align()
            ),
            (32, 8)
        );
        assert_eq!(
            (
                layouts.instantiated_reader.size(),
                layouts.instantiated_reader.align()
            ),
            (40, 8)
        );
        assert_eq!(
            (
                layouts.instantiated_writer.size(),
                layouts.instantiated_writer.align()
            ),
            (32, 8)
        );
        assert_eq!(certificate.costs().runtime, 0);
        assert_eq!(certificate.costs().error_cleanup, 0);
        assert_eq!(certificate.c_backing().size(), 8388608);
        assert_eq!(certificate.c_backing().align(), 16);
        assert_eq!(
            certificate.spawn_bytes().unwrap(),
            certificate.rust_max() + 8388608
        );
        assert!(certificate.rust_max() < 65536);
        println!(
            "W1-H layouts={layouts:?} costs={:?} H={} C={}",
            certificate.costs(),
            certificate.rust_max(),
            certificate.c_backing().size()
        );
    }

    #[test]
    fn source_target_environment_and_pipe_conditions_fail_closed() {
        let base = BuildEvidence {
            compiler_commit: COMPILER_COMMIT,
            release: COMPILER_RELEASE,
            target: TARGET,
            sqlite_features: SQLITE_FEATURES,
            normal_helper_cfg: true,
            inherited_environment: true,
            synchronous_pipe_handles: true,
        };
        assert!(base.verify().is_ok());
        assert_eq!(base.verify_artifact().unwrap(), base.verify().unwrap());
        assert_eq!(
            BuildEvidence {
                compiler_commit: "48a229ceaefd4985c50990b14116b6d856af0985",
                ..base
            }
            .verify(),
            Err(Reject::SourceMismatch)
        );
        for target in [
            "x86_64-pc-windows-gnu",
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-gnu",
        ] {
            assert_eq!(
                BuildEvidence { target, ..base }.verify(),
                Err(Reject::UnsupportedTarget)
            );
        }
        assert_eq!(
            BuildEvidence {
                inherited_environment: false,
                ..base
            }
            .verify(),
            Err(Reject::SourceMismatch)
        );
        assert_eq!(
            BuildEvidence {
                synchronous_pipe_handles: false,
                ..base
            }
            .verify(),
            Err(Reject::SourceMismatch)
        );
        assert_eq!(
            BuildEvidence {
                normal_helper_cfg: false,
                ..base
            }
            .verify(),
            Err(Reject::SourceMismatch)
        );
        assert_eq!(
            Reject::SourceMismatch.outcome(),
            production_protocol::Outcome::UnsupportedEnvelope
        );
    }

    #[test]
    fn small_grant_nonce_limits_and_certificate_gate() {
        let c = certificate(
            OsStr::new(r"C:\trusted\helper.exe"),
            OsStr::new(r"C:\catalog\small.sqlite"),
            SqlRoute::LegacyBuilder,
        );
        let good = request(c, c.rust_max() as u64);
        let admitted = c.admit_request(good, [7; 16], build(), c.shape()).unwrap();
        assert_eq!(admitted.certificate(), c);
        assert_eq!(admitted.certificate().fingerprint(), c.fingerprint());
        let artifact = BuildEvidence {
            compiler_commit: COMPILER_COMMIT,
            release: COMPILER_RELEASE,
            target: TARGET,
            sqlite_features: SQLITE_FEATURES,
            normal_helper_cfg: true,
            inherited_environment: true,
            synchronous_pipe_handles: true,
        }
        .verify_artifact()
        .unwrap();
        assert_eq!(
            HelperRustCertificate::calculate(
                artifact,
                c.shape(),
                FixedLimits::default(),
                SqlRoute::LegacyBuilder
            )
            .unwrap()
            .fingerprint(),
            c.fingerprint()
        );
        assert_eq!(admitted.request(), good.limits());
        assert_eq!(
            c.admit_request(
                request(c, c.rust_max() as u64 - 1),
                [7; 16],
                build(),
                c.shape()
            )
            .unwrap_err(),
            Reject::RustBudgetExceeded
        );
        assert_eq!(
            c.admit_request(good, [8; 16], build(), c.shape())
                .unwrap_err(),
            Reject::NonceMismatch
        );
        let changed = HelperLaunchShape::from_paths(
            OsStr::new(r"C:\trusted\helper.exe"),
            OsStr::new(r"C:\catalog\other.sqlite"),
        )
        .unwrap();
        assert_eq!(
            c.admit_request(good, [7; 16], build(), changed)
                .unwrap_err(),
            Reject::CertificateMismatch
        );
        let mut changed_request = good.limits();
        assert_eq!(
            c.admit_request(request(c, u64::MAX), [7; 16], build(), c.shape())
                .unwrap_err(),
            Reject::Overflow
        );
        changed_request.c_max = 65536;
        assert_eq!(
            c.admit_request(
                changed_request.validate().unwrap(),
                [7; 16],
                build(),
                c.shape()
            )
            .unwrap_err(),
            Reject::InvalidRequest
        );
    }

    #[test]
    fn checked_capacities_and_overflow_precede_owned_construction() {
        assert_eq!(capacity::vec_peak::<u8>(0, 1).unwrap(), 8);
        assert_eq!(capacity::vec_peak::<u16>(0, 5).unwrap(), 24);
        assert_eq!(capacity::vec_peak::<u8>(64, 32).unwrap(), 64);
        assert_eq!(
            capacity::vec_peak::<u64>(0, usize::MAX),
            Err(Reject::Overflow)
        );
        assert_eq!(capacity::add(usize::MAX, 1), Err(Reject::Overflow));
        assert_eq!(capacity::array::<u16>(usize::MAX), Err(Reject::Overflow));
        let shape =
            HelperLaunchShape::from_paths(OsStr::new(r"C:\helper.exe"), OsStr::new("small"))
                .unwrap();
        let mut sentinel = [0xffffu16; 2];
        assert_eq!(
            shape.write_command_line(
                OsStr::new(r"C:\helper.exe"),
                OsStr::new("small"),
                &mut sentinel
            ),
            Err(Reject::RustBudgetExceeded)
        );
        assert_eq!(sentinel, [0xffff; 2]);
        use std::os::windows::ffi::OsStringExt;
        let bad = std::ffi::OsString::from_wide(&[0xd800]);
        assert_eq!(
            HelperLaunchShape::from_paths(OsStr::new(r"C:\helper.exe"), &bad),
            Err(Reject::InvalidPath)
        );
        assert_eq!(
            HelperLaunchShape::from_paths(OsStr::new(r"C:\helper.exe"), OsStr::new("a\0b")),
            Err(Reject::InvalidPath)
        );
        assert_eq!(
            HelperLaunchShape::from_paths(OsStr::new("helper.exe"), OsStr::new("db")),
            Err(Reject::InvalidPath)
        );
    }

    #[test]
    fn invalid_utf16_path_matches_actual_normal_helper_semantics() {
        use std::{io::Write, os::windows::ffi::OsStringExt, process::Stdio};
        let normal = env!("CARGO_BIN_EXE_selected-read-helper");
        let invalid = std::ffi::OsString::from_wide(&[0xd800]);
        assert_eq!(
            HelperLaunchShape::from_paths(OsStr::new(normal), &invalid),
            Err(Reject::InvalidPath)
        );
        let mut frame = [0u8; 72];
        frame[..8].copy_from_slice(b"SHSELREQ");
        frame[8..10].copy_from_slice(&1u16.to_le_bytes());
        frame[12..20].copy_from_slice(&8388608u64.to_le_bytes());
        frame[20..28].copy_from_slice(&65536u64.to_le_bytes());
        frame[28..36].copy_from_slice(&1048576u64.to_le_bytes());
        frame[36..40].copy_from_slice(&256u32.to_le_bytes());
        let mut child = Command::new(normal)
            .arg(&invalid)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&frame).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 128);
        assert_eq!(
            u16::from_le_bytes(output.stdout[10..12].try_into().unwrap()),
            6
        );
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn fixed_sql_route_removes_only_its_actual_allocation_class() {
        let exe = OsStr::new(r"C:\helper.exe");
        let db = OsStr::new(r"C:\small.sqlite");
        let legacy = certificate(exe, db, SqlRoute::LegacyBuilder);
        let fixed = certificate(exe, db, SqlRoute::FixedCStr);
        assert_eq!(
            legacy.rust_max() - fixed.rust_max(),
            source::legacy_sql_upper().unwrap()
        );
        assert_eq!(fixed.costs().sql_and_fields, 0);
        assert_eq!(fixed.costs().stdio_globals, legacy.costs().stdio_globals);
        assert_eq!(fixed.costs().argv, legacy.costs().argv);
        assert!(FIXED_SQL.iter().all(|sql| !sql.to_bytes().contains(&0)));
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(include_str!("../migrations/0001_initial.sql"))
            .unwrap();
        connection
            .execute_batch(include_str!(
                "../migrations/0003_configuration_revision.sql"
            ))
            .unwrap();
        for sql in FIXED_SQL {
            connection.prepare(sql.to_str().unwrap()).unwrap();
        }
    }

    fn compile_audit(output: &std::path::Path) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let dependency = std::env::var_os("RSHELL_RUST_BUDGET_RUSQLITE")
            .expect("审计编译需要精确 Cargo artifact，不搜索 SDK/cache");
        let uuid = std::env::var_os("RSHELL_RUST_BUDGET_UUID")
            .expect("审计编译需要精确 UUID Cargo artifact");
        let result = Command::new("rustc")
            .env("RUSTUP_AUTO_INSTALL", "0")
            .arg("--edition=2024")
            .arg("--crate-name=selected_helper_rust_budget_audit")
            .arg(root.join("tests/support/selected_helper_rust_budget_audit.rs"))
            .arg("--extern")
            .arg(format!(
                "rusqlite={}",
                std::path::Path::new(&dependency).display()
            ))
            .arg("--extern")
            .arg(format!("uuid={}", std::path::Path::new(&uuid).display()))
            .arg("-L")
            .arg(format!(
                "dependency={}",
                std::path::Path::new(&dependency)
                    .parent()
                    .unwrap()
                    .display()
            ))
            .arg("-o")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    struct Audit {
        output: Vec<u8>,
        header: Vec<u64>,
        events: Vec<[u64; 6]>,
    }

    fn run_audit(executable: &std::path::Path, database: &OsStr, bytes: &[u8]) -> Audit {
        use std::io::Write;
        let mut child = Command::new(executable)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .arg(database)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        parse_audit(output, 0)
    }

    fn parse_audit(output: std::process::Output, exit_code: i32) -> Audit {
        assert_eq!(
            output.status.code(),
            Some(exit_code),
            "审计 executable 异常退出"
        );
        assert_eq!(&output.stderr[..8], b"SHRBAUD1");
        let (number_bytes, remainder) = output.stderr[8..].as_chunks::<8>();
        assert!(remainder.is_empty());
        let numbers: Vec<u64> = number_bytes
            .iter()
            .map(|b| u64::from_le_bytes(*b))
            .collect();
        let header = numbers[..11].to_vec();
        let (event_numbers, remainder) = numbers[11..].as_chunks::<6>();
        assert!(remainder.is_empty());
        let events: Vec<[u64; 6]> = event_numbers.to_vec();
        assert_eq!(events.len() as u64, header[6]);
        assert_eq!(
            header[5], 0,
            "每笔 before-allocation 或原 Layout 释放审计失败"
        );
        assert_eq!(header[8], 0, "C backing 必须真实释放");
        // 此值来自隔离入口完成局部析构/runtime cleanup 后的 CRT onExit 回调。
        // 不代表旧 main 的 process::exit(2) 分支完成了相同析构。
        assert_eq!(header[7], 12288, "仅进程寿命 stdin global 允许留存");
        assert!(events.iter().all(|event| event[5] <= header[1]));
        Audit {
            output: output.stdout,
            header,
            events,
        }
    }

    #[test]
    // 只审计隔离入口＋真实 run＋Rust runtime cleanup/CRT onExit，不审计旧 main 全出口。
    fn process_start_request_selected_cleanup_exit_and_std_argv_oracle() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let directory = tempfile::tempdir_in(root.join("../../target/tmp")).unwrap();
        let executable = directory.path().join("预算 helper.exe");
        compile_audit(&executable);
        let database = directory.path().join("普通 small 汉字😀.sqlite");
        let db = rusqlite::Connection::open(&database).unwrap();
        db.execute_batch(include_str!("../migrations/0001_initial.sql"))
            .unwrap();
        db.execute_batch(include_str!(
            "../migrations/0003_configuration_revision.sql"
        ))
        .unwrap();
        db.execute("INSERT INTO connections VALUES('00000000-0000-0000-0000-000000000010',NULL,'示例','host',22,'user','ssh','password',NULL,NULL,'strict',NULL,'合成 note',0,'00000000-0000-0000-0000-000000000001','{\"version\":1,\"overrides\":{}}')", []).unwrap();
        db.execute(
            "INSERT INTO connection_tags VALUES('00000000-0000-0000-0000-000000000010','标签')",
            [],
        )
        .unwrap();
        db.close().unwrap();
        let c = certificate(
            executable.as_os_str(),
            database.as_os_str(),
            SqlRoute::LegacyBuilder,
        );
        let mut r = request(c, c.rust_max() as u64).limits();
        r.connection = None;
        r.frame_count_max = 6;
        r.wire_max = production_protocol::wire_upper(6, r.total_max, 0).unwrap();
        let frame = r.validate().unwrap().encode();
        let good = run_audit(&executable, database.as_os_str(), &frame);
        assert_eq!(good.header[0], c.shape().identity());
        assert_eq!(good.header[1], c.rust_max() as u64);
        assert_eq!(good.header[4], c.c_backing().size() as u64);
        assert_eq!(
            u16::from_le_bytes(good.output[10..12].try_into().unwrap()),
            0,
            "实际 selected preflight 应成功，不是 LoadedRaw 认证"
        );
        assert!(
            good.events
                .iter()
                .any(|event| event[0] == 1 && event[4] == 5)
        );
        assert!(
            good.events
                .iter()
                .any(|event| event[0] == 2 && event[4] == 5)
        );
        let mut selected = request(c, c.rust_max() as u64).limits();
        let mut id = [0u8; 16];
        id[15] = 16;
        selected.connection = Some(id);
        let selected_frame = selected.validate().unwrap().encode();
        let selected = run_audit(&executable, database.as_os_str(), &selected_frame);
        assert_eq!(
            u16::from_le_bytes(selected.output[10..12].try_into().unwrap()),
            0
        );
        assert!(
            selected
                .events
                .iter()
                .any(|event| event[0] == 1 && event[4] == 4)
        );
        let missing_path = directory.path().join("不存在.sqlite");
        let missing_certificate = certificate(
            executable.as_os_str(),
            missing_path.as_os_str(),
            SqlRoute::LegacyBuilder,
        );
        let mut missing_request = r;
        missing_request.helper_rust_max = missing_certificate.rust_max() as u64;
        let failure = run_audit(
            &executable,
            missing_path.as_os_str(),
            &missing_request.validate().unwrap().encode(),
        );
        assert_eq!(
            u16::from_le_bytes(failure.output[10..12].try_into().unwrap()),
            5
        );
        assert!(
            failure
                .events
                .iter()
                .any(|event| event[0] == 2 && event[4] == 5)
        );
        {
            // 隔离入口的写失败返回 ExitCode(2)，database/arguments 已析构；
            // 不是旧 main 直接 process::exit(2) 的执行证据。
            use std::{io::Write, process::Stdio};
            let mut child = Command::new(&executable)
                .arg(&database)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            drop(child.stdout.take().unwrap());
            child.stdin.take().unwrap().write_all(&frame).unwrap();
            let write_failure = parse_audit(child.wait_with_output().unwrap(), 2);
            assert_eq!(write_failure.header[9], 100);
            assert_eq!(write_failure.header[8], 0);
            assert!(write_failure.output.is_empty());
        }
        let mut short = frame;
        short[80..88].copy_from_slice(&(c.rust_max() as u64 - 1).to_le_bytes());
        let rejected = run_audit(&executable, database.as_os_str(), &short);
        assert_eq!(rejected.header[9], 10);
        assert_eq!(rejected.header[4], 0);
        assert_eq!(rejected.header[10], 0);
        assert!(!rejected.events.iter().any(|event| event[1] == 3));
        assert_eq!(
            production_protocol::Footer::decode(&rejected.output)
                .unwrap()
                .outcome,
            production_protocol::Outcome::RustBudgetExceeded
        );
        let invalid = run_audit(&executable, database.as_os_str(), &frame[..17]);
        assert_eq!(invalid.header[9], Reject::InvalidRequest as u64);
        assert_eq!(invalid.header[4], 0);
        let invalid_footer = production_protocol::Footer::decode(&invalid.output).unwrap();
        assert_eq!(invalid_footer.flags & production_protocol::NONCE_VALID, 0);
        assert_eq!(invalid_footer.nonce, [0; 16]);
        let mut overflow = frame;
        overflow[80..88].copy_from_slice(&u64::MAX.to_le_bytes());
        let overflow = run_audit(&executable, database.as_os_str(), &overflow);
        assert_eq!(overflow.header[9], Reject::Overflow as u64);
        assert_eq!(overflow.header[4], 0);
        assert!(!overflow.events.iter().any(|event| event[1] == 3));
        // std args_os 是独立语义 oracle；子进程同时比较 borrowed parser 与实际 OsString。
        for argument in [
            "",
            "a b",
            "a\tb",
            r"plain\tail\",
            r"space tail\",
            "汉字😀",
            "a\"b",
            "a\\\"b",
            "\"\"",
            "\\\\",
            "a b\\\\",
        ] {
            let shape = HelperLaunchShape::from_paths(executable.as_os_str(), OsStr::new(argument))
                .unwrap();
            let mut command = vec![0u16; shape.command_units_with_nul()];
            let length = shape
                .write_command_line(executable.as_os_str(), OsStr::new(argument), &mut command)
                .unwrap();
            assert_eq!(
                HelperLaunchShape::from_command_line(&command[..length - 1]).unwrap(),
                shape
            );
            let oracle = run_audit(&executable, OsStr::new(argument), &[]);
            assert_eq!(oracle.header[0], shape.identity());
        }
        println!(
            "W1-H actual audit: events={} RustPeak={} H={} CPeak={} costs={:?}",
            good.events.len(),
            good.header[3],
            good.header[1],
            good.header[4],
            c.costs()
        );
    }
}

#[cfg(not(all(target_os = "windows", target_env = "msvc", target_arch = "x86_64")))]
#[test]
fn target_certificate_is_disabled() {
    use rust_budget::{source::*, *};
    let evidence = BuildEvidence {
        compiler_commit: COMPILER_COMMIT,
        release: COMPILER_RELEASE,
        target: TARGET,
        sqlite_features: SQLITE_FEATURES,
        normal_helper_cfg: true,
        inherited_environment: true,
        synchronous_pipe_handles: true,
    };
    assert_eq!(evidence.verify(), Err(Reject::UnsupportedTarget));
    assert_eq!(
        HelperLaunchShape::from_paths(std::ffi::OsStr::new("helper"), std::ffi::OsStr::new("db")),
        Err(Reject::UnsupportedTarget)
    );
}
