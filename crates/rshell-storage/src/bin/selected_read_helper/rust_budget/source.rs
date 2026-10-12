//! 源闭包只适用于 b940084d7eb6a299eb4bfeb8e34901bc051e7ac4 的 Windows MSVC。
//! 源链接以 https://github.com/rust-lang/rust/blob/<COMPILER_COMMIT>/ 为前缀。
//!
//! | 分配类 | 精确源函数/容量事件 | 同时份数与释放根 |
//! | --- | --- | --- |
//! | runtime | std/rt.rs::init → thread::current_id；pal/windows::{init,stack_overflow::init} | ID/native TLS、宽 main 名为静态；exception handler/stack guarantee 是 OS 资源，无 Rust alloc 调用 |
//! | argv | std/sys/args/windows.rs::parse_lp_cmd_line；alloc/wtf8/mod.rs::from_wide | 两个 cur Vec<u16> 可同活；两个 Wtf8Buf 从 units 容量逐 scalar append；ret Vec<OsString> 初始 4；Args 的 IntoIter 是最终 root |
//! | path | helper/mod.rs::path_string；alloc/ffi/c_str.rs::spec_new_impl_bytes | path.to_str 借用；CString 精确 bytes+1，内含 Box<[u8]>；OsString 仍活。无 PathBuf 构造/clone |
//! | stdin | std/io/stdio.rs::stdin → alloc/io/buffered/bufreader/buffer.rs::with_capacity | 全局 Box<[MaybeUninit<u8>]> 一份 12288；static OnceLock/Mutex/reader 控制字段无独立 heap，进程寿命 |
//! | stdout | std/io/stdio.rs::stdout → alloc/io/buffered/linewriter.rs::new | 全局 Vec<u8> 一份 1024；cleanup 以容量 0 替换，旧 backing drop 后释放 |
//! | 锁/TLS | std/sync/reentrant_lock.rs::lock → thread::current_id；sys/sync/mutex/futex.rs | 无 thread::current/System Arc；原子锁/WaitOnAddress 为内嵌或 OS，native TLS 无 Rust heap |
//! | stderr/env | normal helper 无 stderr/var/vars_os 调用；fault/barrier 仅 cfg(test) | 不启用这些测试分支；完整继承 env，由 OS/CRT 持有，非 env_clear。panic/abort 不是 typed 预算拒绝 |
//! | SQL/字段 | preflight.rs::{row,prepare,tags}；固定 SQL 接点见 FIXED_SQL | 当前 builder 与固定 CStr 两条证书不能混用；界按固定列集合和同时存活窗口；固定数组/Report/Db/Statement/Arena 在栈上 |
//! | C owner | envelope.rs::Arena::new/drop；ACTIVE const Cell<*mut Arena> | 唯一 Layout(cap,16) 单列 Cbacking；owner、Header 与所有 arena 内块不再计 H；shutdown→Arena::drop→dealloc |
//! | UUID | uuid 1.24.0 parser.rs::try_parse_ascii→const try_parse/parse_hyphenated/decode_hex32；fmt.rs::Hyphenated::encode_lower→encode_hyphenated | const parser 无 heap 调用，错误为 inline ParseOther；formatter 写入调用者 [u8;36]，不经 Display/to_string |
//! | 错误/退出 | io raw_os_error/const_error、Report 数字、SQLite FFI 码；std/rt.rs::cleanup、sys/exit.rs | 不格式化 io::Error/Report；无 owned 错误消息。退出 flush 不扩容；request/argv/stdio 的 grant 保到真实 wait+drain |
//!
//! Rust System.alloc 也必须入账；本闭包不调用 Thread::new 或其他直接 System 分配。
//! init 的 set_name_wide 直接调用 SetThreadDescription；winsock::cleanup 为空函数。
//! std/io/error.rs::from_raw_os_error 提供静态 OsFunctions；core/io/error.rs 调用
//! os_functions_atomic.rs::set_functions（静态 AtomicPtr）与 repr_bitpacked.rs::new_os
//! （inline tagged code）。不调用 error_string/Display，不产生 CustomOwner backing。
//! 可达 panic、新增 env/线程/BufWriter/SQL 构造、console handles、动态诊断改变闭包，
//! 不能继承本证书。stdlib 的 debug console String::from_utf16 分支由 pipe 前件排除。
//!
//! 动态审计覆盖隔离入口、真实 selected_read_helper::run、显式局部析构与 Rust runtime
//! cleanup；进程终止前的 CRT onExit 回调记录其剩余 Layout，不覆盖旧 main 的
//! process::exit(2) 失败出口。旧出口不析构 argv 不会新增 allocation；静态 H 仍完整
//! 保留到真实 process exit、wait 与 drain，不能按隔离入口的析构观测提前释放 grant。

use super::{Reject, capacity};
use std::{alloc::Layout, ffi::CStr};

pub const COMPILER_COMMIT: &str = "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4";
pub const COMPILER_RELEASE: &str = "1.99.0";
pub const TARGET: &str = "x86_64-pc-windows-msvc";
pub const SOURCE_REVISION: u32 = 1;
pub const SQLITE_FEATURES: &str = "rusqlite=0.37.0:bundled,modern_sqlite;libsqlite3-sys=0.35.0:bundled,bundled_bindings,cc,default,min_sqlite_version_3_14_0,pkg-config,vcpkg;uuid=1.24.0:default,rng,serde,std,v4";

/// 父构建所有者从实际 rustc -vV、cfg 和 locked/offline resolve 提供，不来自 IPC。
#[derive(Clone, Copy, Debug)]
pub struct BuildEvidence<'a> {
    pub compiler_commit: &'a str,
    pub release: &'a str,
    pub target: &'a str,
    pub sqlite_features: &'a str,
    pub normal_helper_cfg: bool,
    pub inherited_environment: bool,
    pub synchronous_pipe_handles: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBuild {
    pub(crate) source_revision: u32,
}

impl VerifiedBuild {
    pub(crate) fn verify_local(self) -> Result<(), Reject> {
        if !cfg!(all(
            target_arch = "x86_64",
            target_os = "windows",
            target_env = "msvc",
            target_vendor = "pc",
            target_pointer_width = "64",
            target_endian = "little",
            panic = "unwind"
        )) {
            return Err(Reject::UnsupportedTarget);
        }
        if super::PublicLayouts::current()? != super::PublicLayouts::helper_msvc()? {
            return Err(Reject::SourceMismatch);
        }
        Ok(())
    }
}

impl BuildEvidence<'_> {
    pub fn verify(self) -> Result<VerifiedBuild, Reject> {
        if !cfg!(all(
            target_arch = "x86_64",
            target_os = "windows",
            target_env = "msvc",
            target_vendor = "pc",
            target_pointer_width = "64",
            target_endian = "little",
            panic = "unwind"
        )) || self.target != TARGET
        {
            return Err(Reject::UnsupportedTarget);
        }
        let build = self.verify_artifact()?;
        build.verify_local()?;
        Ok(build)
    }

    /// 父从受信 helper artifact 的构建记录核验；不能填父自身 rustc/target 信息。
    /// 这只允许计算 MSVC helper 的预算，不开放 GNU/mac/Linux helper 模型。
    pub fn verify_artifact(self) -> Result<VerifiedBuild, Reject> {
        if self.target != TARGET {
            return Err(Reject::UnsupportedTarget);
        }
        if self.compiler_commit != COMPILER_COMMIT
            || self.release != COMPILER_RELEASE
            || self.sqlite_features != SQLITE_FEATURES
            || !self.normal_helper_cfg
            || !self.inherited_environment
            || !self.synchronous_pipe_handles
        {
            return Err(Reject::SourceMismatch);
        }
        Ok(VerifiedBuild {
            source_revision: SOURCE_REVISION,
        })
    }
}

/// 固定语句的应用侧接点。直接传 CStr.as_ptr()，不可再经旧 prepare(&str) 的 CString。
/// 静态只读字符串属于 binary mapping，不是 Rust heap。
pub const FIXED_SQL: &[&CStr] = &[
    c"PRAGMA query_only=ON",
    c"PRAGMA mmap_size=0",
    c"PRAGMA encoding",
    c"BEGIN",
    c"ROLLBACK",
    c"SELECT revision,singleton FROM configuration_revision WHERE singleton=1",
    c"SELECT singleton FROM app_settings WHERE singleton=1",
    c"SELECT port,position FROM connections WHERE id=?1",
    c"SELECT typeof(id),octet_length(id),typeof(group_id),octet_length(group_id),typeof(name),octet_length(name),typeof(host),octet_length(host),typeof(username),octet_length(username),typeof(transport),octet_length(transport),typeof(authentication),octet_length(authentication),typeof(credential_ref),octet_length(credential_ref),typeof(identity_file),octet_length(identity_file),typeof(host_key_policy),octet_length(host_key_policy),typeof(remote_command),octet_length(remote_command),typeof(note),octet_length(note),typeof(terminal_profile_id),octet_length(terminal_profile_id),typeof(terminal_overrides_json),octet_length(terminal_overrides_json) FROM connections WHERE id=?1",
    c"SELECT typeof(default_terminal_profile),octet_length(default_terminal_profile),typeof(color_scheme),octet_length(color_scheme),typeof(key_bindings_json),octet_length(key_bindings_json) FROM app_settings WHERE singleton=1",
    c"SELECT typeof(id),octet_length(id),typeof(name),octet_length(name),typeof(settings_json),octet_length(settings_json) FROM terminal_profiles WHERE id=?1",
    c"SELECT terminal_profile_id FROM connections WHERE id=?1",
    c"SELECT default_terminal_profile FROM app_settings WHERE singleton=1",
    c"SELECT id,group_id,name,host,username,transport,authentication,credential_ref,identity_file,host_key_policy,remote_command,note,terminal_profile_id,terminal_overrides_json FROM connections WHERE id=?1",
    c"SELECT default_terminal_profile,color_scheme,key_bindings_json FROM app_settings WHERE singleton=1",
    c"SELECT id,name,settings_json FROM terminal_profiles WHERE id=?1",
    c"SELECT typeof(tag),octet_length(tag) FROM connection_tags WHERE connection_id=?1 ORDER BY tag",
    c"SELECT typeof(tag),octet_length(tag),tag FROM connection_tags WHERE connection_id=?1 ORDER BY tag",
];

const CONNECTION: &[&str] = &[
    "id",
    "group_id",
    "name",
    "host",
    "username",
    "transport",
    "authentication",
    "credential_ref",
    "identity_file",
    "host_key_policy",
    "remote_command",
    "note",
    "terminal_profile_id",
    "terminal_overrides_json",
];
const SETTINGS: &[&str] = &[
    "default_terminal_profile",
    "color_scheme",
    "key_bindings_json",
];
const PROFILE: &[&str] = &["id", "name", "settings_json"];

/// 旧 row 的 format/collect/join 与 prepare CString 源界；不是测量生成的 cap。
pub fn legacy_sql_upper() -> Result<usize, Reject> {
    let mut bound = 0;
    for (columns, table, predicate) in [
        (CONNECTION, "connections", "id=?1"),
        (SETTINGS, "app_settings", "singleton=1"),
        (PROFILE, "terminal_profiles", "id=?1"),
    ] {
        let literal = "typeof(),octet_length()".len();
        let mut meta_len = columns.len() - 1;
        let mut element_peaks = 0;
        let mut projection_len = columns.len() - 1;
        for column in columns {
            let len = capacity::add(
                literal,
                column.len().checked_mul(2).ok_or(Reject::Overflow)?,
            )?;
            meta_len = capacity::add(meta_len, len)?;
            projection_len = capacity::add(projection_len, column.len())?;
            element_peaks = capacity::add(element_peaks, format_upper(literal, len)?)?;
        }
        let mut row = capacity::add(
            element_peaks,
            capacity::array_for(super::PublicLayouts::helper_msvc()?.string, columns.len())?.size(),
        )?;
        row = capacity::add(row, meta_len)?; // join exact backing，之前的 fragments 仍收费。
        row = capacity::add(row, select_upper(meta_len, table, predicate)?)?;
        row = capacity::add(
            row,
            capacity::array_for(
                Layout::from_size_align(16, 8).map_err(|_| Reject::Overflow)?,
                columns.len(),
            )?
            .size(),
        )?;
        row = capacity::add(row, projection_len)?;
        row = capacity::add(row, select_upper(projection_len, table, predicate)?)?;
        // capture 的 format 与 CString 生命周期包含在同一 row 根，不假定早 drop。
        row = capacity::add(
            row,
            select_upper(
                columns.iter().map(|s| s.len()).max().unwrap_or(0),
                table,
                predicate,
            )?,
        )?;
        bound = bound.max(row);
    }
    // 非 row 固定 prepare，包括与 tag meta 同时存活的 materialize prepare。
    let fixed = FIXED_SQL.iter().try_fold(0usize, |sum, sql| {
        capacity::add(sum, sql.to_bytes_with_nul().len())
    })?;
    capacity::add(bound, fixed)
}

fn format_upper(literal_len: usize, final_len: usize) -> Result<usize, Reject> {
    // core::fmt::Arguments::estimated_capacity 至多 2*literal bytes；as_str 优化走 exact。
    let initial = literal_len.checked_mul(2).ok_or(Reject::Overflow)?;
    capacity::vec_peak::<u8>(initial, final_len)
}

fn select_upper(columns: usize, table: &str, predicate: &str) -> Result<usize, Reject> {
    let literal = "SELECT  FROM  WHERE ".len();
    let len = capacity::add(
        capacity::add(capacity::add(literal, columns)?, table.len())?,
        predicate.len(),
    )?;
    capacity::add(format_upper(literal, len)?, capacity::add(len, 1)?)
}

/// Buffer 的真实字段：Box<[MaybeUninit<u8>]>、pos、filled、initialized。
/// 40/8 是排列无关源上界，并由精确 1.99 MSVC compiler 的直接 type-size 诊断互核；
/// 不复制 private struct，不从 BufReader 的 public Layout 反推。
pub fn reader_buffer_control_upper() -> Result<Layout, Reject> {
    capacity::struct_upper(&[
        Layout::new::<Box<[std::mem::MaybeUninit<u8>]>>(),
        Layout::new::<usize>(),
        Layout::new::<usize>(),
        Layout::new::<bool>(),
    ])
}

/// Wtf8Buf 的真实字段：Vec<u8> 与 is_known_utf8；32/8 为排列无关源上界，
/// 并由精确 1.99 MSVC compiler 的直接 type-size 诊断互核，不复制 private struct。
pub fn wtf8_control_upper() -> Result<Layout, Reject> {
    capacity::struct_upper(&[Layout::new::<Vec<u8>>(), Layout::new::<bool>()])
}
