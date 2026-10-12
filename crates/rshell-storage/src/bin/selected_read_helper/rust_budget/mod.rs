//! Helper Rust Layout 的条件证书；不认可 LoadedRaw，不拥有父 process ledger。
//! 父先以 calculate 的完整 H+C 取得真实 reservation 再 spawn，不能在读 request 后
//! 补记 argv/stdin。helper 在 path/SQL/C backing 构造前调用 admit_request。
//! normal bin 的注册和入口调用由整合者完成；此模块不声明现有 bin 已切换。

pub mod capacity;
pub mod launch;
pub mod source;

use super::production_protocol::{Request, WireValidatedRequest};
pub use launch::HelperLaunchShape;
use source::VerifiedBuild;
use std::{
    alloc::Layout,
    ffi::{CString, OsString},
    path::PathBuf,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Reject {
    RustBudgetExceeded = 10,
    Overflow = 11,
    UnsupportedTarget = 12,
    SourceMismatch = 13,
    CertificateMismatch = 14,
    InvalidPath = 15,
    InvalidLaunch = 16,
    InvalidRequest = 17,
    NonceMismatch = 18,
}

impl Reject {
    pub fn outcome(self) -> super::production_protocol::Outcome {
        use super::production_protocol::Outcome;
        match self {
            Self::RustBudgetExceeded => Outcome::RustBudgetExceeded,
            Self::UnsupportedTarget | Self::SourceMismatch | Self::CertificateMismatch => {
                Outcome::UnsupportedEnvelope
            }
            Self::Overflow
            | Self::InvalidPath
            | Self::InvalidLaunch
            | Self::InvalidRequest
            | Self::NonceMismatch => Outcome::InvalidRequest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlRoute {
    LegacyBuilder,
    FixedCStr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicLayouts {
    pub os_string: Layout,
    pub path_buf: Layout,
    pub c_string: Layout,
    pub string: Layout,
    pub reader_buffer_control_upper: Layout,
    pub wtf8_control_upper: Layout,
    pub instantiated_reader: Layout,
    pub instantiated_writer: Layout,
}

impl PublicLayouts {
    /// 表值来自本单元 exact MSVC 编译器/public Layout 与 private 源式、诊断互核。
    /// 父计算只能用 helper 表；current() 用于 helper 自检，不借父 host 布局。
    pub fn helper_msvc() -> Result<Self, Reject> {
        let layout =
            |size, align| Layout::from_size_align(size, align).map_err(|_| Reject::Overflow);
        Ok(Self {
            os_string: layout(32, 8)?,
            path_buf: layout(32, 8)?,
            c_string: layout(16, 8)?,
            string: layout(24, 8)?,
            reader_buffer_control_upper: layout(40, 8)?,
            wtf8_control_upper: layout(32, 8)?,
            instantiated_reader: layout(40, 8)?,
            instantiated_writer: layout(32, 8)?,
        })
    }

    pub fn current() -> Result<Self, Reject> {
        Ok(Self {
            os_string: Layout::new::<OsString>(),
            path_buf: Layout::new::<PathBuf>(),
            c_string: Layout::new::<CString>(),
            string: Layout::new::<String>(),
            reader_buffer_control_upper: source::reader_buffer_control_upper()?,
            wtf8_control_upper: source::wtf8_control_upper()?,
            instantiated_reader: Layout::new::<std::io::BufReader<std::io::Empty>>(),
            instantiated_writer: Layout::new::<std::io::LineWriter<std::io::Sink>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedLimits {
    pub c_max: u64,
    pub field_max: u64,
    pub total_max: u64,
    pub tags_max: u32,
}

impl Default for FixedLimits {
    fn default() -> Self {
        Self {
            c_max: 8 * 1024 * 1024,
            field_max: 65536,
            total_max: 1048576,
            tags_max: 256,
        }
    }
}

impl FixedLimits {
    fn c_layout(self) -> Result<Layout, Reject> {
        if !(65536..=67108864).contains(&self.c_max)
            || !self.c_max.is_multiple_of(16)
            || !(1..=1048576).contains(&self.field_max)
            || !(self.field_max..=4194304).contains(&self.total_max)
            || self.tags_max > 4096
        {
            return Err(Reject::InvalidRequest);
        }
        Layout::from_size_align(
            usize::try_from(self.c_max).map_err(|_| Reject::Overflow)?,
            16,
        )
        .map_err(|_| Reject::Overflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Costs {
    pub runtime: usize,
    pub argv: usize,
    pub path: usize,
    pub stdio_globals: usize,
    pub sql_and_fields: usize,
    pub error_cleanup: usize,
}

impl Costs {
    pub fn total(self) -> Result<usize, Reject> {
        [
            self.runtime,
            self.argv,
            self.path,
            self.stdio_globals,
            self.sql_and_fields,
            self.error_cleanup,
        ]
        .into_iter()
        .try_fold(0, capacity::add)
    }
}

/// 栈值、固定源身份及布局，不创建动态 allocation class 表。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelperRustCertificate {
    build: VerifiedBuild,
    shape: HelperLaunchShape,
    limits: FixedLimits,
    sql_route: SqlRoute,
    layouts: PublicLayouts,
    costs: Costs,
    rust_max: usize,
    c_backing: Layout,
}

/// 固定源/布局/启动身份；是受信 build 的关联值，不是密码学认证或子进程自签名。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateFingerprint {
    pub compiler_commit: &'static str,
    pub target: &'static str,
    pub resolved_features: &'static str,
    pub source_revision: u32,
    pub sql_route: SqlRoute,
    pub layouts: PublicLayouts,
    pub launch: HelperLaunchShape,
    pub limits: FixedLimits,
    pub rust_max: usize,
}

impl HelperRustCertificate {
    pub fn calculate(
        build: VerifiedBuild,
        shape: HelperLaunchShape,
        limits: FixedLimits,
        sql_route: SqlRoute,
    ) -> Result<Self, Reject> {
        let layouts = PublicLayouts::helper_msvc()?;
        let c_backing = limits.c_layout()?;
        let byte = Layout::from_size_align(1, 1).map_err(|_| Reject::Overflow)?;
        let wide = Layout::from_size_align(2, 2).map_err(|_| Reject::Overflow)?;
        let mut argv = capacity::vec_peak_for(layouts.os_string, 0, 2)?;
        for argument in shape.arguments() {
            argv = capacity::add(argv, capacity::vec_peak_for(wide, 0, argument.utf16_units)?)?;
            argv = capacity::add(
                argv,
                capacity::vec_peak_for(byte, argument.utf16_units, argument.encoded_bytes)?,
            )?;
        }
        let path =
            capacity::array_for(byte, capacity::add(shape.arguments()[1].encoded_bytes, 1)?)?
                .size();
        let costs = Costs {
            runtime: 0, // 已列出的 init/cleanup/current_id 源路径无 Rust allocation。
            argv,
            path,
            stdio_globals: capacity::add(
                capacity::array_for(byte, 12288)?.size(),
                capacity::array_for(byte, 1024)?.size(),
            )?,
            sql_and_fields: match sql_route {
                SqlRoute::LegacyBuilder => source::legacy_sql_upper()?,
                SqlRoute::FixedCStr => 0,
            },
            error_cleanup: 0, // 固定 numeric Report、raw_os_error/const_error，无 format。
        };
        let rust_max = costs.total()?;
        capacity::add(rust_max, c_backing.size())?;
        Ok(Self {
            build,
            shape,
            limits,
            sql_route,
            layouts,
            costs,
            rust_max,
            c_backing,
        })
    }

    pub fn rust_max(self) -> usize {
        self.rust_max
    }
    pub fn c_backing(self) -> Layout {
        self.c_backing
    }
    pub fn costs(self) -> Costs {
        self.costs
    }
    pub fn layouts(self) -> PublicLayouts {
        self.layouts
    }
    pub fn shape(self) -> HelperLaunchShape {
        self.shape
    }
    pub fn sql_route(self) -> SqlRoute {
        self.sql_route
    }

    pub fn fingerprint(self) -> CertificateFingerprint {
        CertificateFingerprint {
            compiler_commit: source::COMPILER_COMMIT,
            target: source::TARGET,
            resolved_features: source::SQLITE_FEATURES,
            source_revision: self.build.source_revision,
            sql_route: self.sql_route,
            layouts: self.layouts,
            launch: self.shape,
            limits: self.limits,
            rust_max: self.rust_max,
        }
    }

    pub fn spawn_bytes(self) -> Result<usize, Reject> {
        capacity::add(self.rust_max, self.c_backing.size())
    }

    /// 在实际 argv 构造前也能调用；早期 InvalidRequest 仍持完整 helper reservation。
    pub fn verify_launch(self, actual: HelperLaunchShape) -> Result<(), Reject> {
        let rebuilt = Self::calculate(self.build, actual, self.limits, self.sql_route)?;
        if rebuilt != self {
            return Err(Reject::CertificateMismatch);
        }
        Ok(())
    }

    /// WireValidatedRequest 本身不具备准入效力。nonce、固定 limits、同一源/shape
    /// 的证书和真实 grant 必须全部成立；返回 token 后才能分配 path/SQL/C backing。
    pub fn admit_request(
        self,
        request: WireValidatedRequest,
        expected_nonce: [u8; 16],
        helper_build: VerifiedBuild,
        actual_launch: HelperLaunchShape,
    ) -> Result<AdmittedRequest, Reject> {
        helper_build.verify_local()?;
        if self.build != helper_build {
            return Err(Reject::SourceMismatch);
        }
        self.verify_launch(actual_launch)?;
        let request = request.limits();
        if request.nonce != expected_nonce {
            return Err(Reject::NonceMismatch);
        }
        if (FixedLimits {
            c_max: request.c_max,
            field_max: request.field_max,
            total_max: request.total_max,
            tags_max: request.tags_max,
        }) != self.limits
        {
            return Err(Reject::InvalidRequest);
        }
        let granted = usize::try_from(request.helper_rust_max).map_err(|_| Reject::Overflow)?;
        capacity::array::<u8>(granted)?;
        if request.helper_rust_max < u64::try_from(self.rust_max).map_err(|_| Reject::Overflow)? {
            return Err(Reject::RustBudgetExceeded);
        }
        Ok(AdmittedRequest {
            request,
            certificate: self,
        })
    }
}

/// 私有数值准入 token；不证明 C 事务成功，也不生成 LoadedRaw。
#[derive(Clone, Copy, Debug)]
pub struct AdmittedRequest {
    request: Request,
    certificate: HelperRustCertificate,
}

impl AdmittedRequest {
    pub fn request(self) -> Request {
        self.request
    }
    pub fn certificate(self) -> HelperRustCertificate {
        self.certificate
    }
}
