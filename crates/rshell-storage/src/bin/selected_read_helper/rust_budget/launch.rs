use super::{Reject, capacity};
use std::ffi::OsStr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArgumentShape {
    pub utf16_units: usize,
    pub encoded_bytes: usize,
}

/// 只有受信 exe 与一个 DB 参数。环境完整继承；正常 helper 无 Rust getenv 调用。
/// GetCommandLineW 的原存储由 OS/CRT 持有，不是 Rust allocator Layout。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelperLaunchShape {
    pub(crate) arguments: [ArgumentShape; 2],
    pub(crate) command_units_with_nul: usize,
    pub(crate) identity: u64,
}

impl HelperLaunchShape {
    pub fn arguments(self) -> [ArgumentShape; 2] {
        self.arguments
    }

    pub fn command_units_with_nul(self) -> usize {
        self.command_units_with_nul
    }

    pub fn identity(self) -> u64 {
        self.identity
    }

    /// borrowed 计长先于 Command/OsString/PathBuf/CString 或启动编码的 owned 构造。
    pub fn from_paths(executable: &OsStr, database: &OsStr) -> Result<Self, Reject> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            if !std::path::Path::new(executable).is_absolute()
                || executable.encode_wide().any(|u| u == 0 || u == b'"' as u16)
                || database.to_str().is_none()
                || database.encode_wide().any(|u| u == 0)
            {
                return Err(Reject::InvalidPath);
            }
            let mut arguments = [ArgumentShape::default(); 2];
            let mut identity = Identity::new();
            for (index, path) in [executable, database].into_iter().enumerate() {
                identity.separator(index);
                for unit in path.encode_wide() {
                    arguments[index].utf16_units = capacity::add(arguments[index].utf16_units, 1)?;
                    identity.unit(unit);
                }
                arguments[index].encoded_bytes = path.as_encoded_bytes().len();
            }
            let db_units = quoted_units(database)?;
            let command_units_with_nul = capacity::add(
                capacity::add(arguments[0].utf16_units, db_units)?,
                4, // argv[0] 双引号、分隔空格、终止 NUL。
            )?;
            capacity::array::<u16>(command_units_with_nul)?;
            Ok(Self {
                arguments,
                command_units_with_nul,
                identity: identity.0,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (executable, database);
            Err(Reject::UnsupportedTarget)
        }
    }

    /// 不分配地重放已锁定 std 的命令行语义，供 helper 在 args_os 前核对启动形状。
    /// 空命令行的 current_exe fallback 不属于受信双参数 launcher 的证书。
    pub fn from_command_line(command: &[u16]) -> Result<Self, Reject> {
        if command.is_empty() || command.contains(&0) {
            return Err(Reject::InvalidLaunch);
        }
        let mut position = 0;
        let mut quote = false;
        let mut counts = [Utf16Count::default(); 2];
        let mut identity = Identity::new();
        identity.separator(0);
        while let Some(&unit) = command.get(position) {
            position += 1;
            match unit {
                34 => quote = !quote,
                9 | 32 if !quote => break,
                _ => {
                    counts[0].push(unit)?;
                    identity.unit(unit);
                }
            }
        }
        while command.get(position).is_some_and(|u| matches!(u, 9 | 32)) {
            position += 1;
        }
        if counts[0].units == 0 || position == command.len() {
            return Err(Reject::InvalidLaunch);
        }
        identity.separator(1);
        quote = false;
        // 参数解码以 slash run 为单位；不保存字符或动态节点。
        while let Some(&unit) = command.get(position) {
            if matches!(unit, 9 | 32) && !quote {
                while command.get(position).is_some_and(|u| matches!(u, 9 | 32)) {
                    position += 1;
                }
                if position != command.len() {
                    return Err(Reject::InvalidLaunch);
                }
                break;
            }
            let mut slashes = 0usize;
            while command.get(position) == Some(&92) {
                slashes = capacity::add(slashes, 1)?;
                position += 1;
            }
            let is_quote = command.get(position) == Some(&34);
            let literal_slashes = if is_quote { slashes / 2 } else { slashes };
            for _ in 0..literal_slashes {
                counts[1].push(92)?;
                identity.unit(92);
            }
            if slashes % 2 == 1 && is_quote {
                counts[1].push(34)?;
                identity.unit(34);
                position += 1;
            } else if is_quote {
                position += 1;
                if quote && command.get(position) == Some(&34) {
                    counts[1].push(34)?;
                    identity.unit(34);
                    position += 1;
                } else {
                    quote = !quote;
                }
            } else if let Some(&unit) = command.get(position) {
                // slash run 后的空白必须留给下一轮分隔判断。
                if matches!(unit, 9 | 32) && !quote {
                    continue;
                }
                counts[1].push(unit)?;
                identity.unit(unit);
                position += 1;
            }
        }
        let first = counts[0].finish(false)?;
        let second = counts[1].finish(true)?;
        let command_units_with_nul = capacity::add(command.len(), 1)?;
        capacity::array::<u16>(command_units_with_nul)?;
        Ok(Self {
            arguments: [first, second],
            command_units_with_nul,
            identity: identity.0,
        })
    }

    /// 输出到父已取得的 backing；空间不足时一个 code unit 也不写。
    pub fn write_command_line(
        self,
        executable: &OsStr,
        database: &OsStr,
        output: &mut [u16],
    ) -> Result<usize, Reject> {
        if Self::from_paths(executable, database)? != self {
            return Err(Reject::CertificateMismatch);
        }
        if output.len() < self.command_units_with_nul {
            return Err(Reject::RustBudgetExceeded);
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let mut position = 0;
            let mut put = |unit| {
                output[position] = unit;
                position += 1;
            };
            put(34);
            for unit in executable.encode_wide() {
                put(unit);
            }
            put(34);
            put(32);
            let quote = needs_quotes(database);
            if quote {
                put(34);
            }
            let mut slashes = 0;
            for unit in database.encode_wide() {
                if unit == 34 {
                    for _ in 0..=slashes {
                        put(92);
                    }
                }
                put(unit);
                slashes = if unit == 92 { slashes + 1 } else { 0 };
            }
            if quote {
                for _ in 0..slashes {
                    put(92);
                }
                put(34);
            }
            put(0);
            Ok(position)
        }
        #[cfg(not(windows))]
        {
            let _ = output;
            Err(Reject::UnsupportedTarget)
        }
    }
}

#[cfg(windows)]
fn needs_quotes(path: &OsStr) -> bool {
    path.is_empty() || path.as_encoded_bytes().iter().any(|b| matches!(b, 9 | 32))
}

#[cfg(windows)]
fn quoted_units(path: &OsStr) -> Result<usize, Reject> {
    use std::os::windows::ffi::OsStrExt;
    let quote = needs_quotes(path);
    let mut units = if quote { 2 } else { 0 };
    let mut slashes = 0;
    for unit in path.encode_wide() {
        units = capacity::add(units, 1)?;
        if unit == 34 {
            units = capacity::add(units, capacity::add(slashes, 1)?)?;
        }
        slashes = if unit == 92 {
            capacity::add(slashes, 1)?
        } else {
            0
        };
    }
    if quote {
        units = capacity::add(units, slashes)?;
    }
    Ok(units)
}

#[derive(Clone, Copy, Default)]
struct Utf16Count {
    units: usize,
    bytes: usize,
    high: bool,
    invalid: bool,
}

impl Utf16Count {
    fn push(&mut self, unit: u16) -> Result<(), Reject> {
        self.units = capacity::add(self.units, 1)?;
        if self.high {
            self.high = false;
            if (0xdc00..=0xdfff).contains(&unit) {
                self.bytes = capacity::add(self.bytes, 4)?;
                return Ok(());
            }
            self.bytes = capacity::add(self.bytes, 3)?;
            self.invalid = true;
        }
        match unit {
            0xd800..=0xdbff => self.high = true,
            0xdc00..=0xdfff => {
                self.invalid = true;
                self.bytes = capacity::add(self.bytes, 3)?;
            }
            0..=0x7f => self.bytes = capacity::add(self.bytes, 1)?,
            0x80..=0x7ff => self.bytes = capacity::add(self.bytes, 2)?,
            _ => self.bytes = capacity::add(self.bytes, 3)?,
        }
        Ok(())
    }

    fn finish(mut self, require_utf8: bool) -> Result<ArgumentShape, Reject> {
        if self.high {
            self.invalid = true;
            self.bytes = capacity::add(self.bytes, 3)?;
        }
        if require_utf8 && self.invalid {
            return Err(Reject::InvalidPath);
        }
        Ok(ArgumentShape {
            utf16_units: self.units,
            encoded_bytes: self.bytes,
        })
    }
}

// 非密码学关联值，不替代可信 binary 定位、构建证据或请求 nonce。
struct Identity(u64);
impl Identity {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }
    fn separator(&mut self, index: usize) {
        self.unit(0);
        self.unit(index as u16);
    }
    fn unit(&mut self, unit: u16) {
        for byte in unit.to_le_bytes() {
            self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
    }
}
