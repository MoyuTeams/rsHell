use std::{fmt, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::terminal::{KeyCode, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
    pub pixel_width: u32,
    pub pixel_height: u32,
    pub dpi: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Viewport {
    pub top_stable_row: i64,
    pub rows: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellPosition {
    pub stable_row: i64,
    pub column: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionRange {
    pub start: CellPosition,
    pub end: CellPosition,
    pub rectangular: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    pub needle: String,
    pub case_sensitive: bool,
    pub regex: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchMatch {
    pub start: CellPosition,
    pub end: CellPosition,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalDisplayModes {
    pub alternate_screen: bool,
    pub enhanced_keyboard: bool,
    pub mouse_reporting: bool,
    pub application_cursor: bool,
    pub cursor_hidden: bool,
    pub stale_title: bool,
    /// Bracketed paste (DECSET 2004) is on: the frontend must wrap pasted text in
    /// `ESC [200~` … `ESC [201~`. Not residue — shells turn it on at the prompt.
    #[serde(default)]
    pub bracketed_paste: bool,
}

impl TerminalDisplayModes {
    pub const fn has_residue(self) -> bool {
        self.alternate_screen
            || self.enhanced_keyboard
            || self.mouse_reporting
            || self.application_cursor
            || self.cursor_hidden
            || self.stale_title
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayRecovery {
    pub before: TerminalDisplayModes,
    pub after: TerminalDisplayModes,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderFrame {
    pub generation: u64,
    pub size: TerminalSize,
    pub viewport_top: i64,
    pub rows: Arc<[RenderRow]>,
    pub cursor: Option<RenderCursor>,
    pub title: String,
    #[serde(default)]
    pub display_modes: TerminalDisplayModes,
    #[serde(default)]
    pub alternate_screen: bool,
    #[serde(default)]
    pub mouse_reporting: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderRow {
    pub stable_row: i64,
    pub wrapped: bool,
    pub cells: Arc<[RenderCell]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderCell {
    pub text: String,
    pub width: u8,
    pub foreground: Color,
    pub background: Color,
    pub attributes: CellAttributes,
    #[serde(default)]
    pub selected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Color {
    Default,
    Ansi(u8),
    Rgb(u8, u8, u8),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellAttributes {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
    pub reverse: bool,
    /// SGR 2（dim/faint）。缺省为 false，兼容不含该字段的旧序列化数据。
    #[serde(default)]
    pub dim: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderCursor {
    pub position: CellPosition,
    pub shape: CursorShape,
    pub visible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorShape {
    Block,
    Beam,
    Underline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus {
    pub code: Option<i32>,
    pub success: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionFailure {
    Validation,
    Storage,
    Vault,
    HostKeyRejected,
    HostKeyChanged,
    Authentication,
    Network,
    Pty,
    SshChannel,
    Subprocess,
    Platform,
    Backpressure,
    Timeout,
    Crashed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    Connecting,
    AwaitingHostKey,
    AwaitingAuthentication,
    Connected,
    Reconnecting,
    Closing,
    Exited,
    Failed,
    Crashed,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalInput {
    CommittedText(String),
    Key {
        code: KeyCode,
        modifiers: KeyModifiers,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEventPhase {
    Press,
    Repeat,
    Release,
}

/// 同一硬件事件的双表示；不表示原生文本提交或 IME 文本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalKeyEvent {
    /// 当前布局下未移位的逻辑键；编码器不猜测布局或反推 Shift。
    pub code: KeyCode,
    /// 原调用适配器处理 Shift/布局后交给旧入口的键；非字符键须与 code 相同。
    pub legacy_code: KeyCode,
    pub modifiers: KeyModifiers,
    pub phase: KeyEventPhase,
}

impl fmt::Debug for TerminalInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommittedText(_) => formatter.write_str("CommittedText([REDACTED])"),
            Self::Key { code, modifiers } => formatter
                .debug_struct("Key")
                .field("code", code)
                .field("modifiers", modifiers)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalMouseEvent {
    pub kind: MouseEventKind,
    pub button: Option<MouseButton>,
    pub cell: CellPosition,
    /// Zero-based row in the frame viewport captured with this event.
    #[serde(default)]
    pub viewport_row: u16,
    pub pixel_x: u32,
    pub pixel_y: u32,
    pub modifiers: KeyModifiers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseEventKind {
    Press,
    Release,
    Move,
    Scroll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    Back,
    Forward,
    WheelUp,
    WheelDown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_input_fixtures_keep_decode_and_exhaustive_match() {
        fn old_match(input: TerminalInput) -> String {
            match input {
                TerminalInput::CommittedText(text) => text,
                TerminalInput::Key { code, modifiers } => {
                    assert_eq!(code, KeyCode::Character('A'));
                    assert!(modifiers.shift && modifiers.control);
                    "key".into()
                }
            }
        }

        let text_fixture = r#"{"CommittedText":"输入文本"}"#;
        let key_fixture = r#"{"Key":{"code":{"character":"A"},"modifiers":{"shift":true,"control":true,"alt":false,"super_key":false}}}"#;
        for (fixture, expected) in [(text_fixture, "输入文本"), (key_fixture, "key")] {
            let input: TerminalInput = serde_json::from_str(fixture).unwrap();
            assert_eq!(serde_json::to_string(&input).unwrap(), fixture);
            assert_eq!(old_match(input), expected);
        }
    }

    #[test]
    fn cell_attributes_without_dim_field_decode_as_not_dim() {
        let old =
            r#"{"bold":true,"italic":false,"underline":false,"strike":false,"reverse":false}"#;
        let attributes: CellAttributes = serde_json::from_str(old).unwrap();
        assert!(attributes.bold);
        assert!(!attributes.dim);

        let dim = CellAttributes {
            dim: true,
            ..CellAttributes::default()
        };
        let encoded = serde_json::to_string(&dim).unwrap();
        assert_eq!(
            serde_json::from_str::<CellAttributes>(&encoded).unwrap(),
            dim
        );
    }
}
