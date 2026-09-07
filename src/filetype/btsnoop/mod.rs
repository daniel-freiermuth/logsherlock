// LogCrab - GPL-3.0-or-later
// Copyright (C) 2026 Daniel Freiermuth

mod avrcp;
mod hci;
mod hfp;
mod rfcomm;

use anyhow::Context as _;
use chrono::{DateTime, Local, TimeDelta};
use egui::Ui;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::filetype::{BinaryFileType, InputFileType, LineType};

pub use hci::HciPacketInfo;

// ============================================================================
// BtsnoopLogLine
// ============================================================================

/// `BTSnoop` (Bluetooth HCI log) format log line representing an HCI packet
#[derive(Debug, Clone)]
pub struct BtsnoopLogLine {
    /// Parsed HCI packet information
    pub hci_info: HciPacketInfo,
    /// Original packet number in source file
    pub line_number: usize,
}

impl BtsnoopLogLine {
    #[must_use]
    pub const fn new(hci_info: HciPacketInfo, line_number: usize) -> Self {
        Self {
            hci_info,
            line_number,
        }
    }
}

// ============================================================================
// BtsnoopFileState
// ============================================================================

/// Type alias kept for compatibility; the shared [`crate::filetype::SimpleFileState`]
/// provides all interior-mutable time-offset and calibration state.
pub type BtsnoopFileState = crate::filetype::SimpleFileState;

// ============================================================================
// LineType implementation
// ============================================================================

impl LineType for BtsnoopLogLine {
    type Config = ();
    type FileState = BtsnoopFileState;

    fn file_state_from_v2(time_offset_ms: i64) -> BtsnoopFileState {
        let s = BtsnoopFileState::default();
        s.set_time_offset_ms(time_offset_ms);
        s
    }

    fn timestamp(&self, _config: &(), file_state: &BtsnoopFileState) -> DateTime<Local> {
        self.hci_info.timestamp + chrono::Duration::milliseconds(file_state.time_offset_ms())
    }

    fn message(&self) -> String {
        self.hci_info.format_message()
    }

    fn display_message(&self, _config: &(), file_state: &BtsnoopFileState) -> String {
        let offset_ms = file_state.time_offset_ms();
        if offset_ms != 0 {
            format!(
                "[{}] {}",
                crate::parser::format_time_diff(chrono::Duration::milliseconds(offset_ms)),
                self.message()
            )
        } else {
            self.hci_info.format_message()
        }
    }

    fn raw(&self) -> String {
        self.hci_info.format_raw()
    }

    fn line_number(&self) -> usize {
        self.line_number
    }

    fn egui_render_context_menu(&self, ui: &mut Ui, _config: &(), file_state: &BtsnoopFileState) {
        if ui.button("⏱ Calibrate Time Here").clicked() {
            let raw_time = self.hci_info.timestamp;
            let display_time =
                raw_time + chrono::Duration::milliseconds(file_state.time_offset_ms());
            *file_state
                .calibration
                .lock()
                .expect("calibration lock poisoned") = Some((
                raw_time,
                crate::filetype::CalibrationWindow::new(
                    display_time,
                    false,
                    Some(display_time),
                    raw_time,
                ),
            ));
            ui.close();
        }
    }
}

// ============================================================================
// BtsnoopFileType (InputFileType + BinaryFileType)
// ============================================================================

/// Stateful reader for Bluetooth HCI logs in the `BTSnoop` format.
///
/// All packets are parsed eagerly at `open()` time (the `btsnoop` crate requires the
/// full file in memory), then drained in chunks via `read()`.
pub struct BtsnoopFileType {
    lines: Vec<BtsnoopLogLine>,
    cursor: usize,
    file_size: u64,
}

impl InputFileType for BtsnoopFileType {
    type LineType = BtsnoopLogLine;

    const FILE_EXTENSIONS: &'static [&'static str] = &["log", "btsnoop"];

    fn open(
        path: &Path,
        _config: (),
        _file_state: std::sync::Arc<BtsnoopFileState>,
    ) -> anyhow::Result<Self> {
        let file_size = std::fs::metadata(path).map_or(0, |m| m.len());
        let lines = parse_btsnoop_to_lines(path)?;
        Ok(Self {
            lines,
            cursor: 0,
            file_size,
        })
    }

    fn read(&mut self, lines_to_read: usize) -> anyhow::Result<Vec<Self::LineType>> {
        let end = (self.cursor + lines_to_read).min(self.lines.len());
        let batch = self.lines[self.cursor..end].to_vec();
        self.cursor = end;
        Ok(batch)
    }

    fn bytes_consumed(&self) -> u64 {
        let total = self.lines.len();
        if total == 0 {
            return self.file_size;
        }
        (self.cursor as f64 / total as f64 * self.file_size as f64) as u64
    }
}

impl BinaryFileType for BtsnoopFileType {
    /// `BTSnoop` file magic: `btsnoop\0` (8 bytes)
    const MAGIC_BYTES: &'static [&'static [u8]] = &[b"btsnoop\0"];
}

// ============================================================================
// BTSnoop file reader
// ============================================================================

/// Parse all HCI packets from a btsnoop file and return them as typed log lines.
///
/// All packets are parsed eagerly since the `btsnoop` crate requires the entire file to be
/// in memory.
fn parse_btsnoop_to_lines<P: AsRef<Path>>(path: P) -> anyhow::Result<Vec<BtsnoopLogLine>> {
    profiling::scope!("parse_btsnoop_to_lines");
    let path = path.as_ref();
    tracing::info!("Starting btsnoop parsing: {}", path.display());

    let mut file = File::open(path)
        .with_context(|| format!("Failed to open btsnoop file: {}", path.display()))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .with_context(|| format!("Failed to read btsnoop file: {}", path.display()))?;

    let btsnoop_file = btsnoop::parse_btsnoop_file(&buffer)
        .map_err(|e| anyhow::anyhow!("Failed to parse btsnoop file: {e:?}"))?;

    let mut lines = Vec::with_capacity(btsnoop_file.packets.len());
    let mut line_number = 1usize;

    for packet in &btsnoop_file.packets {
        let duration_since_unix = packet.header.timestamp();
        let Some(timestamp) = TimeDelta::from_std(duration_since_unix)
            .ok()
            .and_then(|delta| {
                DateTime::from_timestamp(0, 0).map(|epoch| (epoch + delta).with_timezone(&Local))
            })
        else {
            tracing::warn!("Failed to convert packet timestamp at line {line_number}, skipping");
            line_number += 1;
            continue;
        };

        if let Some(hci_info) = hci::parse_hci_packet(packet, timestamp) {
            lines.push(BtsnoopLogLine::new(hci_info, line_number));
        }
        line_number += 1;
    }

    tracing::info!("Parsed {} HCI packets from btsnoop file", lines.len());
    Ok(lines)
}
