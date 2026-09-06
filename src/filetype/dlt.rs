// LogCrab - GPL-3.0-or-later
// Copyright (C) 2026 Daniel Freiermuth

use chrono::{DateTime, Local};
use dashmap::DashMap;
use dlt_core::read::{read_message, DltMessageReader};
use egui::Ui;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::{
    atomic::{AtomicI64, AtomicU64, Ordering},
    Arc, Mutex,
};

use crate::filetype::{BinaryFileType, EguiConfig, InputFileType, LineType};
use crate::parser::format_time_diff;

// ============================================================================
// DltLogLine
// ============================================================================

/// DLT (Diagnostic Log and Trace) binary format log line
#[derive(Debug, Clone)]
pub struct DltLogLine {
    /// Parsed DLT message structure
    pub dlt_message: dlt_core::dlt::Message,
    /// Storage header wall-clock timestamp (always available)
    pub storage_time: DateTime<Local>,
    /// Header timestamp in microseconds (time since boot).
    /// `None` when the DLT message has no header timestamp field.
    pub header_timestamp_us: Option<i64>,
    /// Cached ECU ID (empty string when absent)
    pub ecu_id: String,
    /// Cached application ID (empty string when absent)
    pub app_id: String,
    /// Original line number in source file
    pub line_number: usize,
}

impl DltLogLine {
    #[must_use]
    pub const fn new(
        dlt_message: dlt_core::dlt::Message,
        storage_time: DateTime<Local>,
        header_timestamp_us: Option<i64>,
        ecu_id: String,
        app_id: String,
        line_number: usize,
    ) -> Self {
        Self {
            dlt_message,
            storage_time,
            header_timestamp_us,
            ecu_id,
            app_id,
            line_number,
        }
    }

    /// Format DLT message for display.
    ///
    /// `inferred_time` is the calibrated monotonic timestamp when available
    /// (i.e. when in `InferredMonotonic` mode and a boot-time exists for this
    /// line's `(ecu_id, app_id)`). When `None`, storage-time display is used.
    /// Returns the metadata + payload body: `{ecu} {session} {app} {ctx} {type} {payload}`.
    /// Used directly by `message()` and as the trailing part of `display_message()`.
    fn format_body(&self) -> String {
        use dlt_core::dlt::PayloadContent;

        let ecu_header = self
            .dlt_message
            .header
            .ecu_id
            .as_deref()
            .unwrap_or("UnknownECU");
        let session_id = self.dlt_message.header.session_id.unwrap_or(0);

        let (message_type, app_id, ctx_id) = self.dlt_message.extended_header.as_ref().map_or_else(
            || ("Unknown".to_string(), "", ""),
            |ext_header| {
                (
                    format!("{:?}", ext_header.message_type),
                    ext_header.application_id.as_str(),
                    ext_header.context_id.as_str(),
                )
            },
        );

        let payload = match &self.dlt_message.payload {
            PayloadContent::Verbose(args) => {
                let formatted_args: Vec<String> = args
                    .iter()
                    .map(|arg| {
                        let val_str = match &arg.value {
                            dlt_core::dlt::Value::StringVal(s) => s.clone(),
                            dlt_core::dlt::Value::U32(v) => format!("{v}"),
                            dlt_core::dlt::Value::U64(v) => format!("{v}"),
                            dlt_core::dlt::Value::U8(v) => format!("{v}"),
                            dlt_core::dlt::Value::U16(v) => format!("{v}"),
                            dlt_core::dlt::Value::I32(v) => format!("{v}"),
                            dlt_core::dlt::Value::I64(v) => format!("{v}"),
                            dlt_core::dlt::Value::I8(v) => format!("{v}"),
                            dlt_core::dlt::Value::I16(v) => format!("{v}"),
                            dlt_core::dlt::Value::F32(v) => format!("{v}"),
                            dlt_core::dlt::Value::F64(v) => format!("{v}"),
                            dlt_core::dlt::Value::Bool(v) => format!("{v}"),
                            dlt_core::dlt::Value::U128(v) => format!("{v}"),
                            dlt_core::dlt::Value::I128(v) => format!("{v}"),
                            dlt_core::dlt::Value::Raw(bytes) => format!("{bytes:02x?}"),
                        };
                        arg.name
                            .as_ref()
                            .map(|name| format!("{name}: {val_str}"))
                            .unwrap_or(val_str)
                    })
                    .collect();
                formatted_args.join(" || ")
            }
            PayloadContent::NonVerbose(_, bytes) => format!("{bytes:02x?}"),
            PayloadContent::ControlMsg(_, bytes) => format!("ControlMsg: {bytes:02x?}"),
            PayloadContent::NetworkTrace(traces) => {
                format!("NetworkTrace: {} traces", traces.len())
            }
        };

        format!("{ecu_header} {session_id} {app_id} {ctx_id} {message_type} {payload}")
    }

    /// Returns the `[<storage_time> (<diff>) <storage_ecu>]` prefix for inferred-monotonic mode.
    fn format_time_prefix(&self, inferred_time: DateTime<Local>) -> String {
        let storage_ecu = self
            .dlt_message
            .storage_header
            .as_ref()
            .map_or("", |sh| sh.ecu_id.as_str());
        let diff_str = format_time_diff(self.storage_time.signed_duration_since(inferred_time));
        format!("[{} ({diff_str}) {storage_ecu}]", self.storage_time)
    }
}

// ============================================================================
// SyncPoint
// ============================================================================

/// A time sync point that introduces a time offset for all lines from a given
/// line number onwards. Multiple sync points create piecewise-constant offsets
/// along the file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncPoint {
    /// The line number from which this offset takes effect (inclusive).
    pub from_line: usize,
    /// The time offset in milliseconds to apply.
    pub offset_ms: i64,
}

// ============================================================================
// DltFileState
// ============================================================================

/// Pending calibration for a DLT source.
///
/// Created by `egui_render_context_menu`; driven each frame by
/// `DltFileState::egui_render_file_state`. `#[serde(skip)]` — not persisted.
#[derive(Debug, Clone)]
pub struct DltCalibrationState {
    /// ECU ID of the right-clicked line.
    pub ecu_id: String,
    /// Application ID of the right-clicked line.
    pub app_id: String,
    /// Header timestamp of the right-clicked line in microseconds (time since boot).
    pub header_timestamp_us: i64,
    /// Whether this calibration was opened in inferred-monotonic mode.
    /// When `false` the result updates `storage_offset_ms` instead of `boot_times`.
    pub is_inferred: bool,
    /// Raw storage timestamp of the right-clicked line (before any offset).
    /// Used to compute the new `storage_offset_ms` in storage-time mode.
    pub storage_time: chrono::DateTime<chrono::Local>,
    /// The calibration UI window.
    pub window: crate::filetype::CalibrationWindow,
}

/// Pending sync-point calibration — the user right-clicked a line and wants
/// to set a sync point starting at that line number.
pub struct DltSyncPointCalibration {
    /// Line number from which this sync point will apply.
    pub from_line: usize,
    /// The raw storage timestamp of the right-clicked line.
    pub storage_time: chrono::DateTime<chrono::Local>,
    /// Header timestamp (monotonic) of the right-clicked line, if available.
    pub header_timestamp_us: Option<i64>,
    /// ECU ID for inferred boot-time lookup.
    pub ecu_id: String,
    /// App ID for inferred boot-time lookup.
    pub app_id: String,
    /// Whether we're in inferred-monotonic mode.
    pub is_inferred: bool,
    /// The calibration UI window.
    pub window: crate::filetype::CalibrationWindow,
}

/// Per-source persistent state for DLT log sources.
///
/// Owns its interior synchronization so it can live in a bare `Arc` with no
/// outer `RwLock`:
/// - `storage_offset_ms`: `AtomicI64` — lock-free reads from rayon worker threads
/// - `boot_times`: `Arc<DashMap>` — inline writes from `DltFileType::read()` without locking
/// - `calibration`: `Mutex<Option<...>>` — UI-thread-only, always uncontended
pub struct DltFileState {
    /// Storage-time mode: offset added to every `storage_time` timestamp.
    pub storage_offset_ms: AtomicI64,
    /// Inferred-time mode: corrected boot times per `(ecu_id, app_id)`.
    ///
    /// Seeded inline during file loading (first-seen storage heuristic). User
    /// calibration writes into this map and the values are persisted to
    /// `.crab`. On re-open, persisted values take precedence over the
    /// freshly computed defaults, preserving calibration across sessions.
    pub boot_times: Arc<DashMap<(String, String), DateTime<Local>>>,
    /// Sync points: piecewise time offsets that apply from a given line number onwards.
    /// Sorted by `from_line` ascending. Each sync point's offset is *absolute* (not cumulative).
    pub sync_points: Mutex<Vec<SyncPoint>>,
    /// Open calibration window, if any. Not persisted.
    pub calibration: Mutex<Option<DltCalibrationState>>,
    /// Open sync-point calibration window, if any. Not persisted.
    pub sync_point_calibration: Mutex<Option<DltSyncPointCalibration>>,
    /// Whether the sync points management window is open. Not persisted.
    pub show_sync_points_window: std::sync::atomic::AtomicBool,
    /// Pending line jump request from sync-point window click. `usize::MAX` = none.
    pub pending_jump_line: std::sync::atomic::AtomicUsize,
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "sync-point locks intentionally span UI edits to keep each frame's state coherent"
)]
impl DltFileState {
    #[inline]
    pub fn storage_offset_ms(&self) -> i64 {
        self.storage_offset_ms.load(Ordering::Relaxed)
    }

    /// Look up the sync-point offset that applies to a given line number.
    /// Returns 0 if no sync point applies.
    ///
    /// # Panics
    ///
    /// Panics if the sync-points mutex is poisoned.
    pub fn sync_point_offset_ms(&self, line_number: usize) -> i64 {
        let sync_points = self.sync_points.lock().expect("sync_points lock poisoned");
        // Binary search: find the last sync point with from_line <= line_number
        match sync_points.binary_search_by_key(&line_number, |sp| sp.from_line) {
            Ok(idx) => sync_points[idx].offset_ms,
            Err(0) => 0, // line_number is before any sync point
            Err(idx) => sync_points[idx - 1].offset_ms,
        }
    }
}

impl Default for DltFileState {
    fn default() -> Self {
        Self {
            storage_offset_ms: AtomicI64::new(0),
            boot_times: Arc::new(DashMap::new()),
            sync_points: Mutex::new(Vec::new()),
            calibration: Mutex::new(None),
            sync_point_calibration: Mutex::new(None),
            show_sync_points_window: std::sync::atomic::AtomicBool::new(false),
            pending_jump_line: std::sync::atomic::AtomicUsize::new(usize::MAX),
        }
    }
}

impl std::fmt::Debug for DltFileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sp_count = self.sync_points.lock().map_or(0, |v| v.len());
        f.debug_struct("DltFileState")
            .field("storage_offset_ms", &self.storage_offset_ms())
            .field("boot_times_count", &self.boot_times.len())
            .field("sync_points_count", &sp_count)
            .finish_non_exhaustive()
    }
}

impl Clone for DltFileState {
    /// Deep-clones `boot_times` into a fresh `Arc<DashMap>`.
    /// Calibration is transient UI state and is not cloned.
    fn clone(&self) -> Self {
        let bt: DashMap<(String, String), DateTime<Local>> = self
            .boot_times
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        let sp = self
            .sync_points
            .lock()
            .expect("sync_points lock poisoned")
            .clone();
        Self {
            storage_offset_ms: AtomicI64::new(self.storage_offset_ms()),
            boot_times: Arc::new(bt),
            sync_points: Mutex::new(sp),
            calibration: Mutex::new(None),
            sync_point_calibration: Mutex::new(None),
            show_sync_points_window: std::sync::atomic::AtomicBool::new(
                self.show_sync_points_window.load(Ordering::Relaxed),
            ),
            pending_jump_line: std::sync::atomic::AtomicUsize::new(usize::MAX),
        }
    }
}

/// Separator used to encode `(ecu_id, app_id)` tuple keys as JSON-safe strings.
/// ASCII unit-separator (0x1F) is safe: DLT IDs are printable ASCII.
const BOOT_TIME_KEY_SEP: char = '\x1F';

fn boot_times_to_string_map(
    bt: &DashMap<(String, String), DateTime<Local>>,
) -> std::collections::BTreeMap<String, DateTime<Local>> {
    bt.iter()
        .map(|e| {
            let key = format!("{}{BOOT_TIME_KEY_SEP}{}", e.key().0, e.key().1);
            (key, *e.value())
        })
        .collect()
}

fn string_map_to_boot_times(
    map: std::collections::BTreeMap<String, DateTime<Local>>,
) -> DashMap<(String, String), DateTime<Local>> {
    map.into_iter()
        .filter_map(|(k, v)| {
            let (ecu, app) = k.split_once(BOOT_TIME_KEY_SEP)?;
            Some(((ecu.to_string(), app.to_string()), v))
        })
        .collect()
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the lock must span serialization of the sync-point snapshot"
)]
impl serde::Serialize for DltFileState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let sp = self.sync_points.lock().expect("sync_points lock poisoned");
        let mut state = s.serialize_struct("DltFileState", 3)?;
        state.serialize_field("storage_offset_ms", &self.storage_offset_ms())?;
        state.serialize_field("boot_times", &boot_times_to_string_map(&self.boot_times))?;
        state.serialize_field("sync_points", &*sp)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for DltFileState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Helper {
            #[serde(default)]
            storage_offset_ms: i64,
            #[serde(default)]
            boot_times: std::collections::BTreeMap<String, DateTime<Local>>,
            #[serde(default)]
            sync_points: Vec<SyncPoint>,
        }
        let h = Helper::deserialize(d)?;
        Ok(Self {
            storage_offset_ms: AtomicI64::new(h.storage_offset_ms),
            boot_times: Arc::new(string_map_to_boot_times(h.boot_times)),
            sync_points: Mutex::new(h.sync_points),
            calibration: Mutex::new(None),
            sync_point_calibration: Mutex::new(None),
            show_sync_points_window: std::sync::atomic::AtomicBool::new(false),
            pending_jump_line: std::sync::atomic::AtomicUsize::new(usize::MAX),
        })
    }
}

// ============================================================================
// EguiConfig for DltTimestampSource
// ============================================================================

impl EguiConfig for crate::config::DltTimestampSource {
    fn egui_render(&mut self, ui: &mut Ui) -> bool {
        ui.separator();
        ui.label("DLT Timestamp Source:");
        let mut changed = false;
        ui.horizontal(|ui| {
            changed |= ui
                .selectable_value(self, Self::StorageTime, "Storage Timestamp")
                .changed();
            changed |= ui
                .selectable_value(self, Self::InferredMonotonic, "Infer From Monotonic")
                .on_hover_text("More precise in limited timespans")
                .changed();
        });
        changed
    }
}

// ============================================================================
// LineType implementation
// ============================================================================

impl LineType for DltLogLine {
    /// `DltTimestampSource` selects between storage-header wall-clock time and
    /// inferred monotonic timestamps.  Shared across all DLT sources in a
    /// session via `Arc<RwLock<DltTimestampSource>>`.
    type Config = crate::config::DltTimestampSource;
    type FileState = DltFileState;

    fn file_state_from_v2(time_offset_ms: i64) -> DltFileState {
        DltFileState {
            storage_offset_ms: std::sync::atomic::AtomicI64::new(time_offset_ms),
            ..Default::default()
        }
    }

    fn timestamp(
        &self,
        config: &crate::config::DltTimestampSource,
        file_state: &DltFileState,
    ) -> DateTime<Local> {
        use crate::config::DltTimestampSource;
        let sync_offset = file_state.sync_point_offset_ms(self.line_number);
        match config {
            DltTimestampSource::InferredMonotonic => {
                if let Some(header_us) = self.header_timestamp_us {
                    let key = (self.ecu_id.clone(), self.app_id.clone());
                    if let Some(boot_time) = file_state.boot_times.get(&key) {
                        return *boot_time
                            + chrono::TimeDelta::microseconds(header_us)
                            + chrono::Duration::milliseconds(sync_offset);
                    }
                }
                // Fallback: no boot_time for this app yet
                self.storage_time
                    + chrono::Duration::milliseconds(file_state.storage_offset_ms() + sync_offset)
            }
            DltTimestampSource::StorageTime => {
                self.storage_time
                    + chrono::Duration::milliseconds(file_state.storage_offset_ms() + sync_offset)
            }
        }
    }

    fn message(&self) -> String {
        self.format_body()
    }

    fn display_message(
        &self,
        config: &crate::config::DltTimestampSource,
        file_state: &DltFileState,
    ) -> String {
        use crate::config::DltTimestampSource;
        let body = self.format_body();
        let sync_offset = file_state.sync_point_offset_ms(self.line_number);
        let sync_prefix = if sync_offset != 0 {
            format!(
                "[sync:{}] ",
                format_time_diff(chrono::Duration::milliseconds(sync_offset))
            )
        } else {
            String::new()
        };
        match config {
            DltTimestampSource::InferredMonotonic => {
                // In inferred-monotonic mode prepend [<storage_time> (<diff>) <storage_ecu>]
                // so the user always sees the relationship between storage and monotonic time.
                let inferred_time = self.timestamp(config, file_state);
                format!(
                    "{sync_prefix}{} {body}",
                    self.format_time_prefix(inferred_time)
                )
            }
            DltTimestampSource::StorageTime => {
                // In storage-time mode prepend [<offset>] when a calibration offset
                // has been applied, consistent with how other file types behave.
                let offset_ms = file_state.storage_offset_ms();
                if offset_ms != 0 {
                    format!(
                        "{sync_prefix}[{}] {body}",
                        format_time_diff(chrono::Duration::milliseconds(offset_ms))
                    )
                } else {
                    format!("{sync_prefix}{body}")
                }
            }
        }
    }

    fn raw(&self) -> String {
        format!("{:?}", self.dlt_message)
    }

    fn line_number(&self) -> usize {
        self.line_number
    }

    fn egui_render_context_menu(
        &self,
        ui: &mut Ui,
        config: &crate::config::DltTimestampSource,
        file_state: &DltFileState,
    ) {
        if ui.button("\u{23F1} Calibrate Time Here").clicked() {
            use crate::config::DltTimestampSource;

            let is_inferred = matches!(config, DltTimestampSource::InferredMonotonic)
                && self.header_timestamp_us.is_some();

            // Current display time: inferred if available, otherwise storage.
            let current_time = if is_inferred {
                let header_us = self
                    .header_timestamp_us
                    .expect("header_timestamp_us is Some when is_inferred");
                let key = (self.ecu_id.clone(), self.app_id.clone());
                file_state
                    .boot_times
                    .get(&key)
                    .map_or(self.storage_time, |bt| {
                        *bt + chrono::TimeDelta::microseconds(header_us)
                    })
            } else {
                self.storage_time + chrono::Duration::milliseconds(file_state.storage_offset_ms())
            };

            *file_state
                .calibration
                .lock()
                .expect("calibration lock poisoned") = Some(DltCalibrationState {
                ecu_id: self.ecu_id.clone(),
                app_id: self.app_id.clone(),
                header_timestamp_us: self.header_timestamp_us.unwrap_or(0),
                is_inferred,
                storage_time: self.storage_time,
                window: crate::filetype::CalibrationWindow::new(
                    current_time,
                    is_inferred,
                    Some(current_time),
                    self.storage_time,
                ),
            });
            ui.close();
        }

        // Sync point: set a time offset that applies from this line onwards.
        if ui.button("\u{1F4CD} Set Sync Point Here").clicked() {
            use crate::config::DltTimestampSource;

            let is_inferred = matches!(config, DltTimestampSource::InferredMonotonic)
                && self.header_timestamp_us.is_some();

            let current_time = self.timestamp(config, file_state);

            *file_state
                .sync_point_calibration
                .lock()
                .expect("sync_point_calibration lock poisoned") = Some(DltSyncPointCalibration {
                from_line: self.line_number,
                storage_time: self.storage_time,
                header_timestamp_us: self.header_timestamp_us,
                ecu_id: self.ecu_id.clone(),
                app_id: self.app_id.clone(),
                is_inferred,
                window: crate::filetype::CalibrationWindow::new(
                    current_time,
                    false, // not DLT-specific "apply to all" mode
                    Some(current_time),
                    self.storage_time,
                ),
            });
            ui.close();
        }

        // Toggle sync points management window
        if ui.button("\u{1F4CD} Manage Sync Points").clicked() {
            file_state.show_sync_points_window.store(
                !file_state.show_sync_points_window.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            ui.close();
        }
    }
}

impl crate::filetype::LogFileState for DltFileState {
    fn take_pending_jump_line(&self) -> Option<usize> {
        let val = self.pending_jump_line.swap(usize::MAX, Ordering::Relaxed);
        if val == usize::MAX {
            None
        } else {
            Some(val)
        }
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "sync-point locks intentionally span each interactive UI update"
    )]
    fn egui_render_file_state(&self, ui: &egui::Ui, source_path: &std::path::Path) -> bool {
        let mut changed = false;

        // Drive the regular calibration window.
        {
            let mut cal_guard = self.calibration.lock().expect("calibration lock poisoned");
            if let Some(cal) = cal_guard.as_mut() {
                match cal.window.render(ui) {
                    crate::filetype::CalibrationResult::Confirmed {
                        target_time,
                        apply_to_all_apps,
                    } => {
                        if cal.is_inferred {
                            let new_boot_time = target_time
                                - chrono::TimeDelta::microseconds(cal.header_timestamp_us);
                            let key = (cal.ecu_id.clone(), cal.app_id.clone());
                            let ecu_id = cal.ecu_id.clone();

                            if apply_to_all_apps {
                                for mut entry in self.boot_times.iter_mut() {
                                    if entry.key().0 == ecu_id {
                                        *entry.value_mut() = new_boot_time;
                                    }
                                }
                                self.boot_times.entry(key).or_insert(new_boot_time);
                            } else {
                                self.boot_times.insert(key, new_boot_time);
                            }
                        } else {
                            let offset_ms = (target_time - cal.storage_time).num_milliseconds();
                            self.storage_offset_ms
                                .store(offset_ms, std::sync::atomic::Ordering::Relaxed);
                        }

                        *cal_guard = None;
                        changed = true;
                    }
                    crate::filetype::CalibrationResult::Pending => {}
                    crate::filetype::CalibrationResult::Cancelled => {
                        *cal_guard = None;
                    }
                }
            }
        }

        // Drive the sync-point calibration window.
        {
            let mut sp_cal_guard = self
                .sync_point_calibration
                .lock()
                .expect("sync_point_calibration lock poisoned");
            if let Some(sp_cal) = sp_cal_guard.as_mut() {
                match sp_cal.window.render(ui) {
                    crate::filetype::CalibrationResult::Confirmed { target_time, .. } => {
                        // Compute the offset: target_time - raw_time_of_this_line
                        // The raw time is the timestamp *without* the sync point offset
                        // that will be applied. We use the storage_time as the raw base.
                        let raw_time = if sp_cal.is_inferred {
                            if let Some(header_us) = sp_cal.header_timestamp_us {
                                let key = (sp_cal.ecu_id.clone(), sp_cal.app_id.clone());
                                self.boot_times.get(&key).map_or(sp_cal.storage_time, |bt| {
                                    *bt + chrono::TimeDelta::microseconds(header_us)
                                })
                            } else {
                                sp_cal.storage_time
                                    + chrono::Duration::milliseconds(self.storage_offset_ms())
                            }
                        } else {
                            sp_cal.storage_time
                                + chrono::Duration::milliseconds(self.storage_offset_ms())
                        };
                        let offset_ms = (target_time - raw_time).num_milliseconds();
                        let from_line = sp_cal.from_line;

                        let mut sync_points =
                            self.sync_points.lock().expect("sync_points lock poisoned");

                        // Remove any existing sync point at the same line.
                        sync_points.retain(|sp| sp.from_line != from_line);
                        // Insert and keep sorted.
                        let insert_pos = sync_points
                            .binary_search_by_key(&from_line, |sp| sp.from_line)
                            .unwrap_or_else(|pos| pos);
                        sync_points.insert(
                            insert_pos,
                            SyncPoint {
                                from_line,
                                offset_ms,
                            },
                        );

                        *sp_cal_guard = None;
                        // Auto-open the sync points window so the user sees the result.
                        self.show_sync_points_window.store(true, Ordering::Relaxed);
                        changed = true;
                    }
                    crate::filetype::CalibrationResult::Pending => {}
                    crate::filetype::CalibrationResult::Cancelled => {
                        *sp_cal_guard = None;
                    }
                }
            }
        }

        // Render sync points management panel when open.
        if self.show_sync_points_window.load(Ordering::Relaxed) {
            let mut sync_points = self.sync_points.lock().expect("sync_points lock poisoned");
            let mut to_remove: Option<usize> = None;
            let mut open = true;
            let window_title = format!(
                "\u{1F4CD} Sync Points — {}",
                source_path
                    .file_name()
                    .unwrap_or(source_path.as_os_str())
                    .to_string_lossy()
            );
            egui::Window::new(window_title)
                .open(&mut open)
                .collapsible(true)
                .resizable(true)
                .default_width(350.0)
                .show(ui.ctx(), |ui| {
                    if sync_points.is_empty() {
                        ui.label("No sync points set.\nRight-click a line → \"Set Sync Point Here\" to add one.");
                    } else {
                        ui.label("Time sync points (offset applies from line onwards):");
                        ui.add_space(4.0);
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                for (idx, sp) in sync_points.iter_mut().enumerate() {
                                    ui.horizontal(|ui| {
                                        // Clickable line label — jumps to that line.
                                        let line_label = format!("Line {}:", sp.from_line);
                                        if ui
                                            .link(&line_label)
                                            .on_hover_text("Click to jump to this line")
                                            .clicked()
                                        {
                                            self.pending_jump_line.store(
                                                sp.from_line - 1,
                                                Ordering::Relaxed,
                                            );
                                        }
                                        // Editable offset (ms) as a drag value.
                                        let mut offset_ms = sp.offset_ms as f64;
                                        let drag = egui::DragValue::new(&mut offset_ms)
                                            .suffix(" ms")
                                            .speed(100.0);
                                        if ui.add(drag).changed() {
                                            sp.offset_ms = offset_ms as i64;
                                            changed = true;
                                        }
                                        if ui
                                            .small_button("\u{1F5D1}")
                                            .on_hover_text("Remove sync point")
                                            .clicked()
                                        {
                                            to_remove = Some(idx);
                                        }
                                    });
                                }
                            });
                        ui.add_space(4.0);
                        if ui.button("Clear All").clicked() {
                            sync_points.clear();
                            changed = true;
                        }
                    }
                });
            if !open {
                self.show_sync_points_window.store(false, Ordering::Relaxed);
            }
            if let Some(idx) = to_remove {
                sync_points.remove(idx);
                changed = true;
            }
        }

        changed
    }
}

// ============================================================================
// DltFileType (InputFileType + BinaryFileType)
// ============================================================================

/// Minimal `Read` wrapper that counts bytes consumed, used for `ChunkedLoader` progress.
struct ByteCountReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: Read> ByteCountReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn bytes_read_arc(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.count)
    }
}

impl<R: Read> Read for ByteCountReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Stateful streaming reader for AUTOSAR Diagnostic Log and Trace (`.dlt`) files.
///
/// Holds a clone of the `Arc<DashMap>` from [`DltFileState::boot_times`] so that
/// each `read(n)` call can write newly discovered `(ECU, App)` boot-times directly
/// into the shared map — no lock acquisition, no end-of-chunk batch flush.
pub struct DltFileType {
    reader: DltMessageReader<ByteCountReader<BufReader<File>>>,
    /// Shared boot-time map — same `Arc` as `DltFileState::boot_times`.
    boot_times: Arc<DashMap<(String, String), DateTime<Local>>>,
    bytes_read_rc: Arc<AtomicU64>,
    line_number: usize,
}

impl InputFileType for DltFileType {
    type LineType = DltLogLine;

    const FILE_EXTENSIONS: &'static [&'static str] = &["dlt"];

    /// Open a DLT file for pull-based reading.
    fn open(
        path: &Path,
        _config: crate::config::DltTimestampSource,
        file_state: Arc<DltFileState>,
    ) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        // Clone the boot_times Arc so read() can write into it without
        // ever touching the outer Arc<DltFileState>.
        let boot_times = Arc::clone(&file_state.boot_times);
        let file =
            File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
        let inner = ByteCountReader::new(BufReader::new(file));
        let bytes_read_rc = inner.bytes_read_arc();
        let reader = DltMessageReader::new(inner, true);
        Ok(Self {
            reader,
            boot_times,
            bytes_read_rc,
            line_number: 1,
        })
    }

    fn read(&mut self, lines_to_read: usize) -> anyhow::Result<Vec<Self::LineType>> {
        let mut result = Vec::with_capacity(lines_to_read);

        // Safety cap: avoid spinning on files with many un-parseable messages.
        let attempt_limit = lines_to_read * 10 + 64;
        let mut attempts = 0;

        while result.len() < lines_to_read && attempts < attempt_limit {
            attempts += 1;
            match read_message(&mut self.reader, None) {
                Ok(Some(dlt_core::parse::ParsedMessage::Item(msg))) => {
                    if let Some(line) = convert_dlt_message(&msg, self.line_number) {
                        if let Some(header_us) = line.header_timestamp_us {
                            let key = (line.ecu_id.clone(), line.app_id.clone());
                            // Write directly into the shared DashMap — no lock, no buffering.
                            // First-seen wins; persisted calibration loaded at open time is
                            // already present and or_insert_with leaves it untouched.
                            self.boot_times.entry(key).or_insert_with(|| {
                                line.storage_time - chrono::TimeDelta::microseconds(header_us)
                            });
                        }
                        result.push(line);
                        self.line_number += 1;
                    }
                }
                Ok(Some(_)) => {}  // skip non-Item messages (e.g. skipped bytes)
                Ok(None) => break, // EOF
                Err(e) => {
                    tracing::warn!("Failed to parse DLT message: {e:?}");
                    // continue — DLT files sometimes have minor corruption
                }
            }
        }

        Ok(result)
    }

    fn bytes_consumed(&self) -> u64 {
        self.bytes_read_rc.load(Ordering::Relaxed)
    }
}

impl BinaryFileType for DltFileType {
    /// DLT storage header magic: `DLT\x01`
    const MAGIC_BYTES: &'static [&'static [u8]] = &[b"DLT\x01"];
}

// ============================================================================
// DLT parsing utilities (moved from parser/dlt.rs)
// ============================================================================

#[must_use]
pub fn storage_time_to_datetime(
    storage_time: &dlt_core::dlt::DltTimeStamp,
) -> Option<DateTime<Local>> {
    use chrono::TimeZone;
    Local
        .timestamp_opt(
            i64::from(storage_time.seconds),
            storage_time.microseconds * 1000,
        )
        .single()
}

/// Convert a `dlt_core::dlt::Message` to `DltLogLine`.
pub fn convert_dlt_message(msg: &dlt_core::dlt::Message, line_number: usize) -> Option<DltLogLine> {
    let storage_time = storage_time_to_datetime(&msg.storage_header.as_ref()?.timestamp)?;

    if msg.header.ecu_id.is_none() {
        tracing::warn!("DLT message missing ECU ID for line {line_number}");
    }
    if msg.extended_header.is_none() {
        tracing::error!("DLT message missing Extended Header for line {line_number}");
        return None;
    }
    if msg.storage_header.is_none() {
        tracing::error!("DLT message missing Storage Header for line {line_number}");
        return None;
    }

    let header_timestamp_us = msg.header.timestamp.map(|ts| i64::from(ts) * 100);
    let ecu_id = msg.header.ecu_id.as_deref().unwrap_or("").to_string();
    let app_id = msg
        .extended_header
        .as_ref()
        .map_or(String::new(), |ext| ext.application_id.clone());

    Some(DltLogLine::new(
        msg.clone(),
        storage_time,
        header_timestamp_us,
        ecu_id,
        app_id,
        line_number,
    ))
}
