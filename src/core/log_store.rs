// LogCrab - GPL-3.0-or-later
// This file is part of LogCrab.
//
// Copyright (C) 2026 Daniel Freiermuth
//
// LogCrab is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// LogCrab is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with LogCrab.  If not, see <https://www.gnu.org/licenses/>.

use crate::core::session::{CrabFile, SessionError, CRAB_FILE_VERSION};
use crate::core::{SavedFilter, SavedHighlight};
use crate::filetype::{
    btsnoop::BtsnoopFileType, bugreport::BugreportFileType, dlt::DltFileType, dmesg::DmesgFileType,
    generic::GenericFileType, logcat::LogcatFileType, otel::OtelFileType, pcap::PcapFileType,
};
use crate::filetype::{
    btsnoop::BtsnoopLogLine, bugreport::BugreportLogLine, dlt::DltLogLine, dmesg::DmesgLogLine,
    generic::GenericLogLine, logcat::LogcatLogLine, otel::OtelLogLine, pcap::PcapLogLine,
};
use crate::filetype::{InputFileType, LineType, LogFileState};
use crate::ui::tabs::bookmarks_tab::BookmarkData;
use chrono::Local;
use egui;
use indexmap::IndexMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use dashmap::DashMap;

/// Global counter for generating unique source IDs.
/// Source IDs are stable across the lifetime of a source, even when other sources are removed.
static SOURCE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Snapshot of all scoring data for a single source.
///
/// Stored behind a single `ArcSwap` in [`ScoreStore`] so that writers swap
/// all four vectors in one atomic pointer store and readers always see a
/// consistent combination of score + flags.
#[derive(Clone, Default)]
struct ScoreSnapshot {
    /// Anomaly scores indexed by line position (same length as `lines`).
    /// Default score is 0.0; scores range from 0 to 100.
    scores: Vec<f64>,
    /// Whether each line's score was assigned while the target token was UNK.
    /// Parallel to `scores`; `false` when not available.
    unk_flags: Vec<bool>,
    /// Whether each line's target was a rare template (seen < `min_count` times).
    /// Subset of `unk_flags`; `false` when not available or when target is truly unknown.
    rare_flags: Vec<bool>,
    /// Whether each line was actually present in the sidecar's scored set.
    /// `false` means the line was filtered/excluded by the backend (not in corpus).
    scored_flags: Vec<bool>,
}

/// Lock-free storage for anomaly scores.
///
/// Uses `ArcSwap` for atomic pointer swaps — readers never block, and writers
/// simply build a new [`ScoreSnapshot`] and swap it in atomically. This avoids
/// the need for a write lock on `lines` when updating scores and guarantees
/// that readers always see a consistent set of score + flag values.
pub struct ScoreStore {
    data: ArcSwap<ScoreSnapshot>,
}

impl ScoreStore {
    /// Create a new empty score store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: ArcSwap::new(Arc::new(ScoreSnapshot::default())),
        }
    }

    /// Set all scores atomically. The provided slice is copied into a new `Arc`.
    pub fn set_all(&self, scores: &[f64]) {
        self.data.store(Arc::new(ScoreSnapshot {
            scores: scores.to_vec(),
            ..ScoreSnapshot::default()
        }));
    }

    /// Set scores, UNK flags, rare flags, and scored flags atomically.
    pub fn set_all_with_unk(
        &self,
        scores: &[f64],
        unk_flags: &[bool],
        rare_flags: &[bool],
        scored_flags: &[bool],
    ) {
        self.data.store(Arc::new(ScoreSnapshot {
            scores: scores.to_vec(),
            unk_flags: unk_flags.to_vec(),
            rare_flags: rare_flags.to_vec(),
            scored_flags: scored_flags.to_vec(),
        }));
    }

    /// Get the score for a specific line index. Returns 0.0 if out of bounds.
    pub fn get(&self, index: usize) -> f64 {
        let guard = self.data.load();
        guard.scores.get(index).copied().unwrap_or(0.0)
    }

    /// Get the UNK flag for a specific line index. Returns `false` if out of bounds.
    pub fn get_unk(&self, index: usize) -> bool {
        let guard = self.data.load();
        guard.unk_flags.get(index).copied().unwrap_or(false)
    }

    /// Get the rare flag for a specific line index. Returns `false` if out of bounds.
    pub fn get_rare(&self, index: usize) -> bool {
        let guard = self.data.load();
        guard.rare_flags.get(index).copied().unwrap_or(false)
    }

    /// Get the scored flag for a specific line index. Returns `false` if out of bounds.
    pub fn get_scored(&self, index: usize) -> bool {
        let guard = self.data.load();
        guard.scored_flags.get(index).copied().unwrap_or(false)
    }

    /// Get all sidecar fields for a specific line index from a single snapshot load.
    /// Returns `(score, unk, rare, scored)` with out-of-bounds defaults.
    pub fn get_all(&self, index: usize) -> (f64, bool, bool, bool) {
        let guard = self.data.load();
        (
            guard.scores.get(index).copied().unwrap_or(0.0),
            guard.unk_flags.get(index).copied().unwrap_or(false),
            guard.rare_flags.get(index).copied().unwrap_or(false),
            guard.scored_flags.get(index).copied().unwrap_or(false),
        )
    }

    /// Resize the internal vec to accommodate new lines (fills with defaults).
    /// Called when lines are appended to keep scores in sync.
    ///
    /// Uses `rcu` (read-copy-update) to retry if a concurrent setter swaps in a
    /// newer snapshot between our load and store, avoiding lost updates.
    pub fn resize(&self, new_len: usize) {
        // Fast path: skip if already large enough.
        if self.data.load().scores.len() >= new_len {
            return;
        }
        self.data.rcu(|current| {
            if current.scores.len() >= new_len {
                // Another resize (or setter with enough data) already handled it.
                Arc::clone(current)
            } else {
                let mut snapshot = (**current).clone();
                snapshot.scores.resize(new_len, 0.0);
                snapshot.unk_flags.resize(new_len, false);
                snapshot.rare_flags.resize(new_len, false);
                snapshot.scored_flags.resize(new_len, false);
                Arc::new(snapshot)
            }
        });
    }
}

impl Default for ScoreStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ScoreStore {
    fn clone(&self) -> Self {
        Self {
            data: ArcSwap::new(Arc::clone(&self.data.load())),
        }
    }
}

impl std::fmt::Debug for ScoreStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.data.load();
        write!(f, "ScoreStore({} scores)", guard.scores.len())
    }
}

/// A single log source with its lines, wrapped in `RwLock` for thread-safe access.
///
/// # Panics
///
/// Methods accessing internal locks panic if a prior holder poisoned a lock.
pub struct SourceData<FT>
where
    FT: InputFileType,
{
    /// Unique, stable identifier for this source (does not change when other sources are removed)
    source_id: u64,
    /// Path to the source file
    file_path: PathBuf,
    /// Log lines in file order (index = `line_number` - 1, eternal)
    lines: RwLock<Vec<FT::LineType>>,
    /// Indices into `lines`, sorted by timestamp for time-ordered iteration
    by_timestamp: RwLock<Vec<usize>>,
    /// File type config — shared across all sources of this type (e.g. DLT timestamp source setting).
    /// Wrapped in `Arc<RwLock>` so a single instance is shared and can be mutated from the UI.
    pub config: Arc<RwLock<<FT::LineType as LineType>::Config>>,
    /// Per-source file state — user-visible state specific to this file (e.g. time offsets, calibration).
    /// Each `FileState` type owns its interior synchronization; no outer `RwLock` is needed.
    /// Wrapped in `Arc` so that types like `DltFileState` can clone the Arc into the background
    /// loader (e.g. to share the `boot_times` `DashMap`). For all other types the background
    /// loader ignores this Arc entirely.
    pub file_state: Arc<<FT::LineType as LineType>::FileState>,
    /// Bookmarks for this source, keyed by line index within this source
    bookmarks: RwLock<HashMap<usize, Bookmark>>,
    /// Path to the `.crab` session file (immutable after construction).
    crab_path: PathBuf,
    /// OS exclusive lock on the `.crab` session file.
    ///
    /// `None` — lock released because the file was written by a newer `LogCrab`;
    ///           all reads and writes are refused.
    /// `Some(mutex)` — lock held; mutex provides `&mut File` for writes.
    crab: Option<Mutex<File>>,
    version: AtomicU64,
    /// Flag to request cancellation of background loading/scoring operations
    cancel_requested: AtomicBool,
}

impl<FT: InputFileType> std::fmt::Debug for SourceData<FT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceData")
            .field("source_id", &self.source_id)
            .field("file_path", &self.file_path)
            .field("version", &self.version.load(AtomicOrdering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[allow(
    clippy::missing_panics_doc,
    reason = "the shared lock-poisoning precondition is documented on SourceData"
)]
#[allow(
    clippy::significant_drop_tightening,
    reason = "read guards intentionally span related reads to preserve a consistent source snapshot"
)]
impl<FT: InputFileType> SourceData<FT>
where
    FT::LineType: Clone,
{
    /// Create a `SourceData` for a file source.
    ///
    /// Acquires an exclusive lock on the `.crab` session file to prevent multiple
    /// instances from clobbering each other's session state. Parsed session data
    /// (bookmarks, file state) is applied immediately; the saved filters and
    /// highlights are returned to the caller so they never need to be stored.
    ///
    /// If the lock is already held by another instance the file is opened in
    /// **read-only mode**: bookmarks and saved state are not loaded, and writes
    /// are silently skipped for the lifetime of this source.
    ///
    /// Returns `(Self, saved_filters, saved_highlights)`.
    pub fn new(
        file_path: PathBuf,
        config: Arc<RwLock<<FT::LineType as LineType>::Config>>,
        warnings: &crate::ui::ToastSender,
    ) -> (Self, Vec<SavedFilter>, Vec<SavedHighlight>) {
        assert!(
            file_path.file_name().is_some(),
            "file_path must have a filename component: {}",
            file_path.display()
        );

        let crab_path = Self::compute_crab_path(&file_path);
        let (lock_file, maybe_crab) = Self::acquire_crab_lock(&crab_path).map_or_else(
            || {
                tracing::warn!(
                    "Cannot lock {} — opening read-only (file already open in another instance)",
                    crab_path.display()
                );
                warnings.send(format!(
                    "'{}' is already open in another LogCrab instance — \
                    opened read-only (bookmarks and filters not loaded)",
                    file_path
                        .file_name()
                        .unwrap_or(file_path.as_os_str())
                        .to_string_lossy()
                ));
                (None, None)
            },
            |lock_file| Self::open_crab_file(lock_file, &crab_path, warnings),
        );

        // Consume the parsed CrabFile immediately — apply bookmarks/file_state
        // here and return filters/highlights to the caller so nothing lingers.
        let (filters, highlights, bookmarks_vec, file_state_arc) = match maybe_crab {
            Some(crab) => {
                tracing::info!(
                    "Loaded {} bookmarks from {}",
                    crab.bookmarks.len(),
                    crab_path.display()
                );
                (
                    crab.filters,
                    crab.highlights,
                    crab.bookmarks,
                    Arc::new(crab.file_state),
                )
            }
            None => (vec![], vec![], vec![], Arc::new(Default::default())),
        };

        let sd = Self {
            source_id: SOURCE_ID_COUNTER.fetch_add(1, AtomicOrdering::Relaxed),
            file_path,
            lines: RwLock::new(Vec::new()),
            by_timestamp: RwLock::new(Vec::new()),
            config,
            file_state: file_state_arc,
            bookmarks: RwLock::new(
                bookmarks_vec
                    .into_iter()
                    .map(|b| (b.line_index, b))
                    .collect(),
            ),
            crab_path,
            crab: lock_file.map(Mutex::new),
            version: AtomicU64::new(1),
            cancel_requested: AtomicBool::new(false),
        };
        (sd, filters, highlights)
    }

    /// Parse the `.crab` file immediately after locking it.
    ///
    /// Returns `(Some(file), Some(data))` on success.
    /// Returns `(Some(file), None)` when the file is empty or unparseable.
    /// Returns `(None, None)` on `VersionTooNew`, releasing the OS lock.
    fn open_crab_file(
        file: File,
        crab_path: &Path,
        warnings: &crate::ui::ToastSender,
    ) -> (Option<File>, Option<CrabFile<FT>>) {
        let mut file = file;
        match CrabFile::<FT>::load_from_file(&mut file) {
            Ok(data) => (Some(file), Some(data)),
            Err(SessionError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                (Some(file), None) // Empty .crab file (just created)
            }
            Err(SessionError::Parse(_)) => {
                (Some(file), None) // Unparseable, fine for a new session
            }
            Err(SessionError::VersionTooNew { found, supported }) => {
                let msg = format!(
                    ".crab file {} was written by a newer LogCrab (v{found}, app supports up to v{supported}); \
                     bookmarks and file state not loaded",
                    crab_path.display()
                );
                tracing::warn!("{msg}");
                warnings.send(msg);
                // Drop `file` here to release the OS lock.
                (None, None)
            }
            Err(SessionError::StateVersionTooNew {
                slug,
                found,
                supported,
            }) => {
                let msg = format!(
                    ".crab file {}: {slug} state was written by a newer LogCrab \
                     (state v{found}, app supports up to v{supported}); \
                     calibration and file state not loaded",
                    crab_path.display()
                );
                tracing::warn!("{msg}");
                warnings.send(msg);
                // Drop `file` here to release the OS lock — keeping it would
                // allow a future save to overwrite the newer state with our
                // older format, silently destroying the user's calibration.
                (None, None)
            }
            Err(e) => {
                tracing::warn!("Failed to load .crab file {}: {e}", crab_path.display());
                (Some(file), None)
            }
        }
    }

    /// Compute the .crab file path for a given log file path
    fn compute_crab_path(file_path: &Path) -> PathBuf {
        let mut crab_path = file_path.to_path_buf();
        crab_path.set_file_name(format!(
            "{}.crab",
            file_path
                .file_name()
                .expect("file_path must have a filename component")
                .to_string_lossy()
        ));
        crab_path
    }

    /// Acquire an exclusive lock on the .crab file
    /// Returns None if the lock cannot be acquired (file already open in another instance)
    fn acquire_crab_lock(crab_path: &Path) -> Option<File> {
        use fs2::FileExt;
        use std::fs::OpenOptions;

        // Open or create the .crab file
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(crab_path)
        {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("Cannot open .crab file {}: {e}", crab_path.display());
                return None;
            }
        };

        // Try to acquire exclusive lock
        match file.try_lock_exclusive() {
            Ok(()) => {
                tracing::info!(
                    "Successfully acquired exclusive lock on {}",
                    crab_path.display()
                );
                Some(file)
            }
            Err(e) => {
                tracing::error!(
                    "Cannot lock .crab file {} (already open in another instance?): {e}",
                    crab_path.display()
                );
                None
            }
        }
    }

    /// Bump the version number (call after appending lines)
    fn bump_version(&self) {
        self.version.fetch_add(1, AtomicOrdering::SeqCst);
    }

    /// Get current version number (bumped whenever data changes)
    pub fn version(&self) -> u64 {
        profiling::scope!("SourceData::version");
        self.version.load(AtomicOrdering::SeqCst)
    }

    /// Get the file path for this source
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Get the unique, stable identifier for this source
    pub const fn source_id(&self) -> u64 {
        self.source_id
    }

    /// Check if cancellation has been requested
    pub fn is_cancelled(&self) -> bool {
        self.cancel_requested.load(AtomicOrdering::SeqCst)
    }

    // ========================================================================
    // Bookmark Management
    // ========================================================================

    /// Add or update a bookmark for a line in this source
    pub(crate) fn set_bookmark(&self, line_index: usize, name: String) {
        profiling::scope!("SourceData::bookmarks::write");
        let bookmark = Bookmark { line_index, name };
        self.bookmarks
            .write()
            .expect("bookmarks lock poisoned")
            .insert(line_index, bookmark);
    }

    /// Remove a bookmark from this source
    pub(crate) fn remove_bookmark(&self, line_index: usize) -> Option<Bookmark> {
        profiling::scope!("SourceData::bookmarks::write");
        self.bookmarks
            .write()
            .expect("bookmarks lock poisoned")
            .remove(&line_index)
    }

    /// Check if a line has a bookmark
    pub(crate) fn has_bookmark(&self, line_index: usize) -> bool {
        profiling::scope!("SourceData::bookmarks::read");
        self.bookmarks
            .read()
            .expect("bookmarks lock poisoned")
            .contains_key(&line_index)
    }

    /// Get a bookmark by line index
    pub(crate) fn get_bookmark(&self, line_index: usize) -> Option<Bookmark> {
        profiling::scope!("SourceData::bookmarks::read");
        self.bookmarks
            .read()
            .expect("bookmarks lock poisoned")
            .get(&line_index)
            .cloned()
    }

    /// Get all bookmarks for this source
    pub(crate) fn get_bookmarks(&self) -> Vec<Bookmark> {
        profiling::scope!("SourceData::bookmarks::read");
        self.bookmarks
            .read()
            .expect("bookmarks lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Save bookmarks to this source's .crab file
    /// Note: filters and highlights are passed in since they're shared across sources
    pub fn save_crab_file(&self, filters: &[SavedFilter], highlights: &[SavedHighlight]) {
        let Some(mutex) = &self.crab else {
            tracing::warn!(
                "Skipping save to {} — .crab file is from a newer version of LogCrab",
                self.crab_path.display()
            );
            return;
        };
        let mut file = mutex.lock().expect("crab mutex poisoned");
        let crab_data = CrabFile::<FT> {
            version: CRAB_FILE_VERSION,
            bookmarks: self.get_bookmarks(),
            filters: filters.to_vec(),
            highlights: highlights.to_vec(),
            file_state: (*self.file_state).clone(),
        };
        match crab_data.save_to_file(&mut file) {
            Ok(()) => tracing::debug!(
                "Saved .crab file {} with {} bookmarks",
                self.crab_path.display(),
                crab_data.bookmarks.len()
            ),
            Err(e) => tracing::error!(
                "Failed to save .crab file {}: {e}",
                self.crab_path.display()
            ),
        }
    }

    // ========================================================================
    // Time Synchronization
    // ========================================================================

    /// Re-sort `by_timestamp` using the current config and file-state, then bump the version.
    ///
    /// Call this after the shared `config` arc has been mutated externally (e.g.
    /// `DltTimestampSource` was changed), so that timestamp ordering and dependent
    /// filter caches are invalidated.
    pub fn rebuild_time_index(&self) {
        let lines = self.lines.read().expect("lines lock poisoned");
        let config = self.config.read().expect("config lock poisoned");
        let file_state = &*self.file_state;
        let mut indices: Vec<usize> = (0..lines.len()).collect();
        indices.par_sort_by_key(|&idx| lines[idx].timestamp(&config, file_state));
        drop(lines);
        drop(config);
        *self
            .by_timestamp
            .write()
            .expect("by_timestamp lock poisoned") = indices;
        self.bump_version();
    }

    /// Drive any open calibration window for this source (one per frame).
    ///
    /// The `FileState` impl writes the new offset into itself on confirm;
    /// this method bumps the source version so dependent views invalidate.
    /// Returns `(time_changed, optional jump target)`.
    pub fn render_file_state(&self, ui: &egui::Ui) -> (bool, Option<StoreID>) {
        let changed = self.file_state.egui_render_file_state(ui, &self.file_path);
        if changed {
            self.rebuild_time_index();
        }
        let jump = self
            .file_state
            .take_pending_jump_line()
            .map(|line_idx| StoreID::make(self.source_id, line_idx));
        (changed, jump)
    }

    // ========================================================================
    // Line Management
    // ========================================================================

    /// Append lines to this source
    ///
    /// Lines are stored in file order (append-only). Only the timestamp index
    /// needs to be rebuilt. Heavy work is done outside the write lock.
    pub fn append_lines(&self, lines: Vec<FT::LineType>) {
        if lines.is_empty() {
            return;
        }

        profiling::scope!("SourceData::append_lines");

        let config = self.config.read().expect("config lock poisoned");
        let file_state = &*self.file_state;

        // Append lines and capture the range of new indices atomically
        let new_start_idx = {
            profiling::scope!("SourceData::lines::write");
            let mut lines_guard = self.lines.write().expect("lines lock poisoned");
            let start_idx = lines_guard.len();
            tracing::debug!(
                "Appending {} lines to existing {} lines (merge overhead)",
                lines.len(),
                start_idx
            );
            lines_guard.extend(lines);
            start_idx
        };

        // Read lines and build sorted indices for the newly appended range
        let (lines_guard, new_by_ts) = {
            profiling::scope!("SourceData::lines::read");
            let lines_read = self.lines.read().expect("lines lock poisoned");
            profiling::scope!("sort_new_indices");
            let mut indices: Vec<usize> = (new_start_idx..lines_read.len()).collect();
            indices.par_sort_by_key(|&idx| lines_read[idx].timestamp(&*config, file_state));
            (lines_read, indices)
        };

        // Merge into by_timestamp atomically - hold write lock during merge
        {
            profiling::scope!("SourceData::by_timestamp::write");
            let mut by_ts_guard = self
                .by_timestamp
                .write()
                .expect("by_timestamp lock poisoned");

            profiling::scope!("merge_timestamp_indices");
            let existing_len = by_ts_guard.len();
            let mut merged = Vec::with_capacity(existing_len + new_by_ts.len());
            let mut i_exist = 0;
            let mut j_new = 0;

            while i_exist < existing_len && j_new < new_by_ts.len() {
                let ts_exist = lines_guard[by_ts_guard[i_exist]].timestamp(&*config, file_state);
                let ts_new = lines_guard[new_by_ts[j_new]].timestamp(&*config, file_state);
                if ts_exist <= ts_new {
                    merged.push(by_ts_guard[i_exist]);
                    i_exist += 1;
                } else {
                    merged.push(new_by_ts[j_new]);
                    j_new += 1;
                }
            }

            // Append remaining elements
            merged.extend_from_slice(&by_ts_guard[i_exist..]);
            merged.extend_from_slice(&new_by_ts[j_new..]);

            *by_ts_guard = merged;
        }

        drop(lines_guard);
        drop(config);
        self.bump_version();
    }

    /// Get the number of lines
    pub fn len(&self) -> usize {
        profiling::scope!("SourceData::lines::read");
        self.lines.read().expect("lines lock poisoned").len()
    }

    /// Check if this source has no lines
    pub fn is_empty(&self) -> bool {
        profiling::scope!("SourceData::lines::read");
        self.lines.read().expect("lines lock poisoned").is_empty()
    }

    /// Look up a single line and return it as the display [`LogLine`] DTO.
    ///
    /// Acquires `lines`, `config`, and `file_state` locks exactly once so the
    /// timestamp, message, and all other fields are computed under the same
    /// read epoch.  Returns `None` when `line_index` is out of range.
    #[allow(clippy::significant_drop_tightening)]
    pub fn get_as_log_line(&self, line_index: usize) -> Option<LogLine> {
        profiling::scope!("SourceData::get_as_log_line");
        let lines = self.lines.read().expect("lines lock poisoned");
        let config = self.config.read().expect("config lock poisoned");
        let file_state = &*self.file_state;
        let line = lines.get(line_index)?;
        Some(LogLine {
            timestamp: line.timestamp(&*config, file_state),
            message: line.display_message(&*config, file_state),
            raw: line.raw(),
            line_number: line.line_number(),
            anomaly_score: 0.0, // Scores are stored at LogStore level, populated by get_by_id
            sidecar_anomaly_score: 0.0,
            sidecar_score_is_unk: false,
            sidecar_score_is_rare: false,
            sidecar_scored: false,
        })
    }

    /// Returns the canonical sidecar message and timestamp (ms) for a single line.
    ///
    /// Unlike `get_as_log_line`, this calls `LineType::message()` which returns the
    /// format-specific canonical text (e.g. for logcat: just `TAG: text`, without the
    /// PID/TID/level prefix that `display_message` includes).  This is the string that
    /// must be sent to the sidecar because the training vocab was built from the same
    /// `message()` output via `logcrab-export`.
    ///
    /// Returns `None` when `line_index` is out of range.
    pub fn get_sidecar_message(&self, line_index: usize) -> Option<(u64, String)> {
        let lines = self.lines.read().expect("lines lock poisoned");
        let config = self.config.read().expect("config lock poisoned");
        let file_state = &*self.file_state;
        let line = lines.get(line_index)?;
        let ts_ms = line
            .timestamp(&*config, file_state)
            .timestamp_millis()
            .max(0) as u64;
        Some((ts_ms, line.message()))
    }

    /// Filter lines by their *display message* and *raw* string, in timestamp order.
    ///
    /// Unlike `filter_sorted_mapped`, the predicate receives the display message produced
    /// by `display_message(config, file_state)` — which includes any active overlays such
    /// as SOME/IP SD decoded entries — and the raw string.  All config and file-state locks
    /// are acquired once for the whole scan.
    ///
    /// # Panics
    ///
    /// Panics if an internal source lock is poisoned.
    pub fn filter_sorted_by_search<F, C>(
        &self,
        predicate: &F,
        should_cancel: &C,
    ) -> Option<Vec<usize>>
    where
        F: Fn(&str, &str) -> bool + Sync,
        C: Fn() -> bool + Sync,
    {
        profiling::scope!("SourceData::filter_sorted_by_search");
        let lines = self.lines.read().expect("lines lock poisoned");
        let config = self.config.read().expect("config lock poisoned");
        let file_state = &*self.file_state;
        let chunks: Option<Vec<Vec<usize>>> = self
            .by_timestamp
            .read()
            .expect("by_timestamp lock poisoned")
            .par_chunks(256)
            .map(|line_indices| {
                let mut matches = Vec::new();
                for &idx in line_indices {
                    if should_cancel() {
                        return None;
                    }
                    let line = &lines[idx];
                    let display_msg = line.display_message(&*config, file_state);
                    let raw = line.raw();
                    if predicate(&display_msg, &raw) {
                        matches.push(idx);
                    }
                }
                Some(matches)
            })
            .collect();

        chunks.map(|chunks| {
            let match_count = chunks.iter().map(Vec::len).sum();
            let mut matches = Vec::with_capacity(match_count);
            for mut chunk in chunks {
                matches.append(&mut chunk);
            }
            matches
        })
    }

    /// Render format-specific context menu items for the line at `line_index`.
    ///
    /// Must be called inside an egui `context_menu` closure.
    pub fn render_line_context_menu(&self, line_index: usize, ui: &mut egui::Ui) {
        let lines = self.lines.read().expect("lines lock poisoned");
        let config = self.config.read().expect("config lock poisoned");
        let file_state = &*self.file_state;
        if let Some(line) = lines.get(line_index) {
            line.egui_render_context_menu(ui, &*config, file_state);
        }
    }
}

crate::register_filetypes! {
    binary {
        dlt:     Dlt:     DltFileType:     DltLogLine,
        btsnoop: Btsnoop: BtsnoopFileType: BtsnoopLogLine,
        pcap:    Pcap:    PcapFileType:    PcapLogLine,
    }
    text {
        bugreport: Bugreport: BugreportFileType: BugreportLogLine,
        logcat:    Logcat:   LogcatFileType:    LogcatLogLine,
        dmesg:     Dmesg:    DmesgFileType:     DmesgLogLine,
        otel:      Otel:     OtelFileType:      OtelLogLine,
        generic:   Generic:  GenericFileType:   GenericLogLine,
    }
}

/// Display-ready log line, produced by [`LogStore::get_by_id`].
///
/// All fields are pre-computed under the source locks so callers never need a
/// second lookup or lock acquisition.  Format-specific dispatch (context menus,
/// calibration UI) goes through [`StoreID`] + [`LogStore`] methods.
#[derive(Debug, Clone)]
pub struct LogLine {
    /// Fully-adjusted timestamp: config-selected clock + calibration offset.
    pub timestamp: chrono::DateTime<chrono::Local>,
    /// Rendered message text.
    pub message: String,
    /// Original raw source text.
    pub raw: String,
    /// 1-based line number within the source file.
    pub line_number: usize,
    /// Anomaly score in [0, 100].
    pub anomaly_score: f64,
    /// ML sidecar anomaly score in [0, 100]. 0.0 when not available.
    pub sidecar_anomaly_score: f64,
    /// Whether the sidecar score was assigned while the target token was UNK.
    /// Only meaningful when `sidecar_anomaly_score > 0.0`.
    pub sidecar_score_is_unk: bool,
    /// Whether the sidecar score's target was a rare template (seen < `min_count` times).
    /// Only meaningful when `sidecar_score_is_unk` is true.
    pub sidecar_score_is_rare: bool,
    /// Whether this line appeared in the sidecar's scored set.
    /// `false` means the line was excluded by the backend (not in corpus) or no scoring has run.
    pub sidecar_scored: bool,
}

impl LogLine {
    /// Compute the normalised template key for anomaly detection.
    /// This is computed on-demand rather than stored to avoid expensive
    /// regex normalization when not needed (e.g., histogram rendering).
    #[must_use]
    pub fn template_key(&self) -> String {
        crate::parser::normalize_message(&self.message)
    }
}

/// Central storage for log lines from one or more sources.
///
/// Thread-safe: can be shared across threads with `Arc<LogStore>`.
/// Uses `IndexMap` for O(1) source lookup by ID while maintaining insertion order.
///
/// # Panics
///
/// Methods accessing internal locks panic if a prior holder poisoned a lock.
pub struct LogStore {
    /// Sources indexed by their stable `source_id` for O(1) lookup.
    /// `IndexMap` maintains insertion order for consistent UI display.
    sources: RwLock<IndexMap<u64, DataSourceVariant>>,
    /// Version counter that increments when sources are added or removed.
    /// This ensures cache invalidation even when line counts happen to sum to the same value.
    sources_version: AtomicU64,
    /// Anomaly scores keyed by `source_id`. Each source has its own `ScoreStore`.
    /// Stored at `LogStore` level (not `SourceData`) because scores are analysis metadata.
    scores: DashMap<u64, ScoreStore>,
    /// ML sidecar anomaly scores keyed by `source_id`.
    /// Parallel to `scores` but populated by the `LogBERT` sidecar service.
    sidecar_scores: DashMap<u64, ScoreStore>,
    /// Sidecar scoring configuration, set once during session creation.
    /// Read by background loading threads to decide if sidecar scoring should run.
    sidecar_config: RwLock<Option<crate::core::log_file::ScoringConfig>>,
    /// Active explain sessions keyed by `source_id`.
    /// One session per scored file; dropped (closing the WebSocket) when the source is removed.
    explain_sessions: Mutex<HashMap<u64, crate::anomaly::sidecar_client::ExplainSession>>,
}

impl std::fmt::Debug for LogStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogStore")
            .field("sources_count", &self.sources.read().map_or(0, |s| s.len()))
            .field("sources_version", &self.sources_version)
            .field("scores_count", &self.scores.len())
            .field("sidecar_scores_count", &self.sidecar_scores.len())
            .field(
                "sidecar_enabled",
                &self.sidecar_config.read().is_ok_and(|c| c.is_some()),
            )
            .field(
                "explain_sessions",
                &self.explain_sessions.lock().map_or(0, |g| g.len()),
            )
            .finish()
    }
}

impl Clone for LogStore {
    fn clone(&self) -> Self {
        profiling::scope!("LogStore::sources::read");
        Self {
            sources: RwLock::new(self.sources.read().expect("sources lock poisoned").clone()),
            sources_version: AtomicU64::new(self.sources_version.load(AtomicOrdering::SeqCst)),
            scores: self.scores.clone(),
            sidecar_scores: self.sidecar_scores.clone(),
            sidecar_config: RwLock::new(
                self.sidecar_config
                    .read()
                    .expect("sidecar_config lock poisoned")
                    .clone(),
            ),
            // Explain sessions are live resources — clones start with no sessions.
            explain_sessions: Mutex::new(HashMap::new()),
        }
    }
}

/// Version identifier for cache invalidation.
///
/// Two-part version ensures no collisions: `sources` tracks structural changes
/// (add/remove sources), `lines` tracks data changes (lines added/modified).
/// Equality requires both components to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StoreVersion {
    /// Incremented when sources are added or removed
    pub sources: u64,
    /// Sum of per-source versions (incremented when lines are added/modified)
    pub lines: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreID {
    /// Stable source identifier (survives source removals)
    source_id: u64,
    /// Line index within the source
    line_index: usize,
}

impl StoreID {
    /// Return the stable source identifier for this line.
    #[must_use]
    pub const fn source_id(&self) -> u64 {
        self.source_id
    }

    /// Return the 0-based line index within this source.
    #[must_use]
    pub const fn line_index_within_source(&self) -> usize {
        self.line_index
    }

    /// Construct a `StoreID` directly from a source identifier and line index.
    #[must_use]
    pub const fn make(source_id: u64, line_index: usize) -> Self {
        Self {
            source_id,
            line_index,
        }
    }

    /// Compare two `StoreIDs` by their line timestamps.
    ///
    /// When both lines exist in the store, compares by timestamp first,
    /// then by `source_id` and `line_index` for stability.
    /// When lines are missing (e.g., during file loading), falls back to
    /// structural ordering to maintain a valid total order.
    pub fn cmp(&self, other: &Self, store: &LogStore) -> Ordering {
        match (
            store.adjusted_timestamp(self),
            store.adjusted_timestamp(other),
        ) {
            (Some(self_time), Some(other_time)) => {
                // Both lines exist: compare by calibrated timestamp, then structurally for stability
                self_time
                    .cmp(&other_time)
                    .then_with(|| self.source_id.cmp(&other.source_id))
                    .then_with(|| self.line_index.cmp(&other.line_index))
            }
            (Some(_), None) => Ordering::Less, // existing lines come first
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ord::cmp(self, other), // both missing: use derived Ord
        }
    }
}

#[allow(
    clippy::missing_panics_doc,
    reason = "the shared lock-poisoning precondition is documented on LogStore"
)]
#[allow(
    clippy::significant_drop_tightening,
    reason = "read guards intentionally span related store operations to preserve consistent views"
)]
impl LogStore {
    /// Create a new empty `LogStore`
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sources: RwLock::new(IndexMap::new()),
            sources_version: AtomicU64::new(1),
            scores: DashMap::new(),
            sidecar_scores: DashMap::new(),
            sidecar_config: RwLock::new(None),
            explain_sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Rebuild the timestamp-sorted index on every source in the store.
    ///
    /// Writes the relevant `file_config` field into each source's config arc before
    /// rebuilding, so that line ordering reflects the latest settings. Call this
    /// after mutating any field of `GlobalFileConfig` (e.g. via `render`).
    pub fn rebuild_all_time_indices(&self, file_config: &GlobalFileConfig) {
        profiling::scope!("LogStore::rebuild_all_time_indices");
        let sources = self.sources.read().expect("sources lock poisoned");
        for source in sources.values() {
            source.apply_file_config_and_rebuild(file_config);
        }
    }

    /// Insert a pre-constructed [`DataSourceVariant`] directly into the store.
    ///
    /// Used when the caller already has a `DataSourceVariant` (e.g. from
    /// [`crate::core::LogFileLoader::load_file`]) and does not need the concrete
    /// typed `Arc` afterwards.
    pub fn add_source(self: &Arc<Self>, variant: DataSourceVariant) {
        profiling::scope!("LogStore::sources::write");
        let id = variant.source_id();
        self.sources
            .write()
            .expect("sources lock poisoned")
            .insert(id, variant);
        self.sources_version.fetch_add(1, AtomicOrdering::SeqCst);
    }

    /// Check if a file with the given path is already loaded in the store
    pub fn contains_file(&self, path: &Path) -> bool {
        profiling::scope!("LogStore::sources::read");
        let canonical_path = path.canonicalize().ok();
        let sources = self.sources.read().expect("sources lock poisoned");
        sources.values().any(|source| {
            // Try canonical comparison first, fall back to direct comparison
            if let Some(ref canonical) = canonical_path {
                if let Ok(source_canonical) = source.file_path().canonicalize() {
                    return &source_canonical == canonical;
                }
            }
            source.file_path() == path
        })
    }

    /// Get current version for cache invalidation.
    ///
    /// Returns a two-part version:
    /// - `sources`: incremented when sources are added or removed
    /// - `lines`: sum of per-source versions (incremented when lines are added/modified)
    ///
    /// Comparing the full struct ensures no false cache hits.
    pub fn version(&self) -> StoreVersion {
        profiling::scope!("LogStore::version");
        let sources = self.sources_version.load(AtomicOrdering::SeqCst);
        profiling::scope!("LogStore::sources::read");
        let lines: u64 = self
            .sources
            .read()
            .expect("sources lock poisoned")
            .values()
            .map(DataSourceVariant::version)
            .sum();
        StoreVersion { sources, lines }
    }

    /// Get total number of lines across all sources
    pub fn total_lines(&self) -> usize {
        profiling::scope!("LogStore::sources::read");
        self.sources
            .read()
            .expect("sources lock poisoned")
            .values()
            .map(DataSourceVariant::len)
            .sum()
    }

    /// Get the source name (filename) for a given `StoreID`
    pub fn get_source_name(&self, id: &StoreID) -> Option<String> {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources.get(&id.source_id).map(|source| {
            source
                .file_path()
                .file_name()
                .expect("file_path must have a filename component")
                .to_string_lossy()
                .into_owned()
        })
    }

    /// Get the absolute file path of the source for a given `StoreID`
    pub fn get_source_path(&self, id: &StoreID) -> Option<PathBuf> {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources.get(&id.source_id).map(|source| {
            let path = source.file_path();
            std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
        })
    }

    /// Get all source filenames with their stable source IDs
    pub fn get_source_filenames(&self) -> Vec<(u64, String)> {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources
            .values()
            .map(|source| {
                let source_id = source.source_id();
                let filename = source
                    .file_path()
                    .file_name()
                    .expect("file_path must have a filename component")
                    .to_string_lossy()
                    .into_owned();
                (source_id, filename)
            })
            .collect()
    }

    /// Get full file paths for all loaded sources
    pub fn get_source_file_paths(&self) -> Vec<PathBuf> {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources
            .values()
            .map(|source| source.file_path().to_path_buf())
            .collect()
    }

    /// Remove a source by its stable source ID
    ///
    /// Note: `StoreID`s referencing the removed source will simply fail to resolve.
    /// Other `StoreID`s remain valid since they use stable source IDs.
    pub fn remove_source(&self, source_id: u64) -> Option<PathBuf> {
        profiling::scope!("LogStore::sources::write");
        let mut sources = self.sources.write().expect("sources lock poisoned");
        let removed = sources.swap_remove(&source_id)?;
        let path = removed.file_path().to_path_buf();
        drop(sources);
        // Also remove scores and explain session for this source
        self.scores.remove(&source_id);
        self.sidecar_scores.remove(&source_id);
        self.explain_sessions
            .lock()
            .expect("explain_sessions lock poisoned")
            .remove(&source_id);
        self.sources_version.fetch_add(1, AtomicOrdering::SeqCst);
        tracing::info!("Removed source: {}", path.display());
        Some(path)
    }

    // ========================================================================
    // Anomaly Score Management
    // ========================================================================

    /// Set anomaly scores for a source. Scores are indexed by line position.
    ///
    /// This is lock-free for readers — scores are swapped atomically.
    pub fn set_scores(&self, source_id: u64, scores: &[f64]) {
        profiling::scope!("LogStore::set_scores");
        self.scores.entry(source_id).or_default().set_all(scores);
        // Bump version so UI knows to refresh
        self.sources_version.fetch_add(1, AtomicOrdering::SeqCst);
    }

    /// Get the anomaly score for a specific line. Returns 0.0 if not found.
    pub fn get_score(&self, source_id: u64, line_index: usize) -> f64 {
        self.scores
            .get(&source_id)
            .map_or(0.0, |store| store.get(line_index))
    }

    /// Set ML sidecar scores for a source.
    pub fn set_sidecar_scores(&self, source_id: u64, scores: &[f64]) {
        profiling::scope!("LogStore::set_sidecar_scores");
        self.sidecar_scores
            .entry(source_id)
            .or_default()
            .set_all(scores);
        self.sources_version.fetch_add(1, AtomicOrdering::SeqCst);
    }

    /// Set ML sidecar scores, UNK flags, rare flags, and scored flags for a source.
    pub fn set_sidecar_scores_with_unk(
        &self,
        source_id: u64,
        scores: &[f64],
        unk_flags: &[bool],
        rare_flags: &[bool],
        scored_flags: &[bool],
    ) {
        profiling::scope!("LogStore::set_sidecar_scores_with_unk");
        self.sidecar_scores
            .entry(source_id)
            .or_default()
            .set_all_with_unk(scores, unk_flags, rare_flags, scored_flags);
        self.sources_version.fetch_add(1, AtomicOrdering::SeqCst);
    }

    /// Store the explain session for the given `source_id`.
    /// Replaces any previous session for that source (dropping it, which closes the connection).
    pub fn set_explain_session(
        &self,
        source_id: u64,
        session: crate::anomaly::sidecar_client::ExplainSession,
    ) {
        self.explain_sessions
            .lock()
            .expect("explain_sessions lock poisoned")
            .insert(source_id, session);
    }

    /// Request an attention explanation for `target_line_number` on the session for `source_id`.
    /// Returns `false` if there is no session for that source or the request queue is full.
    pub fn request_explanation(&self, source_id: u64, target_line_number: usize) -> bool {
        self.explain_sessions
            .lock()
            .expect("explain_sessions lock poisoned")
            .get(&source_id)
            .is_some_and(|s| s.request(target_line_number))
    }

    /// Poll for a completed explanation on the session for `source_id` without blocking.
    /// Returns `None` if no result is available yet or there is no session for that source.
    pub fn poll_explanation(
        &self,
        source_id: u64,
    ) -> Option<crate::anomaly::sidecar_client::ExplainResult> {
        self.explain_sessions
            .lock()
            .expect("explain_sessions lock poisoned")
            .get(&source_id)
            .and_then(super::super::anomaly::sidecar_client::ExplainSession::try_recv)
    }

    /// Poll the explain session with a richer status that distinguishes "still pending"
    /// from "the WebSocket thread has exited".
    pub fn poll_explain_status(
        &self,
        source_id: u64,
    ) -> crate::anomaly::sidecar_client::ExplainPollStatus {
        use crate::anomaly::sidecar_client::ExplainPollStatus;
        self.explain_sessions
            .lock()
            .expect("explain_sessions lock poisoned")
            .get(&source_id)
            .map_or(
                ExplainPollStatus::Dead,
                super::super::anomaly::sidecar_client::ExplainSession::poll_status,
            )
    }

    /// Get the ML sidecar anomaly score for a specific line. Returns 0.0 if not found.
    pub fn get_sidecar_score(&self, source_id: u64, line_index: usize) -> f64 {
        self.sidecar_scores
            .get(&source_id)
            .map_or(0.0, |store| store.get(line_index))
    }

    /// Get whether the sidecar score for a line was assigned while the target was UNK.
    pub fn get_sidecar_unk(&self, source_id: u64, line_index: usize) -> bool {
        self.sidecar_scores
            .get(&source_id)
            .is_some_and(|store| store.get_unk(line_index))
    }

    /// Get whether the sidecar score's target was a rare template.
    pub fn get_sidecar_rare(&self, source_id: u64, line_index: usize) -> bool {
        self.sidecar_scores
            .get(&source_id)
            .is_some_and(|store| store.get_rare(line_index))
    }

    /// Get whether a line was present in the sidecar's scored set (vs filtered/excluded).
    pub fn get_sidecar_scored(&self, source_id: u64, line_index: usize) -> bool {
        self.sidecar_scores
            .get(&source_id)
            .is_some_and(|store| store.get_scored(line_index))
    }

    /// Get all sidecar fields for a line from a single snapshot load.
    ///
    /// Returns `(score, unk, rare, scored)` — a single `DashMap::get` and a
    /// single `ArcSwap::load`, so all four values are guaranteed to come from
    /// the same [`ScoreSnapshot`].
    fn get_sidecar_all(&self, source_id: u64, line_index: usize) -> (f64, bool, bool, bool) {
        self.sidecar_scores
            .get(&source_id)
            .map_or((0.0, false, false, false), |store| {
                store.get_all(line_index)
            })
    }

    /// Check whether any sidecar scores are stored for the given source.
    pub fn has_sidecar_scores(&self, source_id: u64) -> bool {
        self.sidecar_scores.contains_key(&source_id)
    }

    /// Set the sidecar scoring configuration for this store.
    pub fn set_sidecar_config(&self, config: crate::core::log_file::ScoringConfig) {
        *self
            .sidecar_config
            .write()
            .expect("sidecar_config lock poisoned") = Some(config);
    }

    /// Retrieve a clone of the sidecar scoring configuration (if set).
    pub fn sidecar_config(&self) -> Option<crate::core::log_file::ScoringConfig> {
        self.sidecar_config
            .read()
            .expect("sidecar_config lock poisoned")
            .clone()
    }

    // ========================================================================
    // Bookmark Management (delegates to appropriate SourceData)
    // ========================================================================

    /// Add or update a bookmark
    pub fn set_bookmark(&self, id: &StoreID, name: String) {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        if let Some(source) = sources.get(&id.source_id) {
            source.set_bookmark(id.line_index, name);
        }
    }

    /// Remove a bookmark
    pub fn remove_bookmark(&self, id: &StoreID) -> Option<Bookmark> {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources
            .get(&id.source_id)
            .and_then(|s| s.remove_bookmark(id.line_index))
    }

    /// Drive all open calibration windows across every source (one per frame).
    ///
    /// Returns `(time_changed, optional jump target)`.
    pub fn render_file_states(&self, ui: &egui::Ui) -> (bool, Option<StoreID>) {
        profiling::scope!("LogStore::render_file_states");
        let sources = self.sources.read().expect("sources lock poisoned");
        let mut changed = false;
        let mut jump = None;
        for s in sources.values() {
            let (c, j) = s.render_file_state(ui);
            changed |= c;
            if j.is_some() {
                jump = j;
            }
        }
        (changed, jump)
    }

    /// Render type-specific context menu items for the line at `id`.
    ///
    /// Returns `true` if the source was found. Must be called inside an egui
    /// `context_menu` closure.
    #[allow(clippy::significant_drop_tightening)]
    pub fn render_typed_context_menu_items(&self, id: &StoreID, ui: &mut egui::Ui) -> bool {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        let Some(variant) = sources.get(&id.source_id) else {
            return false;
        };
        variant.render_context_menu(id.line_index, ui);
        true
    }

    /// Check if a line has a bookmark
    pub fn has_bookmark(&self, id: &StoreID) -> bool {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources
            .get(&id.source_id)
            .is_some_and(|s| s.has_bookmark(id.line_index))
    }

    /// Get a bookmark by `StoreID`
    pub fn get_bookmark(&self, id: &StoreID) -> Option<BookmarkData> {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources
            .get(&id.source_id)
            .and_then(|s| s.get_bookmark(id.line_index))
            .map(|b| BookmarkData {
                store_id: *id,
                name: b.name,
            })
    }

    /// Get all bookmarks across all sources, with their `StoreIDs`
    pub fn get_all_bookmarks(&self) -> Vec<BookmarkData> {
        profiling::scope!("LogStore::get_all_bookmarks");
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources
            .values()
            .flat_map(|source| {
                let source_id = source.source_id();
                source
                    .get_bookmarks()
                    .into_iter()
                    .map(move |bookmark| BookmarkData {
                        store_id: StoreID {
                            source_id,
                            line_index: bookmark.line_index,
                        },
                        name: bookmark.name,
                    })
            })
            .collect()
    }

    /// Save all sources' .crab files
    pub fn save_all_crab_files(&self, filters: &[SavedFilter], highlights: &[SavedHighlight]) {
        profiling::scope!("LogStore::save_all_crab_files");
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        for source in sources.values() {
            source.save_crab_file(filters, highlights);
        }
    }

    // ========================================================================
    // Line Queries
    // ========================================================================

    /// Get line indices matching a predicate, sorted by timestamp.
    ///
    /// Uses the pre-sorted `by_timestamp` index within each source, then merges.
    /// Returns `None` when `should_cancel` requests early termination.
    ///
    /// # Panics
    ///
    /// Panics if the source collection lock is poisoned.
    pub fn get_matching_ids<F, C>(&self, predicate: F, should_cancel: &C) -> Option<Vec<StoreID>>
    where
        F: Fn(&str, &str) -> bool + Sync,
        C: Fn() -> bool + Sync,
    {
        profiling::scope!("LogStore::get_matching_ids");
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");

        // Parallel filter each source, collecting only if none were cancelled.
        let per_source: Option<Vec<Vec<StoreID>>> = sources
            .par_values()
            .map(|source| {
                if should_cancel() {
                    return None;
                }
                let source_id = source.source_id();
                source
                    .filter_sorted_by_search(&predicate, should_cancel)
                    .map(|line_indices| {
                        line_indices
                            .into_iter()
                            .map(|line_index| StoreID {
                                source_id,
                                line_index,
                            })
                            .collect()
                    })
            })
            .collect();

        // Release sources lock before merge
        drop(sources);

        per_source.and_then(|per_source| self.merge_sorted_sources(per_source, should_cancel))
    }

    /// K-way merge of sorted sources by timestamp.
    ///
    /// Returns `None` when `should_cancel` requests early termination.
    fn merge_sorted_sources<C>(
        &self,
        sources: Vec<Vec<StoreID>>,
        should_cancel: &C,
    ) -> Option<Vec<StoreID>>
    where
        C: Fn() -> bool + Sync,
    {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        profiling::scope!("LogStore::merge_sorted_sources");

        let total_len: usize = sources.iter().map(Vec::len).sum();
        let mut result = Vec::with_capacity(total_len);

        // Convert to iterators
        let mut iters: Vec<_> = sources.into_iter().map(IntoIterator::into_iter).collect();

        // Use a min-heap: (timestamp, source_idx, store_id) - Reverse for min-heap behavior
        let mut heap: BinaryHeap<Reverse<(chrono::DateTime<Local>, usize, StoreID)>> =
            BinaryHeap::new();

        // Initialize heap with the first timestamped element from every source.
        for (src_idx, iter) in iters.iter_mut().enumerate() {
            for id in iter {
                if should_cancel() {
                    return None;
                }
                if let Some(adjusted_time) = self.adjusted_timestamp(&id) {
                    heap.push(Reverse((adjusted_time, src_idx, id)));
                    break;
                }
            }
        }

        // Merge
        while let Some(Reverse((_, src_idx, id))) = heap.pop() {
            if should_cancel() {
                return None;
            }
            result.push(id);

            // Push the next timestamped element from this source onto the heap.
            for next_id in &mut iters[src_idx] {
                if should_cancel() {
                    return None;
                }
                if let Some(adjusted_time) = self.adjusted_timestamp(&next_id) {
                    heap.push(Reverse((adjusted_time, src_idx, next_id)));
                    break;
                }
            }
        }

        Some(result)
    }

    /// Get the fully-calibrated timestamp for the line identified by `id`.
    ///
    /// Delegates to [`DataSourceVariant::adjusted_timestamp`] which locks `config`
    /// and `file_state` and calls `LineType::timestamp()`.  Both config-driven
    /// source selection (e.g. DLT ECU/session/storage clock) and the per-source
    /// calibration offset are applied.  Returns `None` if the source or line is
    /// not found.
    pub fn adjusted_timestamp(&self, id: &StoreID) -> Option<chrono::DateTime<Local>> {
        profiling::scope!("LogStore::adjusted_timestamp");
        let sources = self.sources.read().expect("sources lock poisoned");
        sources
            .get(&id.source_id)
            .and_then(|s| s.adjusted_timestamp(id.line_index))
    }

    /// Find the position of the line closest to a target timestamp in a sorted list.
    /// Returns the index position within `filtered_indices`.
    ///
    /// Assumes `filtered_indices` are sorted by timestamp.
    pub fn find_closest_line_position_by_time(
        &self,
        filtered_indices: &[StoreID],
        target_time: chrono::DateTime<Local>,
    ) -> Option<usize> {
        profiling::scope!("LogStore::find_closest_line_position_by_time");
        if filtered_indices.is_empty() {
            return None;
        }

        // Binary search to find insertion point
        let idx = filtered_indices.partition_point(|line_idx| {
            self.adjusted_timestamp(line_idx)
                .is_some_and(|ts| ts < target_time)
        });

        // Compare neighbors around the insertion point to find the closest
        match idx {
            0 => Some(0),
            i if i >= filtered_indices.len() => Some(filtered_indices.len() - 1),
            i => {
                let before_ts = self.adjusted_timestamp(&filtered_indices[i - 1])?;
                let after_ts = self.adjusted_timestamp(&filtered_indices[i])?;

                let dist_before = (target_time - before_ts).abs();
                let dist_after = (after_ts - target_time).abs();

                if dist_before <= dist_after {
                    Some(i - 1)
                } else {
                    Some(i)
                }
            }
        }
    }

    pub fn get_by_id(&self, id: &StoreID) -> Option<LogLine> {
        profiling::scope!("LogStore::sources::read");
        let sources = self.sources.read().expect("sources lock poisoned");
        let mut line = sources.get(&id.source_id)?.get_log_line(id.line_index)?;
        line.anomaly_score = self.get_score(id.source_id, id.line_index);
        // Load all sidecar fields from a single snapshot so a concurrent
        // set_all_with_unk cannot produce a torn combination.
        let (sidecar_score, sidecar_unk, sidecar_rare, sidecar_scored) =
            self.get_sidecar_all(id.source_id, id.line_index);
        line.sidecar_anomaly_score = sidecar_score;
        line.sidecar_score_is_unk = sidecar_unk;
        line.sidecar_score_is_rare = sidecar_rare;
        line.sidecar_scored = sidecar_scored;
        Some(line)
    }

    /// Collect the sidecar `InputLine`s for a source — using the canonical `message()`
    /// (not `display_message()`) so they match what `logcrab-export` / training produces.
    ///
    /// Returns `None` when the source is not found.
    pub fn get_sidecar_input_lines_for_source(
        &self,
        source_id: u64,
    ) -> Option<Vec<crate::anomaly::sidecar_client::InputLine>> {
        let sources = self.sources.read().expect("sources lock poisoned");
        let source = sources.get(&source_id)?;
        let slug = source.filetype_slug();
        let count = source.len();
        let lines: Vec<crate::anomaly::sidecar_client::InputLine> = (0..count)
            .filter_map(|i| {
                let (ts_ms, message) = source.get_sidecar_message(i)?;
                let template_key = crate::parser::normalize_message(&message);
                Some(crate::anomaly::sidecar_client::InputLine::new(
                    0,
                    i,
                    ts_ms,
                    message,
                    Some(template_key),
                    None,
                    Some(slug.to_string()),
                ))
            })
            .collect();
        Some(lines)
    }
}

/// Named bookmark with optional description
///
/// Each bookmark is stored within its source's .crab file.
/// The `line_index` is the line number within that source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// Line index within the source (not a global `StoreID`)
    pub line_index: usize,
    pub name: String,
}
