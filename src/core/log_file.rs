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

use crate::anomaly::{
    create_default_scorer, normalize_scores,
    sidecar_client::{InputLine, SidecarClient},
};
use crate::core::log_store::{DataSourceVariant, GlobalFileConfig, LogStore, SourceData};
use crate::core::{ChunkedLoader, SavedFilter, SavedHighlight};
use crate::filetype::{InputFileType, LineType};
use crate::ui::ProgressToastHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread;

/// Initial chunk size for incremental loading — small for fast initial feedback.
const INITIAL_CHUNK_SIZE: usize = 1 << 13; // 8,192 items
/// Maximum chunk size — prevents excessive merge overhead.
const MAX_CHUNK_SIZE: usize = 1 << 18; // 262,144 items
/// Number of chunks between each chunk-size doubling.
const CHUNKS_BEFORE_GROWTH: usize = 3;

/// Configuration for the scoring method when loading a file.
#[derive(Clone)]
pub struct ScoringConfig {
    pub use_sidecar: bool,
    pub sidecar_host: String,
    pub sidecar_port: u16,
    /// Model id (slug) to use. `None` means skip sidecar scoring.
    pub model_id: Option<String>,
}

/// Handles asynchronous loading and processing of log files
pub struct LogFileLoader;

impl LogFileLoader {
    /// Load a file of any supported format into a typed [`DataSourceVariant`].
    ///
    /// Format detection is synchronous and fast (reads ≤16 bytes for binary,
    /// ≤100 KB for text). A background thread is then spawned to drive
    /// [`ChunkedLoader`], so this call returns before the file is fully loaded.
    ///
    /// `file_config` is the session-wide [`GlobalFileConfig`]; each typed source
    /// receives `Arc::clone` of its type's config arc so config mutations propagate live.
    ///
    /// `store` is used to persist anomaly scores after loading completes.
    ///
    /// Returns `None` only if the file cannot be opened for format detection.
    pub fn load_file(
        path: &Path,
        toast: &ProgressToastHandle,
        warnings: &crate::ui::ToastSender,
        file_config: &GlobalFileConfig,
        store: &Arc<LogStore>,
    ) -> Option<(DataSourceVariant, Vec<SavedFilter>, Vec<SavedHighlight>)> {
        crate::core::log_store::try_open_binary(path, toast, warnings, file_config, store).or_else(
            || crate::core::log_store::open_text_source(path, toast, warnings, file_config, store),
        )
    }

    /// Create a typed [`SourceData<T>`], spawn a background loading thread, and
    /// return the source before loading completes.
    ///
    /// `open_fn` is called from the background thread and must return a
    /// ready-to-read [`InputFileType`] for the given path.
    ///
    /// `store` is used to persist anomaly scores after loading completes.
    pub(crate) fn load_typed<FT>(
        path: PathBuf,
        toast: &ProgressToastHandle,
        warnings: &crate::ui::ToastSender,
        config: Arc<RwLock<<FT::LineType as LineType>::Config>>,
        open_fn: impl FnOnce(&Path, Arc<<FT::LineType as LineType>::FileState>) -> anyhow::Result<FT>
            + Send
            + 'static,
        store: &Arc<LogStore>,
    ) -> (Arc<SourceData<FT>>, Vec<SavedFilter>, Vec<SavedHighlight>)
    where
        FT: InputFileType + Send + 'static,
        FT::LineType: Clone,
    {
        let (sd, filters, highlights) = SourceData::new(path.clone(), config, warnings);
        let data_source = Arc::new(sd);
        let source_id = data_source.source_id();
        let source_clone = Arc::clone(&data_source);
        let store_clone = Arc::clone(store);
        let toast_clone = toast.clone();
        thread::spawn(move || {
            Self::background_load(
                path.as_path(),
                &source_clone,
                &toast_clone,
                open_fn,
                &store_clone,
                source_id,
            );
        });
        (data_source, filters, highlights)
    }

    /// Open the file via `open_fn`, drive [`ChunkedLoader`], score, and dismiss the toast.
    fn background_load<FT>(
        path: &Path,
        data_source: &Arc<SourceData<FT>>,
        toast: &ProgressToastHandle,
        open_fn: impl FnOnce(&Path, Arc<<FT::LineType as LineType>::FileState>) -> anyhow::Result<FT>,
        store: &Arc<LogStore>,
        source_id: u64,
    ) where
        FT: InputFileType,
        FT::LineType: Clone,
    {
        let start_time = std::time::Instant::now();
        let file_size = std::fs::metadata(path).map_or(0, |m| m.len());
        let file_name = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned();

        tracing::debug!("background_load: opening {}", path.display());
        let mut file_type = match open_fn(path, Arc::clone(&data_source.file_state)) {
            Ok(ft) => ft,
            Err(e) => {
                tracing::error!("Failed to open {}: {e}", path.display());
                toast.set_error(format!("Failed to open file: {e}"));
                toast.dismiss();
                return;
            }
        };

        let loader = ChunkedLoader {
            initial_chunk_size: INITIAL_CHUNK_SIZE,
            max_chunk_size: MAX_CHUNK_SIZE,
            chunks_before_growth: CHUNKS_BEFORE_GROWTH,
        };

        let load_complete = loader.run(&mut file_type, data_source, &file_name, file_size, toast);

        if toast.is_cancel_requested() {
            tracing::info!("Loading cancelled for {}", path.display());
            store.remove_source(source_id);
            toast.dismiss();
            return;
        }

        if load_complete && !data_source.is_empty() {
            Self::score_lines(data_source, path, toast, start_time, store, source_id);
            if toast.is_cancel_requested() {
                tracing::info!("Scoring cancelled for {}", path.display());
                store.remove_source(source_id);
            }
        } else if data_source.is_empty() {
            toast.set_error("No log lines found in file");
        }
        toast.dismiss();
    }

    /// Score all lines in `data_source` and persist the results.
    ///
    /// Heuristic scoring and sidecar (ML) scoring run in parallel when the
    /// sidecar is configured.  Each scorer stores results independently in `store`.
    fn score_lines<FT>(
        data_source: &Arc<SourceData<FT>>,
        path: &Path,
        toast: &ProgressToastHandle,
        start_time: std::time::Instant,
        store: &Arc<LogStore>,
        source_id: u64,
    ) where
        FT: InputFileType,
        FT::LineType: Clone,
    {
        let sidecar_config = store.sidecar_config().filter(|c| c.use_sidecar);

        std::thread::scope(|s| {
            // ── Sidecar scoring (spawned first so it can overlap with heuristics) ──
            let sidecar_handle = sidecar_config.map(|config| {
                let ds = Arc::clone(data_source);
                let st = Arc::clone(store);
                let sidecar_toast = toast.spawn_sibling("ML Scoring", "Connecting to sidecar...");
                let p = path.to_path_buf();
                s.spawn(move || {
                    Self::score_with_sidecar(&ds, &p, &sidecar_toast, &st, source_id, &config);
                    sidecar_toast.dismiss();
                })
            });

            // ── Heuristic scoring (runs on current thread) ───────────────────────
            Self::score_heuristic(data_source, path, toast, store, source_id);
            // Dismiss the heuristic toast immediately; the sidecar has its own sibling toast.
            // The outer loader owns the primary job lifetime and dismisses it after all phases.

            // Wait for sidecar if it was spawned.
            if let Some(handle) = sidecar_handle {
                if let Err(e) = handle.join() {
                    tracing::error!("Sidecar scoring thread panicked: {e:?}");
                }
            }
        });

        tracing::info!("Total processing time: {:?}", start_time.elapsed());
    }

    /// Run the local heuristic scoring pipeline.
    fn score_heuristic<FT>(
        data_source: &Arc<SourceData<FT>>,
        path: &Path,
        toast: &ProgressToastHandle,
        store: &Arc<LogStore>,
        source_id: u64,
    ) where
        FT: InputFileType,
        FT::LineType: Clone,
    {
        static N_SKIP_INITIAL: usize = 10;

        toast.set_title("Calculating Anomaly Scores");
        toast.update(0.0, "Starting...");

        let score_start = std::time::Instant::now();
        let total_lines = data_source.len();
        tracing::debug!("Starting background anomaly scoring for {total_lines} lines");

        let mut scorer = create_default_scorer();
        let mut raw_scores = Vec::new();

        profiling::scope!("score_lines");

        for idx in 0..total_lines {
            if idx % 1000 == 0 {
                if data_source.is_cancelled() || toast.is_cancel_requested() {
                    tracing::info!("Anomaly scoring cancelled for {}", path.display());
                    toast.set_error("Scoring cancelled".to_string());
                    return;
                }
                let progress = idx as f32 / total_lines as f32;
                toast.update(progress, format!("Scoring... ({idx}/{total_lines})"));
            }

            let Some(log_line) = data_source.get_as_log_line(idx) else {
                tracing::warn!("Skipping scoring for line {idx} due to missing entry");
                raw_scores.push(0.0);
                continue;
            };

            if idx > N_SKIP_INITIAL - 1 {
                raw_scores.push(scorer.score(&log_line));
            }
            scorer.update(&log_line);
        }

        toast.update(0.95, "Normalizing scores...");

        profiling::scope!("normalize_scores");

        let normalized_scores = vec![0.0; N_SKIP_INITIAL]
            .into_iter()
            .chain(normalize_scores(&raw_scores))
            .collect::<Vec<f64>>();

        toast.update(1.0, "Done!");

        if !raw_scores.is_empty() {
            let min_raw = raw_scores.iter().copied().fold(f64::INFINITY, f64::min);
            let max_raw = raw_scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let avg_raw: f64 = raw_scores.iter().sum::<f64>() / raw_scores.len() as f64;
            tracing::info!(
                "Score statistics - Raw: min={:.3}, max={:.3}, avg={:.3}, total_lines={}",
                min_raw,
                max_raw,
                avg_raw,
                raw_scores.len()
            );
        }

        store.set_scores(source_id, &normalized_scores);

        let score_duration = score_start.elapsed();
        tracing::info!(
            "Anomaly scoring took {score_duration:?} for {}",
            path.display()
        );
    }

    /// Score lines using the `LogBERT` sidecar server — V1 WebSocket protocol.
    ///
    /// Builds `InputLine`s from the source data, sends them over a WebSocket
    /// connection, and stores the resulting scores in the store's sidecar score
    /// storage.
    fn score_with_sidecar<FT>(
        data_source: &Arc<SourceData<FT>>,
        path: &Path,
        toast: &ProgressToastHandle,
        store: &Arc<LogStore>,
        source_id: u64,
        config: &ScoringConfig,
    ) where
        FT: InputFileType,
        FT::LineType: Clone,
    {
        let Some(model_id) = config.model_id.as_deref() else {
            tracing::info!("sidecar scoring skipped: no model selected");
            return;
        };

        tracing::info!("Starting sidecar scoring with model {model_id}");
        toast.set_title(format!("ML Scoring ({model_id})"));
        toast.update(0.0, "Connecting to sidecar...");

        let client = match SidecarClient::connect(&config.sidecar_host, config.sidecar_port) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create sidecar client: {e}");
                toast.set_error(format!(
                    "Failed to connect to sidecar at {}:{}: {e}",
                    config.sidecar_host, config.sidecar_port
                ));
                return;
            }
        };

        // Quick health check — fast 30 s timeout already set on the HTTP client.
        if let Err(e) = client.health_check() {
            tracing::error!("Sidecar health check failed: {e}");
            toast.set_error(format!("Sidecar not responding: {e}"));
            return;
        }

        // ── Build InputLines ─────────────────────────────────────────────────
        // Skip template_key pre-computation — the sidecar runs its own extractor
        // server-side, so the client hint is redundant and costs O(N) CPU time
        // before the socket even opens.
        toast.update(0.0, "Preparing lines...");
        let total_lines = data_source.len();
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned());

        let t_prepare = std::time::Instant::now();
        let mut input_lines: Vec<InputLine> = Vec::with_capacity(total_lines);
        for idx in 0..total_lines {
            if idx % 1_000 == 0 && toast.is_cancel_requested() {
                tracing::info!("ML scoring cancelled while preparing {}", path.display());
                return;
            }
            let Some((ts_ms, message)) = data_source.get_sidecar_message(idx) else {
                continue;
            };
            input_lines.push(InputLine::new(
                // Protocol caps source_id to u16 (0–65535); internal IDs are u64 but
                // in practice never exceed that range within a single session.
                source_id as u16,
                idx,
                ts_ms,
                message,
                None, // template_key: let the sidecar extract it
                file_name.clone(),
                Some(FT::SLUG.to_string()),
            ));
        }
        tracing::info!(
            "Prepared {} input lines in {:.1}s",
            input_lines.len(),
            t_prepare.elapsed().as_secs_f32()
        );

        // ── Score stream ─────────────────────────────────────────────────────
        toast.update(0.1, format!("Scoring {} lines...", input_lines.len()));

        let norm_versions = crate::core::log_store::all_normalization_versions();
        // Convert to &str keys as required by score_stream.
        let norm_versions_ref: std::collections::HashMap<&str, u32> =
            norm_versions.iter().map(|(&k, &v)| (k, v)).collect();

        // Use the streaming variant so scores appear in the UI as GPU batches complete.
        let store_cb = Arc::clone(store);
        let toast_cb = toast.clone();
        // Incrementally-maintained score vectors — updated in-place each frame
        // rather than rebuilt from scratch.  Building 4 × 2.7M-entry vectors on
        // every frame (O(N) HashMap lookups) was the primary receive bottleneck.
        let mut raw_scores: Vec<f64> = vec![0.0; total_lines];
        let mut unk_flags: Vec<bool> = vec![false; total_lines];
        let mut rare_flags: Vec<bool> = vec![false; total_lines];
        let mut scored_flags: Vec<bool> = vec![false; total_lines];
        let result = match client.score_stream_streaming(
            model_id,
            &norm_versions_ref,
            &input_lines,
            &|| toast.is_cancel_requested(),
            &mut |new_entries, partial_result, total| {
                // Patch only the lines that changed this frame.
                for (&idx, entry) in new_entries {
                    if idx < total_lines {
                        raw_scores[idx] = entry.score * 5.0;
                        unk_flags[idx] = entry.target_is_unk;
                        rare_flags[idx] = entry.target_is_rare;
                        scored_flags[idx] = true;
                    }
                }
                store_cb.set_sidecar_scores_with_unk(
                    source_id,
                    &raw_scores,
                    &unk_flags,
                    &rare_flags,
                    &scored_flags,
                );

                let progress = partial_result.scored.len() as f32 / total as f32;
                toast_cb.update(
                    progress.mul_add(0.9, 0.1),
                    format!("ML scoring... ({}/{})", partial_result.scored.len(), total),
                );
            },
        ) {
            Ok((r, session)) => {
                store.set_explain_session(source_id, session);
                r
            }
            Err(e) => {
                if toast.is_cancel_requested() {
                    tracing::info!("ML scoring cancelled for {}", path.display());
                } else {
                    tracing::error!("Sidecar score_stream failed: {e}");
                    toast.set_error(format!("Sidecar scoring error: {e}"));
                }
                return;
            }
        };
        drop(client);

        for warning in &result.warnings {
            tracing::warn!("Sidecar: {warning}");
        }

        // Final store update with the complete result set.
        let raw_scores: Vec<f64> = (0..total_lines)
            .map(|idx| result.scored.get(&idx).map_or(0.0, |e| e.score * 5.0))
            .collect();
        let unk_flags: Vec<bool> = (0..total_lines)
            .map(|idx| result.scored.get(&idx).is_some_and(|e| e.target_is_unk))
            .collect();
        let rare_flags: Vec<bool> = (0..total_lines)
            .map(|idx| result.scored.get(&idx).is_some_and(|e| e.target_is_rare))
            .collect();
        let scored_flags: Vec<bool> = (0..total_lines)
            .map(|idx| result.scored.contains_key(&idx))
            .collect();

        tracing::info!(
            "Sidecar scoring complete: {}/{} lines scored for {}",
            result.scored.len(),
            total_lines,
            path.display()
        );
        store.set_sidecar_scores_with_unk(
            source_id,
            &raw_scores,
            &unk_flags,
            &rare_flags,
            &scored_flags,
        );
        toast.update(1.0, "ML scoring done!");
    }
}
