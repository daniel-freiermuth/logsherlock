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

//! Generic adaptive-chunk loading driver for [`InputFileType`] implementations.
//!
//! [`ChunkedLoader`] encapsulates the pattern shared by all file-type parsers:
//! start with a small chunk for fast initial feedback, grow the chunk size
//! exponentially to amortise `SourceData::append_lines` merge overhead, and
//! report progress via a [`ProgressToastHandle`].

use crate::core::log_store::SourceData;
use crate::filetype::InputFileType;
use crate::ui::ProgressToastHandle;
use std::sync::Arc;

/// Adaptive-chunk loading driver.
///
/// Calls [`InputFileType::read`] in loops with exponentially growing chunk
/// sizes, appending each chunk to a [`SourceData`] and updating a progress toast.
///
/// # Chunk growth
///
/// The chunk size starts at `initial_chunk_size`, doubles every
/// `chunks_before_growth` successfully completed chunks, and is capped at
/// `max_chunk_size`. This keeps the UI responsive at the start of loading while
/// minimising append overhead for large files.
#[derive(Debug, Clone)]
pub struct ChunkedLoader {
    /// Number of items to request in the first `read()` call.
    pub initial_chunk_size: usize,
    /// Upper bound for the chunk size after growth.
    pub max_chunk_size: usize,
    /// Number of completed chunks between each doubling of the chunk size.
    pub chunks_before_growth: usize,
}

impl ChunkedLoader {
    /// Drive `input.read()` in adaptive chunks, appending to `data_source`.
    ///
    /// - Stops early if the source or its user-visible job is cancelled.
    /// - Returns `true` if at least one line was loaded before completion or cancellation.
    ///
    /// `file_name` is used only in toast messages (the display name, not the full path).
    pub fn run<FT>(
        &self,
        input: &mut FT,
        data_source: &Arc<SourceData<FT>>,
        file_name: &str,
        file_size: u64,
        toast: &ProgressToastHandle,
    ) -> bool
    where
        FT: InputFileType,
        FT::LineType: Clone,
    {
        profiling::scope!("ChunkedLoader::run");

        let mut current_chunk_size = self.initial_chunk_size;
        let mut chunk_count: usize = 0;
        let start = std::time::Instant::now();

        loop {
            if data_source.is_cancelled() || toast.is_cancel_requested() {
                tracing::info!("ChunkedLoader: cancellation requested, stopping early");
                break;
            }

            let chunk = match input.read(current_chunk_size) {
                Ok(lines) => lines,
                Err(e) => {
                    tracing::error!("ChunkedLoader: read error: {e}");
                    toast.set_error(format!("Read error: {e}"));
                    return false;
                }
            };

            if chunk.is_empty() {
                break;
            }

            data_source.append_lines(chunk);
            chunk_count += 1;

            // Adaptive chunk size growth
            if chunk_count.is_multiple_of(self.chunks_before_growth)
                && current_chunk_size < self.max_chunk_size
            {
                current_chunk_size = (current_chunk_size * 2).min(self.max_chunk_size);
                tracing::debug!("ChunkedLoader: chunk size → {current_chunk_size}");
            }

            // Progress update
            let progress = if file_size > 0 {
                (input.bytes_consumed() as f32 / file_size as f32).min(1.0)
            } else {
                0.0
            };
            toast.update(
                progress,
                format!("Loading {}… ({} lines)", file_name, data_source.len()),
            );
        }

        let elapsed = start.elapsed();
        let total_lines = data_source.len();
        tracing::info!("ChunkedLoader: {total_lines} lines in {chunk_count} chunks ({elapsed:?})");

        !data_source.is_empty()
    }
}
