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

pub mod filter_bar;
pub mod filter_state;
pub mod histogram;
pub mod log_table;

pub use filter_bar::{FilterBar, FilterInternalEvent};
pub use histogram::{Histogram, HistogramMarker};
pub use log_table::{LogTable, LogTableEvent};

use crate::config::GlobalConfig;
use crate::core::log_store::StoreID;
use crate::core::{FilterRequestPriority, SavedFilter};
use crate::input::ShortcutAction;
use crate::ui::filter_highlight::FilterHighlight;
use crate::ui::session_state::{FilterToHighlightData, SessionState};
use crate::ui::tabs::filter_tab::filter_state::FilterState;
use crate::ui::tabs::filter_tab::log_table::TimestampMode;
use crate::ui::tabs::LogCrabTab;
use crate::ui::windows::{ChangeFilternameWindow, RenameFilterResult};
use egui::Ui;
use std::collections::HashMap;
use std::sync::Arc;

/// Events that can be emitted by the filter view
#[derive(Debug, Clone)]
pub enum FilterViewEvent {
    LineSelected {
        store_id: StoreID,
    },
    BookmarkToggled {
        store_id: StoreID,
    },
    FilterNameEditRequested,
    FavoriteToggled,
    /// Convert this filter to a highlight
    ConvertToHighlight,
}

/// Orchestrates the filter view UI using reusable components
pub struct FilterView {
    should_focus_search: bool,
    state: FilterState,
    change_filtername_window: Option<ChangeFilternameWindow>,
    filter_bar: FilterBar,
    /// Whether the attention panel window is visible.
    show_attention_panel: bool,
    /// The line the user last requested an explanation for.
    attention_target: Option<StoreID>,
    /// The most recent result returned by the sidecar explain session.
    attention_result: Option<crate::anomaly::sidecar_client::ExplainResult>,
    /// `true` while an explain request is in flight.
    attention_pending: bool,
    /// Set when the explain session's WebSocket closes unexpectedly.
    attention_error: Option<String>,
}

impl FilterView {
    #[must_use]
    pub const fn new(state: FilterState) -> Self {
        Self {
            should_focus_search: false,
            state,
            change_filtername_window: None,
            filter_bar: FilterBar::new(),
            show_attention_panel: false,
            attention_target: None,
            attention_result: None,
            attention_pending: false,
            attention_error: None,
        }
    }

    pub const fn focus_search_next_frame(&mut self) {
        self.should_focus_search = true;
    }
    /// Render a complete filter view
    ///
    /// Returns events that occurred during rendering
    pub fn render(
        &mut self,
        ui: &mut Ui,
        log_view_state: &mut SessionState,
        global_config: &mut GlobalConfig,
        bookmarked_lines: &HashMap<StoreID, String>,
        all_filter_highlights: &[FilterHighlight],
        histogram_markers: &[HistogramMarker],
    ) -> Vec<FilterViewEvent> {
        profiling::scope!("FilterView::render");

        let selected_line_index = log_view_state.selected_line_index;
        let mut events = Vec::new();
        if self.state.search.check_filter_results() {
            // New filter results arrived - invalidate scroll tracking so we re-scroll
            self.state.last_rendered_selection = None;
        }
        self.state.search.hide_duplicates = global_config.hide_duplicates;
        self.state.search.ensure_cache_valid(
            &log_view_state.store,
            &log_view_state.filter_worker,
            FilterRequestPriority::Interactive,
        );

        // Render filter bar
        let filter_bar_events = {
            profiling::scope!("render_filter_bar");
            self.filter_bar.render(
                ui,
                &mut self.state,
                global_config,
                self.should_focus_search,
                log_view_state,
            )
        };
        self.should_focus_search = false;

        let store = &log_view_state.store;
        // Handle filter bar events that need to bubble up
        for event in filter_bar_events {
            match event {
                FilterInternalEvent::FavoriteSelected {
                    search_text,
                    case_sensitive,
                } => {
                    self.state.search.search_text = search_text;
                    self.state.search.case_sensitive = case_sensitive;
                    log_view_state.modified = true;
                }
                FilterInternalEvent::FilterNameEditRequested => {
                    events.push(FilterViewEvent::FilterNameEditRequested);
                }
                FilterInternalEvent::FavoriteToggled => {
                    events.push(FilterViewEvent::FavoriteToggled);
                }
                FilterInternalEvent::ConvertToHighlight => {
                    events.push(FilterViewEvent::ConvertToHighlight);
                }
                FilterInternalEvent::ExportFiltered => {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Export Filtered Results")
                        .add_filter("Text", &["txt"])
                        .set_file_name("filtered_results.txt")
                        .save_file()
                    {
                        if let Err(e) =
                            export_filtered_results(&self.state, &log_view_state.store, &path)
                        {
                            tracing::error!("Failed to export filtered results: {e}");
                        } else {
                            tracing::info!("Filtered results exported to {}", path.display());
                        }
                    }
                }
            }
        }

        ui.separator();

        // Check for completed filter results from background thread
        let scroll_to_row = {
            profiling::scope!("find_scroll_position");
            if self.state.scroll_locked {
                // Scroll lock active — don't follow the global selection
                None
            } else if self.state.last_rendered_selection == selected_line_index {
                None
            } else {
                self.state.last_rendered_selection = selected_line_index;
                let closest = selected_line_index.and_then(|selected_line_index_inner| {
                    self.state
                        .search
                        .find_closest_row_position_in_cache(selected_line_index_inner, store)
                });
                self.state.closest_row_index = closest;
                closest
            }
        };

        // Render histogram (using Arc<Vec> for cheap cloning)
        let hist_event = {
            profiling::scope!("render_histogram");
            let indices = self.state.search.get_filtered_indices_cached();
            Histogram::render(
                ui,
                store,
                &indices,
                selected_line_index,
                histogram_markers,
                &mut self.state,
                &log_view_state.histogram_worker,
                global_config.color_by_ml_score,
            )
        };
        if let Some(hist_event) = hist_event {
            events.push(FilterViewEvent::LineSelected {
                store_id: hist_event.line_index,
            });
        }

        ui.separator();

        // Render log table
        let closest_row_index = self.state.closest_row_index;
        let model_is_active =
            global_config.use_sidecar_scoring && global_config.selected_model.is_some();
        let table_events = {
            profiling::scope!("render_log_table");
            LogTable::render(
                ui,
                store,
                &mut self.state,
                selected_line_index,
                bookmarked_lines,
                scroll_to_row,
                closest_row_index,
                all_filter_highlights,
                global_config.color_by_ml_score,
                global_config.grey_rare_ml_lines,
                model_is_active,
            )
        };

        // Handle table events
        for event in table_events {
            match event {
                LogTableEvent::LineClicked { line_index } => {
                    events.push(FilterViewEvent::LineSelected {
                        store_id: line_index,
                    });
                }
                LogTableEvent::BookmarkToggled { line_index } => {
                    events.push(FilterViewEvent::BookmarkToggled {
                        store_id: line_index,
                    });
                }
                LogTableEvent::SetTimeZero { line_index } => {
                    self.state.timestamp_mode = store.adjusted_timestamp(&line_index).map_or_else(
                        || {
                            tracing::warn!("Failed to set time zero for line index {line_index:?}");
                            TimestampMode::Absolute
                        },
                        TimestampMode::Relative,
                    );
                }
                LogTableEvent::ExplainAttention { line_index } => {
                    let source_id = line_index.source_id();
                    // Use the 0-based line index that matches line_id.line_number
                    // in the scoring protocol, NOT the 1-based LogLine.line_number.
                    let target_ln = line_index.line_index_within_source();
                    if store.request_explanation(source_id, target_ln) {
                        self.attention_target = Some(line_index);
                        self.attention_pending = true;
                        self.attention_error = None;
                        self.show_attention_panel = true;
                    } else {
                        // Session is closed or was never opened.
                        if let Some(ref sender) = log_view_state.toast_sender {
                            sender.send(
                                "Attention not available: sidecar session is closed".to_string(),
                            );
                        }
                    }
                }
                LogTableEvent::ClassifyLine { line_index, label } => {
                    let source_id = line_index.source_id();
                    // Use the 0-based line index that matches line_id.line_number
                    // in the sidecar protocol, NOT the 1-based LogLine.line_number.
                    let classified_line_number = line_index.line_index_within_source();
                    let Some(sidecar_config) = store.sidecar_config() else {
                        tracing::warn!("classify: no sidecar config set");
                        continue;
                    };
                    let Some(model_id) = sidecar_config.model_id else {
                        tracing::warn!("classify: no model selected");
                        continue;
                    };
                    let host = sidecar_config.sidecar_host;
                    let port = sidecar_config.sidecar_port;
                    let toast_sender = log_view_state.toast_sender.clone();
                    let store_arc = Arc::clone(&log_view_state.store);

                    std::thread::spawn(move || {
                        let result = (|| -> anyhow::Result<()> {
                            let input_lines = store_arc
                                .get_sidecar_input_lines_for_source(source_id)
                                .ok_or_else(|| anyhow::anyhow!("source {source_id} not found"))?;
                            let client = crate::anomaly::sidecar_client::SidecarClient::connect(
                                &host, port,
                            )?;
                            client.submit_sample(
                                &model_id,
                                label,
                                classified_line_number,
                                &input_lines,
                            )?;
                            drop(client);
                            Ok(())
                        })();
                        match result {
                            Ok(()) => {
                                tracing::info!(
                                    "Classification submitted: {label} for line {classified_line_number}"
                                );
                                if let Some(ref sender) = toast_sender {
                                    sender.send_success(format!(
                                        "Submitted as {label} sample (line {classified_line_number})"
                                    ));
                                }
                            }
                            Err(e) => {
                                tracing::error!("Classification upload failed: {e}");
                                if let Some(ref sender) = toast_sender {
                                    sender.send(format!("Classification upload failed: {e}"));
                                }
                            }
                        }
                    });
                }
            }
        }

        // ── Poll for explain results ──────────────────────────────────────────
        if self.attention_pending {
            if let Some(source_id) = self.attention_target.map(|t| t.source_id()) {
                use crate::anomaly::sidecar_client::ExplainPollStatus;
                match store.poll_explain_status(source_id) {
                    ExplainPollStatus::Ready(result)
                        if Some(result.target_line_number)
                            == self.attention_target.map(|t| t.line_index_within_source()) =>
                    {
                        self.attention_result = Some(result);
                        self.attention_pending = false;
                    }
                    ExplainPollStatus::Dead => {
                        self.attention_pending = false;
                        self.attention_error = Some("Sidecar connection lost".to_string());
                    }
                    ExplainPollStatus::Pending | ExplainPollStatus::Ready(_) => {}
                }
            }
        }

        // ── Render attention panel ────────────────────────────────────────────
        if self.show_attention_panel {
            crate::ui::windows::render_attention_panel(
                ui.ctx(),
                &mut self.show_attention_panel,
                store,
                self.attention_target,
                self.attention_result.as_ref(),
                self.attention_pending,
                self.attention_error.as_deref(),
            );
        }

        events
    }

    /// Render a specific filter view
    fn render_filter(
        &mut self,
        ui: &mut Ui,
        data_state: &mut SessionState,
        global_config: &mut GlobalConfig,
        all_filter_highlights: &[FilterHighlight],
        histogram_markers: &[HistogramMarker],
    ) {
        // Convert bookmarks to HashMap<StoreID, String> for the component
        let bookmarked_lines: HashMap<StoreID, String> = data_state
            .get_all_bookmarks()
            .into_iter()
            .map(|bookmark_data| (bookmark_data.store_id, bookmark_data.name))
            .collect();

        // Render using FilterView
        let events = self.render(
            ui,
            data_state,
            global_config,
            &bookmarked_lines,
            all_filter_highlights,
            histogram_markers,
        );

        // Handle events
        for event in events {
            match event {
                FilterViewEvent::LineSelected { store_id } => {
                    data_state.selected_line_index = Some(store_id);
                }
                FilterViewEvent::BookmarkToggled { store_id } => {
                    data_state.selected_line_index = Some(store_id);
                    data_state.toggle_bookmark(store_id);
                    data_state.modified = true;
                }
                FilterViewEvent::FilterNameEditRequested => {
                    // Prompt for new name
                    self.change_filtername_window =
                        Some(ChangeFilternameWindow::new(self.state.name.clone()));
                }
                FilterViewEvent::FavoriteToggled => {
                    let search_text = self.state.search.search_text.clone();
                    let case_sensitive = self.state.search.case_sensitive;

                    // Save global config
                    match GlobalConfig::update(|c| {
                        let pos = c.favorite_filters.iter().position(|f| {
                            f.search_text == search_text && f.case_sensitive == case_sensitive
                        });
                        if let Some(pos) = pos {
                            c.favorite_filters.remove(pos);
                            tracing::info!("Removed favorite: '{search_text}'");
                        } else {
                            c.favorite_filters.push(crate::config::FavoriteFilter::new(
                                search_text.clone(),
                                case_sensitive,
                            ));
                            tracing::info!("Added favorite: '{search_text}'");
                        }
                    }) {
                        Ok(updated) => *global_config = updated,
                        Err(e) => tracing::error!("Failed to save config: {e}"),
                    }
                }
                FilterViewEvent::ConvertToHighlight => {
                    // Request conversion to highlight - LogView will handle it and close this tab
                    data_state.pending_filter_to_highlight = Some(FilterToHighlightData {
                        filter_uuid: self.state.get_id(),
                        name: self.state.name.clone(),
                        search_text: self.state.search.search_text.clone(),
                        case_sensitive: self.state.search.case_sensitive,
                        color: self.state.color,
                        enabled: self.state.enabled,
                        show_in_histogram: self.state.show_in_histogram,
                    });
                }
            }
        }

        // Handle filter name editing dialog
        if let Some(ref mut window) = self.change_filtername_window {
            match window.render(ui) {
                RenameFilterResult::Saved(new_name) => {
                    self.state.name = new_name;
                    self.change_filtername_window = None;
                    data_state.modified = true;
                }
                RenameFilterResult::Pending => {
                    // Still editing
                }
                RenameFilterResult::Cancelled => {
                    // Cancelled
                    self.change_filtername_window = None;
                }
            }
        }
    }

    /// Move selection within a filtered view (only through matched indices)
    pub fn move_selection_in_filter(&self, delta: i32, data_state: &mut SessionState) {
        // Determine current position within filtered list
        data_state.selected_line_index = data_state
            .selected_line_index
            .and_then(|selected| {
                self.state
                    .search
                    .find_closest_row_position_in_cache(selected, &data_state.store)
            })
            .map(|current_pos| {
                let indices = self.state.search.get_filtered_indices_cached();

                let new_pos = if delta < 0 {
                    current_pos.saturating_sub(delta.unsigned_abs() as usize)
                } else {
                    (current_pos + delta as usize).min(indices.len().saturating_sub(1))
                };
                indices[new_pos]
            });
    }

    /// Jump to the first line in a filtered view (Vim-style gg)
    pub fn jump_to_top_in_filter(&self, data_state: &mut SessionState) {
        let indices = self.state.search.get_filtered_indices_cached();
        if let Some(first_line_index) = indices.first().copied() {
            data_state.selected_line_index = Some(first_line_index);
        }
    }

    /// Jump to the last line in a filtered view (Vim-style G)
    pub fn jump_to_bottom_in_filter(&self, data_state: &mut SessionState) {
        if let Some(last_line_index) = self
            .state
            .search
            .get_filtered_indices_cached()
            .last()
            .copied()
        {
            data_state.selected_line_index = Some(last_line_index);
        }
    }

    /// Move selection up by one page in a filtered view
    pub fn page_up_in_filter(&self, data_state: &mut SessionState) {
        // A page is approximately 20-30 lines in typical terminal views
        const PAGE_SIZE: i32 = 25;
        self.move_selection_in_filter(-PAGE_SIZE, data_state);
    }

    /// Move selection down by one page in a filtered view
    pub fn page_down_in_filter(&self, data_state: &mut SessionState) {
        const PAGE_SIZE: i32 = 25;
        self.move_selection_in_filter(PAGE_SIZE, data_state);
    }
}

impl FilterView {
    /// Get the display name for this filter (used in both tab title and histogram marker)
    ///
    /// Priority:
    /// 1. Use explicit name if set
    /// 2. Otherwise use filter text (truncated) if present  
    /// 3. Otherwise show "everything"
    fn get_display_name(&self) -> String {
        if !self.state.name.is_empty() {
            self.state.name.clone()
        } else if self.state.search.search_text.is_empty() {
            "everything".to_string()
        } else {
            let filter_text = &self.state.search.search_text;
            if filter_text.chars().count() > 10 {
                format!("{}…", filter_text.chars().take(9).collect::<String>())
            } else {
                filter_text.clone()
            }
        }
    }
}

impl LogCrabTab for FilterView {
    fn title(&mut self) -> egui::WidgetText {
        let mut layout_job = egui::text::LayoutJob::default();

        layout_job.append(
            "■ ",
            0.0,
            egui::TextFormat {
                color: self.state.color,
                ..Default::default()
            },
        );

        let display_name = self.get_display_name();
        layout_job.append(&display_name, 0.0, egui::TextFormat::default());

        layout_job.into()
    }

    fn render(
        &mut self,
        ui: &mut egui::Ui,
        data_state: &mut SessionState,
        global_config: &mut GlobalConfig,
        all_filter_highlights: &[FilterHighlight],
        histogram_markers: &[HistogramMarker],
    ) {
        // Create a new highlights list with this tab's filter at the front (for priority)
        // This ensures the current tab's filter is always visible and takes precedence
        let mut highlights_with_current = Vec::with_capacity(all_filter_highlights.len() + 1);

        // Add this tab's own filter first (if it has a valid regex)
        if let Ok(regex) = &self.state.search.get_regex() {
            if !self.state.search.search_text.is_empty() {
                highlights_with_current.push(FilterHighlight {
                    regex: regex.clone(),
                    color: self.state.color,
                });
            }
        }

        // Add all other global filters (excluding this one to avoid duplicates)
        for highlight in all_filter_highlights {
            // Skip if this is the same filter (compare by checking if regex patterns match)
            if let Ok(our_regex) = &self.state.search.get_regex() {
                if highlight.regex.as_str() != our_regex.as_str() {
                    highlights_with_current.push(highlight.clone());
                }
            } else {
                highlights_with_current.push(highlight.clone());
            }
        }

        self.render_filter(
            ui,
            data_state,
            global_config,
            &highlights_with_current,
            histogram_markers,
        );
    }

    fn process_events(
        &mut self,
        actions: &[ShortcutAction],
        data_state: &mut SessionState,
    ) -> bool {
        profiling::function_scope!();
        let mut should_save = false;
        for action in actions {
            profiling::scope!("process_event_action");
            match action {
                ShortcutAction::MoveDown => {
                    self.move_selection_in_filter(1, data_state);
                }
                ShortcutAction::MoveUp => {
                    self.move_selection_in_filter(-1, data_state);
                }
                ShortcutAction::ToggleBookmark => {
                    data_state.toggle_bookmark_for_selected();
                    should_save = true;
                }
                ShortcutAction::JumpToTop => {
                    self.jump_to_top_in_filter(data_state);
                }
                ShortcutAction::JumpToBottom => {
                    self.jump_to_bottom_in_filter(data_state);
                }
                ShortcutAction::PageUp => {
                    self.page_up_in_filter(data_state);
                }
                ShortcutAction::PageDown => {
                    self.page_down_in_filter(data_state);
                }
                ShortcutAction::FocusSearch => {
                    self.focus_search_next_frame();
                }
                ShortcutAction::NewFilterTab => {}
                ShortcutAction::NewBookmarksTab => {}
                ShortcutAction::CloseTab => {}
                ShortcutAction::CycleTab => {}
                ShortcutAction::ReverseCycleTab => {}
                ShortcutAction::OpenFile => {}
                ShortcutAction::RenameFilter => {
                    self.change_filtername_window =
                        Some(ChangeFilternameWindow::new(self.state.name.clone()));
                }
                ShortcutAction::FocusPaneLeft => {}
                ShortcutAction::FocusPaneDown => {}
                ShortcutAction::FocusPaneUp => {}
                ShortcutAction::FocusPaneRight => {}
            }
        }
        should_save
    }

    fn try_into_stored_filter(&self) -> Option<SavedFilter> {
        Some((&self.state).into())
    }

    fn get_filter_highlight(&self) -> Option<FilterHighlight> {
        self.state
            .search
            .get_regex()
            .ok()
            .filter(|_| !self.state.search.search_text.is_empty() && self.state.enabled)
            .map(|regex| FilterHighlight {
                regex,
                color: self.state.color,
            })
    }

    fn get_histogram_marker(&mut self) -> Option<HistogramMarker> {
        if !self.state.show_in_histogram {
            return None;
        }
        let indices = self.state.search.get_filtered_indices_cached();
        if indices.is_empty() {
            return None;
        }
        Some(HistogramMarker {
            name: self.get_display_name(),
            indices,
            color: self.state.color,
        })
    }

    fn context_menu(&mut self, ui: &mut egui::Ui) {
        let icon = if self.state.enabled { "👁" } else { "🚫" };
        let text = if self.state.enabled {
            "Hide in other tabs"
        } else {
            "Show in other tabs"
        };

        if ui.button(format!("{icon} {text}")).clicked() {
            self.state.enabled = !self.state.enabled;
            ui.close();
        }
    }

    fn get_uuid(&self) -> Option<usize> {
        Some(self.state.get_id())
    }
}

mod export;
use export::export_filtered_results;
