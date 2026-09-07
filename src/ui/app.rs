use super::windows;
use super::{JobManager, ToastManager};

use std::path::PathBuf;
use std::sync::Arc;

use crate::config::session_history::{RecordedSession, SessionHistory};
use crate::config::GlobalConfig;
use crate::core::histogram_worker::HistogramWorker;
use crate::core::log_store::all_file_extensions;
use crate::core::ScoringConfig;
use crate::core::{FilterWorker, LogStore};
use crate::input::{KeyboardBindings, ShortcutAction};
use crate::ui::tabs::{BookmarksView, HighlightsView};
use crate::ui::CrabSession;
use egui::text::LayoutJob;
use egui::{Color32, Id, LayerId, Order, TextStyle};
use std::fmt::Write;

/// Main application
/// Responsibilities:
/// - Main window
/// - File loading
/// - Right now, scoring. Should be moved into `LogView`
/// - Keyboard shortcut processing
#[allow(clippy::struct_excessive_bools)]
pub struct LogCrabApp {
    /// The main log view component
    session: Option<CrabSession>,

    /// Background filter worker (owned, dropped on app exit)
    filter_worker: FilterWorker,

    /// Background histogram worker (owned, dropped on app exit)
    histogram_worker: HistogramWorker,

    /// Whether to show the anomaly explanation window
    show_anomaly_explanation: bool,

    /// Whether to show the keyboard shortcuts window
    show_shortcuts_window: bool,

    /// Whether to show the about window
    show_about_window: bool,

    /// Sidecar settings window (None when closed)
    sidecar_settings_window: Option<windows::SidecarSettingsWindow>,

    /// Global configuration (shortcuts, favorites, etc.)
    global_config: GlobalConfig,

    /// Keyboard shortcut bindings
    shortcut_bindings: KeyboardBindings,

    /// Pending key rebind action
    pending_rebind: Option<ShortcutAction>,

    /// Pending dropped files to load
    pending_drop_files: Vec<PathBuf>,

    /// Pending source removal (index of source to remove)
    pending_source_removal: Option<u64>,

    /// Toast notification manager
    toast_manager: ToastManager,

    /// Active user-visible background work.
    job_manager: JobManager,

    /// Last lock-free snapshot used when a worker currently updates the job registry.
    job_snapshots: Vec<super::JobSnapshot>,

    /// Persistent session history
    session_history: SessionHistory,

    /// Pending session restore offer: when the user opens a file that belongs
    /// to one or more previous sessions, we show a dialog to let them choose.
    /// Contains (`files_being_opened`, `matching_sessions`).
    pending_session_offer: Option<PendingSessionOffer>,
}

/// State for the "restore session?" dialog
struct PendingSessionOffer {
    /// The file(s) the user originally requested
    files: Vec<PathBuf>,
    /// Previous sessions that contain at least one of those files
    matching_sessions: Vec<RecordedSession>,
}

/// Action chosen in the session offer dialog
enum SessionOfferAction {
    JustTheFiles,
    RestoreSession(usize),
    MergeSession(usize),
    Cancel,
}

impl LogCrabApp {
    /// Update the window title based on open files
    fn update_window_title(&self, ctx: &egui::Context) {
        let title = self.session.as_ref().map_or_else(
            || "LogCrab".to_string(),
            |session| {
                let filenames = session.state.store.get_source_filenames();
                if filenames.is_empty() {
                    "LogCrab".to_string()
                } else {
                    let names: Vec<&str> =
                        filenames.iter().map(|(_, name)| name.as_str()).collect();
                    format!("{} - LogCrab", names.join(", "))
                }
            },
        );
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
    }

    #[must_use]
    pub fn new(cc: &eframe::CreationContext<'_>, files: Vec<PathBuf>) -> Self {
        // Load global configuration
        let global_config = GlobalConfig::load();

        // Apply saved theme
        if global_config.bright_mode {
            cc.egui_ctx.set_visuals(egui::Visuals::light());
        } else {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
        }

        let mut session_history = SessionHistory::load();
        session_history.prune_missing();

        let mut app = Self {
            session: None,
            filter_worker: FilterWorker::new(),
            histogram_worker: HistogramWorker::new(),
            show_anomaly_explanation: false,
            show_shortcuts_window: false,
            show_about_window: false,
            sidecar_settings_window: None,
            shortcut_bindings: KeyboardBindings::load(&global_config),
            global_config,
            pending_rebind: None,
            pending_drop_files: Vec::new(),
            pending_source_removal: None,
            toast_manager: ToastManager::new(cc.egui_ctx.clone()),
            job_manager: JobManager::new(cc.egui_ctx.clone()),
            job_snapshots: Vec::new(),
            session_history,
            pending_session_offer: None,
        };

        // Load initial files if provided via command line
        if !files.is_empty() {
            app.start_new_session();
            for file in files {
                if file.exists() {
                    app.add_file_to_session(file);
                } else {
                    app.toast_manager
                        .show_error(format!("File not found: {}", file.display()));
                }
            }
        }
        app
    }

    pub fn start_new_session(&mut self) {
        // Record the outgoing session before replacing it
        self.record_current_session();

        // Create a new store for this file
        let store = LogStore::new();
        // Push sidecar scoring config so background loading threads can use it
        self.apply_sidecar_config_to_store(&store);
        let mut session = CrabSession::new(
            store,
            self.filter_worker.handle(),
            self.histogram_worker.handle(),
        );
        // Give the session a toast sender so background threads (e.g. classification
        // uploads) can surface success/error notifications without blocking the UI.
        session.state.toast_sender = Some(self.toast_manager.sender());
        self.session = Some(session);
    }

    /// Save the current session's file set into the session history
    fn record_current_session(&mut self) {
        if let Some(ref session) = self.session {
            let paths = session.state.store.get_source_file_paths();
            if !paths.is_empty() {
                match SessionHistory::update(|h| h.record(paths)) {
                    Ok(updated) => self.session_history = updated,
                    Err(e) => tracing::error!("Failed to save session history: {e}"),
                }
            }
        }
    }

    /// Check if any of the given files belong to a previously recorded session.
    /// If so, stash a `PendingSessionOffer` so the UI can show a dialog.
    /// Returns `true` if an offer dialog will be shown (caller should not open the files yet).
    fn check_session_offer(&mut self, files: Vec<PathBuf>) -> bool {
        let mut matching: Vec<RecordedSession> = Vec::new();
        for file in &files {
            for session in self.session_history.sessions_containing(file) {
                // Skip if this session is identical to what was already requested
                if session.same_files(&files) {
                    continue;
                }
                // Skip duplicates
                if matching.iter().any(|m| m.same_files(&session.files)) {
                    continue;
                }
                // Only offer sessions whose files all still exist
                if session.all_files_exist() {
                    matching.push(session.clone());
                }
            }
        }

        if matching.is_empty() {
            return false;
        }

        self.pending_session_offer = Some(PendingSessionOffer {
            files,
            matching_sessions: matching,
        });
        true
    }

    /// Open a set of files as a new session (unconditionally, no session-offer check)
    fn open_files_as_new_session(&mut self, files: Vec<PathBuf>) {
        self.start_new_session();
        for file in files {
            if file.exists() {
                self.add_file_to_session(file);
            } else {
                self.toast_manager
                    .show_error(format!("File not found: {}", file.display()));
            }
        }
    }

    /// Restore a recorded session
    fn restore_session(&mut self, session: &RecordedSession) {
        let files = session.files.clone();
        self.open_files_as_new_session(files);
    }

    /// Build a `ScoringConfig` from the current global config and set it on the store.
    fn apply_sidecar_config_to_store(&self, store: &Arc<LogStore>) {
        store.set_sidecar_config(ScoringConfig {
            use_sidecar: self.global_config.use_sidecar_scoring,
            sidecar_host: self.global_config.sidecar_host.clone(),
            sidecar_port: self.global_config.sidecar_port,
            model_id: self.global_config.selected_model.clone(),
        });
    }

    /// Add a file to the current session
    fn add_file_to_session(&mut self, mut path: PathBuf) {
        if let Some(ref mut session) = self.session {
            // Check if this is a .crab session file
            if path.to_string_lossy().ends_with(".crab") {
                path = PathBuf::from(path.to_string_lossy().trim_end_matches(".crab"));

                if path.exists() {
                    tracing::info!("Loading log file from .crab session: {}", path.display());
                } else {
                    let err_msg = format!("File not found: {}", path.display());
                    tracing::error!("{err_msg}");
                    self.toast_manager.show_error(err_msg);
                    return;
                }
            }
            let file_name = path
                .file_name()
                .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().to_string());
            let job = self
                .job_manager
                .start(format!("Processing {file_name}"), "Starting…");
            let toast_handle = self
                .toast_manager
                .create_progress_toast(file_name, "Starting...")
                .track_job(job);
            let warnings = self.toast_manager.sender();

            session.add_file(
                &path,
                &toast_handle,
                &warnings,
                &self.global_config.file_config,
            );
        }
    }

    /// Show file dialog and load selected file
    fn open_file_dialog(&mut self) {
        let mut dialog = rfd::FileDialog::new()
            .add_filter("Log Files", &all_file_extensions())
            .add_filter("All Files", &["*"]);

        if let Some(ref dir) = self.global_config.last_log_directory {
            dialog = dialog.set_directory(dir);
        }

        if let Some(paths) = dialog.pick_files() {
            if let Some(first) = paths.first() {
                if let Some(parent) = first.parent() {
                    let dir = parent.to_path_buf();
                    match GlobalConfig::update(|c| c.last_log_directory = Some(dir)) {
                        Ok(updated) => self.global_config = updated,
                        Err(e) => tracing::error!("Failed to update config: {e}"),
                    }
                }
            }

            // Check if any of the selected files belong to a previous session
            if !self.check_session_offer(paths.clone()) {
                self.open_files_as_new_session(paths);
            }
        }
    }

    /// Show file dialog and add selected file(s) to the current workspace
    fn add_file_dialog(&mut self) {
        let mut dialog = rfd::FileDialog::new()
            .add_filter("Log Files", &all_file_extensions())
            .add_filter("All Files", &["*"]);

        if let Some(ref dir) = self.global_config.last_log_directory {
            dialog = dialog.set_directory(dir);
        }

        if let Some(paths) = dialog.pick_files() {
            // Remember the directory from the first file
            if let Some(first) = paths.first() {
                if let Some(parent) = first.parent() {
                    let dir = parent.to_path_buf();
                    match GlobalConfig::update(|c| c.last_log_directory = Some(dir)) {
                        Ok(updated) => self.global_config = updated,
                        Err(e) => tracing::error!("Failed to update config: {e}"),
                    }
                }
            }

            // Check if any of the added files belong to a previous session
            if !self.check_session_offer(paths.clone()) {
                for path in paths {
                    self.add_file_to_session(path);
                }
            }
        }
    }

    /// Process multiple dropped files
    /// - If no session exists, first log file is loaded as main file
    /// - If session exists, additional log files are added to the workspace
    /// - All .crab-filters files are imported
    fn process_dropped_files(&mut self, files: Vec<PathBuf>) {
        let mut log_files: Vec<PathBuf> = Vec::new();
        let mut filter_files: Vec<PathBuf> = Vec::new();

        for path in files {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            if ext == "crab-filters" {
                filter_files.push(path);
            } else {
                log_files.push(path);
            }
        }

        // Check session history for dropped log files
        if !log_files.is_empty() && !self.check_session_offer(log_files.clone()) {
            // No session offer — proceed as before
            if self.session.is_none() {
                self.start_new_session();
            }

            for path in log_files {
                tracing::info!("Adding dropped file to workspace: {}", path.display());
                self.add_file_to_session(path);
            }
        }

        // Import filter files if we have a log view
        if !filter_files.is_empty() {
            if let Some(ref mut log_view) = self.session {
                for path in &filter_files {
                    tracing::info!("Importing dropped filter file: {}", path.display());
                    match log_view.import_filters(path) {
                        Ok(count) => {
                            tracing::info!("Imported {count} filters from {}", path.display());
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to import filters from {}: {e}",
                                path.display()
                            );
                            self.toast_manager.show_error(format!(
                                "Failed to import {}: {e}",
                                path.file_name().map_or_else(
                                    || "filters".to_string(),
                                    |n| n.to_string_lossy().to_string()
                                )
                            ));
                        }
                    }
                }
            } else {
                tracing::warn!(
                    "Cannot import filter files - no log file is open. Open a log file first."
                );
                self.toast_manager
                    .show_error("Cannot import filters - open a log file first");
            }
        }
    }

    /// Render top menu bar
    fn render_menu_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.menu_button("File", |ui| {
            if ui.button("Open Log File...").clicked() {
                self.open_file_dialog();
                ui.close();
            }

            if self.session.is_some() && ui.button("Add File to session...").clicked() {
                self.add_file_dialog();
                ui.close();
            }

            // Recent sessions submenu
            if !self.session_history.sessions.is_empty() {
                let mut restore_idx: Option<usize> = None;
                ui.menu_button("Recent Sessions", |ui| {
                    for (idx, session) in self.session_history.sessions.iter().enumerate() {
                        let label = session.display_label();
                        let time_str = session.last_used.format("%Y-%m-%d %H:%M").to_string();
                        let tooltip = session
                            .files
                            .iter()
                            .map(|f| f.display().to_string())
                            .collect::<Vec<_>>()
                            .join("\n");

                        if ui
                            .button(format!("{label}  ({time_str})"))
                            .on_hover_text(tooltip)
                            .clicked()
                        {
                            restore_idx = Some(idx);
                            ui.close();
                        }
                    }
                });
                if let Some(idx) = restore_idx {
                    let session = self.session_history.sessions[idx].clone();
                    self.restore_session(&session);
                }
            }

            // Show submenu to remove individual files
            if let Some(ref session) = self.session {
                let filenames = session.state.store.get_source_filenames();
                if !filenames.is_empty() {
                    ui.menu_button("Remove File from session", |ui| {
                        for (source_id, filename) in filenames {
                            if ui.button(&filename).clicked() {
                                self.pending_source_removal = Some(source_id);
                                ui.close();
                            }
                        }
                    });
                }
            }

            ui.separator();

            if let Some(ref mut log_view) = &mut self.session {
                if ui.button("Export Filters...").clicked() {
                    let mut dialog = rfd::FileDialog::new()
                        .add_filter("Crab Filters", &["crab-filters"])
                        .add_filter("All Files", &["*"])
                        .set_file_name("filters.crab-filters");

                    if let Some(ref dir) = self.global_config.last_filters_directory {
                        dialog = dialog.set_directory(dir);
                    }

                    if let Some(path) = dialog.save_file() {
                        if let Some(parent) = path.parent() {
                            let dir = parent.to_path_buf();
                            match GlobalConfig::update(|c| c.last_filters_directory = Some(dir)) {
                                Ok(updated) => self.global_config = updated,
                                Err(e) => tracing::error!("Failed to update config: {e}"),
                            }
                        }
                        match log_view.export_filters(&path) {
                            Ok(()) => tracing::info!("Filters exported successfully"),
                            Err(e) => tracing::error!("Failed to export filters: {e}"),
                        }
                    }
                    ui.close();
                }
                if ui.button("Import Filters...").clicked() {
                    let mut dialog = rfd::FileDialog::new()
                        .add_filter("Crab Filters", &["crab-filters"])
                        .add_filter("All Files", &["*"]);

                    if let Some(ref dir) = self.global_config.last_filters_directory {
                        dialog = dialog.set_directory(dir);
                    }

                    if let Some(paths) = dialog.pick_files() {
                        // Remember the directory from the first file
                        if let Some(first) = paths.first() {
                            if let Some(parent) = first.parent() {
                                let dir = parent.to_path_buf();
                                match GlobalConfig::update(|c| c.last_filters_directory = Some(dir))
                                {
                                    Ok(updated) => self.global_config = updated,
                                    Err(e) => tracing::error!("Failed to update config: {e}"),
                                }
                            }
                        }
                        for path in paths {
                            match log_view.import_filters(&path) {
                                Ok(count) => {
                                    tracing::info!(
                                        "Imported {count} filters from {}",
                                        path.display()
                                    );
                                }
                                Err(e) => tracing::error!(
                                    "Failed to import filters from {}: {e}",
                                    path.display()
                                ),
                            }
                        }
                    }
                    ui.close();
                }
                ui.separator();
            }

            if ui.button("Sidecar Settings...").clicked() {
                self.sidecar_settings_window = Some(
                    windows::SidecarSettingsWindow::open_with_config(&self.global_config),
                );
                ui.close();
            }

            ui.separator();

            if ui.button("Quit").clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });

        ui.menu_button("View", |ui| {
            if let Some(ref mut log_view) = &mut self.session {
                if ui.button("Add Filter Tab").clicked() {
                    log_view.add_filter_view(false, None);
                    ui.close();
                }

                if ui.button("Add Bookmarks Tab").clicked() {
                    log_view
                        .dock_state
                        .push_to_focused_leaf(Box::new(BookmarksView::default()));
                    ui.close();
                }

                if ui.button("Add Highlights Tab").clicked() {
                    log_view
                        .dock_state
                        .push_to_focused_leaf(Box::new(HighlightsView::new()));
                    ui.close();
                }

                ui.separator();
            }

            if ui
                .checkbox(
                    &mut self.global_config.show_bookmarks_in_timeline,
                    "Show Bookmarks in Timeline",
                )
                .changed()
            {
                let new_val = self.global_config.show_bookmarks_in_timeline;
                match GlobalConfig::update(|c| c.show_bookmarks_in_timeline = new_val) {
                    Ok(updated) => self.global_config = updated,
                    Err(e) => tracing::error!("Failed to update config: {e}"),
                }
            }

            ui.separator();

            if ui
                .checkbox(&mut self.global_config.bright_mode, "Bright Mode")
                .changed()
            {
                // Apply theme change
                if self.global_config.bright_mode {
                    ctx.set_visuals(egui::Visuals::light());
                } else {
                    ctx.set_visuals(egui::Visuals::dark());
                }
                let new_val = self.global_config.bright_mode;
                match GlobalConfig::update(|c| c.bright_mode = new_val) {
                    Ok(updated) => self.global_config = updated,
                    Err(e) => tracing::error!("Failed to update config: {e}"),
                }
            }

            ui.separator();

            if self.global_config.file_config.render(ui) {
                let new_fc = self.global_config.file_config.clone();
                match GlobalConfig::update(|c| c.file_config = new_fc) {
                    Ok(updated) => self.global_config = updated,
                    Err(e) => tracing::error!("Failed to update config: {e}"),
                }
                if let Some(ref mut session) = self.session {
                    session
                        .state
                        .store
                        .rebuild_all_time_indices(&self.global_config.file_config);
                }
            }

            ui.separator();

            if ui
                .checkbox(
                    &mut self.global_config.use_sidecar_scoring,
                    "Enable ML Scoring",
                )
                .on_hover_text("Send log lines to the sidecar server for ML-based anomaly scoring")
                .changed()
            {
                let new_val = self.global_config.use_sidecar_scoring;
                match GlobalConfig::update(|c| c.use_sidecar_scoring = new_val) {
                    Ok(updated) => self.global_config = updated,
                    Err(e) => tracing::error!("Failed to update config: {e}"),
                }
            }

            if ui
                .checkbox(
                    &mut self.global_config.color_by_ml_score,
                    "Color by ML Score",
                )
                .on_hover_text("Color log lines by ML anomaly score instead of local heuristic scorer")
                .changed()
            {
                let new_val = self.global_config.color_by_ml_score;
                match GlobalConfig::update(|c| c.color_by_ml_score = new_val) {
                    Ok(updated) => self.global_config = updated,
                    Err(e) => tracing::error!("Failed to update config: {e}"),
                }
            }

            if self.global_config.color_by_ml_score
                && ui
                    .checkbox(
                        &mut self.global_config.grey_rare_ml_lines,
                        "Grey out rare lines",
                    )
                    .on_hover_text("Show RARE-flagged lines in grey instead of their scored color (rare = in-corpus but seen < min_count times in training)")
                    .changed()
                {
                    let new_val = self.global_config.grey_rare_ml_lines;
                    match GlobalConfig::update(|c| c.grey_rare_ml_lines = new_val) {
                        Ok(updated) => self.global_config = updated,
                        Err(e) => tracing::error!("Failed to update config: {e}"),
                    }
                }

            ui.separator();

            if ui
                .checkbox(
                    &mut self.global_config.hide_duplicates,
                    "Hide Duplicate Lines",
                )
                .on_hover_text("Hide exact duplicate log lines (same timestamp, source, and message)")
                .changed()
            {
                let new_val = self.global_config.hide_duplicates;
                match GlobalConfig::update(|c| c.hide_duplicates = new_val) {
                    Ok(updated) => self.global_config = updated,
                    Err(e) => tracing::error!("Failed to update config: {e}"),
                }
            }
        });

        ui.menu_button("Help", |ui| {
            if ui.button("Anomaly Score Calculation").clicked() {
                self.show_anomaly_explanation = true;
                ui.close();
            }
            if ui.button("Keyboard Shortcuts").clicked() {
                self.show_shortcuts_window = true;
                ui.close();
            }
            ui.separator();
            if ui.button("About LogCrab").clicked() {
                self.show_about_window = true;
                ui.close();
            }
        });
    }

    /// Render bottom status panel
    fn render_status_panel(&mut self, ui: &mut egui::Ui) {
        if let Some(snapshots) = self.job_manager.try_snapshots() {
            self.job_snapshots = snapshots;
        }
        let jobs = &self.job_snapshots;
        ui.horizontal(|ui| {
            // Show filtering indicator if any filter is currently processing
            if self
                .filter_worker
                .handle()
                .is_filtering
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                ui.separator();
                ui.spinner();
                ui.label("Filtering...");
            }

            if !jobs.is_empty() {
                ui.separator();
                ui.collapsing(format!("Jobs ({})", jobs.len()), |ui| {
                    for job in jobs {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.vertical(|ui| {
                                ui.strong(&job.title);
                                ui.small(&job.message);
                                if let Some(progress) = job.progress {
                                    ui.add(
                                        egui::ProgressBar::new(progress)
                                            .desired_width(160.0)
                                            .show_percentage(),
                                    );
                                }
                            });
                            if job.cancelling {
                                ui.add_enabled(false, egui::Button::new("Cancelling…"));
                            } else if ui.button("Cancel").clicked() {
                                job.request_cancel();
                            }
                        });
                    }
                });
            }
        });
    }

    /// Render central content area with dock layout
    fn render_central_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        profiling::scope!("central_panel");

        // Preview hovering files
        Self::preview_files_being_dropped(ctx);

        // Collect dropped files (store for later processing)
        ctx.input(|i| {
            for file in &i.raw.dropped_files {
                if let Some(path) = &file.path {
                    self.pending_drop_files.push(path.clone());
                }
            }
        });

        if let Some(ref mut log_view) = self.session {
            log_view.render(ui, &mut self.global_config);
        } else {
            self.render_welcome_screen(ui);
        }
    }

    /// Render the welcome/start screen shown when no session is active
    fn render_welcome_screen(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.heading("Welcome to LogCrab 🦀");
            ui.add_space(20.0);

            if ui.button("Open Log File").clicked() {
                self.open_file_dialog();
            }

            ui.add_space(30.0);

            // Show previous sessions
            if !self.session_history.sessions.is_empty() {
                ui.separator();
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Previous Sessions").strong());
                ui.add_space(8.0);

                let mut session_to_restore: Option<usize> = None;
                let mut session_to_remove: Option<Vec<PathBuf>> = None;

                egui::ScrollArea::vertical()
                    .max_height(ui.available_height() - 20.0)
                    .show(ui, |ui| {
                        for (idx, session) in self.session_history.sessions.iter().enumerate() {
                            ui.horizontal(|ui| {
                                // Session restore button: show filenames
                                let label = session.display_label();
                                let tooltip = session
                                    .files
                                    .iter()
                                    .map(|f| f.display().to_string())
                                    .collect::<Vec<_>>()
                                    .join("\n");

                                let time_str =
                                    session.last_used.format("%Y-%m-%d %H:%M").to_string();

                                if ui
                                    .button(&label)
                                    .on_hover_text(format!("{tooltip}\n\nLast used: {time_str}"))
                                    .clicked()
                                {
                                    session_to_restore = Some(idx);
                                }

                                ui.weak(&time_str);

                                if ui
                                    .small_button("✕")
                                    .on_hover_text("Remove from history")
                                    .clicked()
                                {
                                    session_to_remove = Some(session.files.clone());
                                }
                            });
                        }
                    });

                if let Some(files) = &session_to_remove {
                    match SessionHistory::update(|h| {
                        h.sessions.retain(|s| !s.same_files(files));
                    }) {
                        Ok(updated) => self.session_history = updated,
                        Err(e) => tracing::error!("Failed to save session history: {e}"),
                    }
                } else if let Some(idx) = session_to_restore {
                    let session = self.session_history.sessions[idx].clone();
                    self.restore_session(&session);
                }
            }
        });
    }

    /// Render the "Restore previous session?" dialog window
    fn render_session_offer_dialog(&mut self, ctx: &egui::Context) {
        let Some(ref offer) = self.pending_session_offer else {
            return;
        };

        let mut action: Option<SessionOfferAction> = None;

        egui::Window::new("Restore Previous Session?")
            .collapsible(false)
            .resizable(true)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let file_label: String = offer
                    .files
                    .iter()
                    .filter_map(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(", ");
                ui.label(format!(
                    "The file(s) you selected ({file_label}) appeared in previous sessions."
                ));
                ui.label("Would you like to restore one of those sessions?");
                ui.add_space(10.0);

                // Option: open just the requested files
                if ui.button(format!("Open only: {file_label}")).clicked() {
                    action = Some(SessionOfferAction::JustTheFiles);
                }

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(6.0);

                // Options: each matching previous session
                for (idx, session) in offer.matching_sessions.iter().enumerate() {
                    let label = session.display_label();
                    let time_str = session.last_used.format("%Y-%m-%d %H:%M").to_string();
                    let tooltip = session
                        .files
                        .iter()
                        .map(|f| f.display().to_string())
                        .collect::<Vec<_>>()
                        .join("\n");

                    ui.label(format!("{label}  ({time_str})"))
                        .on_hover_text(&tooltip);
                    ui.horizontal(|ui| {
                        if ui
                            .button("Replace current session")
                            .on_hover_text(format!("Close current files and restore:\n{tooltip}"))
                            .clicked()
                        {
                            action = Some(SessionOfferAction::RestoreSession(idx));
                        }
                        if ui
                            .button("Merge with current session")
                            .on_hover_text(format!(
                                "Add these files to the current session:\n{tooltip}"
                            ))
                            .clicked()
                        {
                            action = Some(SessionOfferAction::MergeSession(idx));
                        }
                    });
                    ui.add_space(4.0);
                }

                ui.add_space(6.0);
                if ui.button("Cancel").clicked() {
                    action = Some(SessionOfferAction::Cancel);
                }
            });

        if let Some(act) = action {
            // Take ownership of the offer to avoid borrow issues
            let Some(offer) = self.pending_session_offer.take() else {
                return;
            };
            match act {
                SessionOfferAction::JustTheFiles => {
                    if self.session.is_none() {
                        self.open_files_as_new_session(offer.files);
                    } else {
                        for path in offer.files {
                            self.add_file_to_session(path);
                        }
                    }
                }
                SessionOfferAction::RestoreSession(idx) => {
                    let session = &offer.matching_sessions[idx];
                    self.restore_session(session);
                }
                SessionOfferAction::MergeSession(idx) => {
                    let session = &offer.matching_sessions[idx];
                    if self.session.is_none() {
                        self.start_new_session();
                    }
                    for path in &session.files {
                        if path.exists() {
                            self.add_file_to_session(path.clone());
                        }
                    }
                }
                SessionOfferAction::Cancel => {}
            }
        }
    }

    /// Preview hovering files - shows overlay when dragging files over window
    fn preview_files_being_dropped(ctx: &egui::Context) {
        // Show overlay whenever the backend reports hovered files.
        // The XWayland/X11 stuck-overlay edge case (HoveredFileCancelled never
        // sent) is unlikely in practice and less harmful than not showing the
        // overlay at all on Wayland where neither focus nor pointer position are
        // reliably reported during drag-and-drop.
        let active = ctx.input(|i| !i.raw.hovered_files.is_empty());
        if active {
            let text = ctx.input(|i| {
                let mut text = "Drop to open:\n".to_owned();
                for file in &i.raw.hovered_files {
                    if let Some(path) = &file.path {
                        let _ = write!(text, "\n{}", path.display());
                    }
                }
                text
            });

            let screen_rect = ctx.content_rect();
            let painter =
                ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("file_drop_target")));
            painter.rect_filled(screen_rect, 0.0, Color32::from_black_alpha(192));

            let font = TextStyle::Heading.resolve(&ctx.style());
            let mut layout_job =
                LayoutJob::simple(text, font, Color32::WHITE, screen_rect.width() - 40.0);
            layout_job.wrap.max_width = screen_rect.width() - 40.0;

            let galley = painter.layout_job(layout_job);
            let text_pos = screen_rect.center() - galley.rect.size() / 2.0;
            painter.galley(text_pos, galley, Color32::WHITE);
        }
    }

    /// Process keyboard shortcuts and execute actions
    fn process_keyboard_input(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        profiling::scope!("process_keyboard_input");
        // Skip keyboard shortcuts if text input is focused AND no modifiers are pressed
        // This allows shortcuts like Ctrl+w to work even in text fields
        let has_modifiers = raw_input.events.iter().any(|event| {
            matches!(
                event,
                egui::Event::Key { modifiers, .. } if modifiers.ctrl || modifiers.alt || modifiers.command
            )
        });

        if ctx.wants_keyboard_input() && !has_modifiers {
            return;
        }

        let (actions, events_to_remove, shortcuts_changed) = self
            .shortcut_bindings
            .process_input(raw_input, &mut self.pending_rebind);

        // Save shortcuts if they were changed
        if shortcuts_changed {
            self.shortcut_bindings
                .save_to_config(&mut self.global_config);
            let new_shortcuts = self.global_config.shortcuts.clone();
            match GlobalConfig::update(|c| c.shortcuts = new_shortcuts) {
                Ok(updated) => self.global_config = updated,
                Err(e) => tracing::error!("Failed to update config: {e}"),
            }
        }

        if let Some(ref mut log_view) = self.session {
            log_view.process_keyboard_input(&actions);
        }

        for action in actions {
            match action {
                ShortcutAction::ToggleBookmark => {}
                ShortcutAction::FocusSearch => {}
                ShortcutAction::NewFilterTab => {}
                ShortcutAction::NewBookmarksTab => {}
                ShortcutAction::CloseTab => {}
                ShortcutAction::CycleTab => {}
                ShortcutAction::ReverseCycleTab => {}
                ShortcutAction::JumpToTop => {}
                ShortcutAction::JumpToBottom => {}
                ShortcutAction::PageUp => {}
                ShortcutAction::PageDown => {}
                ShortcutAction::OpenFile => {
                    self.open_file_dialog();
                }
                ShortcutAction::RenameFilter => {}
                ShortcutAction::MoveUp => {}
                ShortcutAction::MoveDown => {}
                ShortcutAction::FocusPaneLeft => {}
                ShortcutAction::FocusPaneDown => {}
                ShortcutAction::FocusPaneUp => {}
                ShortcutAction::FocusPaneRight => {}
            }
        }

        // Remove consumed events in reverse order
        for idx in events_to_remove.into_iter().rev() {
            raw_input.events.remove(idx);
        }
    }
}

impl eframe::App for LogCrabApp {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        profiling::scope!("raw_input_hook");
        self.process_keyboard_input(ctx, raw_input);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        profiling::function_scope!();

        // Update window title based on open files
        self.update_window_title(ctx);

        // Process pending dropped files
        if !self.pending_drop_files.is_empty() {
            profiling::scope!("process_dropped_files");
            let files = std::mem::take(&mut self.pending_drop_files);
            self.process_dropped_files(files);
        }

        // Process pending source removal
        if let Some(source_id) = self.pending_source_removal.take() {
            if let Some(ref mut session) = self.session {
                // Save .crab file before removal to persist any unsaved data
                session.save_crab_file();
                session.state.store.remove_source(source_id);
            }
        }

        {
            profiling::scope!("top_panel");
            egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
                egui::MenuBar::new().ui(ui, |ui| {
                    self.render_menu_bar(ui, ctx);
                });
            });
        }

        {
            profiling::scope!("bottom_panel");
            egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
                self.render_status_panel(ui);
            });
        }

        {
            profiling::scope!("central_panel_show");
            egui::CentralPanel::default().show(ctx, |ui| {
                self.render_central_panel(ui, ctx);
            });
        }

        // Show windows
        if self.show_anomaly_explanation {
            windows::render_anomaly_explanation(ctx, &mut self.show_anomaly_explanation);
        }

        if self.show_shortcuts_window {
            windows::render_shortcuts_window(
                ctx,
                &mut self.show_shortcuts_window,
                &mut self.shortcut_bindings,
                &mut self.pending_rebind,
                &mut self.global_config,
            );
        }

        if self.show_about_window {
            windows::render_about_window(ctx, &mut self.show_about_window);
        }

        // Show session offer dialog
        if self.pending_session_offer.is_some() {
            self.render_session_offer_dialog(ctx);
        }

        // Show sidecar settings window
        {
            if let Some(mut sidecar_window) = self.sidecar_settings_window.take() {
                let mut open = true;
                egui::Window::new("Sidecar Settings")
                    .collapsible(false)
                    .resizable(true)
                    .open(&mut open)
                    .show(ctx, |ui| {
                        if sidecar_window.render(ui, &mut self.global_config) {
                            let host = self.global_config.sidecar_host.clone();
                            let port = self.global_config.sidecar_port;
                            let use_sidecar = self.global_config.use_sidecar_scoring;
                            let model = self.global_config.selected_model.clone();
                            match GlobalConfig::update(|c| {
                                c.sidecar_host = host;
                                c.sidecar_port = port;
                                c.use_sidecar_scoring = use_sidecar;
                                c.selected_model = model;
                            }) {
                                Ok(updated) => self.global_config = updated,
                                Err(e) => tracing::error!("Failed to update config: {e}"),
                            }
                            // Update store with new sidecar config
                            if let Some(ref session) = self.session {
                                self.apply_sidecar_config_to_store(&session.state.store);
                            }
                        }
                    });

                if open {
                    self.sidecar_settings_window = Some(sidecar_window);
                }
            }
        }

        // Show toast notifications
        self.toast_manager.show(ctx);

        profiling::finish_frame!();
    }
}

impl Drop for LogCrabApp {
    fn drop(&mut self) {
        // Save .crab files and record session history on exit
        if let Some(ref session) = self.session {
            session.save_crab_file();
        }
        self.record_current_session();
    }
}
