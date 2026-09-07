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

//! Toast notification system with thread-safe handles for background operations.
//!
//! The loader thread can own a `ProgressToastHandle` and update it directly.
//! The `ToastManager` renders all active handles each frame.

use crate::ui::JobHandle;
use egui::{Align2, Color32, Margin};
use egui_toast::{Toast, ToastKind, ToastOptions, ToastStyle, Toasts};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

/// Shared state for a progress toast, updated by the handle, read by the renderer
#[derive(Debug, Clone)]
pub struct ProgressToastState {
    /// Title shown at the top of the toast
    pub title: String,
    /// Current progress (0.0 to 1.0), None for indeterminate
    pub progress: Option<f32>,
    /// Status message
    pub message: String,
    /// When the toast was dismissed (None if still active)
    pub dismissed_at: Option<Instant>,
    /// Optional error message (will show error style)
    pub error: Option<String>,
}

impl Default for ProgressToastState {
    fn default() -> Self {
        Self {
            title: "Loading".to_string(),
            progress: Some(0.0),
            message: String::new(),
            dismissed_at: None,
            error: None,
        }
    }
}

impl ProgressToastState {
    /// Check if this toast should be removed.
    #[must_use]
    pub const fn should_remove(&self) -> bool {
        self.dismissed_at.is_some()
    }
}

/// A lightweight sender that lets any code (including background threads) enqueue
/// toast messages for display on the next UI frame.
///
/// Obtain one via [`ToastManager::sender`]. Multiple senders share the same queues.
#[derive(Clone)]
pub struct ToastSender {
    queue: Arc<Mutex<Vec<String>>>,
    success_queue: Arc<Mutex<Vec<String>>>,
    ctx: egui::Context,
}

impl ToastSender {
    /// Enqueue `message` to be shown as a persistent standalone error toast on
    /// the next UI frame.
    pub fn send(&self, message: impl Into<String>) {
        if let Ok(mut q) = self.queue.lock() {
            q.push(message.into());
        }
        self.ctx.request_repaint();
    }

    /// Enqueue `message` to be shown as a brief auto-closing success toast on
    /// the next UI frame.
    pub fn send_success(&self, message: impl Into<String>) {
        if let Ok(mut q) = self.success_queue.lock() {
            q.push(message.into());
        }
        self.ctx.request_repaint();
    }
}

/// A thread-safe handle to a progress toast.
///
/// Can be sent to background threads and used to update the toast.
/// When dropped, the toast is automatically dismissed.
#[derive(Clone)]
pub struct ProgressToastHandle {
    state: Arc<RwLock<ProgressToastState>>,
    /// Shared list of active progress toasts — kept so we can spawn sibling toasts.
    progress_handles: Arc<Mutex<Vec<Arc<RwLock<ProgressToastState>>>>>,
    /// The corresponding footer job, when this toast represents user-visible work.
    job: Option<JobHandle>,
    ctx: egui::Context,
}

impl ProgressToastHandle {
    fn new(
        ctx: egui::Context,
        progress_handles: Arc<Mutex<Vec<Arc<RwLock<ProgressToastState>>>>>,
        title: String,
        message: String,
    ) -> Self {
        let state = Arc::new(RwLock::new(ProgressToastState {
            title,
            message,
            progress: Some(0.0),
            dismissed_at: None,
            error: None,
        }));
        if let Ok(mut handles) = progress_handles.lock() {
            handles.push(Arc::clone(&state));
        }
        Self {
            state,
            progress_handles,
            job: None,
            ctx,
        }
    }

    /// Create a new sibling progress toast that renders alongside this one.
    /// Can be called from any thread.
    #[must_use]
    pub fn spawn_sibling(&self, title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            self.ctx.clone(),
            Arc::clone(&self.progress_handles),
            title.into(),
            message.into(),
        )
    }

    /// Associate this visual progress indicator with a cancellable footer job.
    #[must_use]
    pub fn track_job(mut self, job: JobHandle) -> Self {
        self.job = Some(job);
        self
    }

    /// Whether the user has requested cooperative cancellation.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.job
            .as_ref()
            .is_some_and(JobHandle::is_cancel_requested)
    }

    pub fn update(&self, progress: f32, message: impl Into<String>) {
        let message = message.into();
        let title = if let Ok(mut state) = self.state.write() {
            state.progress = Some(progress);
            state.message.clone_from(&message);
            state.title.clone()
        } else {
            return;
        };
        if let Some(job) = &self.job {
            job.update(title, Some(progress), message);
        }
        self.ctx.request_repaint();
    }

    pub fn set_title(&self, title: impl Into<String>) {
        let title = title.into();
        if let Ok(mut state) = self.state.write() {
            state.title.clone_from(&title);
        }
        if let Some(job) = &self.job {
            job.update(title, None, String::new());
        }
        self.ctx.request_repaint();
    }

    /// Mark as error (will show error styling)
    pub fn set_error(&self, error: impl Into<String>) {
        if let Ok(mut state) = self.state.write() {
            state.error = Some(error.into());
        }
        self.ctx.request_repaint();
    }

    pub fn dismiss(&self) {
        if let Ok(mut state) = self.state.write() {
            state.dismissed_at = Some(Instant::now());
        }
        if let Some(job) = &self.job {
            job.finish();
        }
        self.ctx.request_repaint();
    }
}

impl Drop for ProgressToastHandle {
    fn drop(&mut self) {
        // Only dismiss if this is the last reference
        if Arc::strong_count(&self.state) <= 1 {
            // self.dismiss();
        }
    }
}

/// Manages toast notifications for the app
pub struct ToastManager {
    /// egui-toast manager for simple toasts (errors, success)
    toasts: Toasts,
    /// Active progress toast handles
    progress_handles: Arc<Mutex<Vec<Arc<RwLock<ProgressToastState>>>>>,
    /// Standalone error notifications enqueued via [`ToastSender`].
    pending_notifications: Arc<Mutex<Vec<String>>>,
    /// Standalone success notifications enqueued via [`ToastSender::send_success`].
    pending_successes: Arc<Mutex<Vec<String>>>,
    /// egui context for repaints
    ctx: egui::Context,
}

impl ToastManager {
    /// Create a new `ToastManager` with the egui context already set
    #[must_use]
    pub fn new(ctx: egui::Context) -> Self {
        let toasts = Toasts::new()
            .anchor(Align2::RIGHT_BOTTOM, (-10.0, -40.0))
            .direction(egui::Direction::BottomUp);

        Self {
            toasts,
            progress_handles: Arc::new(Mutex::new(Vec::new())),
            pending_notifications: Arc::new(Mutex::new(Vec::new())),
            pending_successes: Arc::new(Mutex::new(Vec::new())),
            ctx,
        }
    }

    /// Create a new progress toast and return a handle.
    /// The handle can be sent to background threads.
    pub fn create_progress_toast(
        &self,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> ProgressToastHandle {
        ProgressToastHandle::new(
            self.ctx.clone(),
            Arc::clone(&self.progress_handles),
            title.into(),
            message.into(),
        )
    }

    /// Return a [`ToastSender`] that can enqueue toasts from any thread.
    /// Drained each frame inside [`Self::show`].
    #[must_use]
    pub fn sender(&self) -> ToastSender {
        ToastSender {
            queue: Arc::clone(&self.pending_notifications),
            success_queue: Arc::clone(&self.pending_successes),
            ctx: self.ctx.clone(),
        }
    }

    /// Show an error toast (requires explicit dismissal).
    pub fn show_error(&mut self, message: impl Into<String>) {
        self.toasts.add(Toast {
            text: message.into().into(),
            kind: ToastKind::Error,
            options: ToastOptions::default().duration(None),
            style: ToastStyle {
                close_button_text: "Got it".into(),
                ..Default::default()
            },
        });
    }

    /// Show a brief auto-closing success toast.
    pub fn show_success(&mut self, message: impl Into<String>) {
        self.toasts.add(Toast {
            text: message.into().into(),
            kind: ToastKind::Success,
            options: ToastOptions::default().duration_in_seconds(4.0),
            style: ToastStyle::default(),
        });
    }

    /// Render all toasts - call this in the update loop
    pub fn show(&mut self, ctx: &egui::Context) {
        // Promote any pending standalone notifications to persistent error toasts.
        // Drain into a local vec first to release the lock before calling show_error.
        let pending: Vec<String> = self
            .pending_notifications
            .lock()
            .map(|mut q| q.drain(..).collect())
            .unwrap_or_default();
        for msg in pending {
            self.show_error(msg);
        }

        // Drain success toasts enqueued from background threads.
        let successes: Vec<String> = self
            .pending_successes
            .lock()
            .map(|mut q| q.drain(..).collect())
            .unwrap_or_default();
        for msg in successes {
            self.show_success(msg);
        }

        // Render progress toasts manually (not using egui-toast for these)
        self.render_progress_toasts(ctx);

        // Render simple toasts (errors, success) via egui-toast
        self.toasts.show(ctx);
    }

    fn render_progress_toasts(&self, ctx: &egui::Context) {
        // Clean up dismissed handles and collect active ones
        let active_states: Vec<(usize, ProgressToastState, Arc<RwLock<ProgressToastState>>)> = {
            let mut handles = self
                .progress_handles
                .lock()
                .expect("progress_handles lock poisoned");
            // Remove toasts that have been dismissed long enough
            handles.retain(|state| state.read().is_ok_and(|s| !s.should_remove()));
            handles
                .iter()
                .enumerate()
                .filter_map(|(idx, state)| {
                    state
                        .read()
                        .ok()
                        .map(|s| (idx, s.clone(), Arc::clone(state)))
                })
                .collect()
        };

        if active_states.is_empty() {
            return;
        }

        // Calculate position for progress toasts (above the simple toasts area)
        #[allow(deprecated)]
        let screen_rect = ctx.input(egui::InputState::screen_rect);
        let toast_width = 300.0;
        let toast_margin = 10.0;
        let bottom_offset = 40.0; // Space for status bar

        for (idx, state, state_arc) in &active_states {
            let toast_height = if state.progress.is_some() {
                100.0
            } else {
                80.0
            };
            let y_offset = (*idx as f32).mul_add(toast_height + toast_margin, bottom_offset);

            let pos = egui::pos2(
                screen_rect.right() - toast_width - toast_margin,
                screen_rect.bottom() - y_offset - toast_height,
            );

            egui::Area::new(egui::Id::new(format!("progress_toast_{idx}")))
                .fixed_pos(pos)
                .order(egui::Order::Foreground)
                .show(ctx, |ui| {
                    if Self::render_single_progress_toast(ui, state) {
                        // Close button was clicked - dismiss immediately
                        if let Ok(mut s) = state_arc.write() {
                            s.dismissed_at = Some(Instant::now());
                        }
                    }
                });
        }
    }

    /// Render a single progress toast. Returns true if the close/ack button was clicked.
    fn render_single_progress_toast(ui: &mut egui::Ui, state: &ProgressToastState) -> bool {
        let is_error = state.error.is_some();

        let fill = if is_error {
            Color32::from_rgb(80, 20, 20)
        } else {
            ui.visuals().window_fill
        };

        let inner = egui::Frame::default()
            .fill(fill)
            .stroke(ui.visuals().window_stroke)
            .inner_margin(Margin::same(12))
            .corner_radius(8.0)
            .shadow(egui::epaint::Shadow {
                offset: [0, 2],
                blur: 8,
                spread: 0,
                color: Color32::from_black_alpha(60),
            })
            .show(ui, |ui| {
                ui.set_min_width(280.0);

                let close_clicked = ui
                    .horizontal(|ui| {
                        if !is_error {
                            ui.spinner();
                            ui.add_space(8.0);
                        }
                        ui.strong(&state.title);

                        // Add close button on the right
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.small_button("x").clicked()
                        })
                        .inner
                    })
                    .inner;

                ui.add_space(6.0);

                // Show error or message
                if let Some(ref error) = state.error {
                    ui.colored_label(Color32::from_rgb(255, 100, 100), error);
                } else {
                    // Truncate long messages for display
                    let display_message = if state.message.chars().count() > 50 {
                        // Take the last 47 characters
                        let char_count = state.message.chars().count();
                        let skip_chars = char_count.saturating_sub(47);
                        let truncated: String = state.message.chars().skip(skip_chars).collect();
                        format!("...{truncated}")
                    } else {
                        state.message.clone()
                    };
                    ui.label(&display_message);
                }

                // Progress bar (only if we have determinate progress)
                if let Some(progress) = state.progress {
                    ui.add_space(6.0);
                    let progress_bar = egui::ProgressBar::new(progress)
                        .show_percentage()
                        .fill(Color32::from_rgb(100, 180, 100));
                    ui.add(progress_bar);
                }

                close_clicked
            });

        inner.inner
    }
}
