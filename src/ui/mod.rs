pub mod app;
pub mod filter_highlight;
pub mod jobs;
pub mod log_view;
pub mod session_state;
pub mod tabs;
pub mod toasts;
pub mod windows;

pub use jobs::{JobHandle, JobManager, JobSnapshot};
pub use log_view::CrabSession;
pub use toasts::{ProgressToastHandle, ToastManager, ToastSender};

use egui::Color32;

/// Default color palette for filters and highlights.
/// Colors are medium-saturation to ensure visibility on both dark and light backgrounds.
pub const DEFAULT_PALETTE: [Color32; 8] = [
    Color32::from_rgb(230, 190, 50),  // Golden yellow
    Color32::from_rgb(80, 140, 200),  // Steel blue
    Color32::from_rgb(80, 180, 120),  // Sea green
    Color32::from_rgb(210, 130, 80),  // Warm orange
    Color32::from_rgb(180, 100, 180), // Orchid
    Color32::from_rgb(60, 160, 160),  // Teal
    Color32::from_rgb(210, 90, 90),   // Soft red
    Color32::from_rgb(140, 110, 200), // Soft violet
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneDirection {
    Left,
    Right,
    Up,
    Down,
}
