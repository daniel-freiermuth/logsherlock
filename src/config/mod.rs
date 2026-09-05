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

pub mod session_history;

use crate::core::SearchRule;
use crate::input::ShortcutAction;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// DLT timestamp source configuration
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DltTimestampSource {
    /// Use storage header timestamp (wall-clock time)
    #[default]
    StorageTime,
    /// Use inferred monotonic clock (boot time + header timestamp, more precise in limited timespans)
    InferredMonotonic,
}

/// Current schema version. Bump this whenever the config format changes in a
/// backwards-incompatible way.
///
/// Old binaries that do not know this version fall back to defaults on load
/// rather than silently corrupting the file.
///
/// History:
///   unversioned (v0) — no `schema_version` field
///   v1 — initial versioned schema
///   v2 — added sidecar scoring fields: `use_sidecar_scoring`, `color_by_ml_score`,
///         `grey_rare_ml_lines`, `sidecar_host`, `sidecar_port`, `selected_model`
///   v3 — added `hide_duplicates`
///   v4 — added `file_config.pcap` (`PcapConfig`) with `show_mac_addresses`
pub const SCHEMA_VERSION: u32 = 4;

/// Global user configuration stored in config directory.
///
/// The boolean fields are independent persisted user preferences, so combining
/// them into enums would introduce invalid coupling.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Schema version — no `#[serde(default)]` so that configs written by old
    /// binaries (which lack this field) fail to deserialize and fall back to
    /// defaults rather than being silently misread.
    pub schema_version: u32,

    /// Keyboard shortcuts
    #[serde(default)]
    pub shortcuts: HashMap<ShortcutAction, String>,

    /// Favorite filters that appear in all sessions
    #[serde(default)]
    pub favorite_filters: Vec<FavoriteFilter>,

    /// Use bright/light theme instead of dark (default: false)
    #[serde(default)]
    pub bright_mode: bool,

    /// Last directory used for opening log files
    #[serde(default)]
    pub last_log_directory: Option<PathBuf>,

    /// Last directory used for filter files (import/export)
    #[serde(default)]
    pub last_filters_directory: Option<PathBuf>,

    /// Per-format file type configuration (e.g. DLT timestamp source).
    /// Serialized to the global config file so settings persist across sessions.
    #[serde(default)]
    pub file_config: crate::core::log_store::GlobalFileConfig,

    /// Show bookmarks as markers in the timeline/histogram (default: false)
    #[serde(default)]
    pub show_bookmarks_in_timeline: bool,

    /// If `true`, `save()` is a no-op. Set when the on-disk config was written
    /// by a newer binary (version > `SCHEMA_VERSION`) so we never silently
    /// downgrade it.
    #[serde(skip)]
    pub read_only: bool,

    /// Use `LogBERT` sidecar for anomaly scoring (default: false)
    #[serde(default)]
    pub use_sidecar_scoring: bool,

    /// Color logs by ML score instead of legacy scorer (default: false)
    #[serde(default)]
    pub color_by_ml_score: bool,

    /// In ML score coloring mode, show rare (RARE-flagged) lines in grey instead of their scored color (default: true)
    #[serde(default = "default_grey_rare_ml_lines")]
    pub grey_rare_ml_lines: bool,

    /// Sidecar server host
    #[serde(default = "default_sidecar_host")]
    pub sidecar_host: String,

    /// Sidecar server port
    #[serde(default = "default_sidecar_port")]
    pub sidecar_port: u16,

    /// Hide exact duplicate log lines (same timestamp, source, and message) in filter views.
    #[serde(default)]
    pub hide_duplicates: bool,

    /// Selected model id (slug) for anomaly detection.
    /// `None` means no model is selected; sidecar scoring will be skipped.
    #[serde(default)]
    pub selected_model: Option<String>,
}

fn default_sidecar_host() -> String {
    crate::anomaly::sidecar_client::SidecarClient::default_host().to_string()
}

const fn default_sidecar_port() -> u16 {
    crate::anomaly::sidecar_client::SidecarClient::default_port()
}

const fn default_grey_rare_ml_lines() -> bool {
    true
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            read_only: false,
            shortcuts: HashMap::new(),
            favorite_filters: Vec::new(),
            bright_mode: false,
            last_log_directory: None,
            last_filters_directory: None,
            file_config: crate::core::log_store::GlobalFileConfig::default(),
            show_bookmarks_in_timeline: false,
            use_sidecar_scoring: false,
            color_by_ml_score: false,
            grey_rare_ml_lines: true,
            hide_duplicates: false,
            sidecar_host: default_sidecar_host(),
            sidecar_port: default_sidecar_port(),
            selected_model: None,
        }
    }
}

/// A favorite filter that can be quickly added to any log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FavoriteFilter {
    pub search_text: String,
    pub case_sensitive: bool,
    #[serde(default)]
    pub name: String,
}

impl FavoriteFilter {
    /// Create a new favorite with the given parameters, using `search_text` as the default name
    #[must_use]
    pub fn new(search_text: String, case_sensitive: bool) -> Self {
        let name = search_text.clone();
        Self {
            search_text,
            case_sensitive,
            name,
        }
    }

    /// Get the display name for this favorite (returns name if set, otherwise `search_text`)
    #[must_use]
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.search_text
        } else {
            &self.name
        }
    }

    /// Check if this favorite matches a search rule's search criteria.
    #[must_use]
    pub fn matches(&self, rule: &SearchRule) -> bool {
        rule.matches_search(&self.search_text, self.case_sensitive)
    }
}

impl GlobalConfig {
    /// Get the path to the global config file
    #[must_use]
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|config_dir| {
            let app_config = config_dir.join("logcrab");
            app_config.join("config.json")
        })
    }

    /// Parse config JSON into a `GlobalConfig`, handling version probing and migration.
    ///
    /// Returns `Self::default()` (or a read-only default) on any error.
    fn parse_contents(contents: &str) -> Self {
        #[derive(Deserialize)]
        struct VersionProbe {
            schema_version: Option<u32>,
        }
        let file_version = serde_json::from_str::<VersionProbe>(contents)
            .map_or(0, |p| p.schema_version.unwrap_or(0));

        if file_version > SCHEMA_VERSION {
            tracing::warn!(
                "Config schema version {} is newer than this binary's {} — \
                 using defaults (read-only: will not overwrite)",
                file_version,
                SCHEMA_VERSION
            );
            return Self {
                read_only: true,
                ..Self::default()
            };
        }

        // v0 = old binary that never wrote schema_version: inject the field
        // so the struct can deserialize without losing any existing settings.
        let parse_result: Option<Self> = if file_version == 0 {
            tracing::info!("Config has no schema_version, treating as v0 and migrating");
            serde_json::from_str::<serde_json::Value>(contents)
                .ok()
                .and_then(|mut v| {
                    v.as_object_mut()?
                        .insert("schema_version".to_string(), serde_json::json!(0u32));
                    serde_json::from_value::<Self>(v).ok()
                })
        } else {
            serde_json::from_str::<Self>(contents).ok()
        };

        match parse_result {
            None => {
                tracing::warn!("Failed to parse config, using defaults");
                Self::default()
            }
            Some(mut config) => {
                if config.schema_version < SCHEMA_VERSION {
                    // v1 → v2: sidecar scoring fields added with serde defaults;
                    // no explicit field changes needed — serde already populated them.
                    tracing::info!(
                        "Migrated config from schema v{} to v{}",
                        config.schema_version,
                        SCHEMA_VERSION
                    );
                    config.schema_version = SCHEMA_VERSION;
                }
                tracing::info!(
                    "Loaded {} shortcuts and {} favorite filters",
                    config.shortcuts.len(),
                    config.favorite_filters.len()
                );
                config
            }
        }
    }

    /// Load global config from disk at startup.
    ///
    /// - **Missing `schema_version`**: treated as v0, migrated to current.
    /// - **version < current**: deserialized, then migration logic runs.
    /// - **version == current**: deserialized as-is.
    /// - **version > current**: falls back to defaults with `read_only = true`
    ///   so `update()` will not overwrite the newer-version file.
    pub fn load() -> Self {
        if let Some(path) = Self::config_path() {
            if path.exists() {
                tracing::info!("Loading global config from {}", path.display());
                match std::fs::read_to_string(&path) {
                    Err(e) => tracing::warn!("Failed to read config file: {e}"),
                    Ok(contents) => return Self::parse_contents(&contents),
                }
            } else {
                tracing::info!("No global config found, using defaults");
            }
        }
        Self::default()
    }

    /// Atomically update the on-disk config.
    ///
    /// Acquires an exclusive advisory lock on the config file, re-reads the
    /// current on-disk state, applies `f`, writes back, and releases the lock.
    /// Concurrent instances will block on the lock rather than interleaving
    /// their read-modify-write cycles.
    ///
    /// When the config is read-only (on-disk version is newer than this
    /// binary), `f` is applied only to the in-memory state and no write
    /// occurs, preserving the session's in-memory settings without touching
    /// the file.
    ///
    /// Returns the updated config so the caller can replace its cached copy.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    pub fn update(f: impl FnOnce(&mut Self)) -> Result<Self, String> {
        let path = Self::config_path().ok_or("Could not determine config directory")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {e}"))?;
        }

        // Open or create the file and hold an exclusive lock for the entire
        // read-modify-write cycle.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("Failed to open config file: {e}"))?;

        file.lock_exclusive()
            .map_err(|e| format!("Failed to lock config file: {e}"))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read config file: {e}"))?;

        let mut config = if contents.is_empty() {
            Self::default()
        } else {
            Self::parse_contents(&contents)
        };

        // Apply the caller's mutation. For read-only configs we still apply
        // in-memory so the current session reflects the change.
        f(&mut config);

        if config.read_only {
            tracing::warn!(
                "Config is read-only (on-disk version is newer) — changes not persisted"
            );
            file.unlock().ok();
            return Ok(config);
        }

        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize config: {e}"))?;

        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Failed to seek config file: {e}"))?;
        file.set_len(0)
            .map_err(|e| format!("Failed to truncate config file: {e}"))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write config file: {e}"))?;

        // Lock releases when `file` is dropped here.
        tracing::info!("Updated global config");
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A v0 config (no `schema_version` field) with user settings.
    /// `parse_contents` should inject `schema_version: 0`, deserialize
    /// successfully, then migrate to `SCHEMA_VERSION`.
    #[test]
    fn v0_config_without_schema_version_migrates() {
        let json = r#"{ "bright_mode": true }"#;
        let config = GlobalConfig::parse_contents(json);

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert!(config.bright_mode, "user setting should survive v0 migration");
        assert!(!config.read_only);
    }

    /// A v0 config with shortcuts and favorite filters round-trips correctly.
    #[test]
    fn v0_config_preserves_complex_fields() {
        let json = r#"{
            "shortcuts": { "MoveUp": "k" },
            "favorite_filters": [
                { "search_text": "ERROR", "case_sensitive": false, "name": "errors" }
            ],
            "bright_mode": false
        }"#;
        let config = GlobalConfig::parse_contents(json);

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert_eq!(config.shortcuts.len(), 1);
        assert_eq!(config.favorite_filters.len(), 1);
        assert_eq!(config.favorite_filters[0].search_text, "ERROR");
        assert_eq!(config.favorite_filters[0].name, "errors");
    }

    /// A future version (> SCHEMA_VERSION) should set `read_only = true`
    /// and return defaults so we never silently downgrade.
    #[test]
    fn future_version_sets_read_only() {
        let json = format!(r#"{{ "schema_version": {} }}"#, SCHEMA_VERSION + 95);
        let config = GlobalConfig::parse_contents(&json);

        assert!(config.read_only);
        assert_eq!(config.schema_version, SCHEMA_VERSION); // defaults
        // All user-configurable fields should be defaults
        assert!(!config.bright_mode);
        assert!(config.shortcuts.is_empty());
        assert!(config.favorite_filters.is_empty());
    }

    /// Malformed JSON should fall back to defaults without crashing.
    #[test]
    fn malformed_json_falls_back_to_defaults() {
        let config = GlobalConfig::parse_contents("not json at all {{{");

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert!(!config.read_only);
        assert!(!config.bright_mode);
    }

    /// Valid JSON that is not an object (e.g. an array) should fall back.
    #[test]
    fn json_array_falls_back_to_defaults() {
        let config = GlobalConfig::parse_contents("[1, 2, 3]");

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert!(!config.read_only);
    }

    /// Valid JSON object with unknown fields should preserve known fields
    /// via `#[serde(default)]` and ignore the unknown ones.
    #[test]
    fn unknown_fields_preserves_known() {
        let json = format!(
            r#"{{
                "schema_version": {},
                "bright_mode": true,
                "totally_made_up_field": 42
            }}"#,
            SCHEMA_VERSION
        );
        let config = GlobalConfig::parse_contents(&json);

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert!(config.bright_mode);
        assert!(!config.read_only);
    }

    /// A v1 config should deserialize and have its schema_version bumped
    /// to SCHEMA_VERSION. Serde defaults fill any new fields.
    #[test]
    fn v1_config_migrates_to_current() {
        let json = r#"{ "schema_version": 1, "bright_mode": true }"#;
        let config = GlobalConfig::parse_contents(json);

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert!(config.bright_mode);
        assert!(!config.read_only);
        // v2+ fields should be their serde defaults
        assert!(!config.use_sidecar_scoring);
        assert!(!config.hide_duplicates);
    }

    /// A config at the current SCHEMA_VERSION should deserialize as-is
    /// with no migration.
    #[test]
    fn current_version_no_migration() {
        let json = format!(
            r#"{{ "schema_version": {}, "bright_mode": true }}"#,
            SCHEMA_VERSION
        );
        let config = GlobalConfig::parse_contents(&json);

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert!(config.bright_mode);
        assert!(!config.read_only);
    }

    /// Empty string input should fall back to defaults (the VersionProbe
    /// parse fails, file_version becomes 0, then Value parse also fails).
    #[test]
    fn empty_string_falls_back_to_defaults() {
        let config = GlobalConfig::parse_contents("");

        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert!(!config.read_only);
    }
}
