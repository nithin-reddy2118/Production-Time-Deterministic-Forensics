//! Layered config schema (architecture §24).
//!
//! This module implements all four static-precedence layers:
//! **defaults -> file (TOML) -> env -> explicit override**. The fifth
//! layer, dynamic control-plane push, is a networking-stack consumer
//! (Module 8) of this exact same `PartialRecorderConfig::merge` machinery
//! and is the only remaining same-shaped follow-up — nothing here is a
//! stub for it.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required field '{0}' was not set by any config layer")]
    MissingRequired(&'static str),

    #[error("invalid value for '{field}': {reason}")]
    InvalidValue { field: &'static str, reason: String },

    #[error("failed to read config file {path}: {source}")]
    FileRead { path: String, source: std::io::Error },

    #[error("failed to parse TOML config: {0}")]
    TomlParse(#[from] toml::de::Error),
}

impl PartialEq for ConfigError {
    /// Manual `PartialEq` because `toml::de::Error` and `std::io::Error`
    /// don't implement it. Two `FileRead`/`TomlParse` errors compare equal
    /// iff their variant matches — sufficient for the test assertions in
    /// this module, which only need to confirm *which* failure occurred.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MissingRequired(a), Self::MissingRequired(b)) => a == b,
            (Self::InvalidValue { field: fa, reason: ra }, Self::InvalidValue { field: fb, reason: rb }) => fa == fb && ra == rb,
            (Self::FileRead { path: pa, .. }, Self::FileRead { path: pb, .. }) => pa == pb,
            (Self::TomlParse(_), Self::TomlParse(_)) => true,
            _ => false,
        }
    }
}
impl Eq for ConfigError {}

/// Every field optional — a *layer's contribution* to the final config.
/// Layers are merged left-to-right in ascending precedence: a `Some` in a
/// higher-precedence layer overwrites a `Some` from a lower one; `None`
/// never overwrites.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PartialRecorderConfig {
    pub sink_capacity: Option<usize>,
    pub poll_interval: Option<Duration>,
    pub ingestion_endpoint: Option<String>,
    pub follow_children: Option<bool>,
}

impl PartialRecorderConfig {
    /// Merge `other` on top of `self` (`other` wins on conflicts). Consumes
    /// both and returns the combined layer, so callers chain:
    /// `defaults().merge(from_env()).merge(cli_overrides)`.
    pub fn merge(self, other: PartialRecorderConfig) -> PartialRecorderConfig {
        PartialRecorderConfig {
            sink_capacity: other.sink_capacity.or(self.sink_capacity),
            poll_interval: other.poll_interval.or(self.poll_interval),
            ingestion_endpoint: other.ingestion_endpoint.or(self.ingestion_endpoint),
            follow_children: other.follow_children.or(self.follow_children),
        }
    }

    /// Read overrides from environment variables. Recognized:
    ///   `PTDF_SINK_CAPACITY`   (usize)
    ///   `PTDF_POLL_INTERVAL_MS` (u64, milliseconds)
    ///   `PTDF_INGESTION_ENDPOINT` (string)
    ///   `PTDF_FOLLOW_CHILDREN` (bool: "true"/"false"/"1"/"0")
    /// Unrecognized or unparseable values are reported via `ConfigError`
    /// rather than silently ignored — a typo'd env var should not silently
    /// fall back to a default in a production recording agent.
    pub fn from_env_map(env: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let mut partial = PartialRecorderConfig::default();

        if let Some(v) = env.get("PTDF_SINK_CAPACITY") {
            partial.sink_capacity = Some(v.parse::<usize>().map_err(|e| ConfigError::InvalidValue {
                field: "PTDF_SINK_CAPACITY",
                reason: e.to_string(),
            })?);
        }

        if let Some(v) = env.get("PTDF_POLL_INTERVAL_MS") {
            let ms = v.parse::<u64>().map_err(|e| ConfigError::InvalidValue {
                field: "PTDF_POLL_INTERVAL_MS",
                reason: e.to_string(),
            })?;
            partial.poll_interval = Some(Duration::from_millis(ms));
        }

        if let Some(v) = env.get("PTDF_INGESTION_ENDPOINT") {
            partial.ingestion_endpoint = Some(v.clone());
        }

        if let Some(v) = env.get("PTDF_FOLLOW_CHILDREN") {
            let parsed = match v.as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => {
                    return Err(ConfigError::InvalidValue {
                        field: "PTDF_FOLLOW_CHILDREN",
                        reason: format!("expected true/false/1/0, got '{other}'"),
                    })
                }
            };
            partial.follow_children = Some(parsed);
        }

        Ok(partial)
    }

    /// Load the file layer from a TOML string. Field names in the file
    /// match the config field names (`sink_capacity`, `poll_interval_ms`,
    /// `ingestion_endpoint`, `follow_children`) — `poll_interval_ms` is a
    /// plain integer in the file rather than `Duration` because `Duration`
    /// has no canonical human-writable TOML representation; the conversion
    /// to `Duration` happens here, once, rather than pushing a
    /// serialization concern onto every caller.
    pub fn from_toml_str(contents: &str) -> Result<Self, ConfigError> {
        #[derive(serde::Deserialize, Default)]
        #[serde(deny_unknown_fields)]
        struct TomlLayer {
            sink_capacity: Option<usize>,
            poll_interval_ms: Option<u64>,
            ingestion_endpoint: Option<String>,
            follow_children: Option<bool>,
        }

        let layer: TomlLayer = toml::from_str(contents)?;
        Ok(PartialRecorderConfig {
            sink_capacity: layer.sink_capacity,
            poll_interval: layer.poll_interval_ms.map(Duration::from_millis),
            ingestion_endpoint: layer.ingestion_endpoint,
            follow_children: layer.follow_children,
        })
    }

    /// Load the file layer from a path on disk. A missing file is treated
    /// as "this layer contributes nothing" (`Ok(Self::default())`) rather
    /// than an error — the file layer is optional by design (env vars and
    /// CLI flags alone are a valid, common configuration path, e.g. in a
    /// container where config is entirely env-driven); a *malformed*
    /// existing file is still a hard error, since silently ignoring a
    /// present-but-broken config file could mask a real operator mistake.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        match std::fs::read_to_string(path_ref) {
            Ok(contents) => Self::from_toml_str(&contents),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ConfigError::FileRead { path: path_ref.display().to_string(), source: e }),
        }
    }
}

/// The finalized, fully-populated config every component actually uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecorderConfig {
    pub sink_capacity: usize,
    pub poll_interval: Duration,
    pub ingestion_endpoint: String,
    pub follow_children: bool,
}

impl RecorderConfig {
    /// Built-in defaults — the lowest-precedence layer.
    pub fn defaults() -> PartialRecorderConfig {
        PartialRecorderConfig {
            sink_capacity: Some(65_536),
            poll_interval: Some(Duration::from_millis(10)),
            ingestion_endpoint: None, // no safe default — must come from a real layer
            follow_children: Some(true),
        }
    }

    /// Apply defaults, requiring every field to end up populated.
    /// `ingestion_endpoint` has no built-in default (there is no
    /// universally-safe endpoint to guess), so finalize fails with
    /// `MissingRequired` if no layer supplied it — deliberately fail-closed
    /// rather than silently recording with nowhere to ship data.
    pub fn finalize(partial: PartialRecorderConfig) -> Result<Self, ConfigError> {
        let with_defaults = Self::defaults().merge(partial);
        Ok(RecorderConfig {
            sink_capacity: with_defaults
                .sink_capacity
                .ok_or(ConfigError::MissingRequired("sink_capacity"))?,
            poll_interval: with_defaults
                .poll_interval
                .ok_or(ConfigError::MissingRequired("poll_interval"))?,
            ingestion_endpoint: with_defaults
                .ingestion_endpoint
                .ok_or(ConfigError::MissingRequired("ingestion_endpoint"))?,
            follow_children: with_defaults
                .follow_children
                .ok_or(ConfigError::MissingRequired("follow_children"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn merge_lets_later_layer_win() {
        let base = PartialRecorderConfig { sink_capacity: Some(1), ..Default::default() };
        let over = PartialRecorderConfig { sink_capacity: Some(2), ..Default::default() };
        let merged = base.merge(over);
        assert_eq!(merged.sink_capacity, Some(2));
    }

    #[test]
    fn merge_does_not_let_none_overwrite_some() {
        let base = PartialRecorderConfig { sink_capacity: Some(1), ..Default::default() };
        let over = PartialRecorderConfig { sink_capacity: None, ..Default::default() };
        let merged = base.merge(over);
        assert_eq!(merged.sink_capacity, Some(1), "None in a higher layer must not erase a lower layer's value");
    }

    #[test]
    fn finalize_fails_closed_when_ingestion_endpoint_missing() {
        let partial = PartialRecorderConfig::default();
        let err = RecorderConfig::finalize(partial).unwrap_err();
        assert_eq!(err, ConfigError::MissingRequired("ingestion_endpoint"));
    }

    #[test]
    fn finalize_succeeds_once_endpoint_is_supplied() {
        let partial = PartialRecorderConfig {
            ingestion_endpoint: Some("https://ingest.example.invalid".into()),
            ..Default::default()
        };
        let cfg = RecorderConfig::finalize(partial).unwrap();
        assert_eq!(cfg.sink_capacity, 65_536, "unset fields must fall back to defaults");
        assert_eq!(cfg.ingestion_endpoint, "https://ingest.example.invalid");
    }

    #[test]
    fn env_layer_parses_all_recognized_vars() {
        let e = env(&[
            ("PTDF_SINK_CAPACITY", "128"),
            ("PTDF_POLL_INTERVAL_MS", "50"),
            ("PTDF_INGESTION_ENDPOINT", "https://x.invalid"),
            ("PTDF_FOLLOW_CHILDREN", "false"),
        ]);
        let partial = PartialRecorderConfig::from_env_map(&e).unwrap();
        assert_eq!(partial.sink_capacity, Some(128));
        assert_eq!(partial.poll_interval, Some(Duration::from_millis(50)));
        assert_eq!(partial.ingestion_endpoint, Some("https://x.invalid".to_string()));
        assert_eq!(partial.follow_children, Some(false));
    }

    #[test]
    fn env_layer_rejects_unparseable_values_instead_of_ignoring() {
        let e = env(&[("PTDF_SINK_CAPACITY", "not-a-number")]);
        let err = PartialRecorderConfig::from_env_map(&e).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { field: "PTDF_SINK_CAPACITY", .. }));
    }

    #[test]
    fn env_layer_rejects_invalid_bool_values() {
        let e = env(&[("PTDF_FOLLOW_CHILDREN", "maybe")]);
        let err = PartialRecorderConfig::from_env_map(&e).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { field: "PTDF_FOLLOW_CHILDREN", .. }));
    }

    #[test]
    fn full_precedence_chain_defaults_then_env_then_explicit_override() {
        let e = env(&[("PTDF_SINK_CAPACITY", "999"), ("PTDF_INGESTION_ENDPOINT", "https://env.invalid")]);
        let from_env = PartialRecorderConfig::from_env_map(&e).unwrap();
        let cli_override = PartialRecorderConfig {
            ingestion_endpoint: Some("https://cli.invalid".into()),
            ..Default::default()
        };

        let merged = RecorderConfig::defaults().merge(from_env).merge(cli_override);
        let cfg = RecorderConfig::finalize(merged).unwrap();

        assert_eq!(cfg.sink_capacity, 999, "env layer should win over built-in default");
        assert_eq!(cfg.ingestion_endpoint, "https://cli.invalid", "CLI layer should win over env");
        assert_eq!(cfg.poll_interval, Duration::from_millis(10), "untouched field keeps built-in default");
    }

    #[test]
    fn toml_layer_parses_all_fields() {
        let toml = r#"
            sink_capacity = 4096
            poll_interval_ms = 25
            ingestion_endpoint = "https://ingest.toml.invalid"
            follow_children = false
        "#;
        let partial = PartialRecorderConfig::from_toml_str(toml).unwrap();
        assert_eq!(partial.sink_capacity, Some(4096));
        assert_eq!(partial.poll_interval, Some(Duration::from_millis(25)));
        assert_eq!(partial.ingestion_endpoint, Some("https://ingest.toml.invalid".to_string()));
        assert_eq!(partial.follow_children, Some(false));
    }

    #[test]
    fn toml_layer_allows_partial_specification() {
        let toml = r#"sink_capacity = 100"#;
        let partial = PartialRecorderConfig::from_toml_str(toml).unwrap();
        assert_eq!(partial.sink_capacity, Some(100));
        assert_eq!(partial.poll_interval, None);
    }

    #[test]
    fn toml_layer_rejects_unknown_fields() {
        let toml = r#"not_a_real_field = 1"#;
        let err = PartialRecorderConfig::from_toml_str(toml);
        assert!(err.is_err(), "an unrecognized key likely indicates a typo and should fail loudly");
    }

    #[test]
    fn toml_layer_rejects_malformed_toml() {
        let toml = r#"sink_capacity = "not a number""#;
        assert!(PartialRecorderConfig::from_toml_str(toml).is_err());
    }

    #[test]
    fn missing_config_file_yields_empty_layer_not_an_error() {
        let partial = PartialRecorderConfig::from_toml_file("/definitely/does/not/exist.toml").unwrap();
        assert_eq!(partial, PartialRecorderConfig::default());
    }

    #[test]
    fn existing_but_malformed_config_file_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "sink_capacity = [1, 2, 3]").unwrap();
        assert!(PartialRecorderConfig::from_toml_file(&path).is_err());
    }

    #[test]
    fn full_precedence_chain_including_file_layer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ptdf.toml");
        std::fs::write(&path, "sink_capacity = 500\ningestion_endpoint = \"https://file.invalid\"\n").unwrap();

        let from_file = PartialRecorderConfig::from_toml_file(&path).unwrap();
        let from_env = PartialRecorderConfig::from_env_map(&env(&[("PTDF_SINK_CAPACITY", "700")])).unwrap();

        let merged = RecorderConfig::defaults().merge(from_file).merge(from_env);
        let cfg = RecorderConfig::finalize(merged).unwrap();

        assert_eq!(cfg.sink_capacity, 700, "env layer must win over the file layer");
        assert_eq!(cfg.ingestion_endpoint, "https://file.invalid", "file layer wins over the built-in default when env doesn't set it");
    }
}
