use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const PORTABLE_DATA_DIR_NAME: &str = "data";
const PORTABLE_PREFERENCES_DIR_NAME: &str = "preferences";
const PORTABLE_UI_PREFERENCES_FILE_NAME: &str = "ui_preferences.json";

pub const ALLOWED_PORTABLE_PREFERENCE_KEYS: &[&str] = &[
    "theme",
    "layout",
    "pane_sizes",
    "last_route",
    "column_widths",
    "reduced_motion",
    "graph_viewport_defaults",
];

const FORBIDDEN_PORTABLE_PREFERENCE_KEYS: &[&str] = &[
    "findings",
    "alerts",
    "incidents",
    "evidence",
    "evidence_bundles",
    "graph_data",
    "graph_nodes",
    "graph_edges",
    "graph_paths",
    "graph_snapshots",
    "response_plans",
    "response_results",
    "rollback_state",
    "report_drafts",
    "report_sections",
    "export_history",
    "raw_packets",
    "payloads",
    "http_bodies",
    "cookies",
    "tokens",
    "credentials",
    "api_keys",
    "process_snapshots",
    "connection_snapshots",
    "flow_attribution",
    "intelligence_packs",
    "ioc_lists",
    "allowlists",
    "blocklists",
    "network_metadata",
    "dns_observations",
    "tls_observations",
    "http_metadata",
    "runtime_profiles",
    "privacy_policies",
    "response_policies",
    "session_state",
    "stream_state",
    "checkpoint_cursors",
    "settings_change_history",
    "audit_records",
    "raw_packet",
    "payload",
    "http_body",
    "cookie",
    "token",
    "credential",
    "api_key",
    "private_key",
    "hostname",
    "machine_guid",
    "mac_address",
];

pub type PortablePreferences = BTreeMap<String, Value>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreferenceError {
    PreferenceRejected { reason: String },
    Io(String),
    Serialization(String),
}

impl PreferenceError {
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::PreferenceRejected {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::PreferenceRejected { reason } => reason,
            Self::Io(reason) | Self::Serialization(reason) => reason,
        }
    }
}

impl fmt::Display for PreferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreferenceRejected { reason } => {
                write!(formatter, "portable preference rejected: {reason}")
            }
            Self::Io(reason) => write!(formatter, "portable preference io error: {reason}"),
            Self::Serialization(reason) => {
                write!(
                    formatter,
                    "portable preference serialization error: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for PreferenceError {}

impl From<std::io::Error> for PreferenceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for PreferenceError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

pub type PreferenceResult<T> = Result<T, PreferenceError>;

#[derive(Clone, Debug, Default)]
pub struct PortablePreferenceValidator;

impl PortablePreferenceValidator {
    pub fn validate_key_value(&self, key: &str, value: &Value) -> PreferenceResult<()> {
        self.validate_key(key)?;
        if value_contains_potential_security_data(key)
            || value_contains_potential_security_data_value(value)
        {
            return Err(PreferenceError::rejected(
                "value contains potential security data",
            ));
        }

        match key {
            "theme" => validate_theme(value),
            "layout" => validate_object_like(key, value),
            "pane_sizes" => validate_pane_sizes(value),
            "last_route" => validate_last_route(value),
            "column_widths" => validate_column_widths(value),
            "reduced_motion" => validate_boolean(key, value),
            "graph_viewport_defaults" => validate_graph_viewport_defaults(value),
            _ => Err(PreferenceError::rejected(
                "key not in allowed portable preference whitelist",
            )),
        }
    }

    pub fn validate_key(&self, key: &str) -> PreferenceResult<()> {
        if key.trim().is_empty() || key.len() > 96 {
            return Err(PreferenceError::rejected(
                "key not in allowed portable preference whitelist",
            ));
        }
        if !ALLOWED_PORTABLE_PREFERENCE_KEYS.contains(&key) || contains_forbidden_marker(key) {
            return Err(PreferenceError::rejected(
                "key not in allowed portable preference whitelist",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PortablePreferenceStore {
    portable_root: PathBuf,
    preferences_path: PathBuf,
    preferences: PortablePreferences,
    validator: PortablePreferenceValidator,
}

impl PortablePreferenceStore {
    pub fn new(portable_root: &Path) -> Self {
        let preferences_path = portable_root
            .join(PORTABLE_DATA_DIR_NAME)
            .join(PORTABLE_PREFERENCES_DIR_NAME)
            .join(PORTABLE_UI_PREFERENCES_FILE_NAME);
        Self {
            portable_root: portable_root.to_path_buf(),
            preferences_path,
            preferences: PortablePreferences::new(),
            validator: PortablePreferenceValidator,
        }
    }

    pub fn preferences_path(&self) -> &Path {
        &self.preferences_path
    }

    pub fn load(&mut self) -> PreferenceResult<PortablePreferences> {
        if !self.preferences_path.exists() {
            self.preferences.clear();
            return Ok(self.preferences.clone());
        }

        let content = fs::read_to_string(&self.preferences_path)?;
        let content = content.trim_start_matches('\u{feff}');
        if content.trim().is_empty() {
            self.preferences.clear();
            return Ok(self.preferences.clone());
        }

        let value = match serde_json::from_str::<Value>(content) {
            Ok(value) => value,
            Err(_) => {
                self.preferences.clear();
                return Ok(self.preferences.clone());
            }
        };
        let Some(object) = value.as_object() else {
            self.preferences.clear();
            return Ok(self.preferences.clone());
        };

        let mut loaded = PortablePreferences::new();
        for (key, value) in object {
            if self.validator.validate_key_value(key, value).is_err() {
                self.preferences.clear();
                return Ok(self.preferences.clone());
            }
            loaded.insert(key.clone(), value.clone());
        }
        self.preferences = loaded;
        Ok(self.preferences.clone())
    }

    pub fn set(&mut self, key: &str, value: Value) -> PreferenceResult<()> {
        self.validator.validate_key_value(key, &value)?;
        self.preferences.insert(key.to_string(), value);
        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> PreferenceResult<()> {
        self.validator.validate_key(key)?;
        self.preferences.remove(key);
        Ok(())
    }

    pub fn save(&self) -> PreferenceResult<()> {
        self.validate_preferences_path()?;
        for (key, value) in &self.preferences {
            self.validator.validate_key_value(key, value)?;
        }
        if let Some(parent) = self.preferences_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &self.preferences_path,
            serde_json::to_string_pretty(&self.preferences)?,
        )?;
        Ok(())
    }

    pub fn validate_key_value(&self, key: &str, value: &Value) -> PreferenceResult<()> {
        self.validator.validate_key_value(key, value)
    }

    pub fn preferences(&self) -> &PortablePreferences {
        &self.preferences
    }

    fn validate_preferences_path(&self) -> PreferenceResult<()> {
        fs::create_dir_all(&self.portable_root)?;
        let parent = self
            .preferences_path
            .parent()
            .ok_or_else(|| PreferenceError::rejected("preferences path has no parent"))?;
        fs::create_dir_all(parent)?;

        let portable_root = fs::canonicalize(&self.portable_root)?;
        let parent = fs::canonicalize(parent)?;
        if parent.starts_with(portable_root) {
            Ok(())
        } else {
            Err(PreferenceError::rejected(
                "preferences path escapes portable root",
            ))
        }
    }
}

fn validate_theme(value: &Value) -> PreferenceResult<()> {
    match value.as_str() {
        Some("dark" | "light" | "system" | "deep-dark") => Ok(()),
        _ => Err(PreferenceError::rejected("theme value is invalid")),
    }
}

fn validate_boolean(key: &str, value: &Value) -> PreferenceResult<()> {
    if value.is_boolean() {
        Ok(())
    } else {
        Err(PreferenceError::rejected(format!("{key} must be boolean")))
    }
}

fn validate_object_like(key: &str, value: &Value) -> PreferenceResult<()> {
    let Some(object) = value.as_object() else {
        return Err(PreferenceError::rejected(format!("{key} must be object")));
    };
    if serde_json::to_string(object)?.len() > 4096 {
        return Err(PreferenceError::rejected(format!("{key} is too large")));
    }
    validate_json_value_shape(object)
}

fn validate_pane_sizes(value: &Value) -> PreferenceResult<()> {
    let Some(object) = value.as_object() else {
        return Err(PreferenceError::rejected("pane_sizes must be object"));
    };
    if object.is_empty() {
        return Err(PreferenceError::rejected("pane_sizes must not be empty"));
    }

    if object.values().all(Value::is_number) {
        return validate_numeric_group_sum(object);
    }

    for value in object.values() {
        let Some(group) = value.as_object() else {
            return Err(PreferenceError::rejected(
                "pane_sizes groups must contain numeric objects",
            ));
        };
        validate_numeric_group_sum(group)?;
    }
    Ok(())
}

fn validate_numeric_group_sum(object: &Map<String, Value>) -> PreferenceResult<()> {
    if object.is_empty() {
        return Err(PreferenceError::rejected(
            "pane_sizes group must not be empty",
        ));
    }
    let mut sum = 0.0;
    for value in object.values() {
        let number = value.as_f64().ok_or_else(|| {
            PreferenceError::rejected("pane_sizes values must be positive numbers")
        })?;
        if !number.is_finite() || number <= 0.0 {
            return Err(PreferenceError::rejected(
                "pane_sizes values must be positive numbers",
            ));
        }
        sum += number;
    }
    if approximately(sum, 1.0, 0.02) || approximately(sum, 100.0, 2.0) {
        Ok(())
    } else {
        Err(PreferenceError::rejected(
            "pane_sizes values must sum to approximately 1.0 or 100",
        ))
    }
}

fn validate_last_route(value: &Value) -> PreferenceResult<()> {
    let Some(route) = value.as_str() else {
        return Err(PreferenceError::rejected("last_route must be string"));
    };
    if route.is_empty()
        || route.len() > 160
        || !route.starts_with('/')
        || route.contains("..")
        || !route
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '-' | '_'))
    {
        return Err(PreferenceError::rejected(
            "last_route is not a safe app route",
        ));
    }
    Ok(())
}

fn validate_column_widths(value: &Value) -> PreferenceResult<()> {
    let Some(object) = value.as_object() else {
        return Err(PreferenceError::rejected("column_widths must be object"));
    };
    validate_positive_number_leaves("column_widths", object, 64.0, 1200.0)
}

fn validate_graph_viewport_defaults(value: &Value) -> PreferenceResult<()> {
    let Some(object) = value.as_object() else {
        return Err(PreferenceError::rejected(
            "graph_viewport_defaults must be object",
        ));
    };
    if serde_json::to_string(object)?.len() > 2048 {
        return Err(PreferenceError::rejected(
            "graph_viewport_defaults is too large",
        ));
    }
    for (key, value) in object {
        match (key.as_str(), value) {
            ("zoom", Value::Number(number)) => {
                let zoom = number.as_f64().unwrap_or_default();
                if !(0.1..=4.0).contains(&zoom) {
                    return Err(PreferenceError::rejected(
                        "graph_viewport_defaults zoom is out of range",
                    ));
                }
            }
            ("x" | "y", Value::Number(number)) => {
                let offset = number.as_f64().unwrap_or(f64::NAN);
                if !offset.is_finite() || offset.abs() > 10_000.0 {
                    return Err(PreferenceError::rejected(
                        "graph_viewport_defaults offset is out of range",
                    ));
                }
            }
            ("layout", Value::String(layout)) => {
                if !matches!(layout.as_str(), "force" | "grid" | "dagre" | "radial") {
                    return Err(PreferenceError::rejected(
                        "graph_viewport_defaults layout is invalid",
                    ));
                }
            }
            (_, Value::Bool(_) | Value::Number(_) | Value::String(_)) => {}
            _ => {
                return Err(PreferenceError::rejected(
                    "graph_viewport_defaults contains unsupported value",
                ));
            }
        }
    }
    Ok(())
}

fn validate_json_value_shape(object: &Map<String, Value>) -> PreferenceResult<()> {
    for (key, value) in object {
        if contains_forbidden_marker(key) {
            return Err(PreferenceError::rejected(
                "value contains potential security data",
            ));
        }
        match value {
            Value::Null => {}
            Value::Bool(_) => {}
            Value::Number(number) => {
                let Some(number) = number.as_f64() else {
                    return Err(PreferenceError::rejected("number is invalid"));
                };
                if !number.is_finite() || number.abs() > 10_000.0 {
                    return Err(PreferenceError::rejected("number is out of range"));
                }
            }
            Value::String(value) => {
                if value.len() > 256 {
                    return Err(PreferenceError::rejected("string value is too long"));
                }
            }
            Value::Array(values) => {
                if values.len() > 32 {
                    return Err(PreferenceError::rejected("array value is too large"));
                }
                for value in values {
                    validate_json_leaf(value)?;
                }
            }
            Value::Object(child) => validate_json_value_shape(child)?,
        }
    }
    Ok(())
}

fn validate_json_leaf(value: &Value) -> PreferenceResult<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
        Value::Array(values) => {
            for value in values {
                validate_json_leaf(value)?;
            }
            Ok(())
        }
        Value::Object(object) => validate_json_value_shape(object),
    }
}

fn validate_positive_number_leaves(
    context: &str,
    object: &Map<String, Value>,
    min: f64,
    max: f64,
) -> PreferenceResult<()> {
    for (key, value) in object {
        if contains_forbidden_marker(key) {
            return Err(PreferenceError::rejected(
                "value contains potential security data",
            ));
        }
        match value {
            Value::Number(number) => {
                let number = number.as_f64().unwrap_or(f64::NAN);
                if !number.is_finite() || number < min || number > max {
                    return Err(PreferenceError::rejected(format!(
                        "{context} values must be positive numbers"
                    )));
                }
            }
            Value::Object(child) => validate_positive_number_leaves(context, child, min, max)?,
            _ => {
                return Err(PreferenceError::rejected(format!(
                    "{context} values must be positive numbers"
                )));
            }
        }
    }
    Ok(())
}

fn approximately(value: f64, target: f64, tolerance: f64) -> bool {
    (value - target).abs() <= tolerance
}

fn value_contains_potential_security_data_value(value: &Value) -> bool {
    match value {
        Value::String(value) => value_contains_potential_security_data(value),
        Value::Array(values) => values
            .iter()
            .any(value_contains_potential_security_data_value),
        Value::Object(object) => object.iter().any(|(key, value)| {
            value_contains_potential_security_data(key)
                || value_contains_potential_security_data_value(value)
        }),
        _ => false,
    }
}

fn value_contains_potential_security_data(value: &str) -> bool {
    contains_forbidden_marker(value)
        || looks_like_ipv4(value)
        || looks_like_domain(value)
        || contains_windows_drive_path(value)
        || contains_hash_like_token(value)
        || contains_base64_like_token(value)
}

fn contains_forbidden_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    FORBIDDEN_PORTABLE_PREFERENCE_KEYS
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn looks_like_ipv4(value: &str) -> bool {
    tokens(value, |ch| ch.is_ascii_digit() || ch == '.')
        .iter()
        .any(|token| {
            let parts = token.split('.').collect::<Vec<_>>();
            parts.len() == 4
                && parts.iter().all(|part| {
                    !part.is_empty()
                        && part.len() <= 3
                        && part.chars().all(|ch| ch.is_ascii_digit())
                        && part.parse::<u8>().is_ok()
                })
        })
}

fn looks_like_domain(value: &str) -> bool {
    tokens(value, |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')
    })
    .iter()
    .any(|token| {
        token.len() <= 253
            && token.contains('.')
            && token.chars().any(|ch| ch.is_ascii_alphabetic())
            && token
                .split('.')
                .all(|part| !part.is_empty() && part.len() <= 63)
            && token
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic()))
    })
}

fn contains_windows_drive_path(value: &str) -> bool {
    let chars = value.chars().collect::<Vec<_>>();
    chars.windows(3).any(|window| {
        window[0].is_ascii_alphabetic() && window[1] == ':' && matches!(window[2], '\\' | '/')
    })
}

fn contains_hash_like_token(value: &str) -> bool {
    tokens(value, |ch| ch.is_ascii_hexdigit())
        .iter()
        .any(|token| token.len() >= 32 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn contains_base64_like_token(value: &str) -> bool {
    tokens(value, |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-')
    })
    .iter()
    .any(|token| {
        token.len() > 32
            && token
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-'))
            && token.chars().any(|ch| ch.is_ascii_uppercase())
            && token.chars().any(|ch| ch.is_ascii_lowercase())
            && token.chars().any(|ch| ch.is_ascii_digit())
    })
}

fn tokens(value: &str, keep: impl Fn(char) -> bool) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        if keep(ch) {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::env;
    use uuid::Uuid;

    #[test]
    fn allowed_portable_preference_keys_accept_valid_values() {
        let validator = PortablePreferenceValidator;
        for (key, value) in [
            ("theme", json!("dark")),
            (
                "layout",
                json!({
                    "sidebar_collapsed": false,
                    "detail_drawer_open": true,
                    "bottom_graph_open": true
                }),
            ),
            (
                "pane_sizes",
                json!({
                    "horizontal": { "sidebar": 20, "content": 55, "detail_drawer": 25 },
                    "vertical": { "content": 65, "bottom_graph": 35 }
                }),
            ),
            ("last_route", json!("/overview")),
            (
                "column_widths",
                json!({ "overview": { "name": 220, "risk": 96 } }),
            ),
            ("reduced_motion", json!(false)),
            (
                "graph_viewport_defaults",
                json!({ "zoom": 1.0, "x": 0, "y": 0, "layout": "force" }),
            ),
        ] {
            validator
                .validate_key_value(key, &value)
                .unwrap_or_else(|error| panic!("{key} rejected: {error}"));
        }
    }

    #[test]
    fn forbidden_portable_preference_keys_are_rejected() {
        let validator = PortablePreferenceValidator;
        for key in [
            "findings",
            "alerts",
            "incidents",
            "evidence",
            "graph_data",
            "response_plans",
            "raw_packets",
            "tokens",
            "runtime_profiles",
        ] {
            let error = validator
                .validate_key_value(key, &json!({}))
                .expect_err("forbidden key should be rejected");
            assert!(matches!(error, PreferenceError::PreferenceRejected { .. }));
            assert_eq!(
                error.reason(),
                "key not in allowed portable preference whitelist"
            );
        }
    }

    #[test]
    fn privacy_sensitive_preference_values_are_rejected() {
        let validator = PortablePreferenceValidator;
        for value in [
            json!("/host/192.168.1.25"),
            json!("QWxhZGRpbjpvcGVuIHNlc2FtZQpBQUFBMTIzNDU2Nzg5MA=="),
            json!("C:\\Users\\Alice\\Documents"),
            json!("a3c8a6b47d159e5b6f7d4f3f9e7a4c2b"),
            json!("evil.example.com"),
        ] {
            let error = validator
                .validate_key_value("last_route", &value)
                .expect_err("sensitive value should be rejected");
            assert_eq!(error.reason(), "value contains potential security data");
        }
    }

    #[test]
    fn invalid_shapes_are_rejected() {
        let validator = PortablePreferenceValidator;
        assert!(validator
            .validate_key_value("theme", &json!("malicious"))
            .is_err());
        assert!(validator
            .validate_key_value("last_route", &json!("../../../etc/passwd"))
            .is_err());
        assert!(validator
            .validate_key_value("pane_sizes", &json!({ "a": 20, "b": 20 }))
            .is_err());
        assert!(validator
            .validate_key_value("reduced_motion", &json!("false"))
            .is_err());
    }

    #[test]
    fn empty_preferences_file_loads_as_empty_map() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("empty");
        let mut store = PortablePreferenceStore::new(&root);
        fs::create_dir_all(store.preferences_path().parent().expect("parent"))?;
        fs::write(store.preferences_path(), "")?;

        assert!(store.load()?.is_empty());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn invalid_preferences_file_loads_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("invalid-load");
        let mut store = PortablePreferenceStore::new(&root);
        fs::create_dir_all(store.preferences_path().parent().expect("parent"))?;
        fs::write(
            store.preferences_path(),
            serde_json::to_string_pretty(&json!({ "findings": [] }))?,
        )?;

        assert!(store.load()?.is_empty());
        assert!(store.preferences().is_empty());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn utf8_bom_preferences_file_loads_valid_map() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("bom-load");
        let mut store = PortablePreferenceStore::new(&root);
        fs::create_dir_all(store.preferences_path().parent().expect("parent"))?;
        let content = serde_json::to_vec_pretty(&json!({
            "theme": "dark",
            "layout": {
                "sidebar_collapsed": false,
                "detail_drawer_open": true,
                "bottom_graph_open": true
            },
            "pane_sizes": {
                "horizontal": { "sidebar": 20, "content": 55, "detail_drawer": 25 },
                "vertical": { "content": 65, "bottom_graph": 35 }
            },
            "last_route": "/settings",
            "column_widths": {},
            "reduced_motion": false,
            "graph_viewport_defaults": { "zoom": 1.0, "x": 0, "y": 0, "layout": "force" }
        }))?;
        let mut bom_content = vec![0xef, 0xbb, 0xbf];
        bom_content.extend(content);
        fs::write(store.preferences_path(), bom_content)?;

        let preferences = store.load()?;

        assert_eq!(preferences.get("theme"), Some(&json!("dark")));
        assert_eq!(preferences.len(), ALLOWED_PORTABLE_PREFERENCE_KEYS.len());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn preferences_survive_restart_while_session_data_can_be_deleted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("survive");
        let session_dir = root
            .join("temp")
            .join("sessions")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&session_dir)?;

        let mut store = PortablePreferenceStore::new(&root);
        store.set("theme", json!("dark"))?;
        store.set(
            "pane_sizes",
            json!({
                "horizontal": { "sidebar": 20, "content": 55, "detail_drawer": 25 },
                "vertical": { "content": 65, "bottom_graph": 35 }
            }),
        )?;
        store.save()?;
        fs::remove_dir_all(&session_dir)?;

        let mut loaded = PortablePreferenceStore::new(&root);
        let preferences = loaded.load()?;
        assert_eq!(preferences.get("theme"), Some(&json!("dark")));
        assert!(preferences.contains_key("pane_sizes"));
        assert!(!session_dir.exists());
        assert!(loaded.preferences_path().exists());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn remove_valid_key_updates_persisted_preferences() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("remove");
        let mut store = PortablePreferenceStore::new(&root);
        store.set("theme", json!("dark"))?;
        store.remove("theme")?;
        store.save()?;

        let content = fs::read_to_string(store.preferences_path())?;
        assert_eq!(serde_json::from_str::<Value>(&content)?, json!({}));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    fn temp_root(label: &str) -> PathBuf {
        env::current_dir()
            .unwrap_or_else(|_| env::temp_dir())
            .join("target")
            .join("portable-preference-tests")
            .join(format!("{label}-{}", Uuid::new_v4()))
    }
}
