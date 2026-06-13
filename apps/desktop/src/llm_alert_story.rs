use crate::DesktopStorageState;
use reqwest::blocking::Client;
use reqwest::{StatusCode, Url};
use sentinel_app_core::{
    generate_llm_alert_story, GenerateLlmAlertStoryRequest, LlmAlertStoryGenerationGate,
    LlmAlertStoryProviderClient, LlmAlertStoryProviderOutput, ReadOnlyCommandState,
};
use sentinel_contracts::{
    CommandResult, CoreError, ErrorCode, ErrorSeverity, LlmAlertStoryCapabilityStatus,
    LlmAlertStoryDraft, LlmAlertStoryProvider, LlmAlertStoryRecord, LlmAlertStoryRequest,
    LlmAlertStorySettings, LlmAlertStoryStatusView, LlmApiKeyStorageMode, Timestamp, TraceId,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

const WARNING_TEXT: &str =
    "Only bounded redacted alert metadata is sent after an explicit Generate action.";
const PROFILE_MODE_PORTABLE_NO_RETENTION: &str = "portable-no-retention";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateLlmAlertStorySettingsRequest {
    pub settings: LlmAlertStorySettings,
    pub base_url: Option<String>,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

impl fmt::Debug for UpdateLlmAlertStorySettingsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateLlmAlertStorySettingsRequest")
            .field("settings", &self.settings)
            .field("base_url", &self.base_url.as_ref().map(|_| "[configured]"))
            .field("reason_redacted", &self.reason_redacted)
            .field("requested_by_redacted", &self.requested_by_redacted)
            .finish()
    }
}

impl UpdateLlmAlertStorySettingsRequest {
    fn validate(&self) -> CommandResult<Option<String>> {
        require_reason(&self.reason_redacted)?;
        self.settings.validate().map_err(|error| {
            validation_error(error.to_string(), "update_llm_alert_story_settings")
        })?;
        self.base_url.as_deref().map(validate_base_url).transpose()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveLlmAlertStoryApiKeyRequest {
    pub api_key: String,
    pub storage_mode: LlmApiKeyStorageMode,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

impl fmt::Debug for SaveLlmAlertStoryApiKeyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaveLlmAlertStoryApiKeyRequest")
            .field("api_key", &"[redacted]")
            .field("storage_mode", &self.storage_mode)
            .field("reason_redacted", &self.reason_redacted)
            .field("requested_by_redacted", &self.requested_by_redacted)
            .finish()
    }
}

impl SaveLlmAlertStoryApiKeyRequest {
    fn validate(&self) -> CommandResult<String> {
        require_reason(&self.reason_redacted)?;
        if self.storage_mode != LlmApiKeyStorageMode::SessionOnly {
            return Err(validation_error(
                "LLM alert-story API keys are session-only",
                "save_llm_alert_story_api_key",
            ));
        }
        let api_key = self.api_key.trim().to_string();
        if api_key.is_empty() {
            return Err(validation_error(
                "LLM alert-story API key is required",
                "save_llm_alert_story_api_key",
            ));
        }
        Ok(api_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearLlmAlertStoryApiKeyRequest {
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestLlmAlertStoryConnectionRequest {
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

trait ProviderTransport {
    fn test_connection(&self, config: &ProviderConfig, api_key: &str) -> ConnectionCheckOutcome;
    fn generate(
        &self,
        config: &ProviderConfig,
        api_key: &str,
        request: &LlmAlertStoryRequest,
    ) -> CommandResult<LlmAlertStoryProviderOutput>;
}

#[derive(Clone)]
struct ProviderConfig {
    provider: LlmAlertStoryProvider,
    model: String,
    base_url: String,
    timeout_seconds: u64,
}

struct HttpProviderTransport;

impl ProviderTransport for HttpProviderTransport {
    fn test_connection(&self, config: &ProviderConfig, api_key: &str) -> ConnectionCheckOutcome {
        let client = match provider_client(config.timeout_seconds) {
            Ok(client) => client,
            Err(_) => return ConnectionCheckOutcome::Degraded("provider_client_build_failed"),
        };
        let endpoint = format!("{}/models", config.base_url.trim_end_matches('/'));
        let request = provider_auth(client.get(endpoint), &config.provider, api_key);
        match request.send() {
            Ok(response) if response.status().is_success() => ConnectionCheckOutcome::Authorized,
            Ok(response) => map_http_status(response.status()),
            Err(error) if error.is_timeout() => {
                ConnectionCheckOutcome::ProviderUnavailable("provider_timeout")
            }
            Err(_) => ConnectionCheckOutcome::ProviderUnavailable("provider_request_failed"),
        }
    }

    fn generate(
        &self,
        config: &ProviderConfig,
        api_key: &str,
        request: &LlmAlertStoryRequest,
    ) -> CommandResult<LlmAlertStoryProviderOutput> {
        let client = provider_client(config.timeout_seconds)
            .map_err(|_| provider_error("provider_client_build_failed"))?;
        let request_json =
            serde_json::to_string(request).map_err(|_| provider_error("request_encode_failed"))?;
        let instruction = "Return JSON only with fields alert_narrative_redacted, likely_attack_summary_redacted, confidence_uncertainty_redacted, evidence_summary_redacted, affected_entities_redacted, investigation_suggestions_redacted, report_text_redacted. Use uncertainty language and no raw values.";
        let (endpoint, body) = match config.provider {
            LlmAlertStoryProvider::AnthropicCompatible => (
                format!("{}/messages", config.base_url.trim_end_matches('/')),
                json!({
                    "model": config.model,
                    "max_tokens": 1200,
                    "system": instruction,
                    "messages": [{"role": "user", "content": request_json}]
                }),
            ),
            LlmAlertStoryProvider::OpenAiCompatible | LlmAlertStoryProvider::DeepSeek => (
                format!("{}/chat/completions", config.base_url.trim_end_matches('/')),
                json!({
                    "model": config.model,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": instruction},
                        {"role": "user", "content": request_json}
                    ]
                }),
            ),
        };
        let body =
            serde_json::to_string(&body).map_err(|_| provider_error("request_encode_failed"))?;
        let response = provider_auth(client.post(endpoint), &config.provider, api_key)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|_| provider_error("provider_request_failed"))?;
        if !response.status().is_success() {
            return Err(provider_error("provider_rejected_request"));
        }
        let response_text = response
            .text()
            .map_err(|_| provider_error("provider_response_read_failed"))?;
        let response_hash = format!("{:x}", Sha256::digest(response_text.as_bytes()));
        let envelope: Value = serde_json::from_str(&response_text)
            .map_err(|_| provider_error("provider_response_parse_failed"))?;
        let content = provider_content(&config.provider, &envelope)
            .ok_or_else(|| provider_error("provider_response_content_missing"))?;
        let draft: LlmAlertStoryDraft = serde_json::from_str(content)
            .map_err(|_| provider_error("provider_story_parse_failed"))?;
        Ok(LlmAlertStoryProviderOutput {
            draft,
            response_hash,
        })
    }
}

struct ProviderClientAdapter<'a> {
    transport: &'a dyn ProviderTransport,
    config: &'a ProviderConfig,
    api_key: &'a str,
}

impl LlmAlertStoryProviderClient for ProviderClientAdapter<'_> {
    fn generate(
        &self,
        request: &LlmAlertStoryRequest,
    ) -> CommandResult<LlmAlertStoryProviderOutput> {
        self.transport.generate(self.config, self.api_key, request)
    }
}

fn provider_client(timeout_seconds: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
}

fn provider_auth(
    request: reqwest::blocking::RequestBuilder,
    provider: &LlmAlertStoryProvider,
    api_key: &str,
) -> reqwest::blocking::RequestBuilder {
    match provider {
        LlmAlertStoryProvider::AnthropicCompatible => request
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01"),
        LlmAlertStoryProvider::OpenAiCompatible | LlmAlertStoryProvider::DeepSeek => {
            request.bearer_auth(api_key)
        }
    }
}

fn provider_content<'a>(provider: &LlmAlertStoryProvider, envelope: &'a Value) -> Option<&'a str> {
    match provider {
        LlmAlertStoryProvider::AnthropicCompatible => envelope
            .get("content")?
            .as_array()?
            .first()?
            .get("text")?
            .as_str(),
        LlmAlertStoryProvider::OpenAiCompatible | LlmAlertStoryProvider::DeepSeek => envelope
            .get("choices")?
            .as_array()?
            .first()?
            .get("message")?
            .get("content")?
            .as_str(),
    }
}

fn map_http_status(status: StatusCode) -> ConnectionCheckOutcome {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            ConnectionCheckOutcome::Revoked("provider_auth_rejected")
        }
        StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => {
            ConnectionCheckOutcome::ProviderUnavailable("provider_unavailable")
        }
        _ => ConnectionCheckOutcome::Degraded("provider_rejected_request"),
    }
}

enum ConnectionCheckOutcome {
    Authorized,
    Revoked(&'static str),
    ProviderUnavailable(&'static str),
    Degraded(&'static str),
}

struct LlmAlertStoryController {
    settings: LlmAlertStorySettings,
    session_api_key: Option<String>,
    base_url: Option<String>,
    portable_mode: bool,
    last_successful_check: Option<Timestamp>,
    last_successful_generation: Option<Timestamp>,
    last_story_id: Option<sentinel_contracts::LlmAlertStoryId>,
    story_count: u32,
    last_error_code: Option<String>,
    last_status: Option<LlmAlertStoryCapabilityStatus>,
}

impl LlmAlertStoryController {
    fn bootstrap(storage: &DesktopStorageState) -> Self {
        Self {
            settings: LlmAlertStorySettings::safe_default(),
            session_api_key: None,
            base_url: None,
            portable_mode: storage.profile_mode() == PROFILE_MODE_PORTABLE_NO_RETENTION,
            last_successful_check: None,
            last_successful_generation: None,
            last_story_id: None,
            story_count: 0,
            last_error_code: None,
            last_status: None,
        }
    }

    fn status_view(&self) -> LlmAlertStoryStatusView {
        LlmAlertStoryStatusView {
            settings: self.settings.clone(),
            api_key_configured: self.session_api_key.is_some(),
            capability_status: self.resolve_status(),
            os_keystore_supported: false,
            last_successful_check: self.last_successful_check.clone(),
            last_successful_generation: self.last_successful_generation.clone(),
            last_story_id: self.last_story_id.clone(),
            story_count: self.story_count,
            base_url_configured: self.base_url.is_some(),
            last_error_code: self.last_error_code.clone(),
            warning_redacted: WARNING_TEXT.to_string(),
            generated_at: Timestamp::now(),
        }
    }

    fn update_settings(
        &mut self,
        request: UpdateLlmAlertStorySettingsRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        let base_url = request.validate()?;
        if request.settings.api_key_storage_mode != LlmApiKeyStorageMode::SessionOnly {
            self.session_api_key = None;
            self.last_status = Some(LlmAlertStoryCapabilityStatus::Unsupported);
            self.last_error_code = Some("session_only_key_required".to_string());
            return Ok(self.status_view());
        }
        self.settings = request.settings;
        self.base_url = base_url;
        self.last_status = None;
        self.last_error_code = None;
        Ok(self.status_view())
    }

    fn save_api_key(
        &mut self,
        request: SaveLlmAlertStoryApiKeyRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        self.session_api_key = Some(request.validate()?);
        self.settings.api_key_storage_mode = LlmApiKeyStorageMode::SessionOnly;
        self.last_status = None;
        self.last_error_code = None;
        Ok(self.status_view())
    }

    fn clear_api_key(
        &mut self,
        request: ClearLlmAlertStoryApiKeyRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        require_reason(&request.reason_redacted)?;
        self.clear_session();
        self.last_status = Some(LlmAlertStoryCapabilityStatus::Revoked);
        Ok(self.status_view())
    }

    fn test_connection(
        &mut self,
        request: TestLlmAlertStoryConnectionRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        require_reason(&request.reason_redacted)?;
        self.test_connection_with_transport(&HttpProviderTransport)
    }

    fn test_connection_with_transport(
        &mut self,
        transport: &dyn ProviderTransport,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        let Some(api_key) = self.session_api_key.as_deref() else {
            self.last_status = Some(LlmAlertStoryCapabilityStatus::ApiKeyRequired);
            self.last_error_code = Some("api_key_required".to_string());
            return Ok(self.status_view());
        };
        if !self.settings.enabled || !self.settings.authorization_granted {
            self.last_status = Some(LlmAlertStoryCapabilityStatus::AuthorizationRequired);
            self.last_error_code = Some("authorization_required".to_string());
            return Ok(self.status_view());
        }
        let config = self.provider_config();
        match transport.test_connection(&config, api_key) {
            ConnectionCheckOutcome::Authorized => {
                self.last_status = Some(LlmAlertStoryCapabilityStatus::Authorized);
                self.last_successful_check = Some(Timestamp::now());
                self.last_error_code = None;
            }
            ConnectionCheckOutcome::Revoked(code) => {
                self.last_status = Some(LlmAlertStoryCapabilityStatus::Revoked);
                self.last_error_code = Some(code.to_string());
            }
            ConnectionCheckOutcome::ProviderUnavailable(code) => {
                self.last_status = Some(LlmAlertStoryCapabilityStatus::ProviderUnavailable);
                self.last_error_code = Some(code.to_string());
            }
            ConnectionCheckOutcome::Degraded(code) => {
                self.last_status = Some(LlmAlertStoryCapabilityStatus::Degraded);
                self.last_error_code = Some(code.to_string());
            }
        }
        Ok(self.status_view())
    }

    fn generate_with_transport(
        &mut self,
        read: &ReadOnlyCommandState,
        request: GenerateLlmAlertStoryRequest,
        transport: &dyn ProviderTransport,
    ) -> CommandResult<LlmAlertStoryRecord> {
        let api_key = self.session_api_key.clone().unwrap_or_default();
        let gate = LlmAlertStoryGenerationGate {
            enabled: self.settings.enabled,
            authorization_granted: self.settings.authorization_granted,
            session_api_key_available: !api_key.is_empty(),
        };
        let config = self.provider_config();
        self.last_status = Some(LlmAlertStoryCapabilityStatus::Pending);
        let provider = ProviderClientAdapter {
            transport,
            config: &config,
            api_key: &api_key,
        };
        match generate_llm_alert_story(
            read,
            &request,
            &gate,
            config.provider.clone(),
            config.model.clone(),
            &provider,
        ) {
            Ok(story) => {
                self.last_status = Some(LlmAlertStoryCapabilityStatus::Authorized);
                self.last_successful_generation = Some(story.generated_at.clone());
                self.last_story_id = Some(story.story_id.clone());
                self.story_count = self.story_count.saturating_add(1);
                self.last_error_code = None;
                Ok(story)
            }
            Err(error) => {
                self.last_status = Some(if error.error_code == ErrorCode::ValidationFailure {
                    LlmAlertStoryCapabilityStatus::RedactionFailed
                } else {
                    LlmAlertStoryCapabilityStatus::Degraded
                });
                self.last_error_code = Some("story_generation_failed".to_string());
                Err(error)
            }
        }
    }

    fn provider_config(&self) -> ProviderConfig {
        ProviderConfig {
            provider: self.settings.provider.clone(),
            model: self.settings.model.clone(),
            base_url: self
                .base_url
                .clone()
                .unwrap_or_else(|| default_base_url(&self.settings.provider).to_string()),
            timeout_seconds: self.settings.timeout_seconds,
        }
    }

    fn resolve_status(&self) -> LlmAlertStoryCapabilityStatus {
        if let Some(status) = &self.last_status {
            return status.clone();
        }
        if self.settings.enabled {
            if !self.settings.authorization_granted {
                return LlmAlertStoryCapabilityStatus::AuthorizationRequired;
            }
            if self.session_api_key.is_none() {
                return LlmAlertStoryCapabilityStatus::ApiKeyRequired;
            }
            return LlmAlertStoryCapabilityStatus::Authorized;
        }
        if self.portable_mode {
            LlmAlertStoryCapabilityStatus::PortableAvailable
        } else {
            LlmAlertStoryCapabilityStatus::LlmDisabled
        }
    }

    fn clear_session(&mut self) {
        self.session_api_key = None;
        self.last_successful_check = None;
        self.last_error_code = None;
    }
}

pub struct DesktopLlmAlertStoryState {
    controller: Mutex<LlmAlertStoryController>,
}

impl DesktopLlmAlertStoryState {
    pub fn bootstrap(storage: &DesktopStorageState) -> CommandResult<Self> {
        Ok(Self {
            controller: Mutex::new(LlmAlertStoryController::bootstrap(storage)),
        })
    }

    pub fn get_status(&self) -> CommandResult<LlmAlertStoryStatusView> {
        Ok(self.lock_controller()?.status_view())
    }

    pub fn update_settings(
        &self,
        request: UpdateLlmAlertStorySettingsRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        self.lock_controller()?.update_settings(request)
    }

    pub fn save_api_key(
        &self,
        request: SaveLlmAlertStoryApiKeyRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        self.lock_controller()?.save_api_key(request)
    }

    pub fn clear_api_key(
        &self,
        request: ClearLlmAlertStoryApiKeyRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        self.lock_controller()?.clear_api_key(request)
    }

    pub fn test_connection(
        &self,
        request: TestLlmAlertStoryConnectionRequest,
    ) -> CommandResult<LlmAlertStoryStatusView> {
        self.lock_controller()?.test_connection(request)
    }

    pub fn generate(
        &self,
        read: &ReadOnlyCommandState,
        request: GenerateLlmAlertStoryRequest,
    ) -> CommandResult<LlmAlertStoryRecord> {
        self.lock_controller()?
            .generate_with_transport(read, request, &HttpProviderTransport)
    }

    pub fn clear_session(&self) -> CommandResult<()> {
        self.lock_controller()?.clear_session();
        Ok(())
    }

    fn lock_controller(&self) -> CommandResult<std::sync::MutexGuard<'_, LlmAlertStoryController>> {
        self.controller
            .lock()
            .map_err(|_| internal_error("desktop_llm_alert_story_state_lock"))
    }
}

fn default_base_url(provider: &LlmAlertStoryProvider) -> &'static str {
    match provider {
        LlmAlertStoryProvider::OpenAiCompatible => "https://api.openai.com/v1",
        LlmAlertStoryProvider::DeepSeek => "https://api.deepseek.com",
        LlmAlertStoryProvider::AnthropicCompatible => "https://api.anthropic.com/v1",
    }
}

fn validate_base_url(value: &str) -> CommandResult<String> {
    if value.len() > 256 {
        return Err(validation_error(
            "provider base URL is too long",
            "llm_base_url",
        ));
    }
    let parsed = Url::parse(value)
        .map_err(|_| validation_error("provider base URL is invalid", "llm_base_url"))?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(validation_error(
            "provider base URL must be credential-free HTTPS",
            "llm_base_url",
        ));
    }
    Ok(value.trim_end_matches('/').to_string())
}

fn require_reason(reason_redacted: &str) -> CommandResult<()> {
    if reason_redacted.trim().is_empty() {
        Err(validation_error(
            "mutation reason is required",
            "llm_alert_story_reason",
        ))
    } else {
        Ok(())
    }
}

fn validation_error(message: impl Into<String>, operation: &'static str) -> CoreError {
    CoreError::new(ErrorCode::ValidationFailure, message)
        .with_trace_id(TraceId::new_v4())
        .with_redacted_details(json!({ "operation": operation }))
}

fn provider_error(code: &'static str) -> CoreError {
    CoreError::new(
        ErrorCode::ServiceUnavailable,
        "LLM provider operation did not complete",
    )
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_code": code }))
}

fn internal_error(operation: &'static str) -> CoreError {
    CoreError::new(
        ErrorCode::InternalError,
        "LLM alert-story state operation failed",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "operation": operation }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_app_core::{demo_story::FixtureRunner, ReadOnlyCommandState};
    use std::cell::Cell;

    struct FakeTransport {
        generation_calls: Cell<u32>,
        output: LlmAlertStoryProviderOutput,
    }

    impl ProviderTransport for FakeTransport {
        fn test_connection(
            &self,
            _config: &ProviderConfig,
            _api_key: &str,
        ) -> ConnectionCheckOutcome {
            ConnectionCheckOutcome::Authorized
        }

        fn generate(
            &self,
            _config: &ProviderConfig,
            _api_key: &str,
            _request: &LlmAlertStoryRequest,
        ) -> CommandResult<LlmAlertStoryProviderOutput> {
            self.generation_calls.set(self.generation_calls.get() + 1);
            Ok(self.output.clone())
        }
    }

    #[test]
    fn providers_and_session_only_keys_are_supported_without_readback() {
        for provider in [
            LlmAlertStoryProvider::DeepSeek,
            LlmAlertStoryProvider::OpenAiCompatible,
            LlmAlertStoryProvider::AnthropicCompatible,
        ] {
            assert!(default_base_url(&provider).starts_with("https://"));
        }
        let storage = DesktopStorageState::degraded_with_profile_mode("unavailable", "ephemeral");
        let state = DesktopLlmAlertStoryState::bootstrap(&storage).expect("state");
        let status = state
            .save_api_key(SaveLlmAlertStoryApiKeyRequest {
                api_key: "session-secret-value".to_string(),
                storage_mode: LlmApiKeyStorageMode::SessionOnly,
                reason_redacted: "temporary provider access".to_string(),
                requested_by_redacted: Some("local_user".to_string()),
            })
            .expect("save");
        let serialized = serde_json::to_string(&status).expect("status");
        assert!(status.api_key_configured);
        assert!(!serialized.contains("session-secret-value"));
        assert!(!status.os_keystore_supported);
    }

    #[test]
    fn enabled_without_session_key_reports_api_key_required_without_provider_call() {
        let storage = DesktopStorageState::degraded_with_profile_mode("unavailable", "ephemeral");
        let mut controller = LlmAlertStoryController::bootstrap(&storage);
        controller.settings.enabled = true;
        controller.settings.authorization_granted = true;

        let status = controller.status_view();

        assert_eq!(
            status.capability_status,
            LlmAlertStoryCapabilityStatus::ApiKeyRequired
        );
        assert!(!status.api_key_configured);
    }

    #[test]
    fn explicit_generation_uses_provider_once_and_clear_revokes_session_key() {
        let storage = DesktopStorageState::degraded_with_profile_mode("unavailable", "ephemeral");
        let mut controller = LlmAlertStoryController::bootstrap(&storage);
        controller.settings.enabled = true;
        controller.settings.authorization_granted = true;
        controller.session_api_key = Some("session-secret-value".to_string());
        let replay = FixtureRunner::from_default_fixture()
            .expect("fixture")
            .run()
            .expect("replay");
        let state = replay
            .read_model
            .into_read_state(ReadOnlyCommandState::bootstrap().expect("read"));
        let alert_id = sentinel_app_core::search_alerts(
            &state,
            sentinel_contracts::QueryRequest::new(sentinel_contracts::QueryScope::Global),
        )
        .expect("alerts")
        .items[0]
            .id()
            .clone();
        let transport = FakeTransport {
            generation_calls: Cell::new(0),
            output: LlmAlertStoryProviderOutput {
                draft: safe_draft(),
                response_hash: "b".repeat(64),
            },
        };
        let story = controller
            .generate_with_transport(
                &state,
                GenerateLlmAlertStoryRequest {
                    alert_id,
                    incident_id: None,
                    reason_redacted: "generate bounded story".to_string(),
                    requested_by_redacted: Some("local_user".to_string()),
                    explicit_user_action: true,
                    replay: false,
                },
                &transport,
            )
            .expect("story");
        assert_eq!(transport.generation_calls.get(), 1);
        assert!(story.redaction_passed);
        controller.clear_session();
        assert!(controller.session_api_key.is_none());
    }

    fn safe_draft() -> LlmAlertStoryDraft {
        LlmAlertStoryDraft {
            alert_narrative_redacted: "Bounded metadata indicates an alert sequence.".to_string(),
            likely_attack_summary_redacted: "Linked degraded techniques may apply.".to_string(),
            confidence_uncertainty_redacted: "Confidence is limited.".to_string(),
            evidence_summary_redacted: "Evidence refs support analyst review.".to_string(),
            affected_entities_redacted: vec!["entity:redacted".to_string()],
            investigation_suggestions_redacted: vec!["Review linked evidence refs.".to_string()],
            report_text_redacted: "AI-generated story for analyst review.".to_string(),
        }
    }
}
