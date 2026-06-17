use chrono::{DateTime, TimeZone, Timelike, Utc};
use sentinel_contracts::{
    ApiGatewayAuthMode, ApiGatewayCheckpointState, ApiGatewayClientConfig, ApiGatewayClientState,
    ApiGatewayEndpointKind, ApiGatewayPageCursor, ApiGatewayPollOutcome, ApiGatewayPollRequest,
    ApiGatewayProviderKind, HttpMetadata, HttpMethod, PrivacyClass, QualityScore, Timestamp,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiGatewayHttpRequest {
    pub method: String,
    pub endpoint_kind: ApiGatewayEndpointKind,
    pub provider_kind: ApiGatewayProviderKind,
    pub query_shape: BTreeMap<String, String>,
    pub body_shape: Option<String>,
    pub auth_mode: ApiGatewayAuthMode,
    pub continuation_present: bool,
    pub max_records_per_page: u16,
    pub read_only: bool,
    pub timeout_millis: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ApiGatewayHttpResponse {
    pub status_code: u16,
    pub body: String,
    pub next_page_token: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

impl fmt::Debug for ApiGatewayHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiGatewayHttpResponse")
            .field("status_code", &self.status_code)
            .field("body_len", &self.body.len())
            .field("next_page_token_present", &self.next_page_token.is_some())
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ApiGatewayCredentialMaterial {
    AwsSigV4Session {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    BearerToken(String),
    ApiKey(String),
}

impl ApiGatewayCredentialMaterial {
    pub fn auth_mode(&self) -> ApiGatewayAuthMode {
        match self {
            Self::AwsSigV4Session { .. } => ApiGatewayAuthMode::AwsSigV4Session,
            Self::BearerToken(_) => ApiGatewayAuthMode::BearerTokenSession,
            Self::ApiKey(_) => ApiGatewayAuthMode::ApiKeySession,
        }
    }

    pub fn clear(&mut self) {
        match self {
            Self::AwsSigV4Session {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                access_key_id.clear();
                secret_access_key.clear();
                if let Some(session_token) = session_token {
                    session_token.clear();
                }
            }
            Self::BearerToken(token) | Self::ApiKey(token) => token.clear(),
        }
    }
}

impl fmt::Debug for ApiGatewayCredentialMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiGatewayCredentialMaterial")
            .field("auth_mode", &self.auth_mode())
            .field("material", &"redacted")
            .finish()
    }
}

pub struct ApiGatewayClientSession {
    credential: Option<ApiGatewayCredentialMaterial>,
    next_page_token: Option<String>,
    requests_this_tick: u16,
    revoked: bool,
}

impl ApiGatewayClientSession {
    pub fn new(credential: Option<ApiGatewayCredentialMaterial>) -> Self {
        Self {
            credential,
            next_page_token: None,
            requests_this_tick: 0,
            revoked: false,
        }
    }

    pub fn without_credentials() -> Self {
        Self::new(None)
    }

    pub fn reset_tick(&mut self) {
        self.requests_this_tick = 0;
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.clear();
    }

    pub fn clear(&mut self) {
        if let Some(credential) = &mut self.credential {
            credential.clear();
        }
        self.credential = None;
        if let Some(token) = &mut self.next_page_token {
            token.clear();
        }
        self.next_page_token = None;
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn has_credential(&self) -> bool {
        self.credential.is_some()
    }

    pub fn continuation_present(&self) -> bool {
        self.next_page_token.is_some()
    }

    pub fn next_page_token_for_test(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }

    fn set_next_page_token(&mut self, next_page_token: Option<String>) {
        if let Some(token) = &mut self.next_page_token {
            token.clear();
        }
        self.next_page_token = next_page_token;
    }
}

impl Drop for ApiGatewayClientSession {
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for ApiGatewayClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiGatewayClientSession")
            .field("credential_present", &self.credential.is_some())
            .field("next_page_token_present", &self.next_page_token.is_some())
            .field("requests_this_tick", &self.requests_this_tick)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiGatewayClientError {
    Transport(String),
    MalformedResponse(&'static str),
    InvalidTimestamp(String),
}

impl ApiGatewayClientError {
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }
}

impl fmt::Display for ApiGatewayClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(message) => write!(f, "API gateway transport failed: {message}"),
            Self::MalformedResponse(kind) => {
                write!(f, "API gateway response is malformed: {kind}")
            }
            Self::InvalidTimestamp(value) => {
                write!(f, "API gateway timestamp is invalid: {value}")
            }
        }
    }
}

impl std::error::Error for ApiGatewayClientError {}

pub trait ApiGatewayTransport {
    fn send(
        &mut self,
        request: &ApiGatewayHttpRequest,
        credential: Option<&ApiGatewayCredentialMaterial>,
    ) -> Result<ApiGatewayHttpResponse, ApiGatewayClientError>;
}

pub struct ApiGatewayProviderClient<T> {
    transport: T,
}

impl<T> ApiGatewayProviderClient<T>
where
    T: ApiGatewayTransport,
{
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub fn poll_once(
        &mut self,
        request: ApiGatewayPollRequest,
        session: &mut ApiGatewayClientSession,
    ) -> Result<ApiGatewayPollOutcome, ApiGatewayClientError> {
        if session.is_revoked() {
            return Ok(ApiGatewayPollOutcome::empty(
                ApiGatewayClientState::Revoked,
                request.cursor,
            ));
        }

        if session.requests_this_tick >= allowed_pages_this_tick(&request.config) {
            let mut outcome =
                ApiGatewayPollOutcome::empty(ApiGatewayClientState::RateLimited, request.cursor);
            outcome.retry_after_bucket = Some("next_tick".to_string());
            outcome
                .degraded_reasons
                .push("client_rate_limit_budget_exhausted".to_string());
            return Ok(outcome);
        }

        let auth_mode = request
            .credential_ref
            .as_ref()
            .map(|credential| credential.auth_mode)
            .unwrap_or(ApiGatewayAuthMode::None);
        let credential = match auth_mode {
            ApiGatewayAuthMode::None => None,
            expected => match session.credential.as_ref() {
                Some(credential) if credential.auth_mode() == expected => Some(credential),
                _ => {
                    let mut outcome = ApiGatewayPollOutcome::empty(
                        ApiGatewayClientState::MissingCredentials,
                        request.cursor,
                    );
                    outcome
                        .degraded_reasons
                        .push("credential_material_missing_or_mismatched".to_string());
                    return Ok(outcome);
                }
            },
        };

        let http_request = build_http_request(&request, auth_mode, session.continuation_present());
        let response = self.transport.send(&http_request, credential)?;
        session.requests_this_tick = session.requests_this_tick.saturating_add(1);

        match response.status_code {
            200..=299 => {
                let provider_kind = request.config.provider_kind;
                let max_records = request.config.bounded_max_records_per_page() as usize;
                let normalization =
                    normalize_response_events(provider_kind, max_records, &response.body)?;
                session.set_next_page_token(response.next_page_token);
                let cursor = cursor_from_session(session);
                let mut outcome = ApiGatewayPollOutcome::empty(
                    if normalization.http_metadata.is_empty()
                        && normalization.skipped_record_count > 0
                    {
                        ApiGatewayClientState::Degraded
                    } else {
                        ApiGatewayClientState::PageFetched
                    },
                    cursor,
                );
                outcome.http_metadata = normalization.http_metadata;
                outcome.requested_page_count = 1;
                outcome.accepted_record_count = normalization.accepted_record_count;
                outcome.skipped_record_count = normalization.skipped_record_count;
                outcome.degraded_reasons = normalization.degraded_reasons;
                Ok(outcome)
            }
            401 | 403 => {
                session.clear();
                let mut outcome = ApiGatewayPollOutcome::empty(
                    ApiGatewayClientState::MissingCredentials,
                    cursor_from_session(session),
                );
                outcome.requested_page_count = 1;
                outcome
                    .degraded_reasons
                    .push("auth_failed_credentials_cleared".to_string());
                Ok(outcome)
            }
            429 => Ok(retry_outcome(
                request.cursor,
                response.retry_after_seconds,
                "provider_rate_limited",
            )),
            500..=599 => Ok(retry_outcome(
                request.cursor,
                response.retry_after_seconds,
                "provider_server_error",
            )),
            _ => {
                let mut outcome =
                    ApiGatewayPollOutcome::empty(ApiGatewayClientState::Failed, request.cursor);
                outcome.requested_page_count = 1;
                outcome
                    .degraded_reasons
                    .push(format!("provider_status_{}", response.status_code));
                Ok(outcome)
            }
        }
    }
}

struct NormalizedPage {
    http_metadata: Vec<HttpMetadata>,
    accepted_record_count: u16,
    skipped_record_count: u16,
    degraded_reasons: Vec<String>,
}

fn allowed_pages_this_tick(config: &ApiGatewayClientConfig) -> u16 {
    let per_tick = config.bounded_max_pages_per_tick() as u16;
    let per_minute = config.rate_limit_per_minute.max(1);
    per_tick.min(per_minute)
}

fn build_http_request(
    request: &ApiGatewayPollRequest,
    auth_mode: ApiGatewayAuthMode,
    continuation_present: bool,
) -> ApiGatewayHttpRequest {
    let mut query_shape = BTreeMap::new();
    query_shape.insert(
        "max_records".to_string(),
        request.config.bounded_max_records_per_page().to_string(),
    );
    query_shape.insert(
        "continuation".to_string(),
        if continuation_present {
            "present"
        } else {
            "absent"
        }
        .to_string(),
    );
    if let Some(region_bucket) = request.config.region_bucket.as_deref() {
        query_shape.insert("region_bucket".to_string(), safe_label(region_bucket, 48));
    }
    if let Some(workspace_bucket) = request.config.workspace_bucket.as_deref() {
        query_shape.insert(
            "workspace_bucket".to_string(),
            safe_label(workspace_bucket, 48),
        );
    }

    let (method, body_shape) = match request.config.endpoint_kind {
        ApiGatewayEndpointKind::AwsCloudWatchLogEvents => {
            query_shape.insert(
                "api".to_string(),
                "cloudwatch_filter_log_events".to_string(),
            );
            (
                "POST".to_string(),
                Some("aws_api_gateway_access_logs_read_only_shape".to_string()),
            )
        }
        ApiGatewayEndpointKind::AzureApimGatewayLogs => {
            query_shape.insert(
                "api".to_string(),
                "azure_monitor_apim_gateway_logs".to_string(),
            );
            query_shape.insert("filter".to_string(), "time_window_and_category".to_string());
            ("GET".to_string(), None)
        }
        ApiGatewayEndpointKind::KongAdminApiRequests => {
            query_shape.insert(
                "api".to_string(),
                "kong_admin_api_read_only_logs".to_string(),
            );
            ("GET".to_string(), None)
        }
        ApiGatewayEndpointKind::EnvoyAdminAccessLogs => {
            query_shape.insert(
                "api".to_string(),
                "envoy_admin_access_log_snapshot".to_string(),
            );
            ("GET".to_string(), None)
        }
        ApiGatewayEndpointKind::GenericJsonPage => {
            query_shape.insert("api".to_string(), "generic_json_page".to_string());
            ("GET".to_string(), None)
        }
    };

    ApiGatewayHttpRequest {
        method,
        endpoint_kind: request.config.endpoint_kind,
        provider_kind: request.config.provider_kind,
        query_shape,
        body_shape,
        auth_mode,
        continuation_present,
        max_records_per_page: request.config.bounded_max_records_per_page(),
        read_only: true,
        timeout_millis: request.config.timeout_millis,
    }
}

fn retry_outcome(
    cursor: ApiGatewayPageCursor,
    retry_after_seconds: Option<u64>,
    reason: &str,
) -> ApiGatewayPollOutcome {
    let mut outcome = ApiGatewayPollOutcome::empty(ApiGatewayClientState::RetryScheduled, cursor);
    outcome.requested_page_count = 1;
    outcome.retry_after_bucket = Some(retry_after_bucket(retry_after_seconds));
    outcome.degraded_reasons.push(reason.to_string());
    outcome
}

fn retry_after_bucket(value: Option<u64>) -> String {
    match value.unwrap_or(0) {
        0 => "retry_unspecified".to_string(),
        1..=15 => "retry_seconds_1_15".to_string(),
        16..=60 => "retry_seconds_16_60".to_string(),
        61..=300 => "retry_minutes_1_5".to_string(),
        _ => "retry_minutes_over_5".to_string(),
    }
}

fn normalize_response_events(
    provider_kind: ApiGatewayProviderKind,
    max_records: usize,
    body: &str,
) -> Result<NormalizedPage, ApiGatewayClientError> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| ApiGatewayClientError::MalformedResponse("json"))?;
    let records = event_records(&value);
    let mut http_metadata = Vec::new();
    let mut skipped_record_count = 0u16;
    let mut degraded_reasons = BTreeSet::new();

    for record in records.into_iter().take(max_records) {
        match normalize_event(provider_kind, record) {
            Ok(http) => http_metadata.push(http),
            Err(reason) => {
                skipped_record_count = skipped_record_count.saturating_add(1);
                degraded_reasons.insert(reason.to_string());
            }
        }
    }

    Ok(NormalizedPage {
        accepted_record_count: http_metadata.len() as u16,
        http_metadata,
        skipped_record_count,
        degraded_reasons: degraded_reasons.into_iter().collect(),
    })
}

fn event_records(value: &Value) -> Vec<&Value> {
    if let Some(records) = value.as_array() {
        return records.iter().collect();
    }
    for key in [
        "events", "Events", "records", "items", "data", "value", "logs",
    ] {
        if let Some(records) = value.get(key).and_then(Value::as_array) {
            return records.iter().collect();
        }
    }
    if value.is_object() {
        vec![value]
    } else {
        Vec::new()
    }
}

fn normalize_event(
    provider_kind: ApiGatewayProviderKind,
    record: &Value,
) -> Result<HttpMetadata, &'static str> {
    let timestamp = event_timestamp(record).map_err(|_| "timestamp_missing_or_invalid")?;
    let service = service_category(provider_kind, record);
    let route_bucket = route_bucket(record);
    let method = method_category(record);
    let status_code = status_code(record);
    let request_bytes = number_at_any_path(
        record,
        &[
            &["requestLength"],
            &["requestSize"],
            &["requestBytes"],
            &["bytesIn"],
            &["bytes_received"],
            &["request", "size"],
            &["request", "bytes"],
        ],
    );
    let response_bytes = number_at_any_path(
        record,
        &[
            &["responseLength"],
            &["responseSize"],
            &["responseBytes"],
            &["bytesOut"],
            &["bytes_sent"],
            &["body_bytes_sent"],
            &["response", "size"],
            &["response", "bytes"],
        ],
    );

    let mut http = HttpMetadata::new(method.clone());
    http.timestamp = bucket_timestamp_to_hour(timestamp);
    http.method = method.clone();
    http.scheme = Some(scheme_category(record));
    http.host_protected = Some(format!("api_gateway#{service}"));
    http.path_template_protected = Some(format!("/api_gateway/{route_bucket}"));
    http.endpoint_fingerprint = Some(endpoint_fingerprint(
        provider_kind,
        &service,
        &method,
        status_code,
        &route_bucket,
    ));
    http.status_code = status_code;
    http.status_family = status_code.map(|code| format!("{}xx", code / 100));
    http.result_label = Some(result_label(status_code));
    http.request_size_bytes = request_bytes;
    http.response_size_bytes = response_bytes;
    http.request_content_length_bytes = request_bytes;
    http.response_content_length_bytes = response_bytes;
    http.upload_download_ratio = upload_download_ratio(request_bytes, response_bytes);
    http.content_type = content_type_category(record);
    http.user_agent_family = user_agent_family(record);
    http.api_hint = Some("api_gateway_provider_metadata".to_string());
    http.waf_action = waf_action(record);
    http.waf_rule_id = waf_rule_ref(record);
    http.waf_attack_class = waf_attack_class(record);
    http.visible_plaintext = true;
    http.privacy_class = PrivacyClass::Internal;
    http.quality_score = quality(0.74);
    Ok(http)
}

fn event_timestamp(record: &Value) -> Result<Timestamp, ApiGatewayClientError> {
    if let Some(millis) = number_at_any_path(
        record,
        &[
            &["requestTimeEpoch"],
            &["timestamp_ms"],
            &["timestampMs"],
            &["timeEpochMs"],
            &["timeGeneratedMs"],
        ],
    ) {
        let datetime = Utc
            .timestamp_millis_opt(millis as i64)
            .single()
            .ok_or_else(|| ApiGatewayClientError::InvalidTimestamp(millis.to_string()))?;
        return Ok(Timestamp::from_datetime(datetime));
    }
    if let Some(seconds) = number_at_any_path(
        record,
        &[
            &["timestamp_seconds"],
            &["timestampSeconds"],
            &["timeEpoch"],
            &["unixTimestamp"],
        ],
    ) {
        let datetime = Utc
            .timestamp_opt(seconds as i64, 0)
            .single()
            .ok_or_else(|| ApiGatewayClientError::InvalidTimestamp(seconds.to_string()))?;
        return Ok(Timestamp::from_datetime(datetime));
    }
    let raw = string_at_any_path(
        record,
        &[
            &["requestTime"],
            &["timestamp"],
            &["time"],
            &["ts"],
            &["datetime"],
            &["dateTime"],
            &["TimeGenerated"],
        ],
    )
    .ok_or(ApiGatewayClientError::MalformedResponse("timestamp"))?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|value| Timestamp::from_datetime(value.with_timezone(&Utc)))
        .map_err(|_| ApiGatewayClientError::InvalidTimestamp(raw))
}

fn bucket_timestamp_to_hour(timestamp: Timestamp) -> Timestamp {
    let datetime = timestamp.as_datetime();
    let bucket = datetime
        .date_naive()
        .and_hms_opt(datetime.hour(), 0, 0)
        .expect("valid UTC hour bucket");
    Timestamp::from_datetime(DateTime::from_naive_utc_and_offset(bucket, Utc))
}

fn service_category(provider_kind: ApiGatewayProviderKind, record: &Value) -> String {
    let hint = string_at_any_path(
        record,
        &[
            &["provider"],
            &["service"],
            &["gateway"],
            &["serviceName"],
            &["gatewayName"],
            &["resourceType"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();
    if hint.contains("apim") || hint.contains("azure") {
        "azure_apim".to_string()
    } else if hint.contains("kong") {
        "kong_gateway".to_string()
    } else if hint.contains("envoy") {
        "envoy_gateway".to_string()
    } else if hint.contains("aws") || hint.contains("execute-api") {
        "aws_api_gateway".to_string()
    } else {
        match provider_kind {
            ApiGatewayProviderKind::AwsApiGateway => "aws_api_gateway",
            ApiGatewayProviderKind::AzureApim => "azure_apim",
            ApiGatewayProviderKind::Kong => "kong_gateway",
            ApiGatewayProviderKind::Envoy => "envoy_gateway",
            ApiGatewayProviderKind::Generic => "api_gateway",
        }
        .to_string()
    }
}

fn route_bucket(record: &Value) -> String {
    let raw = string_at_any_path(
        record,
        &[
            &["routeKey"],
            &["route_key"],
            &["route"],
            &["resource"],
            &["path"],
            &["requestPath"],
            &["requestUri"],
            &["request_uri"],
            &["url"],
            &["request", "path"],
            &["request", "uri"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();
    if raw.is_empty() {
        "route_unknown".to_string()
    } else if raw.contains("graphql") {
        "route_graphql".to_string()
    } else if raw.contains("auth") || raw.contains("login") || raw.contains("token") {
        "route_auth".to_string()
    } else if raw.contains("admin") || raw.contains("manage") {
        "route_admin".to_string()
    } else if raw.contains("api") || raw.contains("v1") || raw.contains("v2") {
        "route_api".to_string()
    } else {
        "route_other".to_string()
    }
}

fn method_category(record: &Value) -> HttpMethod {
    match string_at_any_path(
        record,
        &[
            &["httpMethod"],
            &["http_method"],
            &["requestMethod"],
            &["method"],
            &["request", "method"],
            &["http", "method"],
        ],
    )
    .or_else(|| route_method(record))
    .unwrap_or_else(|| "GET".to_string())
    .to_ascii_uppercase()
    .as_str()
    {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "TRACE" => HttpMethod::Trace,
        "CONNECT" => HttpMethod::Connect,
        _ => HttpMethod::Other,
    }
}

fn route_method(record: &Value) -> Option<String> {
    let route = string_at_any_path(record, &[&["routeKey"], &["route_key"], &["route"]])?;
    route.split_whitespace().next().map(ToString::to_string)
}

fn status_code(record: &Value) -> Option<u16> {
    number_at_any_path(
        record,
        &[
            &["status"],
            &["statusCode"],
            &["status_code"],
            &["responseStatus"],
            &["response", "status"],
            &["response", "statusCode"],
        ],
    )
    .and_then(|value| u16::try_from(value).ok())
    .filter(|status| (100..=599).contains(status))
}

fn scheme_category(record: &Value) -> String {
    let raw = string_at_any_path(
        record,
        &[
            &["scheme"],
            &["protocol"],
            &["request", "scheme"],
            &["request", "protocol"],
        ],
    )
    .unwrap_or_else(|| "https".to_string())
    .to_ascii_lowercase();
    if raw.contains("http/2") || raw.contains("http/3") || raw.contains("https") {
        "https".to_string()
    } else if raw.contains("http") {
        "http".to_string()
    } else {
        "https".to_string()
    }
}

fn result_label(status_code: Option<u16>) -> String {
    match status_code {
        Some(401 | 403 | 429) => "api_gateway_auth_or_throttle".to_string(),
        Some(400..=499) => "api_gateway_client_error".to_string(),
        Some(500..=599) => "api_gateway_server_error".to_string(),
        Some(200..=399) => "api_gateway_success".to_string(),
        Some(_) => "api_gateway_observed".to_string(),
        None => "api_gateway_status_missing".to_string(),
    }
}

fn content_type_category(record: &Value) -> Option<String> {
    let raw = string_at_any_path(
        record,
        &[
            &["contentType"],
            &["content_type"],
            &["response", "content_type"],
            &["request", "content_type"],
        ],
    )?
    .to_ascii_lowercase();
    let category = if raw.contains("json") {
        "application_json"
    } else if raw.contains("xml") {
        "application_xml"
    } else if raw.contains("html") {
        "text_html"
    } else {
        "other"
    };
    Some(category.to_string())
}

fn user_agent_family(record: &Value) -> Option<String> {
    let raw = string_at_any_path(
        record,
        &[
            &["userAgent"],
            &["user_agent"],
            &["request", "user_agent"],
            &["request", "userAgent"],
        ],
    )?
    .to_ascii_lowercase();
    let category = if raw.contains("bot") || raw.contains("crawler") || raw.contains("spider") {
        "bot"
    } else if raw.contains("curl") || raw.contains("wget") || raw.contains("python") {
        "scripted_client"
    } else if raw.contains("mozilla") || raw.contains("chrome") || raw.contains("safari") {
        "browser"
    } else {
        "other"
    };
    Some(category.to_string())
}

fn waf_action(record: &Value) -> Option<String> {
    let raw = string_at_any_path(record, &[&["wafAction"], &["waf_action"], &["action"]])?
        .to_ascii_lowercase();
    let category = if raw.contains("block") || raw.contains("deny") {
        "blocked"
    } else if raw.contains("allow") || raw.contains("pass") {
        "allowed"
    } else if raw.contains("challenge") {
        "challenged"
    } else {
        "observed"
    };
    Some(category.to_string())
}

fn waf_rule_ref(record: &Value) -> Option<String> {
    let raw = string_at_any_path(record, &[&["wafRuleId"], &["waf_rule_id"], &["ruleId"]])?;
    Some(safe_digest_label("waf-rule", &raw))
}

fn waf_attack_class(record: &Value) -> Option<String> {
    let raw = string_at_any_path(
        record,
        &[
            &["wafAttackClass"],
            &["waf_attack_class"],
            &["attackClass"],
            &["attack_class"],
        ],
    )?
    .to_ascii_lowercase();
    let category = if raw.contains("sql") {
        "sql_injection"
    } else if raw.contains("xss") || raw.contains("script") {
        "xss"
    } else if raw.contains("bot") {
        "bot"
    } else {
        "other"
    };
    Some(category.to_string())
}

fn upload_download_ratio(request_bytes: Option<u64>, response_bytes: Option<u64>) -> Option<f32> {
    let request = request_bytes? as f32;
    let response = response_bytes.unwrap_or(0).max(1) as f32;
    Some(request / response)
}

fn endpoint_fingerprint(
    provider_kind: ApiGatewayProviderKind,
    service: &str,
    method: &HttpMethod,
    status_code: Option<u16>,
    route_bucket: &str,
) -> String {
    safe_digest_label(
        "endpoint",
        &format!("{provider_kind:?}:{service}:{method:?}:{status_code:?}:{route_bucket}"),
    )
}

fn cursor_from_session(session: &ApiGatewayClientSession) -> ApiGatewayPageCursor {
    match session.next_page_token.as_deref() {
        Some(token) => ApiGatewayPageCursor::from_safe_checkpoint(
            "continuation_present",
            Some(safe_digest_label("cursor", token)),
            Timestamp::now(),
        ),
        None => ApiGatewayPageCursor {
            safe_cursor_bucket: "end_reached".to_string(),
            next_page_token_hash: None,
            checkpoint_state: ApiGatewayCheckpointState::EndReached,
            updated_at: Timestamp::now(),
        },
    }
}

fn quality(value: f32) -> QualityScore {
    QualityScore::new(value).unwrap_or_default()
}

fn safe_digest_label(prefix: &str, value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut output = String::with_capacity(prefix.len() + 1 + 16);
    output.push_str(prefix);
    output.push('#');
    for byte in digest.iter().take(8) {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn safe_label(value: &str, max_len: usize) -> String {
    let mut output = String::new();
    for ch in value.chars() {
        let safe = if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        output.push(safe);
        if output.len() >= max_len {
            break;
        }
    }
    if output.is_empty() {
        "unknown".to_string()
    } else {
        output
    }
}

fn string_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at_path(value, path))
        .and_then(string_from_value)
}

fn number_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<u64> {
    paths
        .iter()
        .find_map(|path| value_at_path(value, path))
        .and_then(number_from_value)
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn string_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn number_from_value(value: &Value) -> Option<u64> {
    match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.trim().parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{ApiGatewayCredentialRef, ApiGatewayPageCursor};

    #[derive(Default)]
    struct RecordingTransport {
        calls: Vec<ApiGatewayHttpRequest>,
        response: Option<ApiGatewayHttpResponse>,
    }

    impl ApiGatewayTransport for RecordingTransport {
        fn send(
            &mut self,
            request: &ApiGatewayHttpRequest,
            _credential: Option<&ApiGatewayCredentialMaterial>,
        ) -> Result<ApiGatewayHttpResponse, ApiGatewayClientError> {
            self.calls.push(request.clone());
            self.response
                .clone()
                .ok_or_else(|| ApiGatewayClientError::transport("missing test response"))
        }
    }

    fn aws_request() -> ApiGatewayPollRequest {
        ApiGatewayPollRequest::new(
            ApiGatewayClientConfig::new(
                ApiGatewayProviderKind::AwsApiGateway,
                ApiGatewayEndpointKind::AwsCloudWatchLogEvents,
            ),
            Some(ApiGatewayCredentialRef::new(
                "credential_session#api-gateway",
                ApiGatewayAuthMode::AwsSigV4Session,
                None,
            )),
            ApiGatewayPageCursor::empty(Timestamp::now()),
        )
    }

    fn aws_session() -> ApiGatewayClientSession {
        ApiGatewayClientSession::new(Some(ApiGatewayCredentialMaterial::AwsSigV4Session {
            access_key_id: "AKIA_TEST_ONLY".to_string(),
            secret_access_key: "secret_access_key_SHOULD_NOT_LEAK".to_string(),
            session_token: Some("session_token_SHOULD_NOT_LEAK".to_string()),
        }))
    }

    #[test]
    fn api_gateway_aws_page_normalizes_without_identifier_exposure() {
        let body = r#"{
          "events": [{
            "requestTime": "2026-06-16T12:34:56Z",
            "httpMethod": "POST",
            "domainName": "customer.example.test",
            "path": "/prod/orders/customer-42?token=secret",
            "sourceIp": "203.0.113.10",
            "requestId": "sensitive-request-id",
            "status": 403,
            "requestLength": 4096,
            "responseLength": 256,
            "userAgent": "curl/8.0 secret-profile",
            "x-api-key": "SHOULD_NOT_LEAK",
            "payload": "secret"
          }]
        }"#;
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(ApiGatewayHttpResponse {
                status_code: 200,
                body: body.to_string(),
                next_page_token: Some("RAW_API_CURSOR_SHOULD_NOT_LEAK".to_string()),
                retry_after_seconds: None,
            }),
        };
        let mut client = ApiGatewayProviderClient::new(transport);
        let mut session = aws_session();

        let outcome = client
            .poll_once(aws_request(), &mut session)
            .expect("poll succeeds");

        assert_eq!(outcome.client_state, ApiGatewayClientState::PageFetched);
        assert_eq!(outcome.accepted_record_count, 1);
        assert_eq!(outcome.http_metadata.len(), 1);
        assert_eq!(outcome.http_metadata[0].method, HttpMethod::Post);
        assert_eq!(outcome.http_metadata[0].status_code, Some(403));
        assert_eq!(
            outcome.http_metadata[0].api_hint.as_deref(),
            Some("api_gateway_provider_metadata")
        );
        assert_eq!(
            outcome.cursor.checkpoint_state,
            ApiGatewayCheckpointState::CursorHashPresent
        );
        assert_eq!(
            session.next_page_token_for_test(),
            Some("RAW_API_CURSOR_SHOULD_NOT_LEAK")
        );

        let transport = client.into_inner();
        assert_eq!(transport.calls.len(), 1);
        assert!(transport.calls[0].read_only);
        assert_eq!(transport.calls[0].method, "POST");

        let serialized = serde_json::to_string(&outcome).expect("serialize outcome");
        let debug_session = format!("{session:?}");
        for value in [serialized, debug_session] {
            assert!(!value.contains("customer.example.test"));
            assert!(!value.contains("/prod/orders"));
            assert!(!value.contains("203.0.113."));
            assert!(!value.contains("sensitive-request-id"));
            assert!(!value.contains("RAW_API_CURSOR"));
            assert!(!value.contains("AKIA_TEST_ONLY"));
            assert!(!value.contains("secret_access_key"));
            assert!(!value.contains("session_token"));
            assert!(!value.contains("x-api-key"));
            assert!(!value.contains("token=secret"));
            assert!(!value.contains("payload"));
        }
    }

    #[test]
    fn api_gateway_missing_credentials_does_not_call_transport() {
        let transport = RecordingTransport::default();
        let mut client = ApiGatewayProviderClient::new(transport);
        let mut session = ApiGatewayClientSession::without_credentials();

        let outcome = client
            .poll_once(aws_request(), &mut session)
            .expect("missing credentials are classified");
        let transport = client.into_inner();

        assert_eq!(
            outcome.client_state,
            ApiGatewayClientState::MissingCredentials
        );
        assert!(transport.calls.is_empty());
        assert!(outcome
            .degraded_reasons
            .contains(&"credential_material_missing_or_mismatched".to_string()));
    }

    #[test]
    fn api_gateway_auth_failure_clears_in_memory_credentials() {
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(ApiGatewayHttpResponse {
                status_code: 403,
                body: "{}".to_string(),
                next_page_token: Some("ignored_after_auth_failure".to_string()),
                retry_after_seconds: None,
            }),
        };
        let mut client = ApiGatewayProviderClient::new(transport);
        let mut session = aws_session();

        let outcome = client
            .poll_once(aws_request(), &mut session)
            .expect("auth failure classified");

        assert_eq!(
            outcome.client_state,
            ApiGatewayClientState::MissingCredentials
        );
        assert!(!session.has_credential());
        assert!(session.next_page_token_for_test().is_none());
        assert!(outcome
            .degraded_reasons
            .contains(&"auth_failed_credentials_cleared".to_string()));
    }

    #[test]
    fn api_gateway_rate_limit_preserves_checkpoint_without_call() {
        let mut request = aws_request();
        request.config.max_pages_per_tick = 1;
        request.config.rate_limit_per_minute = 1;
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(ApiGatewayHttpResponse {
                status_code: 200,
                body: r#"{"events":[]}"#.to_string(),
                next_page_token: None,
                retry_after_seconds: None,
            }),
        };
        let mut client = ApiGatewayProviderClient::new(transport);
        let mut session = aws_session();

        let first = client
            .poll_once(request.clone(), &mut session)
            .expect("first request succeeds");
        let second = client
            .poll_once(request, &mut session)
            .expect("second request is rate limited");
        let transport = client.into_inner();

        assert_eq!(first.client_state, ApiGatewayClientState::PageFetched);
        assert_eq!(second.client_state, ApiGatewayClientState::RateLimited);
        assert_eq!(transport.calls.len(), 1);
        assert_eq!(second.retry_after_bucket.as_deref(), Some("next_tick"));
    }
}
