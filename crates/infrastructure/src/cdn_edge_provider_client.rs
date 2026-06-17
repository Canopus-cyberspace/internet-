use chrono::{DateTime, TimeZone, Timelike, Utc};
use sentinel_contracts::{
    CdnEdgeAuthMode, CdnEdgeCheckpointState, CdnEdgeClientConfig, CdnEdgeClientState,
    CdnEdgeEndpointKind, CdnEdgePageCursor, CdnEdgePollOutcome, CdnEdgePollRequest,
    CdnEdgeProviderKind, HttpMetadata, HttpMethod, PortableApiMethodCategory,
    PortableProviderCategory, PortableProviderConfidenceBucket, PortableProviderRiskCategory,
    PortableSaasCloudMetadata, PortableStatusBucket, PortableUploadDownloadRatioBucket,
    PrivacyClass, QualityScore, RedactionStatus, Timestamp,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CdnEdgeHttpRequest {
    pub method: String,
    pub endpoint_kind: CdnEdgeEndpointKind,
    pub provider_kind: CdnEdgeProviderKind,
    pub query_shape: BTreeMap<String, String>,
    pub body_shape: Option<String>,
    pub auth_mode: CdnEdgeAuthMode,
    pub continuation_present: bool,
    pub max_records_per_page: u16,
    pub read_only: bool,
    pub timeout_millis: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CdnEdgeHttpResponse {
    pub status_code: u16,
    pub body: String,
    pub next_page_token: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

impl fmt::Debug for CdnEdgeHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CdnEdgeHttpResponse")
            .field("status_code", &self.status_code)
            .field("body_len", &self.body.len())
            .field("next_page_token_present", &self.next_page_token.is_some())
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum CdnEdgeCredentialMaterial {
    BearerToken(String),
    AwsSigV4Session {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    SharedKeySession {
        key_id: String,
        secret_key: String,
    },
}

impl CdnEdgeCredentialMaterial {
    pub fn auth_mode(&self) -> CdnEdgeAuthMode {
        match self {
            Self::BearerToken(_) => CdnEdgeAuthMode::BearerTokenSession,
            Self::AwsSigV4Session { .. } => CdnEdgeAuthMode::AwsSigV4Session,
            Self::SharedKeySession { .. } => CdnEdgeAuthMode::SharedKeySession,
        }
    }

    pub fn clear(&mut self) {
        match self {
            Self::BearerToken(token) => token.clear(),
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
            Self::SharedKeySession { key_id, secret_key } => {
                key_id.clear();
                secret_key.clear();
            }
        }
    }
}

impl fmt::Debug for CdnEdgeCredentialMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CdnEdgeCredentialMaterial")
            .field("auth_mode", &self.auth_mode())
            .field("material", &"redacted")
            .finish()
    }
}

pub struct CdnEdgeClientSession {
    credential: Option<CdnEdgeCredentialMaterial>,
    next_page_token: Option<String>,
    requests_this_tick: u16,
    revoked: bool,
}

impl CdnEdgeClientSession {
    pub fn new(credential: Option<CdnEdgeCredentialMaterial>) -> Self {
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

impl Drop for CdnEdgeClientSession {
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for CdnEdgeClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CdnEdgeClientSession")
            .field("credential_present", &self.credential.is_some())
            .field("next_page_token_present", &self.next_page_token.is_some())
            .field("requests_this_tick", &self.requests_this_tick)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CdnEdgeClientError {
    Transport(String),
    MalformedResponse(&'static str),
    InvalidTimestamp(String),
}

impl CdnEdgeClientError {
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }
}

impl fmt::Display for CdnEdgeClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(message) => write!(f, "CDN edge transport failed: {message}"),
            Self::MalformedResponse(kind) => write!(f, "CDN edge response is malformed: {kind}"),
            Self::InvalidTimestamp(value) => write!(f, "CDN edge timestamp is invalid: {value}"),
        }
    }
}

impl std::error::Error for CdnEdgeClientError {}

pub trait CdnEdgeTransport {
    fn send(
        &mut self,
        request: &CdnEdgeHttpRequest,
        credential: Option<&CdnEdgeCredentialMaterial>,
    ) -> Result<CdnEdgeHttpResponse, CdnEdgeClientError>;
}

pub struct CdnEdgeProviderClient<T> {
    transport: T,
}

impl<T> CdnEdgeProviderClient<T>
where
    T: CdnEdgeTransport,
{
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub fn poll_once(
        &mut self,
        request: CdnEdgePollRequest,
        session: &mut CdnEdgeClientSession,
    ) -> Result<CdnEdgePollOutcome, CdnEdgeClientError> {
        if session.is_revoked() {
            return Ok(CdnEdgePollOutcome::empty(
                CdnEdgeClientState::Revoked,
                request.cursor,
            ));
        }

        if session.requests_this_tick >= allowed_pages_this_tick(&request.config) {
            let mut outcome =
                CdnEdgePollOutcome::empty(CdnEdgeClientState::RateLimited, request.cursor);
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
            .unwrap_or(CdnEdgeAuthMode::None);
        let credential = match auth_mode {
            CdnEdgeAuthMode::None => None,
            expected => match session.credential.as_ref() {
                Some(credential) if credential.auth_mode() == expected => Some(credential),
                _ => {
                    let mut outcome = CdnEdgePollOutcome::empty(
                        CdnEdgeClientState::MissingCredentials,
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
                let endpoint_kind = request.config.endpoint_kind;
                let max_records = request.config.bounded_max_records_per_page() as usize;
                let normalization = normalize_response_events(
                    provider_kind,
                    endpoint_kind,
                    max_records,
                    &response.body,
                )?;
                session.set_next_page_token(response.next_page_token);
                let cursor = cursor_from_session(session);
                let mut outcome = CdnEdgePollOutcome::empty(
                    if normalization.http_metadata.is_empty()
                        && normalization.skipped_record_count > 0
                    {
                        CdnEdgeClientState::Degraded
                    } else {
                        CdnEdgeClientState::PageFetched
                    },
                    cursor,
                );
                outcome.http_metadata = normalization.http_metadata;
                outcome.provider_metadata = normalization.provider_metadata;
                outcome.requested_page_count = 1;
                outcome.accepted_record_count = normalization.accepted_record_count;
                outcome.skipped_record_count = normalization.skipped_record_count;
                outcome.degraded_reasons = normalization.degraded_reasons;
                Ok(outcome)
            }
            401 | 403 => {
                session.clear();
                let mut outcome = CdnEdgePollOutcome::empty(
                    CdnEdgeClientState::MissingCredentials,
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
                    CdnEdgePollOutcome::empty(CdnEdgeClientState::Failed, request.cursor);
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
    provider_metadata: Vec<PortableSaasCloudMetadata>,
    accepted_record_count: u16,
    skipped_record_count: u16,
    degraded_reasons: Vec<String>,
}

fn allowed_pages_this_tick(config: &CdnEdgeClientConfig) -> u16 {
    let per_tick = config.bounded_max_pages_per_tick() as u16;
    let per_minute = config.rate_limit_per_minute.max(1);
    per_tick.min(per_minute)
}

fn build_http_request(
    request: &CdnEdgePollRequest,
    auth_mode: CdnEdgeAuthMode,
    continuation_present: bool,
) -> CdnEdgeHttpRequest {
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
    if let Some(dataset_bucket) = request.config.dataset_bucket.as_deref() {
        query_shape.insert("dataset_bucket".to_string(), safe_label(dataset_bucket, 48));
    }

    let (method, body_shape) = match request.config.endpoint_kind {
        CdnEdgeEndpointKind::CloudflareHttpRequests => {
            query_shape.insert("api".to_string(), "http_requests_adaptive".to_string());
            (
                "POST".to_string(),
                Some("cloudflare_http_requests_read_only_shape".to_string()),
            )
        }
        CdnEdgeEndpointKind::CloudFrontStandardLogs => {
            query_shape.insert(
                "api".to_string(),
                "cloudfront_standard_logs_page".to_string(),
            );
            ("GET".to_string(), None)
        }
        CdnEdgeEndpointKind::AzureFrontDoorAccessLogs => {
            query_shape.insert("api".to_string(), "azure_frontdoor_access_logs".to_string());
            query_shape.insert("filter".to_string(), "time_window_and_category".to_string());
            ("GET".to_string(), None)
        }
        CdnEdgeEndpointKind::FastlyLogInsights => {
            query_shape.insert("api".to_string(), "fastly_log_insights".to_string());
            ("GET".to_string(), None)
        }
        CdnEdgeEndpointKind::AkamaiDataStream => {
            query_shape.insert("api".to_string(), "akamai_datastream_page".to_string());
            ("GET".to_string(), None)
        }
        CdnEdgeEndpointKind::GenericJsonPage => {
            query_shape.insert("api".to_string(), "generic_json_page".to_string());
            ("GET".to_string(), None)
        }
    };

    CdnEdgeHttpRequest {
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
    cursor: CdnEdgePageCursor,
    retry_after_seconds: Option<u64>,
    reason: &str,
) -> CdnEdgePollOutcome {
    let mut outcome = CdnEdgePollOutcome::empty(CdnEdgeClientState::RetryScheduled, cursor);
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
    provider_kind: CdnEdgeProviderKind,
    endpoint_kind: CdnEdgeEndpointKind,
    max_records: usize,
    body: &str,
) -> Result<NormalizedPage, CdnEdgeClientError> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| CdnEdgeClientError::MalformedResponse("json"))?;
    let records = event_records(&value);
    let mut http_metadata = Vec::new();
    let mut provider_metadata = Vec::new();
    let mut skipped_record_count = 0u16;
    let mut degraded_reasons = BTreeSet::new();

    for record in records.into_iter().take(max_records) {
        match normalize_event(provider_kind, endpoint_kind, record) {
            Ok((http, provider)) => {
                http_metadata.push(http);
                provider_metadata.push(provider);
            }
            Err(reason) => {
                skipped_record_count = skipped_record_count.saturating_add(1);
                degraded_reasons.insert(reason.to_string());
            }
        }
    }

    Ok(NormalizedPage {
        accepted_record_count: http_metadata.len() as u16,
        http_metadata,
        provider_metadata,
        skipped_record_count,
        degraded_reasons: degraded_reasons.into_iter().collect(),
    })
}

fn event_records(value: &Value) -> Vec<&Value> {
    if let Some(records) = value.as_array() {
        return records.iter().collect();
    }
    for key in [
        "data", "records", "items", "logs", "events", "Events", "value", "results",
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
    provider_kind: CdnEdgeProviderKind,
    endpoint_kind: CdnEdgeEndpointKind,
    record: &Value,
) -> Result<(HttpMetadata, PortableSaasCloudMetadata), &'static str> {
    let timestamp = event_timestamp(record).map_err(|_| "timestamp_missing_or_invalid")?;
    let service = service_category(provider_kind, record);
    let method = method_category(record);
    let status_code = status_code(record);
    let status_bucket = status_bucket_from_code(status_code);
    let result = result_category(record, status_code);
    let route_bucket = route_bucket(record);
    let request_bytes = number_at_any_path(
        record,
        &[
            &["ClientRequestBytes"],
            &["clientRequestBytes"],
            &["cs-bytes"],
            &["requestBytes"],
            &["requestSize"],
            &["request_length"],
            &["request", "bytes"],
        ],
    );
    let response_bytes = number_at_any_path(
        record,
        &[
            &["EdgeResponseBytes"],
            &["edgeResponseBytes"],
            &["OriginResponseBytes"],
            &["sc-bytes"],
            &["responseBytes"],
            &["responseSize"],
            &["body_bytes_sent"],
            &["response", "bytes"],
        ],
    );

    let mut http = HttpMetadata::new(method.clone());
    http.timestamp = bucket_timestamp_to_hour(timestamp.clone());
    http.method = method.clone();
    http.scheme = Some(scheme_category(record));
    http.host_protected = Some(format!("cdn_provider#{service}"));
    http.path_template_protected = Some(format!("/cdn_edge/{route_bucket}"));
    http.endpoint_fingerprint = Some(endpoint_fingerprint(
        provider_kind,
        &service,
        &method,
        &status_bucket,
        &result,
        &route_bucket,
    ));
    http.status_code = status_code;
    http.status_family = status_code.map(|code| format!("{}xx", code / 100));
    http.result_label = Some(result_label(&service, &result, status_code));
    http.request_size_bytes = request_bytes;
    http.response_size_bytes = response_bytes;
    http.request_content_length_bytes = request_bytes;
    http.response_content_length_bytes = response_bytes;
    http.upload_download_ratio = upload_download_ratio(request_bytes, response_bytes);
    http.content_type = content_type_category(record);
    http.user_agent_family = user_agent_family(record);
    http.api_hint = Some("cdn_edge_provider_metadata".to_string());
    http.visible_plaintext = true;
    http.privacy_class = PrivacyClass::Internal;
    http.quality_score = quality(0.72);

    let api_method = cdn_api_method_category(&method);
    let mut provider = PortableSaasCloudMetadata::new(
        PortableProviderCategory::Cdn,
        bucket_timestamp_to_hour(timestamp),
    );
    provider.service_category = Some(service.clone());
    provider.provider_risk_category = provider_risk_category(&status_bucket, &result);
    provider.provider_confidence = provider_confidence(provider_kind, endpoint_kind);
    provider.endpoint_fingerprint = http.endpoint_fingerprint.clone();
    provider.api_method_category = api_method.clone();
    provider.status_bucket = status_bucket;
    provider.upload_download_ratio_bucket = ratio_bucket(api_method, request_bytes, response_bytes);
    provider.auth_result_category = auth_result_category(&provider.status_bucket);
    provider.destination_category = Some(destination_category(&result, status_code));
    provider.identity_label_redacted = None;
    provider.source_session_label = None;
    provider.redaction_status = RedactionStatus::Redacted;
    provider.quality_score = quality(0.66);

    Ok((http, provider))
}

fn event_timestamp(record: &Value) -> Result<Timestamp, CdnEdgeClientError> {
    if let Some(millis) = number_at_any_path(
        record,
        &[
            &["edgeStartTimestampMs"],
            &["EdgeStartTimestampMs"],
            &["timestamp_ms"],
            &["timestampMs"],
            &["timeEpochMs"],
        ],
    ) {
        let datetime = Utc
            .timestamp_millis_opt(millis as i64)
            .single()
            .ok_or_else(|| CdnEdgeClientError::InvalidTimestamp(millis.to_string()))?;
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
            .ok_or_else(|| CdnEdgeClientError::InvalidTimestamp(seconds.to_string()))?;
        return Ok(Timestamp::from_datetime(datetime));
    }
    let raw = string_at_any_path(
        record,
        &[
            &["datetime"],
            &["dateTime"],
            &["timestamp"],
            &["time"],
            &["ts"],
            &["EdgeStartTimestamp"],
            &["edgeStartTimestamp"],
            &["date"],
        ],
    )
    .ok_or(CdnEdgeClientError::MalformedResponse("timestamp"))?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|value| Timestamp::from_datetime(value.with_timezone(&Utc)))
        .map_err(|_| CdnEdgeClientError::InvalidTimestamp(raw))
}

fn bucket_timestamp_to_hour(timestamp: Timestamp) -> Timestamp {
    let datetime = timestamp.as_datetime();
    let bucket = datetime
        .date_naive()
        .and_hms_opt(datetime.hour(), 0, 0)
        .expect("valid UTC hour bucket");
    Timestamp::from_datetime(DateTime::from_naive_utc_and_offset(bucket, Utc))
}

fn service_category(provider_kind: CdnEdgeProviderKind, record: &Value) -> String {
    let hint = string_at_any_path(
        record,
        &[
            &["service"],
            &["serviceCategory"],
            &["provider"],
            &["edgeProvider"],
            &["ResourceProvider"],
            &["category"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();
    if hint.contains("cloudflare") || record.get("RayID").is_some() || record.get("rayId").is_some()
    {
        "cloudflare_edge".to_string()
    } else if hint.contains("cloudfront") || record.get("x-edge-result-type").is_some() {
        "cloudfront_edge".to_string()
    } else if hint.contains("frontdoor") || hint.contains("front_door") || hint.contains("azure") {
        "azure_front_door".to_string()
    } else if hint.contains("fastly") {
        "fastly_edge".to_string()
    } else if hint.contains("akamai") {
        "akamai_edge".to_string()
    } else {
        match provider_kind {
            CdnEdgeProviderKind::CloudflareHttp => "cloudflare_edge",
            CdnEdgeProviderKind::CloudFront => "cloudfront_edge",
            CdnEdgeProviderKind::AzureFrontDoor => "azure_front_door",
            CdnEdgeProviderKind::Fastly => "fastly_edge",
            CdnEdgeProviderKind::Akamai => "akamai_edge",
            CdnEdgeProviderKind::Generic => "cdn_edge",
        }
        .to_string()
    }
}

fn method_category(record: &Value) -> HttpMethod {
    match string_at_any_path(
        record,
        &[
            &["ClientRequestMethod"],
            &["clientRequestMethod"],
            &["cs-method"],
            &["method"],
            &["httpMethod"],
            &["request", "method"],
        ],
    )
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

fn status_code(record: &Value) -> Option<u16> {
    number_at_any_path(
        record,
        &[
            &["EdgeResponseStatus"],
            &["edgeResponseStatus"],
            &["OriginResponseStatus"],
            &["originResponseStatus"],
            &["sc-status"],
            &["status"],
            &["statusCode"],
            &["status_code"],
            &["httpStatusCode"],
            &["response", "status"],
        ],
    )
    .and_then(|value| u16::try_from(value).ok())
    .filter(|status| (100..=599).contains(status))
}

fn status_bucket_from_code(status_code: Option<u16>) -> PortableStatusBucket {
    match status_code {
        Some(200..=299) => PortableStatusBucket::Success,
        Some(300..=399) => PortableStatusBucket::Redirect,
        Some(401 | 403) => PortableStatusBucket::AuthError,
        Some(404) => PortableStatusBucket::NotFound,
        Some(429) => PortableStatusBucket::RateLimited,
        Some(400..=499) => PortableStatusBucket::ClientError,
        Some(500..=599) => PortableStatusBucket::ServerError,
        _ => PortableStatusBucket::Unknown,
    }
}

fn result_category(record: &Value, status_code: Option<u16>) -> String {
    let raw = string_at_any_path(
        record,
        &[
            &["CacheCacheStatus"],
            &["cacheStatus"],
            &["x-edge-result-type"],
            &["x-edge-detailed-result-type"],
            &["edgeResultType"],
            &["result"],
            &["outcome"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();
    if raw.contains("hit") {
        "cache_hit".to_string()
    } else if raw.contains("miss") {
        "cache_miss".to_string()
    } else if raw.contains("limit") || status_code == Some(429) {
        "edge_rate_limited".to_string()
    } else if raw.contains("error") || matches!(status_code, Some(500..=599)) {
        "origin_or_edge_error".to_string()
    } else if matches!(status_code, Some(300..=399)) {
        "edge_redirect".to_string()
    } else if matches!(status_code, Some(200..=299)) {
        "edge_success".to_string()
    } else {
        "edge_observed".to_string()
    }
}

fn route_bucket(record: &Value) -> String {
    let raw = string_at_any_path(
        record,
        &[
            &["ClientRequestURI"],
            &["clientRequestUri"],
            &["cs-uri-stem"],
            &["requestUri"],
            &["path"],
            &["url"],
            &["request", "path"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();
    if raw.is_empty() {
        "route_unknown".to_string()
    } else if raw.contains("api") {
        "route_api".to_string()
    } else if raw.contains("static") || raw.contains("assets") || raw.contains("img") {
        "route_static_asset".to_string()
    } else if raw.contains("auth") || raw.contains("login") {
        "route_auth".to_string()
    } else {
        "route_other".to_string()
    }
}

fn scheme_category(record: &Value) -> String {
    match string_at_any_path(
        record,
        &[
            &["ClientRequestScheme"],
            &["clientRequestScheme"],
            &["cs-protocol"],
            &["scheme"],
            &["protocol"],
            &["request", "scheme"],
        ],
    )
    .unwrap_or_else(|| "https".to_string())
    .to_ascii_lowercase()
    .as_str()
    {
        "http" => "http",
        _ => "https",
    }
    .to_string()
}

fn cdn_api_method_category(method: &HttpMethod) -> PortableApiMethodCategory {
    match method {
        HttpMethod::Get | HttpMethod::Head => PortableApiMethodCategory::Read,
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => PortableApiMethodCategory::Write,
        HttpMethod::Delete => PortableApiMethodCategory::Delete,
        _ => PortableApiMethodCategory::Other,
    }
}

fn ratio_bucket(
    api_method: PortableApiMethodCategory,
    request_bytes: Option<u64>,
    response_bytes: Option<u64>,
) -> PortableUploadDownloadRatioBucket {
    if matches!(
        api_method,
        PortableApiMethodCategory::Write | PortableApiMethodCategory::Delete
    ) {
        return PortableUploadDownloadRatioBucket::UploadHeavy;
    }
    match upload_download_ratio(request_bytes, response_bytes) {
        Some(value) if value >= 8.0 => PortableUploadDownloadRatioBucket::UploadBurst,
        Some(value) if value >= 2.0 => PortableUploadDownloadRatioBucket::UploadHeavy,
        Some(value) if value <= 0.5 => PortableUploadDownloadRatioBucket::DownloadHeavy,
        Some(_) => PortableUploadDownloadRatioBucket::Balanced,
        None => PortableUploadDownloadRatioBucket::Unknown,
    }
}

fn upload_download_ratio(request_bytes: Option<u64>, response_bytes: Option<u64>) -> Option<f32> {
    let request = request_bytes? as f32;
    let response = response_bytes.unwrap_or(0).max(1) as f32;
    Some(request / response)
}

fn provider_risk_category(
    status_bucket: &PortableStatusBucket,
    result: &str,
) -> PortableProviderRiskCategory {
    if matches!(
        status_bucket,
        PortableStatusBucket::ServerError
            | PortableStatusBucket::RateLimited
            | PortableStatusBucket::AuthError
    ) || result.contains("error")
    {
        PortableProviderRiskCategory::Medium
    } else if matches!(status_bucket, PortableStatusBucket::Success) && result.contains("hit") {
        PortableProviderRiskCategory::Low
    } else {
        PortableProviderRiskCategory::Unknown
    }
}

fn provider_confidence(
    provider_kind: CdnEdgeProviderKind,
    endpoint_kind: CdnEdgeEndpointKind,
) -> PortableProviderConfidenceBucket {
    match (provider_kind, endpoint_kind) {
        (CdnEdgeProviderKind::CloudflareHttp, CdnEdgeEndpointKind::CloudflareHttpRequests)
        | (CdnEdgeProviderKind::CloudFront, CdnEdgeEndpointKind::CloudFrontStandardLogs)
        | (CdnEdgeProviderKind::AzureFrontDoor, CdnEdgeEndpointKind::AzureFrontDoorAccessLogs)
        | (CdnEdgeProviderKind::Fastly, CdnEdgeEndpointKind::FastlyLogInsights)
        | (CdnEdgeProviderKind::Akamai, CdnEdgeEndpointKind::AkamaiDataStream) => {
            PortableProviderConfidenceBucket::Medium
        }
        _ => PortableProviderConfidenceBucket::Low,
    }
}

fn auth_result_category(status_bucket: &PortableStatusBucket) -> Option<String> {
    match status_bucket {
        PortableStatusBucket::Success => Some("success".to_string()),
        PortableStatusBucket::AuthError => Some("auth_error".to_string()),
        PortableStatusBucket::RateLimited => Some("rate_limited".to_string()),
        PortableStatusBucket::ClientError | PortableStatusBucket::NotFound => {
            Some("client_error".to_string())
        }
        PortableStatusBucket::ServerError => Some("server_error".to_string()),
        _ => None,
    }
}

fn destination_category(result: &str, status_code: Option<u16>) -> String {
    if result.contains("cache_hit") {
        "edge_cache".to_string()
    } else if result.contains("rate_limited") {
        "edge_rate_limited".to_string()
    } else if result.contains("error") || matches!(status_code, Some(500..=599)) {
        "origin_or_edge_error".to_string()
    } else if matches!(status_code, Some(300..=399)) {
        "edge_redirect".to_string()
    } else {
        "cdn_edge".to_string()
    }
}

fn result_label(service: &str, result: &str, status_code: Option<u16>) -> String {
    match status_code {
        Some(401 | 403 | 429) => format!("{service}_auth_or_throttle"),
        Some(400..=499) => format!("{service}_client_error"),
        Some(500..=599) => format!("{service}_origin_or_service_error"),
        Some(200..=399) => format!("{service}_{result}"),
        Some(_) => format!("{service}_observed"),
        None => format!("{service}_status_missing"),
    }
}

fn content_type_category(record: &Value) -> Option<String> {
    let raw = string_at_any_path(
        record,
        &[
            &["contentType"],
            &["content_type"],
            &["responseContentType"],
            &["request", "content_type"],
            &["response", "content_type"],
        ],
    )?
    .to_ascii_lowercase();
    let category = if raw.contains("json") {
        "application_json"
    } else if raw.contains("html") {
        "text_html"
    } else if raw.contains("image") {
        "image"
    } else if raw.contains("javascript") || raw.contains("script") {
        "script"
    } else if raw.contains("css") {
        "style"
    } else {
        "other"
    };
    Some(category.to_string())
}

fn user_agent_family(record: &Value) -> Option<String> {
    let raw = string_at_any_path(
        record,
        &[
            &["ClientRequestUserAgent"],
            &["clientRequestUserAgent"],
            &["cs(User-Agent)"],
            &["userAgent"],
            &["user_agent"],
            &["request", "user_agent"],
        ],
    )?
    .to_ascii_lowercase();
    let category = if raw.contains("bot") || raw.contains("crawler") || raw.contains("spider") {
        "bot"
    } else if raw.contains("curl") || raw.contains("wget") {
        "scripted_client"
    } else if raw.contains("mozilla") || raw.contains("chrome") || raw.contains("safari") {
        "browser"
    } else {
        "other"
    };
    Some(category.to_string())
}

fn endpoint_fingerprint(
    provider_kind: CdnEdgeProviderKind,
    service: &str,
    method: &HttpMethod,
    status_bucket: &PortableStatusBucket,
    result: &str,
    route_bucket: &str,
) -> String {
    safe_digest_label(
        "endpoint",
        &format!(
            "{provider_kind:?}:{service}:{method:?}:{status_bucket:?}:{result}:{route_bucket}"
        ),
    )
}

fn cursor_from_session(session: &CdnEdgeClientSession) -> CdnEdgePageCursor {
    match session.next_page_token.as_deref() {
        Some(token) => CdnEdgePageCursor::from_safe_checkpoint(
            "continuation_present",
            Some(safe_digest_label("cursor", token)),
            Timestamp::now(),
        ),
        None => CdnEdgePageCursor {
            safe_cursor_bucket: "end_reached".to_string(),
            next_page_token_hash: None,
            checkpoint_state: CdnEdgeCheckpointState::EndReached,
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
    use sentinel_contracts::{CdnEdgeCredentialRef, CdnEdgePageCursor};

    #[derive(Default)]
    struct RecordingTransport {
        calls: Vec<CdnEdgeHttpRequest>,
        response: Option<CdnEdgeHttpResponse>,
    }

    impl CdnEdgeTransport for RecordingTransport {
        fn send(
            &mut self,
            request: &CdnEdgeHttpRequest,
            _credential: Option<&CdnEdgeCredentialMaterial>,
        ) -> Result<CdnEdgeHttpResponse, CdnEdgeClientError> {
            self.calls.push(request.clone());
            self.response
                .clone()
                .ok_or_else(|| CdnEdgeClientError::transport("missing test response"))
        }
    }

    fn cloudflare_request() -> CdnEdgePollRequest {
        CdnEdgePollRequest::new(
            CdnEdgeClientConfig::new(
                CdnEdgeProviderKind::CloudflareHttp,
                CdnEdgeEndpointKind::CloudflareHttpRequests,
            ),
            Some(CdnEdgeCredentialRef::new(
                "credential_session#cdn-edge",
                CdnEdgeAuthMode::BearerTokenSession,
                None,
            )),
            CdnEdgePageCursor::empty(Timestamp::now()),
        )
    }

    fn bearer_session() -> CdnEdgeClientSession {
        CdnEdgeClientSession::new(Some(CdnEdgeCredentialMaterial::BearerToken(
            "Bearer SHOULD_NOT_LEAK".to_string(),
        )))
    }

    #[test]
    fn cdn_edge_cloudflare_page_normalizes_without_identifier_exposure() {
        let body = r#"{
          "data": [{
            "datetime": "2026-06-16T12:34:56Z",
            "ClientRequestMethod": "GET",
            "ClientRequestHost": "customer.example.test",
            "ClientRequestURI": "/private/path/customer-42?token=secret",
            "ClientIP": "203.0.113.10",
            "RayID": "sensitive-ray-id",
            "EdgeResponseStatus": 200,
            "CacheCacheStatus": "hit",
            "ClientRequestBytes": 128,
            "EdgeResponseBytes": 4096,
            "ClientRequestUserAgent": "Mozilla/5.0 secret-profile",
            "payload": "secret"
          }]
        }"#;
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(CdnEdgeHttpResponse {
                status_code: 200,
                body: body.to_string(),
                next_page_token: Some("RAW_CDN_CURSOR_SHOULD_NOT_LEAK".to_string()),
                retry_after_seconds: None,
            }),
        };
        let mut client = CdnEdgeProviderClient::new(transport);
        let mut session = bearer_session();

        let outcome = client
            .poll_once(cloudflare_request(), &mut session)
            .expect("poll succeeds");

        assert_eq!(outcome.client_state, CdnEdgeClientState::PageFetched);
        assert_eq!(outcome.accepted_record_count, 1);
        assert_eq!(outcome.http_metadata.len(), 1);
        assert_eq!(outcome.provider_metadata.len(), 1);
        assert_eq!(
            outcome.provider_metadata[0].provider_category,
            PortableProviderCategory::Cdn
        );
        assert_eq!(
            outcome.provider_metadata[0].service_category.as_deref(),
            Some("cloudflare_edge")
        );
        assert_eq!(
            outcome.cursor.checkpoint_state,
            CdnEdgeCheckpointState::CursorHashPresent
        );
        assert_eq!(
            session.next_page_token_for_test(),
            Some("RAW_CDN_CURSOR_SHOULD_NOT_LEAK")
        );

        let transport = client.into_inner();
        assert_eq!(transport.calls.len(), 1);
        assert!(transport.calls[0].read_only);
        assert_eq!(transport.calls[0].method, "POST");

        let serialized = serde_json::to_string(&outcome).expect("serialize outcome");
        let debug_session = format!("{session:?}");
        for value in [serialized, debug_session] {
            assert!(!value.contains("customer.example.test"));
            assert!(!value.contains("/private/path"));
            assert!(!value.contains("203.0.113."));
            assert!(!value.contains("sensitive-ray-id"));
            assert!(!value.contains("RAW_CDN_CURSOR"));
            assert!(!value.contains("Bearer SHOULD_NOT_LEAK"));
            assert!(!value.contains("token=secret"));
            assert!(!value.contains("payload"));
        }
    }

    #[test]
    fn cdn_edge_missing_credentials_does_not_call_transport() {
        let transport = RecordingTransport::default();
        let mut client = CdnEdgeProviderClient::new(transport);
        let mut session = CdnEdgeClientSession::without_credentials();

        let outcome = client
            .poll_once(cloudflare_request(), &mut session)
            .expect("missing credentials are classified");
        let transport = client.into_inner();

        assert_eq!(outcome.client_state, CdnEdgeClientState::MissingCredentials);
        assert!(transport.calls.is_empty());
        assert!(outcome
            .degraded_reasons
            .contains(&"credential_material_missing_or_mismatched".to_string()));
    }

    #[test]
    fn cdn_edge_auth_failure_clears_in_memory_credentials() {
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(CdnEdgeHttpResponse {
                status_code: 403,
                body: "{}".to_string(),
                next_page_token: Some("ignored_after_auth_failure".to_string()),
                retry_after_seconds: None,
            }),
        };
        let mut client = CdnEdgeProviderClient::new(transport);
        let mut session = bearer_session();

        let outcome = client
            .poll_once(cloudflare_request(), &mut session)
            .expect("auth failure classified");

        assert_eq!(outcome.client_state, CdnEdgeClientState::MissingCredentials);
        assert!(!session.has_credential());
        assert!(session.next_page_token_for_test().is_none());
        assert!(outcome
            .degraded_reasons
            .contains(&"auth_failed_credentials_cleared".to_string()));
    }

    #[test]
    fn cdn_edge_rate_limit_preserves_checkpoint_without_call() {
        let mut request = cloudflare_request();
        request.config.max_pages_per_tick = 1;
        request.config.rate_limit_per_minute = 1;
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(CdnEdgeHttpResponse {
                status_code: 200,
                body: r#"{"data":[]}"#.to_string(),
                next_page_token: None,
                retry_after_seconds: None,
            }),
        };
        let mut client = CdnEdgeProviderClient::new(transport);
        let mut session = bearer_session();

        let first = client
            .poll_once(request.clone(), &mut session)
            .expect("first request succeeds");
        let second = client
            .poll_once(request, &mut session)
            .expect("second request is rate limited");
        let transport = client.into_inner();

        assert_eq!(first.client_state, CdnEdgeClientState::PageFetched);
        assert_eq!(second.client_state, CdnEdgeClientState::RateLimited);
        assert_eq!(transport.calls.len(), 1);
        assert_eq!(second.retry_after_bucket.as_deref(), Some("next_tick"));
    }
}
