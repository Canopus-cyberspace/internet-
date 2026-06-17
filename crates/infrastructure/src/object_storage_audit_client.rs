use chrono::{DateTime, TimeZone, Timelike, Utc};
use sentinel_contracts::{
    ObjectStorageAuditAuthMode, ObjectStorageAuditCheckpointState, ObjectStorageAuditClientConfig,
    ObjectStorageAuditClientState, ObjectStorageAuditEndpointKind, ObjectStorageAuditPageCursor,
    ObjectStorageAuditPollOutcome, ObjectStorageAuditPollRequest, ObjectStorageAuditProviderKind,
    PortableApiMethodCategory, PortableProviderCategory, PortableProviderConfidenceBucket,
    PortableProviderRiskCategory, PortableSaasCloudMetadata, PortableStatusBucket,
    PortableUploadDownloadRatioBucket, QualityScore, RedactionStatus, Timestamp,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStorageAuditHttpRequest {
    pub method: String,
    pub endpoint_kind: ObjectStorageAuditEndpointKind,
    pub provider_kind: ObjectStorageAuditProviderKind,
    pub query_shape: BTreeMap<String, String>,
    pub body_shape: Option<String>,
    pub auth_mode: ObjectStorageAuditAuthMode,
    pub continuation_present: bool,
    pub max_records_per_page: u16,
    pub read_only: bool,
    pub timeout_millis: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStorageAuditHttpResponse {
    pub status_code: u16,
    pub body: String,
    pub next_page_token: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

impl fmt::Debug for ObjectStorageAuditHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStorageAuditHttpResponse")
            .field("status_code", &self.status_code)
            .field("body_len", &self.body.len())
            .field("next_page_token_present", &self.next_page_token.is_some())
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ObjectStorageAuditCredentialMaterial {
    AwsSigV4Session {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    BearerToken(String),
    AccessKeySession {
        access_key_id: String,
        secret_access_key: String,
    },
}

impl ObjectStorageAuditCredentialMaterial {
    pub fn auth_mode(&self) -> ObjectStorageAuditAuthMode {
        match self {
            Self::AwsSigV4Session { .. } => ObjectStorageAuditAuthMode::AwsSigV4Session,
            Self::BearerToken(_) => ObjectStorageAuditAuthMode::BearerTokenSession,
            Self::AccessKeySession { .. } => ObjectStorageAuditAuthMode::AccessKeySession,
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
            Self::BearerToken(token) => token.clear(),
            Self::AccessKeySession {
                access_key_id,
                secret_access_key,
            } => {
                access_key_id.clear();
                secret_access_key.clear();
            }
        }
    }
}

impl fmt::Debug for ObjectStorageAuditCredentialMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStorageAuditCredentialMaterial")
            .field("auth_mode", &self.auth_mode())
            .field("material", &"redacted")
            .finish()
    }
}

pub struct ObjectStorageAuditClientSession {
    credential: Option<ObjectStorageAuditCredentialMaterial>,
    next_page_token: Option<String>,
    requests_this_tick: u16,
    revoked: bool,
}

impl ObjectStorageAuditClientSession {
    pub fn new(credential: Option<ObjectStorageAuditCredentialMaterial>) -> Self {
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

impl Drop for ObjectStorageAuditClientSession {
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for ObjectStorageAuditClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStorageAuditClientSession")
            .field("credential_present", &self.credential.is_some())
            .field("next_page_token_present", &self.next_page_token.is_some())
            .field("requests_this_tick", &self.requests_this_tick)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStorageAuditClientError {
    Transport(String),
    MalformedResponse(&'static str),
    InvalidTimestamp(String),
}

impl ObjectStorageAuditClientError {
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }
}

impl fmt::Display for ObjectStorageAuditClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(message) => {
                write!(f, "object storage audit transport failed: {message}")
            }
            Self::MalformedResponse(kind) => {
                write!(f, "object storage audit response is malformed: {kind}")
            }
            Self::InvalidTimestamp(value) => {
                write!(f, "object storage audit timestamp is invalid: {value}")
            }
        }
    }
}

impl std::error::Error for ObjectStorageAuditClientError {}

pub trait ObjectStorageAuditTransport {
    fn send(
        &mut self,
        request: &ObjectStorageAuditHttpRequest,
        credential: Option<&ObjectStorageAuditCredentialMaterial>,
    ) -> Result<ObjectStorageAuditHttpResponse, ObjectStorageAuditClientError>;
}

pub struct ObjectStorageAuditProviderClient<T> {
    transport: T,
}

impl<T> ObjectStorageAuditProviderClient<T>
where
    T: ObjectStorageAuditTransport,
{
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub fn poll_once(
        &mut self,
        request: ObjectStorageAuditPollRequest,
        session: &mut ObjectStorageAuditClientSession,
    ) -> Result<ObjectStorageAuditPollOutcome, ObjectStorageAuditClientError> {
        if session.is_revoked() {
            return Ok(ObjectStorageAuditPollOutcome::empty(
                ObjectStorageAuditClientState::Revoked,
                request.cursor,
            ));
        }

        if session.requests_this_tick >= allowed_pages_this_tick(&request.config) {
            let mut outcome = ObjectStorageAuditPollOutcome::empty(
                ObjectStorageAuditClientState::RateLimited,
                request.cursor,
            );
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
            .unwrap_or(ObjectStorageAuditAuthMode::None);
        let credential = match auth_mode {
            ObjectStorageAuditAuthMode::None => None,
            expected => match session.credential.as_ref() {
                Some(credential) if credential.auth_mode() == expected => Some(credential),
                _ => {
                    let mut outcome = ObjectStorageAuditPollOutcome::empty(
                        ObjectStorageAuditClientState::MissingCredentials,
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
                let mut outcome = ObjectStorageAuditPollOutcome::empty(
                    if normalization.metadata.is_empty() && normalization.skipped_record_count > 0 {
                        ObjectStorageAuditClientState::Degraded
                    } else {
                        ObjectStorageAuditClientState::PageFetched
                    },
                    cursor,
                );
                outcome.metadata = normalization.metadata;
                outcome.requested_page_count = 1;
                outcome.accepted_record_count = normalization.accepted_record_count;
                outcome.skipped_record_count = normalization.skipped_record_count;
                outcome.degraded_reasons = normalization.degraded_reasons;
                Ok(outcome)
            }
            401 | 403 => {
                session.clear();
                let mut outcome = ObjectStorageAuditPollOutcome::empty(
                    ObjectStorageAuditClientState::MissingCredentials,
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
                let mut outcome = ObjectStorageAuditPollOutcome::empty(
                    ObjectStorageAuditClientState::Failed,
                    request.cursor,
                );
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
    metadata: Vec<PortableSaasCloudMetadata>,
    accepted_record_count: u16,
    skipped_record_count: u16,
    degraded_reasons: Vec<String>,
}

fn allowed_pages_this_tick(config: &ObjectStorageAuditClientConfig) -> u16 {
    let per_tick = config.bounded_max_pages_per_tick() as u16;
    let per_minute = config.rate_limit_per_minute.max(1);
    per_tick.min(per_minute)
}

fn build_http_request(
    request: &ObjectStorageAuditPollRequest,
    auth_mode: ObjectStorageAuditAuthMode,
    continuation_present: bool,
) -> ObjectStorageAuditHttpRequest {
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

    let (method, body_shape) = match request.config.endpoint_kind {
        ObjectStorageAuditEndpointKind::CloudTrailLookupEvents => {
            query_shape.insert("api".to_string(), "lookup_events".to_string());
            (
                "POST".to_string(),
                Some("cloudtrail_lookup_events_read_only_shape".to_string()),
            )
        }
        ObjectStorageAuditEndpointKind::AzureActivityLogs => {
            query_shape.insert("api_version".to_string(), "activity_logs".to_string());
            query_shape.insert("filter".to_string(), "time_window_and_category".to_string());
            ("GET".to_string(), None)
        }
        ObjectStorageAuditEndpointKind::GoogleCloudAuditLogs => {
            query_shape.insert("api".to_string(), "logging_entries_list".to_string());
            query_shape.insert("filter".to_string(), "storage_audit_log_name".to_string());
            (
                "POST".to_string(),
                Some("google_logging_entries_list_shape".to_string()),
            )
        }
        ObjectStorageAuditEndpointKind::CloudflareR2Audit => {
            query_shape.insert("api".to_string(), "r2_audit_events".to_string());
            ("GET".to_string(), None)
        }
        ObjectStorageAuditEndpointKind::MinioAudit => {
            query_shape.insert("api".to_string(), "audit_log_page".to_string());
            ("GET".to_string(), None)
        }
        ObjectStorageAuditEndpointKind::GenericJsonPage => {
            query_shape.insert("api".to_string(), "generic_json_page".to_string());
            ("GET".to_string(), None)
        }
    };

    ObjectStorageAuditHttpRequest {
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
    cursor: ObjectStorageAuditPageCursor,
    retry_after_seconds: Option<u64>,
    reason: &str,
) -> ObjectStorageAuditPollOutcome {
    let mut outcome =
        ObjectStorageAuditPollOutcome::empty(ObjectStorageAuditClientState::RetryScheduled, cursor);
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
    provider_kind: ObjectStorageAuditProviderKind,
    endpoint_kind: ObjectStorageAuditEndpointKind,
    max_records: usize,
    body: &str,
) -> Result<NormalizedPage, ObjectStorageAuditClientError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|_| ObjectStorageAuditClientError::MalformedResponse("json"))?;
    let records = event_records(&value);
    let mut metadata = Vec::new();
    let mut skipped_record_count = 0u16;
    let mut degraded_reasons = BTreeSet::new();

    for record in records.into_iter().take(max_records) {
        match normalize_event(provider_kind, endpoint_kind, record) {
            Ok(item) => metadata.push(item),
            Err(reason) => {
                skipped_record_count = skipped_record_count.saturating_add(1);
                degraded_reasons.insert(reason.to_string());
            }
        }
    }

    Ok(NormalizedPage {
        accepted_record_count: metadata.len() as u16,
        metadata,
        skipped_record_count,
        degraded_reasons: degraded_reasons.into_iter().collect(),
    })
}

fn event_records(value: &Value) -> Vec<&Value> {
    if let Some(records) = value.as_array() {
        return records.iter().collect();
    }
    for key in ["Events", "events", "value", "records", "items", "entries"] {
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
    provider_kind: ObjectStorageAuditProviderKind,
    endpoint_kind: ObjectStorageAuditEndpointKind,
    record: &Value,
) -> Result<PortableSaasCloudMetadata, &'static str> {
    let timestamp = event_timestamp(record).map_err(|_| "timestamp_missing_or_invalid")?;
    let service = service_category(provider_kind, record);
    let activity = activity_label(record);
    let api_method = api_method_category(&activity, read_only_value(record));
    let status_bucket = status_bucket(record);
    let mut metadata = PortableSaasCloudMetadata::new(
        PortableProviderCategory::ObjectStorage,
        bucket_timestamp_to_hour(timestamp),
    );
    metadata.service_category = Some(service.clone());
    metadata.provider_risk_category = provider_risk_category(&api_method, &status_bucket);
    metadata.provider_confidence = provider_confidence(provider_kind, endpoint_kind);
    metadata.endpoint_fingerprint = Some(endpoint_fingerprint(
        provider_kind,
        &service,
        &api_method,
        &status_bucket,
    ));
    metadata.api_method_category = api_method;
    metadata.status_bucket = status_bucket;
    metadata.upload_download_ratio_bucket =
        transfer_ratio_bucket(&metadata.api_method_category, read_only_value(record));
    metadata.auth_result_category = auth_result_category(&metadata.status_bucket);
    metadata.destination_category = destination_category(provider_kind);
    metadata.identity_label_redacted = None;
    metadata.source_session_label = None;
    metadata.redaction_status = RedactionStatus::Redacted;
    metadata.quality_score = event_quality_score(record, &metadata);
    Ok(metadata)
}

fn event_timestamp(record: &Value) -> Result<Timestamp, ObjectStorageAuditClientError> {
    if let Some(millis) = number_at_any_path(
        record,
        &[
            &["timestamp_ms"],
            &["timestampMs"],
            &["eventTimestampMs"],
            &["timeEpochMs"],
        ],
    ) {
        let datetime = Utc
            .timestamp_millis_opt(millis as i64)
            .single()
            .ok_or_else(|| ObjectStorageAuditClientError::InvalidTimestamp(millis.to_string()))?;
        return Ok(Timestamp::from_datetime(datetime));
    }
    if let Some(seconds) = number_at_any_path(
        record,
        &[
            &["timestamp_seconds"],
            &["timestampSeconds"],
            &["eventTimestampSeconds"],
            &["timeEpoch"],
        ],
    ) {
        let datetime = Utc
            .timestamp_opt(seconds as i64, 0)
            .single()
            .ok_or_else(|| ObjectStorageAuditClientError::InvalidTimestamp(seconds.to_string()))?;
        return Ok(Timestamp::from_datetime(datetime));
    }
    let raw = string_at_any_path(
        record,
        &[
            &["EventTime"],
            &["eventTime"],
            &["eventTimestamp"],
            &["timestamp"],
            &["time"],
            &["ts"],
            &["event", "time"],
            &["protoPayload", "timestamp"],
            &["datetime"],
            &["date"],
        ],
    )
    .ok_or(ObjectStorageAuditClientError::MalformedResponse(
        "timestamp",
    ))?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|value| Timestamp::from_datetime(value.with_timezone(&Utc)))
        .map_err(|_| ObjectStorageAuditClientError::InvalidTimestamp(raw))
}

fn bucket_timestamp_to_hour(timestamp: Timestamp) -> Timestamp {
    let datetime = timestamp.as_datetime();
    let bucket = datetime
        .date_naive()
        .and_hms_opt(datetime.hour(), 0, 0)
        .expect("valid UTC hour bucket");
    Timestamp::from_datetime(DateTime::from_naive_utc_and_offset(bucket, Utc))
}

fn service_category(provider_kind: ObjectStorageAuditProviderKind, record: &Value) -> String {
    let hint = string_at_any_path(
        record,
        &[
            &["EventSource"],
            &["eventSource"],
            &["source"],
            &["service"],
            &["serviceName"],
            &["protoPayload", "serviceName"],
            &["resourceProviderName", "value"],
            &["provider"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();

    if hint.contains("s3") {
        "aws_s3".to_string()
    } else if hint.contains("blob") || hint.contains("storage") && hint.contains("azure") {
        "azure_blob".to_string()
    } else if hint.contains("storage.googleapis") || hint.contains("gcs") {
        "google_cloud_storage".to_string()
    } else if hint.contains("r2") || hint.contains("cloudflare") {
        "cloudflare_r2".to_string()
    } else if hint.contains("minio") {
        "minio".to_string()
    } else {
        match provider_kind {
            ObjectStorageAuditProviderKind::AwsCloudTrail => "aws_s3",
            ObjectStorageAuditProviderKind::AzureActivity => "azure_blob",
            ObjectStorageAuditProviderKind::GoogleCloudAudit => "google_cloud_storage",
            ObjectStorageAuditProviderKind::CloudflareR2 => "cloudflare_r2",
            ObjectStorageAuditProviderKind::Minio => "minio",
            ObjectStorageAuditProviderKind::Generic => "object_storage",
        }
        .to_string()
    }
}

fn activity_label(record: &Value) -> String {
    string_at_any_path(
        record,
        &[
            &["EventName"],
            &["eventName"],
            &["operationName", "value"],
            &["operationName"],
            &["operation"],
            &["activity"],
            &["activity_category"],
            &["methodName"],
            &["protoPayload", "methodName"],
            &["action"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase()
}

fn read_only_value(record: &Value) -> Option<bool> {
    bool_at_any_path(record, &[&["ReadOnly"], &["readOnly"], &["read_only"]])
}

fn api_method_category(activity: &str, read_only: Option<bool>) -> PortableApiMethodCategory {
    if read_only == Some(true) {
        return PortableApiMethodCategory::Read;
    }
    if activity.contains("delete") || activity.contains("remove") {
        PortableApiMethodCategory::Delete
    } else if activity.contains("policy")
        || activity.contains("acl")
        || activity.contains("permission")
        || activity.contains("publicaccess")
        || activity.contains("public_access")
        || activity.contains("replication")
        || activity.contains("lifecycle")
        || activity.contains("admin")
    {
        PortableApiMethodCategory::Admin
    } else if activity.contains("put")
        || activity.contains("write")
        || activity.contains("upload")
        || activity.contains("create")
        || activity.contains("copy")
        || activity.contains("restore")
    {
        PortableApiMethodCategory::Write
    } else if activity.contains("auth") || activity.contains("login") {
        PortableApiMethodCategory::Auth
    } else if activity.contains("get") || activity.contains("read") || activity.contains("list") {
        PortableApiMethodCategory::Read
    } else if activity.trim().is_empty() {
        PortableApiMethodCategory::Unknown
    } else {
        PortableApiMethodCategory::Other
    }
}

fn status_bucket(record: &Value) -> PortableStatusBucket {
    if let Some(code) = number_at_any_path(
        record,
        &[
            &["status_code"],
            &["statusCode"],
            &["httpStatus"],
            &["status", "code"],
            &["protoPayload", "status", "code"],
        ],
    ) {
        return match code {
            200..=299 => PortableStatusBucket::Success,
            300..=399 => PortableStatusBucket::Redirect,
            401 | 403 => PortableStatusBucket::AuthError,
            404 => PortableStatusBucket::NotFound,
            429 => PortableStatusBucket::RateLimited,
            400..=499 => PortableStatusBucket::ClientError,
            500..=599 => PortableStatusBucket::ServerError,
            _ => PortableStatusBucket::Unknown,
        };
    }
    let value = string_at_any_path(
        record,
        &[
            &["ErrorCode"],
            &["errorCode"],
            &["error_code"],
            &["status", "value"],
            &["status"],
            &["result"],
            &["outcome"],
            &["severity"],
        ],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();
    if value.is_empty() || value == "success" || value == "succeeded" || value == "ok" {
        PortableStatusBucket::Success
    } else if value.contains("throttl") || value.contains("rate") {
        PortableStatusBucket::RateLimited
    } else if value.contains("accessdenied")
        || value.contains("unauthor")
        || value.contains("forbidden")
        || value.contains("auth")
        || value.contains("permission")
    {
        PortableStatusBucket::AuthError
    } else if value.contains("notfound") || value.contains("not_found") {
        PortableStatusBucket::NotFound
    } else if value.contains("server") || value.contains("internal") {
        PortableStatusBucket::ServerError
    } else {
        PortableStatusBucket::ClientError
    }
}

fn transfer_ratio_bucket(
    api_method: &PortableApiMethodCategory,
    read_only: Option<bool>,
) -> PortableUploadDownloadRatioBucket {
    match (api_method, read_only) {
        (_, Some(true)) | (PortableApiMethodCategory::Read, _) => {
            PortableUploadDownloadRatioBucket::DownloadHeavy
        }
        (PortableApiMethodCategory::Write, Some(false)) => {
            PortableUploadDownloadRatioBucket::UploadBurst
        }
        (PortableApiMethodCategory::Write, _) => PortableUploadDownloadRatioBucket::UploadHeavy,
        (PortableApiMethodCategory::Admin | PortableApiMethodCategory::Delete, _) => {
            PortableUploadDownloadRatioBucket::Balanced
        }
        _ => PortableUploadDownloadRatioBucket::Unknown,
    }
}

fn provider_risk_category(
    api_method: &PortableApiMethodCategory,
    status_bucket: &PortableStatusBucket,
) -> PortableProviderRiskCategory {
    match (api_method, status_bucket) {
        (PortableApiMethodCategory::Admin | PortableApiMethodCategory::Delete, _) => {
            PortableProviderRiskCategory::High
        }
        (_, PortableStatusBucket::AuthError | PortableStatusBucket::RateLimited) => {
            PortableProviderRiskCategory::Medium
        }
        (PortableApiMethodCategory::Write, _) => PortableProviderRiskCategory::Medium,
        (PortableApiMethodCategory::Read, PortableStatusBucket::Success) => {
            PortableProviderRiskCategory::Low
        }
        _ => PortableProviderRiskCategory::Unknown,
    }
}

fn provider_confidence(
    provider_kind: ObjectStorageAuditProviderKind,
    endpoint_kind: ObjectStorageAuditEndpointKind,
) -> PortableProviderConfidenceBucket {
    match (provider_kind, endpoint_kind) {
        (
            ObjectStorageAuditProviderKind::AwsCloudTrail,
            ObjectStorageAuditEndpointKind::CloudTrailLookupEvents,
        )
        | (
            ObjectStorageAuditProviderKind::AzureActivity,
            ObjectStorageAuditEndpointKind::AzureActivityLogs,
        )
        | (
            ObjectStorageAuditProviderKind::GoogleCloudAudit,
            ObjectStorageAuditEndpointKind::GoogleCloudAuditLogs,
        )
        | (
            ObjectStorageAuditProviderKind::CloudflareR2,
            ObjectStorageAuditEndpointKind::CloudflareR2Audit,
        )
        | (ObjectStorageAuditProviderKind::Minio, ObjectStorageAuditEndpointKind::MinioAudit) => {
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

fn destination_category(provider_kind: ObjectStorageAuditProviderKind) -> Option<String> {
    Some(
        match provider_kind {
            ObjectStorageAuditProviderKind::AwsCloudTrail => "aws_object_storage",
            ObjectStorageAuditProviderKind::AzureActivity => "azure_object_storage",
            ObjectStorageAuditProviderKind::GoogleCloudAudit => "google_object_storage",
            ObjectStorageAuditProviderKind::CloudflareR2 => "cloudflare_object_storage",
            ObjectStorageAuditProviderKind::Minio => "self_hosted_object_storage",
            ObjectStorageAuditProviderKind::Generic => "object_storage",
        }
        .to_string(),
    )
}

fn event_quality_score(record: &Value, metadata: &PortableSaasCloudMetadata) -> QualityScore {
    let mut score: f32 = 0.48;
    if metadata.service_category.is_some() {
        score += 0.08;
    }
    if metadata.api_method_category != PortableApiMethodCategory::Unknown {
        score += 0.08;
    }
    if metadata.status_bucket != PortableStatusBucket::Unknown {
        score += 0.06;
    }
    if read_only_value(record).is_some() {
        score += 0.04;
    }
    QualityScore::new(score.min(0.78)).unwrap_or_default()
}

fn endpoint_fingerprint(
    provider_kind: ObjectStorageAuditProviderKind,
    service: &str,
    api_method: &PortableApiMethodCategory,
    status_bucket: &PortableStatusBucket,
) -> String {
    safe_digest_label(
        "endpoint",
        &format!("{provider_kind:?}:{service}:{api_method:?}:{status_bucket:?}"),
    )
}

fn cursor_from_session(session: &ObjectStorageAuditClientSession) -> ObjectStorageAuditPageCursor {
    match session.next_page_token.as_deref() {
        Some(token) => ObjectStorageAuditPageCursor::from_safe_checkpoint(
            "continuation_present",
            Some(safe_digest_label("cursor", token)),
            Timestamp::now(),
        ),
        None => ObjectStorageAuditPageCursor {
            safe_cursor_bucket: "end_reached".to_string(),
            next_page_token_hash: None,
            checkpoint_state: ObjectStorageAuditCheckpointState::EndReached,
            updated_at: Timestamp::now(),
        },
    }
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

fn bool_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<bool> {
    paths
        .iter()
        .find_map(|path| value_at_path(value, path))
        .and_then(bool_from_value)
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

fn bool_from_value(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{ObjectStorageAuditCredentialRef, PortableUploadDownloadRatioBucket};

    #[derive(Default)]
    struct RecordingTransport {
        calls: Vec<ObjectStorageAuditHttpRequest>,
        response: Option<ObjectStorageAuditHttpResponse>,
    }

    impl ObjectStorageAuditTransport for RecordingTransport {
        fn send(
            &mut self,
            request: &ObjectStorageAuditHttpRequest,
            _credential: Option<&ObjectStorageAuditCredentialMaterial>,
        ) -> Result<ObjectStorageAuditHttpResponse, ObjectStorageAuditClientError> {
            self.calls.push(request.clone());
            self.response
                .clone()
                .ok_or_else(|| ObjectStorageAuditClientError::transport("missing test response"))
        }
    }

    fn cloudtrail_request() -> ObjectStorageAuditPollRequest {
        ObjectStorageAuditPollRequest::new(
            ObjectStorageAuditClientConfig::new(
                ObjectStorageAuditProviderKind::AwsCloudTrail,
                ObjectStorageAuditEndpointKind::CloudTrailLookupEvents,
            ),
            Some(ObjectStorageAuditCredentialRef::new(
                "credential_session#object-storage",
                ObjectStorageAuditAuthMode::AwsSigV4Session,
                None,
            )),
            ObjectStorageAuditPageCursor::empty(Timestamp::now()),
        )
    }

    fn aws_session() -> ObjectStorageAuditClientSession {
        ObjectStorageAuditClientSession::new(Some(
            ObjectStorageAuditCredentialMaterial::AwsSigV4Session {
                access_key_id: "AKIA_TEST_ONLY".to_string(),
                secret_access_key: "secret_access_key_SHOULD_NOT_LEAK".to_string(),
                session_token: Some("session_token_SHOULD_NOT_LEAK".to_string()),
            },
        ))
    }

    #[test]
    fn object_storage_audit_cloudtrail_page_normalizes_without_identifier_exposure() {
        let body = r#"{
          "Events": [{
            "EventTime": "2026-06-16T12:34:56Z",
            "EventSource": "s3.amazonaws.com",
            "EventName": "PutObject",
            "ReadOnly": false,
            "Username": "alice@example.test",
            "Resources": [{"ResourceName": "private-bucket/customer-secret.txt"}],
            "CloudTrailEvent": "{\"sourceIPAddress\":\"203.0.113.10\",\"requestParameters\":{\"bucketName\":\"private-bucket\"},\"payload\":\"secret\"}"
          }]
        }"#;
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(ObjectStorageAuditHttpResponse {
                status_code: 200,
                body: body.to_string(),
                next_page_token: Some("RAW_NEXT_PAGE_TOKEN_SHOULD_NOT_LEAK".to_string()),
                retry_after_seconds: None,
            }),
        };
        let mut client = ObjectStorageAuditProviderClient::new(transport);
        let mut session = aws_session();

        let outcome = client
            .poll_once(cloudtrail_request(), &mut session)
            .expect("poll succeeds");

        assert_eq!(
            outcome.client_state,
            ObjectStorageAuditClientState::PageFetched
        );
        assert_eq!(outcome.accepted_record_count, 1);
        assert_eq!(outcome.metadata.len(), 1);
        let metadata = &outcome.metadata[0];
        assert_eq!(
            metadata.provider_category,
            PortableProviderCategory::ObjectStorage
        );
        assert_eq!(metadata.service_category.as_deref(), Some("aws_s3"));
        assert_eq!(
            metadata.api_method_category,
            PortableApiMethodCategory::Write
        );
        assert_eq!(
            metadata.upload_download_ratio_bucket,
            PortableUploadDownloadRatioBucket::UploadBurst
        );
        assert_eq!(metadata.redaction_status, RedactionStatus::Redacted);
        assert!(metadata.identity_label_redacted.is_none());
        assert!(metadata.source_session_label.is_none());
        assert_eq!(
            outcome.cursor.checkpoint_state,
            ObjectStorageAuditCheckpointState::CursorHashPresent
        );
        assert_eq!(
            session.next_page_token_for_test(),
            Some("RAW_NEXT_PAGE_TOKEN_SHOULD_NOT_LEAK")
        );

        let serialized = serde_json::to_string(&outcome).expect("serialize outcome");
        let debug_session = format!("{session:?}");
        for value in [serialized, debug_session] {
            assert!(!value.contains("alice@example.test"));
            assert!(!value.contains("private-bucket"));
            assert!(!value.contains("customer-secret"));
            assert!(!value.contains("RAW_NEXT_PAGE_TOKEN"));
            assert!(!value.contains("AKIA_TEST_ONLY"));
            assert!(!value.contains("secret_access_key"));
            assert!(!value.contains("session_token"));
            assert!(!value.contains("payload"));
        }
    }

    #[test]
    fn object_storage_audit_missing_credentials_does_not_call_transport() {
        let transport = RecordingTransport::default();
        let mut client = ObjectStorageAuditProviderClient::new(transport);
        let mut session = ObjectStorageAuditClientSession::without_credentials();

        let outcome = client
            .poll_once(cloudtrail_request(), &mut session)
            .expect("missing credentials are classified");
        let transport = client.into_inner();

        assert_eq!(
            outcome.client_state,
            ObjectStorageAuditClientState::MissingCredentials
        );
        assert!(transport.calls.is_empty());
        assert!(outcome
            .degraded_reasons
            .contains(&"credential_material_missing_or_mismatched".to_string()));
    }

    #[test]
    fn object_storage_audit_auth_failure_clears_in_memory_credentials() {
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(ObjectStorageAuditHttpResponse {
                status_code: 403,
                body: "{}".to_string(),
                next_page_token: Some("ignored_after_auth_failure".to_string()),
                retry_after_seconds: None,
            }),
        };
        let mut client = ObjectStorageAuditProviderClient::new(transport);
        let mut session = aws_session();

        let outcome = client
            .poll_once(cloudtrail_request(), &mut session)
            .expect("auth failure classified");

        assert_eq!(
            outcome.client_state,
            ObjectStorageAuditClientState::MissingCredentials
        );
        assert!(!session.has_credential());
        assert!(session.next_page_token_for_test().is_none());
        assert!(outcome
            .degraded_reasons
            .contains(&"auth_failed_credentials_cleared".to_string()));
    }

    #[test]
    fn object_storage_audit_rate_limit_preserves_checkpoint_without_call() {
        let mut request = cloudtrail_request();
        request.config.max_pages_per_tick = 1;
        request.config.rate_limit_per_minute = 1;
        let transport = RecordingTransport {
            calls: Vec::new(),
            response: Some(ObjectStorageAuditHttpResponse {
                status_code: 200,
                body: r#"{"Events":[]}"#.to_string(),
                next_page_token: None,
                retry_after_seconds: None,
            }),
        };
        let mut client = ObjectStorageAuditProviderClient::new(transport);
        let mut session = aws_session();

        let first = client
            .poll_once(request.clone(), &mut session)
            .expect("first request succeeds");
        let second = client
            .poll_once(request, &mut session)
            .expect("second request is rate limited");
        let transport = client.into_inner();

        assert_eq!(
            first.client_state,
            ObjectStorageAuditClientState::PageFetched
        );
        assert_eq!(
            second.client_state,
            ObjectStorageAuditClientState::RateLimited
        );
        assert_eq!(transport.calls.len(), 1);
        assert_eq!(second.retry_after_bucket.as_deref(), Some("next_tick"));
    }
}
