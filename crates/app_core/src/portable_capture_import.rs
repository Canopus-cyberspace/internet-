use crate::read_commands::ReadOnlyCommandState;
use sentinel_capabilities::{
    preview_portable_capture_import as capability_preview_portable_capture_import,
    run_portable_capture_lite_with_service_contexts, PortableCaptureLiteError,
    PortableCaptureLitePreparedBatch, PortableCaptureLiteRunResult,
};
use sentinel_contracts::{
    CommandResult, CoreError, DataSourceId, ErrorCode, ErrorSeverity, IncidentId,
    PortableAuthSummary, PortableCaptureInputSourceType, PortableCaptureProvenance,
    PortableDeceptionSummary, PortableSaasCloudSummary, ServiceCapabilityContext, Timestamp,
    TraceId,
};
use sentinel_infrastructure::ElevatedServiceIpcClient;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableCaptureImportFileRequest {
    pub source_path: String,
    pub source_type: Option<PortableCaptureInputSourceType>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableCaptureImportConfirmation {
    pub preview_id: DataSourceId,
    pub user_confirmed: bool,
    pub reason_redacted: String,
    pub requested_by_redacted: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableCaptureImportPreview {
    pub preview_id: DataSourceId,
    pub provenance: PortableCaptureProvenance,
    pub declared_topics: Vec<String>,
    pub generated_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedPortableCaptureImport {
    pub preview: PortableCaptureImportPreview,
    pub prepared_batch: PortableCaptureLitePreparedBatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableCaptureImportResult {
    pub preview_id: DataSourceId,
    pub provenance: PortableCaptureProvenance,
    pub emitted_topics: Vec<String>,
    pub flow_count: usize,
    pub session_count: usize,
    pub dns_count: usize,
    pub tls_count: usize,
    pub http_metadata_count: usize,
    pub auth_metadata_count: usize,
    pub auth_summary: Option<PortableAuthSummary>,
    pub saas_cloud_metadata_count: usize,
    pub saas_cloud_summary: Option<PortableSaasCloudSummary>,
    pub deception_event_count: usize,
    pub deception_summary: Option<PortableDeceptionSummary>,
    pub security_fact_count: usize,
    pub attack_hypothesis_count: usize,
    pub finding_count: usize,
    pub alert_candidate_count: usize,
    pub alert_count: usize,
    pub incident_candidate_count: usize,
    pub incident_count: usize,
    pub incident_ids: Vec<IncidentId>,
    pub report_traceability_ready: bool,
}

pub fn prepare_portable_capture_import(
    source_type: PortableCaptureInputSourceType,
    content: &str,
    file_size_bytes: usize,
) -> CommandResult<PreparedPortableCaptureImport> {
    let prepared_batch =
        capability_preview_portable_capture_import(source_type, content, file_size_bytes)
            .map_err(portable_capture_error)?;
    Ok(PreparedPortableCaptureImport {
        preview: PortableCaptureImportPreview {
            preview_id: prepared_batch.provenance.provenance_id.clone(),
            provenance: prepared_batch.provenance.clone(),
            declared_topics: prepared_batch.declared_topics.clone(),
            generated_at: Timestamp::now(),
        },
        prepared_batch,
    })
}

pub fn ingest_portable_capture_import(
    state: &mut ReadOnlyCommandState,
    prepared: &PreparedPortableCaptureImport,
) -> CommandResult<PortableCaptureImportResult> {
    let run_result = execute_portable_capture_import(prepared).map_err(portable_capture_error)?;
    apply_portable_capture_run(state, &run_result);
    Ok(PortableCaptureImportResult {
        preview_id: prepared.preview.preview_id.clone(),
        provenance: run_result.provenance.clone(),
        emitted_topics: run_result.emitted_topics.clone(),
        flow_count: run_result.flow_records.len(),
        session_count: run_result.session_records.len(),
        dns_count: run_result.dns_observations.len(),
        tls_count: run_result.tls_observations.len(),
        http_metadata_count: run_result.http_metadata.len(),
        auth_metadata_count: run_result.auth_metadata.len(),
        auth_summary: run_result.auth_summary.clone(),
        saas_cloud_metadata_count: run_result.saas_cloud_metadata.len(),
        saas_cloud_summary: run_result.saas_cloud_summary.clone(),
        deception_event_count: run_result.deception_events.len(),
        deception_summary: run_result.deception_summary.clone(),
        security_fact_count: run_result.security_facts.len(),
        attack_hypothesis_count: run_result.attack_hypotheses.len(),
        finding_count: run_result.findings.len(),
        alert_candidate_count: run_result.alert_candidate_count,
        alert_count: run_result.alerts.len(),
        incident_candidate_count: run_result.incident_candidate_count,
        incident_count: run_result.incidents.len(),
        incident_ids: run_result
            .incidents
            .iter()
            .map(|incident| incident.id().clone())
            .collect(),
        report_traceability_ready: !run_result.findings.is_empty()
            && !run_result.evidence.is_empty(),
    })
}

pub fn apply_portable_capture_run(
    state: &mut ReadOnlyCommandState,
    run_result: &PortableCaptureLiteRunResult,
) {
    state.flows.items.extend(run_result.flow_records.clone());
    state.dns.items.extend(run_result.dns_observations.clone());
    state.tls.items.extend(run_result.tls_observations.clone());
    state
        .http_metadata
        .items
        .extend(run_result.http_metadata.clone());
    state.findings.items.extend(run_result.findings.clone());
    state.alerts.items.extend(run_result.alerts.clone());
    state.incidents.items.extend(run_result.incidents.clone());
    state
        .security_facts
        .items
        .extend(run_result.security_facts.clone());
    state
        .attack_hypotheses
        .items
        .extend(run_result.attack_hypotheses.clone());
    if let Some(summary) = &run_result.fusion_summary {
        state.fusion_summaries.push(summary.clone());
    }
    state
        .portable_capture_sources
        .push(run_result.provenance.clone());
}

fn execute_portable_capture_import(
    prepared: &PreparedPortableCaptureImport,
) -> Result<PortableCaptureLiteRunResult, PortableCaptureLiteError> {
    let runtime_service_contexts = safe_service_capability_contexts_for_import();
    run_portable_capture_lite_with_service_contexts(
        &prepared.prepared_batch,
        &runtime_service_contexts,
    )
}

fn safe_service_capability_contexts_for_import() -> Vec<ServiceCapabilityContext> {
    ElevatedServiceIpcClient::default()
        .safe_capability_contexts()
        .map(|snapshot| snapshot.contexts)
        .unwrap_or_default()
}

fn portable_capture_error(error: impl ToString) -> CoreError {
    CoreError::new(
        ErrorCode::ValidationFailure,
        "portable capture import failed safety validation",
    )
    .with_severity(ErrorSeverity::Error)
    .with_trace_id(TraceId::new_v4())
    .with_redacted_details(json!({ "error_redacted": error.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explicit_session_export::prepare_explicit_export;
    use crate::mutation_commands::{confirm_portable_capture_import, MutationCommandState};
    use sentinel_contracts::session_export::{ExportRequest, SaveAction};
    use sentinel_contracts::SessionId;

    fn har_fixture() -> String {
        serde_json::json!({
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-06-11T02:00:00Z",
                        "time": 150,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/42?access_token=secret",
                            "headersSize": 240,
                            "bodySize": 64000,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 1024,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 1024 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:10Z",
                        "time": 80,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/43?user=alice",
                            "headersSize": 220,
                            "bodySize": 1024,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 120,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 120 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:20Z",
                        "time": 75,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/44?session_token=shh",
                            "headersSize": 220,
                            "bodySize": 1100,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 110,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 110 }
                        }
                    },
                    {
                        "startedDateTime": "2026-06-11T02:00:30Z",
                        "time": 70,
                        "serverIPAddress": "203.0.113.10",
                        "request": {
                            "method": "POST",
                            "url": "https://uploader.example.test/upload/45?path=C:/Users/Alice/Desktop",
                            "headersSize": 220,
                            "bodySize": 1200,
                            "headers": [
                                { "name": "User-Agent", "value": "curl/8.8.0" }
                            ]
                        },
                        "response": {
                            "status": 201,
                            "headersSize": 180,
                            "bodySize": 100,
                            "headers": [],
                            "content": { "mimeType": "application/json", "size": 100 }
                        }
                    }
                ]
            }
        })
        .to_string()
    }

    fn jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-11T10:05:00Z",
                "src_ip": "192.0.2.15",
                "src_port": 51515,
                "dst_ip": "203.0.113.22",
                "dst_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_out": 72000,
                "bytes_in": 2200,
                "packets_out": 5,
                "packets_in": 3,
                "http": {
                    "method": "POST",
                    "url": "https://jsonl.example.test/upload/9?token=abcdef1234567890",
                    "status_code": 200,
                    "request_size_bytes": 72000,
                    "response_size_bytes": 2200,
                    "content_type": "application/json",
                    "user_agent": "python-requests/2.32.0"
                },
                "dns": {
                    "query_name": "api.jsonl.example.test",
                    "query_type": "A",
                    "resolver_ip": "192.0.2.53",
                    "client_ip": "192.0.2.15",
                    "answers": [{ "answer_type": "ip", "value": "203.0.113.22", "ttl_seconds": 60 }]
                },
                "tls": {
                    "sni": "api.jsonl.example.test",
                    "alpn": ["h2"],
                    "tls_version": "TLS1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384"
                }
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-11T10:05:30Z",
                "src_ip": "192.0.2.15",
                "src_port": 51516,
                "dst_ip": "203.0.113.22",
                "dst_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_out": 76000,
                "bytes_in": 1800,
                "packets_out": 5,
                "packets_in": 2,
                "http": {
                    "method": "POST",
                    "url": "https://jsonl.example.test/upload/10?path=C:/Users/Alice/Desktop",
                    "status_code": 200,
                    "request_size_bytes": 76000,
                    "response_size_bytes": 1800,
                    "content_type": "application/json",
                    "user_agent": "python-requests/2.32.0"
                }
            })
            .to_string(),
        ]
        .join("\n")
    }

    fn auth_jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-12T06:00:00Z",
                "provider": "vpn",
                "identity": "alice@example.test",
                "session_id": "alpha-session",
                "auth_result": "failed",
                "mfa_result": "prompted",
                "service": "ssh",
                "attempt_count": 3,
                "failure_reason": "invalid_password"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T06:02:00Z",
                "provider": "vpn",
                "identity": "alice@example.test",
                "session_id": "alpha-session",
                "auth_result": "failed",
                "mfa_result": "failed",
                "service": "ssh",
                "attempt_count": 4,
                "failure_reason": "invalid_password"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T06:04:00Z",
                "provider": "vpn",
                "identity": "alice@example.test",
                "session_id": "alpha-session",
                "auth_result": "failed",
                "mfa_result": "failed",
                "service": "ssh",
                "attempt_count": 5,
                "failure_reason": "invalid_password"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T06:10:00Z",
                "provider": "idp",
                "identity": "priv@example.test",
                "session_id": "beta-session",
                "auth_result": "success",
                "role_class": "admin",
                "service": "admin_portal",
                "attempt_count": 1
            })
            .to_string(),
        ]
        .join("\n")
    }

    fn saas_cloud_jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-12T07:00:00Z",
                "provider_category": "object_storage",
                "service_category": "object_storage",
                "provider_confidence": "high",
                "endpoint_fingerprint": "endpoint#object-storage",
                "api_method_category": "write",
                "status_bucket": "success",
                "upload_download_ratio_bucket": "upload_burst",
                "identity_hash": "identity-cloud-a",
                "session": "session-cloud-a"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T07:01:00Z",
                "provider_category": "object_storage",
                "service_category": "object_storage",
                "provider_confidence": "high",
                "endpoint_fingerprint": "endpoint#object-storage",
                "api_method_category": "write",
                "status_bucket": "success",
                "upload_download_ratio_bucket": "upload_burst",
                "identity_hash": "identity-cloud-a",
                "session": "session-cloud-a"
            })
            .to_string(),
        ]
        .join("\n")
    }

    fn deception_jsonl_fixture() -> String {
        [
            serde_json::json!({
                "timestamp": "2026-06-12T08:00:00Z",
                "decoy_sensor_ref": "edge-sensor-a",
                "event_category": "probe",
                "source_context_category": "external",
                "destination_service_category": "admin_service",
                "interaction_count": 12,
                "protocol_category": "ssh"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T08:01:00Z",
                "decoy_sensor_ref": "edge-sensor-a",
                "event_category": "probe",
                "source_context_category": "external",
                "destination_service_category": "admin_service",
                "interaction_count_bucket": "single",
                "protocol_category": "telnet"
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-06-12T08:02:00Z",
                "decoy_sensor_ref": "edge-sensor-a",
                "event_category": "connection",
                "source_context_category": "external",
                "destination_service_category": "admin_service",
                "interaction_count_bucket": "low",
                "protocol_category": "http"
            })
            .to_string(),
        ]
        .join("\n")
    }

    #[test]
    fn portable_har_import_positive_path_updates_runtime_state() {
        let fixture = har_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("prepare");
        let mut state = MutationCommandState::bootstrap().expect("state");

        let receipt = confirm_portable_capture_import(
            &mut state,
            &prepared,
            PortableCaptureImportConfirmation {
                preview_id: prepared.preview.preview_id.clone(),
                user_confirmed: true,
                reason_redacted: "portable metadata import confirmed".to_string(),
                requested_by_redacted: Some("local_user".to_string()),
            },
        )
        .expect("confirm import");

        assert_eq!(receipt.result.flow_count, 4);
        assert_eq!(state.read_state().flows.items.len(), 4);
        assert_eq!(state.read_state().portable_capture_sources.len(), 1);
    }

    #[test]
    fn portable_preview_only_creates_no_runtime_state() {
        let fixture = har_fixture();
        let _prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let state = ReadOnlyCommandState::bootstrap().expect("state");

        assert!(state.flows.items.is_empty());
        assert!(state.findings.items.is_empty());
        assert!(state.incidents.items.is_empty());
        assert!(state.portable_capture_sources.is_empty());
    }

    #[test]
    fn portable_jsonl_import_positive_path_updates_dns_tls_and_http_state() {
        let fixture = jsonl_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("prepare");
        let mut read_state = ReadOnlyCommandState::bootstrap().expect("read");

        let result =
            ingest_portable_capture_import(&mut read_state, &prepared).expect("ingest import");

        assert_eq!(result.dns_count, 1);
        assert_eq!(result.tls_count, 1);
        assert_eq!(read_state.http_metadata.items.len(), 2);
        assert_eq!(read_state.portable_capture_sources.len(), 1);
    }

    #[test]
    fn portable_auth_import_emits_bounded_auth_summary_without_runtime_leakage() {
        let fixture = auth_jsonl_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedAuthSecurityLog,
            &fixture,
            fixture.len(),
        )
        .expect("prepare auth");
        let mut read_state = ReadOnlyCommandState::bootstrap().expect("read");

        let result =
            ingest_portable_capture_import(&mut read_state, &prepared).expect("ingest auth");

        assert_eq!(result.auth_metadata_count, 4);
        assert_eq!(result.flow_count, 0);
        assert!(result.finding_count >= 1);
        let summary = result.auth_summary.expect("auth summary");
        assert_eq!(summary.auth_record_count, 4);
        assert!(summary.source_session_count >= 1);
        let serialized = serde_json::to_string(&summary).expect("serialize auth summary");
        assert!(!serialized.contains("identity#"));
        assert!(!serialized.contains("session#"));
        assert!(!serialized.contains("alice@example.test"));
        assert!(!serialized.contains("priv@example.test"));
        assert!(!serialized.contains("alpha-session"));
    }

    #[test]
    fn portable_saas_cloud_import_emits_bounded_summary_without_runtime_leakage() {
        let fixture = saas_cloud_jsonl_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedSaasCloudMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("prepare saas cloud");
        let mut read_state = ReadOnlyCommandState::bootstrap().expect("read");

        let result =
            ingest_portable_capture_import(&mut read_state, &prepared).expect("ingest saas cloud");

        assert_eq!(result.saas_cloud_metadata_count, 2);
        assert!(result.finding_count >= 1);
        let summary = result.saas_cloud_summary.expect("saas cloud summary");
        assert_eq!(summary.metadata_record_count, 2);
        assert!(!summary.finding_refs.is_empty());
        assert!(read_state.flows.items.is_empty());
        assert_eq!(read_state.portable_capture_sources.len(), 1);

        let serialized = serde_json::to_string(&summary).expect("serialize saas cloud summary");
        for marker in [
            "identity-cloud-a",
            "session-cloud-a",
            "identity#",
            "session#",
            "https://",
            "tenant",
            "authorization",
            "cookie",
        ] {
            assert!(
                !serialized.contains(marker),
                "SaaS/cloud app-core summary leaked forbidden marker {marker}"
            );
        }
    }

    #[test]
    fn portable_deception_import_emits_bounded_summary_without_runtime_leakage() {
        let fixture = deception_jsonl_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedDeceptionEventLog,
            &fixture,
            fixture.len(),
        )
        .expect("prepare deception");
        let mut read_state = ReadOnlyCommandState::bootstrap().expect("read");

        let result =
            ingest_portable_capture_import(&mut read_state, &prepared).expect("ingest deception");

        assert_eq!(result.deception_event_count, 3);
        assert!(result.finding_count >= 1);
        let summary = result.deception_summary.expect("deception summary");
        assert_eq!(summary.event_record_count, 3);
        assert_eq!(summary.decoy_sensor_count, 1);
        assert!(!summary.finding_refs.is_empty());
        assert!(read_state.flows.items.is_empty());
        assert_eq!(read_state.portable_capture_sources.len(), 1);

        let serialized = serde_json::to_string(&summary).expect("serialize deception summary");
        for marker in [
            "edge-sensor-a",
            "source_ip",
            "192.0.2.",
            "payload",
            "credential",
            "token",
            "https://",
        ] {
            assert!(
                !serialized.contains(marker),
                "deception app-core summary leaked forbidden marker {marker}"
            );
        }
    }

    #[test]
    fn portable_auth_preview_only_creates_no_runtime_state() {
        let fixture = auth_jsonl_fixture();
        let _prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedAuthSecurityLog,
            &fixture,
            fixture.len(),
        )
        .expect("preview auth");
        let state = ReadOnlyCommandState::bootstrap().expect("state");

        assert!(state.flows.items.is_empty());
        assert!(state.findings.items.is_empty());
        assert!(state.portable_capture_sources.is_empty());
    }

    #[test]
    fn portable_import_rejects_malformed_file() {
        let error = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            "{bad jsonl",
            10,
        )
        .expect_err("malformed rejected");

        assert!(error.message.contains("portable capture import"));
    }

    #[test]
    fn portable_import_rejects_oversized_file() {
        let oversized = "x".repeat(sentinel_capabilities::MAX_PORTABLE_CAPTURE_IMPORT_BYTES + 1);
        let error = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &oversized,
            oversized.len(),
        )
        .expect_err("oversized rejected");

        assert!(error.message.contains("portable capture import"));
    }

    #[test]
    fn portable_import_redaction_scrubs_tokens_private_markers_and_local_paths() {
        let fixture = jsonl_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let serialized =
            serde_json::to_string(&prepared.prepared_batch.http_metadata).expect("serialize http");

        for marker in [
            "token=abcdef1234567890",
            "access_token",
            "C:/Users/Alice/Desktop",
            "Alice",
        ] {
            assert!(
                !serialized.contains(marker),
                "portable import preview leaked forbidden marker {marker}"
            );
        }
    }

    #[test]
    fn portable_import_confirmed_ingest_emits_declared_topics_only() {
        let fixture = har_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let mut read_state = ReadOnlyCommandState::bootstrap().expect("read");

        let result =
            ingest_portable_capture_import(&mut read_state, &prepared).expect("ingest import");
        let declared = prepared
            .preview
            .declared_topics
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();

        assert!(result
            .emitted_topics
            .iter()
            .all(|topic| declared.contains(topic)));
    }

    #[test]
    fn portable_import_reaches_risk_and_report_traceability_path() {
        let fixture = har_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let mut state = MutationCommandState::bootstrap().expect("state");
        let import_receipt = confirm_portable_capture_import(
            &mut state,
            &prepared,
            PortableCaptureImportConfirmation {
                preview_id: prepared.preview.preview_id.clone(),
                user_confirmed: true,
                reason_redacted: "portable metadata import confirmed".to_string(),
                requested_by_redacted: Some("local_user".to_string()),
            },
        )
        .expect("confirm import");
        let export_preview = prepare_explicit_export(
            state.read_state(),
            ExportRequest::new(
                SessionId::new_v4(),
                SaveAction::SaveSession,
                "portable-import.sgsession",
                "local_user",
            )
            .expect("export request"),
        )
        .expect("session export preview");

        assert!(import_receipt.result.report_traceability_ready);
        assert!(
            import_receipt.result.alert_count > 0
                || import_receipt.result.alert_candidate_count > 0
        );
        assert!(export_preview
            .content_redacted
            .contains("\"imported_capture_sources\": 1"));
        assert!(export_preview
            .content_redacted
            .contains("\"portable_capture_sources\""));
        assert!(!export_preview
            .content_redacted
            .contains("access_token=secret"));
        assert!(!export_preview
            .content_redacted
            .contains("C:/Users/Alice/Desktop"));
    }

    #[test]
    fn portable_import_helper_reports_traceability_ready_when_findings_exist() {
        let fixture = har_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");
        let mut read_state = ReadOnlyCommandState::bootstrap().expect("read");

        let result =
            ingest_portable_capture_import(&mut read_state, &prepared).expect("ingest import");

        assert!(result.report_traceability_ready);
        assert!(result.security_fact_count > 0);
        assert_eq!(
            read_state.security_facts.items.len(),
            result.security_fact_count
        );
        assert_eq!(
            read_state.attack_hypotheses.items.len(),
            result.attack_hypothesis_count
        );
        assert_eq!(read_state.fusion_summaries.len(), 1);
        assert!(!read_state.fusion_summaries[0].automatic_llm_calls);
        assert!(result.finding_count >= 1);
        assert!(result.alert_count > 0 || result.alert_candidate_count > 0);
    }

    #[test]
    fn portable_import_runtime_uses_safe_service_snapshot_contexts_without_service_dependency() {
        let fixture = har_fixture();
        let prepared = prepare_portable_capture_import(
            PortableCaptureInputSourceType::ImportedHar,
            &fixture,
            fixture.len(),
        )
        .expect("preview");

        let result = execute_portable_capture_import(&prepared).expect("run import");

        assert!(result
            .service_capability_contexts
            .iter()
            .any(|context| context.source_provenance_id.starts_with("service_ipc.")));
        assert!(result.service_capability_contexts.len() >= 6);
        assert!(result
            .service_capability_contexts
            .iter()
            .all(|context| context.validate_boundary().is_ok()));
        assert!(result
            .emitted_topics
            .iter()
            .any(|topic| topic == "service.capability_status"));
    }
}
