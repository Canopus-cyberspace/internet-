import type { Id, JsonValue, PrivacyClass, Timestamp } from "./common";

export type PortableCaptureInputSourceTypeDto =
  | "imported_har"
  | "imported_jsonl_network_metadata"
  | "imported_web_access_log"
  | "imported_auth_security_log"
  | "imported_saas_cloud_metadata"
  | "imported_deception_event_log";

export type RedactionStatusDto =
  | "not_required"
  | "redacted"
  | "tokenized"
  | "hashed"
  | "partially_redacted"
  | "suppressed"
  | "redaction_required";

export type LocalMetadataProxyStateDto = "stopped" | "running" | "degraded";

export interface LocalMetadataProxyStartRequestDto {
  listen_port?: number | null;
}

export interface LocalMetadataProxyStatusDto {
  state: LocalMetadataProxyStateDto;
  listen_host: string;
  listen_port?: number | null;
  requests_captured: number;
  requests_rejected: number;
  dropped_batches: number;
  pending_batches: number;
  pending_event_count: number;
  drained_event_count: number;
  last_capture_at?: Timestamp | null;
  last_error_code?: string | null;
  localhost_only: boolean;
  metadata_only: boolean;
  message_redacted: string;
}

export type MetadataWatchSourceKindDto =
  | "watched_har_folder"
  | "watched_jsonl_folder"
  | "tailed_web_log"
  | "tailed_auth_security_log"
  | "tailed_saas_cloud_jsonl"
  | "tailed_deception_honeypot_jsonl"
  | "localhost_proxy_continuous_drain"
  | "manual_import";

export type MetadataWatchSourceStateDto =
  | "preview"
  | "enabled"
  | "active"
  | "paused"
  | "disabled"
  | "revoked"
  | "stopped";

export type MetadataSamplingModeDto =
  | "manual_preview_confirm"
  | "interval_tick"
  | "continuous_drain";

export type MetadataSamplingLoopStateDto =
  | "disabled"
  | "running"
  | "paused"
  | "shutting_down";

export type MetadataSamplingLoopActionDto =
  | "enable"
  | "disable"
  | "pause_all"
  | "resume_all"
  | "shutdown";

export type MetadataParserFamilyDto =
  | "har"
  | "jsonl_network"
  | "web_access_log"
  | "auth_security_log"
  | "saas_cloud_jsonl"
  | "deception_jsonl"
  | "local_proxy_metadata";

export type MetadataSourceHealthStateDto =
  | "disabled"
  | "enabled"
  | "active"
  | "idle"
  | "paused"
  | "degraded"
  | "backpressure"
  | "parser_error"
  | "source_unavailable"
  | "cursor_reset_required"
  | "rotation_detected"
  | "oversized_input_skipped"
  | "permission_required"
  | "revoked"
  | "stopped";

export type MetadataRetentionModeDto = "no_retention" | "session_only_redacted";

export type MetadataWatchLifecycleActionDto =
  | "enable"
  | "pause"
  | "resume"
  | "disable"
  | "revoke"
  | "clear_inactive";

export interface MetadataWatchCountersDto {
  sampled_record_count: number;
  sampled_byte_count: number;
  skipped_record_count: number;
  malformed_record_count: number;
  duplicate_record_count: number;
  backpressure_drop_count: number;
  batch_count: number;
}

export interface MetadataWatchCheckpointDto {
  checkpoint_id: Id;
  source_id: Id;
  source_kind: MetadataWatchSourceKindDto;
  safe_cursor_bucket: string;
  safe_generation_hash: string;
  sampled_time_bucket?: Timestamp | null;
  handoff_time_bucket?: Timestamp | null;
  parser_schema_version: string;
  redaction_schema_version: string;
  health_state: MetadataSourceHealthStateDto;
  provenance_id?: Id | null;
}

export interface MetadataWatchSourcePreviewRequestDto {
  source_kind: MetadataWatchSourceKindDto;
  parser_family: MetadataParserFamilyDto;
  display_label_redacted: string;
  sampling_mode: MetadataSamplingModeDto;
  interval_seconds: number;
  max_records_per_tick: number;
  max_bytes_per_tick: number;
  reason_redacted: string;
}

export interface MetadataWatchSourcePreviewDto {
  preview_id: Id;
  source_kind: MetadataWatchSourceKindDto;
  parser_family: MetadataParserFamilyDto;
  display_label_redacted: string;
  sampling_mode: MetadataSamplingModeDto;
  interval_seconds: number;
  max_records_per_tick: number;
  max_bytes_per_tick: number;
  retention_mode: MetadataRetentionModeDto;
  redaction_policy: string;
  privacy_boundary: string;
  portable_default_available: boolean;
  generated_at: Timestamp;
}

export interface MetadataWatchSourceConfirmationDto {
  preview_id: Id;
  user_confirmed: boolean;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface MetadataWatchLifecycleRequestDto {
  source_id: Id;
  action: MetadataWatchLifecycleActionDto;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface MetadataSamplingTickRequestDto {
  source_id?: Id | null;
  max_sources: number;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface MetadataSamplingLoopControlRequestDto {
  action: MetadataSamplingLoopActionDto;
  max_sources_per_cycle: number;
  max_concurrent_sources: number;
  max_files_per_tick: number;
  per_source_timeout_millis: number;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface MetadataSamplingLoopRunRequestDto {
  max_sources: number;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface MetadataWatchSourceStatusDto {
  source_id: Id;
  source_kind: MetadataWatchSourceKindDto;
  state: MetadataWatchSourceStateDto;
  health_state: MetadataSourceHealthStateDto;
  sampling_mode: MetadataSamplingModeDto;
  interval_seconds: number;
  max_records_per_tick: number;
  max_bytes_per_tick: number;
  parser_family: MetadataParserFamilyDto;
  redaction_policy: string;
  retention_mode: MetadataRetentionModeDto;
  checkpoint: MetadataWatchCheckpointDto;
  counters: MetadataWatchCountersDto;
  last_sampled_at?: Timestamp | null;
  last_ingested_at?: Timestamp | null;
  degraded_reason?: string | null;
  error_category?: string | null;
  provenance_id?: Id | null;
  privacy_boundary: string;
  portable_default_available: boolean;
  sampler_ids: string[];
  fact_count: number;
  hypothesis_count: number;
  finding_count: number;
  evidence_refs: Id[];
}

export interface MetadataSamplingBatchSummaryDto {
  batch_id: Id;
  source_id: Id;
  source_kind: MetadataWatchSourceKindDto;
  parser_family: MetadataParserFamilyDto;
  started_at: Timestamp;
  completed_at: Timestamp;
  health_state: MetadataSourceHealthStateDto;
  sampled_record_count: number;
  sampled_byte_count: number;
  skipped_record_count: number;
  malformed_record_count: number;
  duplicate_record_count: number;
  backpressure_drop_count: number;
  emitted_topics: string[];
  fact_refs: Id[];
  evidence_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  report_refresh_marker: boolean;
  attack_refresh_marker: boolean;
  story_available_marker: boolean;
  triage_advisory_only: boolean;
  automatic_llm_calls: boolean;
  response_execution: boolean;
}

export interface MetadataWatchControllerStatusDto {
  generated_at: Timestamp;
  scheduler_mode: string;
  running: boolean;
  loop_state: MetadataSamplingLoopStateDto;
  loop_enabled: boolean;
  loop_paused: boolean;
  scheduled_source_count: number;
  max_sources_per_cycle: number;
  max_concurrent_sources: number;
  max_files_per_tick: number;
  per_source_timeout_millis: number;
  enabled_source_count: number;
  active_source_count: number;
  paused_source_count: number;
  degraded_source_count: number;
  revoked_source_count: number;
  backpressure_source_count: number;
  total_sampled_record_count: number;
  total_duplicate_record_count: number;
  total_malformed_record_count: number;
  total_backpressure_drop_count: number;
  last_tick_at?: Timestamp | null;
  last_scheduled_at?: Timestamp | null;
  graceful_shutdown_requested: boolean;
  latest_batch_id?: Id | null;
  latest_checkpoint_id?: Id | null;
  latest_provenance_id?: Id | null;
  fusion_refresh_count: number;
  report_refresh_marker_count: number;
  attack_refresh_marker_count: number;
  triage_advisory_only: boolean;
  automatic_llm_calls: boolean;
  response_execution: boolean;
  privacy_class: PrivacyClass;
}

export interface MetadataSamplingTickResultDto {
  controller_status: MetadataWatchControllerStatusDto;
  batches: MetadataSamplingBatchSummaryDto[];
  source_statuses: MetadataWatchSourceStatusDto[];
}

export interface PortableCaptureImportFileRequestDto {
  source_path: string;
  source_type?: PortableCaptureInputSourceTypeDto | null;
}

export interface PortableCaptureImportConfirmationDto {
  preview_id: Id;
  user_confirmed: boolean;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface PortableCaptureRecordCountsDto {
  flow_records: number;
  session_records: number;
  dns_records: number;
  tls_records: number;
  http_metadata_records: number;
  auth_metadata_records: number;
  saas_cloud_metadata_records: number;
  deception_event_records: number;
}

export type PortableAuthRiskBucketDto =
  | "low"
  | "medium"
  | "high"
  | "unknown";

export type PortableAuthResultCategoryDto =
  | "success"
  | "failure"
  | "blocked"
  | "challenge"
  | "timeout"
  | "unknown";

export interface PortableAuthCategoryCountDto {
  category: string;
  count: number;
}

export interface PortableAuthServiceOutcomeCountDto {
  service_category: string;
  auth_result: PortableAuthResultCategoryDto;
  count: number;
}

export interface PortableAuthSummaryDto {
  provenance_id: Id;
  auth_record_count: number;
  identity_session_risk_bucket: PortableAuthRiskBucketDto;
  source_session_count: number;
  provider_category_counts: PortableAuthCategoryCountDto[];
  service_outcome_counts: PortableAuthServiceOutcomeCountDto[];
  first_seen_category_flags: string[];
  privileged_role_record_count: number;
  degraded_visibility_flags: string[];
  finding_refs: Id[];
  evidence_refs: Id[];
  graph_hint_refs: Id[];
}

export interface PortableSaasCloudCategoryCountDto {
  category: string;
  count: number;
}

export interface PortableSaasCloudSummaryDto {
  provenance_id: Id;
  metadata_record_count: number;
  provider_category_counts: PortableSaasCloudCategoryCountDto[];
  provider_risk_counts: PortableSaasCloudCategoryCountDto[];
  unknown_provider_count: number;
  degraded_visibility_flags: string[];
  finding_refs: Id[];
  evidence_refs: Id[];
  graph_hint_refs: Id[];
}

export interface PortableDeceptionCategoryCountDto {
  category: string;
  count: number;
}

export interface PortableDeceptionSummaryDto {
  provenance_id: Id;
  event_record_count: number;
  decoy_sensor_count: number;
  event_category_counts: PortableDeceptionCategoryCountDto[];
  protocol_category_counts: PortableDeceptionCategoryCountDto[];
  degraded_visibility_flags: string[];
  finding_refs: Id[];
  evidence_refs: Id[];
  graph_hint_refs: Id[];
}

export interface PortableCaptureProvenanceDto {
  provenance_id: Id;
  source_type: PortableCaptureInputSourceTypeDto;
  record_counts: PortableCaptureRecordCountsDto;
  redaction_status: RedactionStatusDto;
}

export interface PortableCaptureImportPreviewDto {
  preview_id: Id;
  provenance: PortableCaptureProvenanceDto;
  declared_topics: string[];
  generated_at: Timestamp;
}

export interface PortableCaptureImportResultDto {
  preview_id: Id;
  provenance: PortableCaptureProvenanceDto;
  emitted_topics: string[];
  flow_count: number;
  session_count: number;
  dns_count: number;
  tls_count: number;
  http_metadata_count: number;
  auth_metadata_count: number;
  auth_summary?: PortableAuthSummaryDto | null;
  saas_cloud_metadata_count: number;
  saas_cloud_summary?: PortableSaasCloudSummaryDto | null;
  deception_event_count: number;
  deception_summary?: PortableDeceptionSummaryDto | null;
  security_fact_count: number;
  attack_hypothesis_count: number;
  finding_count: number;
  alert_candidate_count: number;
  alert_count: number;
  incident_candidate_count: number;
  incident_count: number;
  incident_ids: Id[];
  report_traceability_ready: boolean;
}

export interface FlowRecordDto {
  flow_id?: Id;
  process_ref?: Id | null;
  destination_redacted?: string;
  protocol?: string;
  risk_score?: JsonValue;
  [key: string]: JsonValue | undefined;
}

export interface DnsObservationDto {
  dns_id?: Id;
  query_name_redacted?: string;
  answer_summary_redacted?: string;
  [key: string]: JsonValue | undefined;
}

export interface TlsObservationDto {
  tls_id?: Id;
  server_name_redacted?: string;
  certificate_summary_redacted?: string;
  [key: string]: JsonValue | undefined;
}
