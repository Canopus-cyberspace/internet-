import type { Id, JsonValue, PrivacyClass, Timestamp } from "./common";

export type PortableCaptureInputSourceTypeDto =
  | "imported_har"
  | "imported_jsonl_network_metadata"
  | "imported_dns_resolver_log"
  | "imported_api_gateway_log"
  | "imported_waf_log"
  | "imported_cdn_edge_log"
  | "imported_sdn_control_plane_log"
  | "imported_object_storage_audit_log"
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

export type NetworkProviderKindDto =
  | "portable_metadata"
  | "ip_helper"
  | "etw_network"
  | "windows_dns"
  | "windows_auth_remote"
  | "windows_rdp_operational"
  | "windows_smb_operational"
  | "windows_ssh_operational"
  | "npcap_packet"
  | "capture_broker"
  | "none";

export type NetworkProviderControllerModeDto =
  | "portable_only"
  | "ip_helper_only"
  | "etw_plus_ip_helper"
  | "packet_enhanced"
  | "degraded"
  | "unavailable";

export type NetworkProviderControllerStateDto =
  | "inactive"
  | "probing"
  | "ready"
  | "activating"
  | "active"
  | "paused"
  | "degraded"
  | "stopping"
  | "stopped"
  | "revoked"
  | "failed";

export type NetworkProviderImplementationStateDto =
  | "not_implemented"
  | "implemented_inactive"
  | "available"
  | "unavailable"
  | "unsupported_platform"
  | "permission_required"
  | "authorization_required"
  | "degraded"
  | "revoked"
  | "failed";

export type NetworkProviderLifecycleStateDto =
  | "inactive"
  | "probing"
  | "ready"
  | "activating"
  | "active"
  | "paused"
  | "degraded"
  | "stopping"
  | "stopped"
  | "revoked"
  | "failed";

export type EtwAuthorizationStateDto = "required" | "authorized" | "invalidated";

export type EtwLifecycleStateDto =
  | "inactive"
  | "activating"
  | "active"
  | "pausing"
  | "paused"
  | "resuming"
  | "degraded"
  | "stopping"
  | "stopped"
  | "failed";

export type EtwRuntimeSessionStateDto =
  | "not_created"
  | "control_session_active"
  | "control_session_paused"
  | "control_session_stopped"
  | "unavailable";

export type EtwFallbackStateDto =
  | "ip_helper_active"
  | "ip_helper_available"
  | "portable_metadata_only"
  | "unavailable";

export type NetworkVisibilityDimensionDto =
  | "portable_metadata_visibility"
  | "connection_table_visibility"
  | "short_lived_network_event_visibility"
  | "process_category_visibility"
  | "process_network_category_visibility"
  | "packet_header_visibility"
  | "packet_payload_visibility"
  | "specific_process_identity_visibility"
  | "specific_destination_identity_visibility";

export type NetworkVisibilityStateDto = "available" | "unavailable" | "degraded";

export interface NetworkProviderZeroCountersDto {
  ip_helper_calls: number;
  etw_calls: number;
  dns_sensing_calls: number;
  dns_observation_publications: number;
  dns_detector_invocations: number;
  dns_detector_consumed: number;
  npcap_probes: number;
  capture_broker_launches: number;
  native_network_topic_publications: number;
  process_network_facts: number;
  packet_facts: number;
}

export interface NetworkProviderStatusDto {
  provider_id: string;
  provider_kind: NetworkProviderKindDto;
  adapter_boundary: string;
  implementation_state: NetworkProviderImplementationStateDto;
  lifecycle_state: NetworkProviderLifecycleStateDto;
  activation_allowed: boolean;
  activation_unavailable_reason?: string | null;
  degraded_reason?: string | null;
  dependency_refs: string[];
  policy_refs: string[];
  provenance_refs: string[];
  bounded_counters: NetworkProviderZeroCountersDto;
  redaction_status: RedactionStatusDto;
}

export interface NetworkVisibilityDimensionStatusDto {
  dimension: NetworkVisibilityDimensionDto;
  visibility_state: NetworkVisibilityStateDto;
  degraded_reason?: string | null;
}

export interface NetworkVisibilitySummaryDto {
  visibility_ref: string;
  dimensions: NetworkVisibilityDimensionStatusDto[];
  provenance_refs: string[];
  generated_at: Timestamp;
  redaction_status: RedactionStatusDto;
}

export interface NetworkFallbackPlanDto {
  fallback_plan_ref: string;
  selected_mode: NetworkProviderControllerModeDto;
  selection_order: NetworkProviderKindDto[];
  fallback_rules: string[];
  degraded_reason?: string | null;
  policy_refs: string[];
  redaction_status: RedactionStatusDto;
}

export interface NetworkProviderPolicySummaryDto {
  policy_ref: string;
  provider_activation_allowed: boolean;
  activation_unavailable_reason: string;
  ip_helper_execution_available_over_production_ipc: boolean;
  production_ipc_execution_unavailable_reason: string;
  required_gates: string[];
  provider_readiness_creates_evidence: boolean;
  provider_availability_creates_findings: boolean;
  production_provider_mutations_enabled: boolean;
  redaction_status: RedactionStatusDto;
}

export interface NetworkProviderDependencySummaryDto {
  dependency_ref: string;
  dependency_refs: string[];
  degraded_reason?: string | null;
  redaction_status: RedactionStatusDto;
}

export interface NetworkProviderLifecycleSummaryDto {
  lifecycle_ref: string;
  controller_state: NetworkProviderControllerStateDto;
  selected_mode: NetworkProviderControllerModeDto;
  active_provider_count: number;
  inactive_provider_count: number;
  degraded_provider_count: number;
  redaction_status: RedactionStatusDto;
}

export interface NetworkProviderAuditSummaryDto {
  audit_ref: string;
  declared_status_topics: string[];
  audit_refs: string[];
  status_publication_count: number;
  provider_execution_event_count: number;
  redaction_status: RedactionStatusDto;
}

export interface EtwLifecycleStatusDto {
  lifecycle_ref: string;
  ownership_ref: string;
  ownership_epoch: number;
  schema_version: unknown;
  lifecycle_state: EtwLifecycleStateDto;
  session_state: EtwRuntimeSessionStateDto;
  authorization_state: EtwAuthorizationStateDto;
  session_generation: number;
  control_thread_active: boolean;
  control_thread_joined: boolean;
  trace_session_created: boolean;
  provider_enabled: boolean;
  collection_started: boolean;
  consumer_started: boolean;
  consumer_worker_active: boolean;
  consumer_worker_joined: boolean;
  raw_event_count: number;
  normalized_event_count: number;
  dropped_event_count: number;
  rate_limited_event_count: number;
  schema_rejected_event_count: number;
  published_batch_count: number;
  eventbus_publication_count: number;
  security_fact_count: number;
  activation_count: number;
  pause_count: number;
  resume_count: number;
  stop_count: number;
  fallback_state: EtwFallbackStateDto;
  degraded_reason?: string | null;
  authorization_refs: string[];
  audit_refs: string[];
  provenance_refs: string[];
  updated_at: Timestamp;
  redaction_status: RedactionStatusDto;
}

export type IpHelperScheduleStateDto =
  | "not_configured"
  | "configured_disabled"
  | "configured_enabled"
  | "paused"
  | "invalidated"
  | "revoked"
  | "degraded";

export type IpHelperScheduleIntervalBucketDto =
  | "fifteen_seconds"
  | "thirty_seconds"
  | "one_minute"
  | "five_minutes";

export type IpHelperScheduleTimeoutBucketDto =
  | "two_hundred_fifty_millis"
  | "one_second"
  | "five_seconds";

export type IpHelperScheduleRetryBudgetBucketDto = "none" | "one" | "three";

export type IpHelperScheduleRetryDelayBucketDto =
  | "none"
  | "five_seconds"
  | "thirty_seconds";

export type IpHelperScheduleLeaseStateDto =
  | "no_lease"
  | "active"
  | "paused"
  | "invalidated"
  | "revoked"
  | "expired";

export type IpHelperScheduleNextDueCategoryDto =
  | "not_running"
  | "ineligible"
  | "deferred"
  | "due_soon"
  | "due_now";

export type IpHelperSchedulerRegistrationStateDto = "configured";

export type IpHelperScheduleCountBucketDto = "zero" | "one" | "few" | "many";

export type IpHelperScheduledCycleTypeDto = "scheduled";
export type IpHelperScheduledDueStateDto = "not_due" | "due" | "deferred" | "blocked";
export type IpHelperScheduledAuthorizationStateDto =
  | "valid"
  | "invalid"
  | "revoked"
  | "stale_epoch"
  | "policy_mismatch";
export type IpHelperScheduledExecutionResultDto =
  | "not_started"
  | "completed"
  | "skipped"
  | "failed"
  | "timed_out"
  | "busy";
export type IpHelperScheduledRetryStateDto = "none" | "scheduled" | "exhausted" | "cleared";
export type IpHelperScheduledBackpressureStateDto =
  | "none"
  | "low"
  | "moderate"
  | "high"
  | "saturated";
export type IpHelperScheduledFreshnessStateDto =
  | "fresh"
  | "aging"
  | "stale"
  | "missing"
  | "unavailable"
  | "revoked";
export type IpHelperScheduledMissedSampleStateDto =
  | "on_time"
  | "delayed"
  | "missed_once"
  | "repeatedly_missed"
  | "paused"
  | "blocked"
  | "revoked";

export interface IpHelperScheduledCycleRecordDto {
  cycle_ref: string;
  scheduler_item_ref: string;
  schedule_ref: string;
  cycle_type: IpHelperScheduledCycleTypeDto;
  due_state: IpHelperScheduledDueStateDto;
  authorization_state: IpHelperScheduledAuthorizationStateDto;
  execution_result: IpHelperScheduledExecutionResultDto;
  retry_state: IpHelperScheduledRetryStateDto;
  backpressure_state: IpHelperScheduledBackpressureStateDto;
  freshness_result: IpHelperScheduledFreshnessStateDto;
  missed_sample_result: IpHelperScheduledMissedSampleStateDto;
  started_time_bucket?: Timestamp | null;
  completed_time_bucket?: Timestamp | null;
  duration_bucket: string;
  provider_call_count_bucket: IpHelperScheduleCountBucketDto;
  batch_refs: string[];
  fact_refs: string[];
  snapshot_refs: string[];
  audit_refs: string[];
  degraded_reason?: string | null;
  provenance_id: string;
  redaction_status: RedactionStatusDto;
}

export interface IpHelperScheduleConfigDto {
  interval_bucket: IpHelperScheduleIntervalBucketDto;
  provider_timeout_bucket: IpHelperScheduleTimeoutBucketDto;
  execution_timeout_bucket: IpHelperScheduleTimeoutBucketDto;
  retry_budget_bucket: IpHelperScheduleRetryBudgetBucketDto;
  retry_delay_bucket: IpHelperScheduleRetryDelayBucketDto;
  maximum_records: number;
  maximum_bytes: number;
  no_overlap_marker: boolean;
  no_catch_up_marker: boolean;
}

export interface IpHelperScheduleStatusDto {
  schema_version: unknown;
  schedule_ref: string;
  provider_category: NetworkProviderKindDto;
  scheduler_owner_ref: string;
  ownership_epoch: number;
  schedule_state: IpHelperScheduleStateDto;
  enabled_marker: boolean;
  paused_marker: boolean;
  config: IpHelperScheduleConfigDto;
  session_bound_marker: boolean;
  restart_disabled_marker: boolean;
  policy_id: string;
  policy_version: unknown;
  authorization_refs: string[];
  lease_state: IpHelperScheduleLeaseStateDto;
  schedule_lease_ref?: string | null;
  scheduler_registration: IpHelperSchedulerRegistrationStateDto;
  timer_runtime_active: boolean;
  next_due_category: IpHelperScheduleNextDueCategoryDto;
  execution_count_bucket: IpHelperScheduleCountBucketDto;
  skipped_count_bucket: IpHelperScheduleCountBucketDto;
  automatic_provider_calls: number;
  scheduler_triggered_provider_calls: number;
  latest_manual_sample_ref?: string | null;
  latest_scheduled_cycle_ref?: string | null;
  latest_scheduled_execution_result: IpHelperScheduledExecutionResultDto;
  latest_scheduled_cycle?: IpHelperScheduledCycleRecordDto | null;
  manual_sample_count_bucket: IpHelperScheduleCountBucketDto;
  scheduled_sample_count_bucket: IpHelperScheduleCountBucketDto;
  retry_count_bucket: IpHelperScheduleCountBucketDto;
  timeout_count_bucket: IpHelperScheduleCountBucketDto;
  overlap_skip_count_bucket: IpHelperScheduleCountBucketDto;
  backpressure_state: IpHelperScheduledBackpressureStateDto;
  freshness_state: IpHelperScheduledFreshnessStateDto;
  missed_sample_state: IpHelperScheduledMissedSampleStateDto;
  schedule_lease_valid: boolean;
  created_time_bucket: Timestamp;
  updated_time_bucket: Timestamp;
  audit_refs: string[];
  provenance_id: string;
  redaction_status: RedactionStatusDto;
  degraded_reason?: string | null;
}

export interface NetworkProviderControllerStatusDto {
  controller_ref: string;
  ownership_ref: string;
  ownership_epoch: number;
  runtime_owner: string;
  schema_version: unknown;
  controller_state: NetworkProviderControllerStateDto;
  selected_mode: NetworkProviderControllerModeDto;
  providers: NetworkProviderStatusDto[];
  visibility_summary: NetworkVisibilitySummaryDto;
  fallback_plan: NetworkFallbackPlanDto;
  dependency_summary: NetworkProviderDependencySummaryDto;
  policy_summary: NetworkProviderPolicySummaryDto;
  lifecycle_summary: NetworkProviderLifecycleSummaryDto;
  audit_summary: NetworkProviderAuditSummaryDto;
  ip_helper_schedule: IpHelperScheduleStatusDto;
  etw_lifecycle: EtwLifecycleStatusDto;
  provider_zero: NetworkProviderZeroCountersDto;
  generated_at: Timestamp;
  redaction_status: RedactionStatusDto;
}

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
  | "tailed_dns_resolver_log"
  | "tailed_api_gateway_log"
  | "tailed_waf_log"
  | "tailed_cdn_edge_log"
  | "tailed_sdn_control_plane_log"
  | "tailed_object_storage_audit_log"
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
  | "dns_resolver_log"
  | "api_gateway_log"
  | "waf_log"
  | "cdn_edge_log"
  | "sdn_control_plane_log"
  | "object_storage_audit_log"
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
  sdn_control_plane_records: number;
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
  sdn_control_plane_metadata_count: number;
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
