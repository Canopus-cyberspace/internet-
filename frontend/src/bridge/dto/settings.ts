import type { JsonValue, MutationReasonDto } from "./common";

export interface RuntimeProfileDto {
  privacy_policy: JsonValue;
  response_policy: JsonValue;
  report_export_policy: JsonValue;
  [key: string]: JsonValue;
}

export type LlmAlertStoryProviderDto =
  | "open_ai_compatible"
  | "deep_seek"
  | "anthropic_compatible";

export type LlmApiKeyStorageModeDto = "session_only" | "os_keystore";

export type LlmAlertStoryCapabilityStatusDto =
  | "portable_available"
  | "llm_disabled"
  | "api_key_required"
  | "authorization_required"
  | "authorized"
  | "provider_unavailable"
  | "degraded"
  | "revoked"
  | "unsupported"
  | "pending"
  | "redaction_failed";

export interface LlmAlertStorySettingsDto {
  enabled: boolean;
  provider: LlmAlertStoryProviderDto;
  model: string;
  api_key_storage_mode: LlmApiKeyStorageModeDto;
  authorization_granted: boolean;
  timeout_seconds: number;
}

export interface LlmAlertStoryStatusDto {
  settings: LlmAlertStorySettingsDto;
  api_key_configured: boolean;
  capability_status: LlmAlertStoryCapabilityStatusDto;
  os_keystore_supported: boolean;
  last_successful_check: string | null;
  last_successful_generation: string | null;
  last_story_id: string | null;
  story_count: number;
  base_url_configured: boolean;
  last_error_code: string | null;
  warning_redacted: string;
  generated_at: string;
}

export interface ApplyRuntimeProfileRequestDto extends MutationReasonDto {
  profile: RuntimeProfileDto;
}

export interface UpdatePrivacyPolicyRequestDto extends MutationReasonDto {
  policy: JsonValue;
}

export interface UpdateResponsePolicyRequestDto extends MutationReasonDto {
  policy: JsonValue;
}

export interface EnableForensicModeRequestDto extends MutationReasonDto {
  scope: JsonValue;
}

export interface DisableForensicModeRequestDto extends MutationReasonDto {}

export interface SettingsMutationResultDto {
  runtime_profile: RuntimeProfileDto;
  change_request: JsonValue;
  impact_analysis: JsonValue;
}

export interface UpdateLlmAlertStorySettingsRequestDto extends MutationReasonDto {
  settings: LlmAlertStorySettingsDto;
  base_url?: string | null;
}

export interface SaveLlmAlertStoryApiKeyRequestDto extends MutationReasonDto {
  api_key: string;
  storage_mode: LlmApiKeyStorageModeDto;
}

export interface ClearLlmAlertStoryApiKeyRequestDto extends MutationReasonDto {}

export interface TestLlmAlertStoryConnectionRequestDto extends MutationReasonDto {}

export interface LlmAttackTechniqueRefDto {
  tactic_id: string;
  technique_id: string;
}

export interface LlmAlertStoryDraftDto {
  alert_narrative_redacted: string;
  likely_attack_summary_redacted: string;
  confidence_uncertainty_redacted: string;
  evidence_summary_redacted: string;
  affected_entities_redacted: string[];
  investigation_suggestions_redacted: string[];
  report_text_redacted: string;
}

export interface LlmAlertStoryRecordDto {
  story_id: string;
  alert_ref: string;
  incident_ref?: string | null;
  provider: LlmAlertStoryProviderDto;
  model: string;
  request_hash: string;
  response_hash: string;
  generated_at: string;
  ai_generated: boolean;
  redaction_passed: boolean;
  degraded: boolean;
  story: LlmAlertStoryDraftDto;
  evidence_refs: string[];
  risk_refs: string[];
  attack_refs: LlmAttackTechniqueRefDto[];
}

export interface GenerateLlmAlertStoryRequestDto extends MutationReasonDto {
  alert_id: string;
  incident_id?: string | null;
  explicit_user_action: true;
  replay: false;
}

export type NativePermissionActionDto =
  | "request_authorization"
  | "grant_authorization"
  | "revoke_authorization"
  | "disable_capability"
  | "recheck_status"
  | "clear_inactive_state";

export interface AuthorizedNativeCapabilityStatusDto {
  capability_id: string;
  category: string;
  lifecycle_state: string;
  availability_state: string;
  permission_state: string;
  authorization_mode: string;
  access_mode: string;
  enabled: boolean;
  revoked: boolean;
  health_state: string;
  degraded_reason?: string | null;
  visibility_scope: string;
  portable_default_available: false;
  last_checked_time_bucket?: string | null;
  provenance_id: string;
  audit_refs: string[];
  redaction_status: string;
  telemetry_collection_active: false;
  response_execution_allowed: false;
  automatic_llm_calls: false;
}

export interface NativePermissionActionRequestDto {
  capability_id: string;
  action: NativePermissionActionDto;
  explicit_user_action: boolean;
  reason_redacted: string;
}

export interface NativePermissionPreviewDto {
  capability: AuthorizedNativeCapabilityStatusDto;
  requested_action: NativePermissionActionDto;
  state_change_performed: false;
  telemetry_collection_started: false;
  response_execution_started: false;
  service_installation_started: false;
  driver_loading_started: false;
  automatic_llm_calls: false;
  boundary_summary_redacted: string;
}

export interface NativePermissionActionResultDto {
  capability: AuthorizedNativeCapabilityStatusDto;
  audit_entry: JsonValue;
  emitted_status_events: JsonValue[];
  telemetry_collection_started: false;
  response_execution_started: false;
  service_installation_started: false;
  driver_loading_started: false;
  host_mutation_performed: false;
  automatic_llm_calls: false;
}

export interface NativePermissionStatusSummaryDto {
  capability_count: number;
  permission_required_count: number;
  requested_count: number;
  granted_inactive_count: number;
  revoked_count: number;
  degraded_count: number;
  unsupported_count: number;
  portable_default_active: boolean;
  session_bound_authorization: true;
  telemetry_collection_active: false;
  response_execution_allowed: false;
  automatic_llm_calls: false;
  capability_refs: string[];
  audit_refs: string[];
  generated_at: string;
}

export interface NativeVisibilitySummaryDto {
  available_scope_categories: string[];
  missing_visibility_flags: string[];
  degraded_reasons: string[];
  capability_refs: string[];
  audit_refs: string[];
  granted_permission_creates_evidence: false;
  native_required_attack_coverage_supported: false;
  future_sampler_ready: false;
  portable_default_active: boolean;
  metadata_only: true;
  generated_at: string;
}

export interface NativePermissionAuditSummaryDto {
  entries: JsonValue[];
  audit_refs: string[];
  revoked_capability_refs: string[];
  generated_at: string;
}

export interface NativeSamplerSchemaDeclarationDto {
  schema_id: string;
  schema_version: JsonValue;
  field_categories: string[];
  declared_field_labels: string[];
  output_fact_categories: string[];
  declared_only: true;
  raw_fields_allowed: false;
  redaction_status: string;
}

export interface NativeSamplerContractDto {
  contract_id: string;
  sampler_id: string;
  category: string;
  required_capability_id: string;
  required_permission_state: string;
  authorization_mode: string;
  read_only: true;
  response_capable: boolean;
  readiness_state: string;
  supported_platform: string;
  portable_default_available: false;
  sampling_mode: string;
  max_records_per_tick: number;
  max_bytes_per_tick: number;
  output_fact_categories: string[];
  declared_event_topics: string[];
  redaction_policy_id: string;
  privacy_boundary: string;
  retention_mode: string;
  visibility_scope: string;
  schema: NativeSamplerSchemaDeclarationDto;
  degraded_reason?: string | null;
  missing_prerequisite_flags: string[];
  audit_refs: string[];
  provenance_id: string;
  redaction_status: string;
  privacy_class: string;
  last_reviewed_time_bucket?: string | null;
  sampler_implemented: boolean;
  sampler_active: false;
  telemetry_collection_active: false;
  response_execution_allowed: false;
  automatic_llm_calls: false;
}

export interface NativeSamplerAuthorizationReviewDto {
  review_id: string;
  sampler_id: string;
  category: string;
  capability_id: string;
  permission_state: string;
  readiness_state: string;
  allowed: boolean;
  blocked_reason?: string | null;
  degraded_reason?: string | null;
  missing_prerequisite_flags: string[];
  required_user_action: string;
  future_collection_allowed: boolean;
  future_response_allowed: false;
  sampler_active: false;
  telemetry_collection_started: false;
  response_execution_started: false;
  service_installation_started: false;
  driver_loading_started: false;
  host_mutation_performed: false;
  automatic_llm_calls: false;
  schema_safety_state: string;
  evidence_quality_effect: string;
  report_export_suitable: boolean;
  declared_event_topics: string[];
  output_fact_categories: string[];
  audit_refs: string[];
  provenance_id: string;
  time_bucket: string;
  redaction_status: string;
}

export interface NativeSamplerStatusEventDto {
  topic: string;
  sampler_id: string;
  category: string;
  capability_id: string;
  readiness_state: string;
  permission_state: string;
  health_state: string;
  degraded_reason?: string | null;
  missing_prerequisite_flags: string[];
  schema_version: JsonValue;
  declared_output_categories: string[];
  audit_refs: string[];
  provenance_id: string;
  time_bucket: string;
  redaction_status: string;
}

export interface FutureSecurityFactMappingDeclarationDto {
  mapping_id: string;
  sampler_id: string;
  sampler_category: string;
  output_fact_category: string;
  declared_field_categories: string[];
  declared_only: true;
  emits_security_facts_now: false;
  quality_gate_required: true;
  visibility_gate_required: true;
  report_export_suitability_gate: true;
  forbidden_raw_fields_rejected: true;
  provenance_id: string;
  schema_version: JsonValue;
  redaction_status: string;
}

export interface FutureSecurityFactMappingSummaryDto {
  mappings: FutureSecurityFactMappingDeclarationDto[];
  mapping_count: number;
  emitted_security_fact_count: 0;
  sampler_refs: string[];
  generated_at: string;
}

export interface NativeSamplerReadinessDetailDto {
  contract: NativeSamplerContractDto;
  review: NativeSamplerAuthorizationReviewDto;
  status_events: NativeSamplerStatusEventDto[];
  future_mappings: FutureSecurityFactMappingDeclarationDto[];
}

export interface NativeSamplerReadinessSummaryDto {
  contract_count: number;
  review_count: number;
  ready_when_implemented_count: number;
  blocked_count: number;
  degraded_count: number;
  not_implemented_count: number;
  active_sampler_count: 0;
  future_collection_allowed_count: number;
  future_response_allowed_count: 0;
  endpoint_security_facts_emitted: false;
  telemetry_collection_active: false;
  response_execution_allowed: false;
  automatic_llm_calls: false;
  portable_default_active: boolean;
  no_telemetry_collected: true;
  contract_refs: string[];
  review_refs: string[];
  audit_refs: string[];
  missing_endpoint_visibility_flags: string[];
  degraded_reasons: string[];
  generated_at: string;
}

export interface NativeSamplerBlockedSummaryDto {
  blocked_count: number;
  blocked_sampler_refs: string[];
  blocked_reasons: string[];
  revoked_sampler_refs: string[];
  disabled_sampler_refs: string[];
  unsafe_schema_sampler_refs: string[];
  response_capable_sampler_refs: string[];
  generated_at: string;
}

export interface MissingEndpointVisibilitySummaryDto {
  missing_visibility_flags: string[];
  sampler_refs: string[];
  degraded_reasons: string[];
  endpoint_required_hypotheses_degraded: boolean;
  native_attack_rows_supported: false;
  edr_coverage_claimed: false;
  generated_at: string;
}

export interface EdrReadinessSummaryDto {
  contract_ready_count: number;
  readiness_approved_count: number;
  implemented_sampler_count: number;
  active_sampler_count: number;
  blocked_sampler_count: number;
  telemetry_collection_active: boolean;
  response_execution_allowed: false;
  endpoint_security_facts_emitted: boolean;
  edr_coverage_claimed: false;
  portable_default_active: boolean;
  no_telemetry_collected: boolean;
  sampler_refs: string[];
  audit_refs: string[];
  missing_endpoint_visibility: MissingEndpointVisibilitySummaryDto;
  generated_at: string;
}

export type NativeSamplerRuntimeActionDto =
  | "preview_activation"
  | "activate"
  | "sample_now"
  | "scheduled_sample"
  | "pause"
  | "resume"
  | "stop"
  | "revoke"
  | "refresh_status"
  | "read_latest_bounded_batch"
  | "clear_inactive_runtime_state";

export interface NativeSamplerRuntimeActionRequestDto {
  sampler_id: string;
  action: NativeSamplerRuntimeActionDto;
  explicit_user_action: boolean;
  enable_interval_sampling: boolean;
  max_records_per_sample: number;
  max_bytes_per_sample: number;
  timeout_millis: number;
  reason_redacted: string;
}

export interface NativeSamplerActivationPreviewDto {
  sampler_id: string;
  category: string;
  readiness_state: string;
  current_runtime_state: string;
  activation_allowed: boolean;
  blocked_reason?: string | null;
  state_change_performed: false;
  telemetry_collection_started: false;
  response_execution_started: false;
  service_installation_started: false;
  driver_loading_started: false;
  host_mutation_performed: false;
  automatic_llm_calls: false;
  boundary_summary_redacted: string;
}

export interface NativeSamplerCounterSummaryDto {
  sampled_record_count: number;
  sampled_record_count_bucket: string;
  skipped_record_count: number;
  skipped_record_count_bucket: string;
  malformed_record_count: number;
  rejected_record_count: number;
  duplicate_suppressed_count: number;
  backpressure_event_count: number;
  timeout_count: number;
  duration_bucket: string;
  bytes_processed_bucket: string;
  unknown_category_ratio_bucket: string;
}

export interface NativeSamplerRuntimeStatusDto {
  sampler_id: string;
  category: string;
  capability_id: string;
  readiness_state: string;
  runtime_state: string;
  permission_state: string;
  provider_category: string;
  platform_category: string;
  provider_availability_state: string;
  health_state: string;
  degraded_reason?: string | null;
  missing_prerequisite_flags: string[];
  interval_sampling_enabled: boolean;
  max_records_per_sample: number;
  max_bytes_per_sample: number;
  timeout_millis: number;
  queue_size_bound: number;
  latest_batch_id?: string | null;
  latest_sample_time_bucket?: string | null;
  counters: NativeSamplerCounterSummaryDto;
  emitted_topics: string[];
  fact_refs: string[];
  evidence_refs: string[];
  audit_refs: string[];
  provenance_id: string;
  redaction_status: string;
  telemetry_collection_active: boolean;
  response_execution_allowed: false;
  service_installation_started: false;
  driver_loading_started: false;
  host_mutation_performed: false;
  automatic_llm_calls: false;
}

export interface NativeHealthMetadataRecordDto {
  health_observation_id: string;
  sampler_id: string;
  provider_category: string;
  platform_category: string;
  provider_availability_state: string;
  authorization_state: string;
  runtime_state: string;
  health_state: string;
  degraded_reason?: string | null;
  missing_prerequisite_flags: string[];
  sample_duration_bucket: string;
  sampled_record_count_bucket: string;
  skipped_record_count_bucket: string;
  malformed_record_count_bucket: string;
  rejected_record_count_bucket: string;
  timeout_bucket: string;
  last_sample_time_bucket: string;
  schema_version: JsonValue;
  provenance_id: string;
  audit_refs: string[];
  redaction_status: string;
  quality_score: number;
}

export interface NativeServiceMetadataRecordDto {
  service_observation_id: string;
  service_category: string;
  service_state_bucket: string;
  startup_type_bucket: string;
  trust_category: string;
  signedness_bucket: string;
  privilege_context_category: string;
  host_criticality_category: string;
  first_seen_in_session: boolean;
  count_bucket: string;
  changed_state: boolean;
  sampler_id: string;
  sample_batch_id: string;
  time_bucket: string;
  confidence_hint: number;
  evidence_refs: string[];
  provenance_id: string;
  redaction_status: string;
  missing_visibility_flags: string[];
}

export interface NativeProcessMetadataRecordDto {
  process_observation_id: string;
  process_category: string;
  parent_process_category: string;
  relation_category: string;
  execution_context_category: string;
  trust_category: string;
  signedness_bucket: string;
  privilege_context_category: string;
  integrity_context_bucket: string;
  session_context_category: string;
  lifecycle_state_bucket: string;
  first_seen_in_session: boolean;
  population_count_bucket: string;
  start_count_bucket: string;
  stop_count_bucket: string;
  changed_category: boolean;
  sampler_id: string;
  sample_batch_id: string;
  time_bucket: string;
  confidence_hint: number;
  evidence_refs: string[];
  provenance_id: string;
  redaction_status: string;
  missing_visibility_flags: string[];
}

export interface NativeSamplerRuntimeBatchDto {
  batch_id: string;
  sampler_id: string;
  category: string;
  runtime_state: string;
  provider_category: string;
  platform_category: string;
  health_record?: NativeHealthMetadataRecordDto | null;
  service_records: NativeServiceMetadataRecordDto[];
  process_records: NativeProcessMetadataRecordDto[];
  counters: NativeSamplerCounterSummaryDto;
  emitted_topics: string[];
  fact_refs: string[];
  evidence_refs: string[];
  audit_refs: string[];
  provenance_id: string;
  time_bucket: string;
  redaction_status: string;
  response_execution_allowed: false;
  host_mutation_performed: false;
  automatic_llm_calls: false;
}

export interface NativeServiceCategoryCountDto {
  service_category: string;
  count_bucket: string;
  observation_count: number;
}

export interface NativeServiceBucketCountDto {
  label: string;
  count_bucket: string;
  observation_count: number;
}

export interface NativeProcessCategoryCountDto {
  process_category: string;
  count_bucket: string;
  observation_count: number;
}

export interface NativeProcessBucketCountDto {
  label: string;
  count_bucket: string;
  observation_count: number;
}

export interface NativeSamplerRuntimeSummaryDto {
  runtime_count: number;
  active_count: number;
  paused_count: number;
  degraded_count: number;
  stopped_count: number;
  revoked_count: number;
  latest_batch_refs: string[];
  fact_refs: string[];
  evidence_refs: string[];
  audit_refs: string[];
  service_category_counts: NativeServiceCategoryCountDto[];
  service_state_counts: NativeServiceBucketCountDto[];
  startup_type_counts: NativeServiceBucketCountDto[];
  process_category_counts: NativeProcessCategoryCountDto[];
  parent_process_category_counts: NativeProcessCategoryCountDto[];
  process_relation_counts: NativeProcessBucketCountDto[];
  execution_context_counts: NativeProcessBucketCountDto[];
  process_trust_counts: NativeProcessBucketCountDto[];
  process_signedness_counts: NativeProcessBucketCountDto[];
  process_privilege_counts: NativeProcessBucketCountDto[];
  process_lifecycle_counts: NativeProcessBucketCountDto[];
  quality_bucket: string;
  service_visibility_available: boolean;
  native_health_visibility_available: boolean;
  process_visibility_available: boolean;
  parent_process_visibility_available: boolean;
  process_network_attribution_available: false;
  packet_visibility_available: false;
  response_execution_allowed: false;
  edr_coverage_claimed: false;
  automatic_llm_calls: false;
  statuses: NativeSamplerRuntimeStatusDto[];
  generated_at: string;
}

export interface NativeSamplerRuntimeAuditEntryDto {
  audit_id: string;
  sampler_id: string;
  action: NativeSamplerRuntimeActionDto;
  resulting_runtime_state: string;
  time_bucket: string;
  provenance_id: string;
  summary_redacted: string;
}

export interface NativeSamplerRuntimeActionResultDto {
  status: NativeSamplerRuntimeStatusDto;
  latest_batch?: NativeSamplerRuntimeBatchDto | null;
  audit_entry: NativeSamplerRuntimeAuditEntryDto;
  emitted_topics: string[];
  preview_only: false;
  telemetry_collection_started: boolean;
  response_execution_started: false;
  service_installation_started: false;
  driver_loading_started: false;
  host_mutation_performed: false;
  automatic_llm_calls: false;
}

export type NativeSchedulerControllerStateDto =
  | "disabled"
  | "ready"
  | "running"
  | "paused"
  | "degraded"
  | "stopping"
  | "stopped"
  | "revoked"
  | "failed";

export type NativeScheduleIntervalBucketDto =
  | "one_minute"
  | "five_minutes"
  | "fifteen_minutes"
  | "hourly";

export type NativeScheduleTimeoutBucketDto =
  | "one_second"
  | "five_seconds"
  | "fifteen_seconds"
  | "thirty_seconds";

export type NativeScheduleRetryBudgetBucketDto = "none" | "one" | "two" | "three";

export type NativeSchedulerActionDto =
  | "preview_enable_sampler"
  | "enable_sampler"
  | "disable_sampler"
  | "disable_scheduler"
  | "pause"
  | "resume"
  | "begin_stop"
  | "complete_stop"
  | "refresh_status"
  | "run_tick";

export type NativeSchedulerCycleStateDto = "started" | "completed" | "skipped";

export type NativeSchedulerBackpressureStateDto =
  | "none"
  | "low"
  | "moderate"
  | "high"
  | "saturated";

export type NativeTelemetryFreshnessStateDto =
  | "fresh"
  | "aging"
  | "stale"
  | "missing"
  | "unavailable"
  | "revoked";

export type NativeTelemetryDimensionDto =
  | "health"
  | "service"
  | "process"
  | "parent_category";

export type NativeMissedSampleStateDto =
  | "on_time"
  | "delayed"
  | "missed_once"
  | "repeatedly_missed"
  | "paused"
  | "blocked"
  | "revoked";

export interface NativeSchedulerSamplerCycleResultDto {
  sampler_id: string;
  cycle_state: NativeSchedulerCycleStateDto;
  skip_reason?: string | null;
  batch_ref?: string | null;
  fact_refs: string[];
  audit_refs: string[];
  runtime_validation_passed: boolean;
  event_bus_dispatched: boolean;
  dag_dispatched: boolean;
  plugin_runtime_dispatched: boolean;
  execution_control_applied: boolean;
  overlap_prevented: boolean;
  timeout_enforced: boolean;
  cancellation_requested: boolean;
  retryable: boolean;
  retry_scheduled: boolean;
  retry_exhausted: boolean;
  retry_attempt: number;
  retry_budget: number;
  retry_delay_millis: number;
}

export interface NativeSchedulerExecutionControlSummaryDto {
  cycle_id: string;
  global_concurrency_limit: number;
  per_category_concurrency_limit: number;
  active_execution_count: number;
  selected_sampler_ids: string[];
  overlap_prevented_count: number;
  timeout_enforced_count: number;
  cancellation_requested: boolean;
  retry_scheduled_count: number;
  retry_exhausted_count: number;
  provider_timeout_millis: number;
  execution_timeout_millis: number;
  global_cycle_timeout_millis: number;
  retry_delay_millis: number;
  emitted_topics: string[];
  provenance_id: string;
  redaction_status: string;
  automatic_llm_calls: false;
  response_execution_started: false;
}

export interface NativeSchedulerBackpressureSummaryDto {
  cycle_id: string;
  state: NativeSchedulerBackpressureStateDto;
  active_task_count: number;
  pending_due_task_count: number;
  event_bus_backlog_count: number;
  dag_backlog_count: number;
  timeout_rate_bucket: NativeSchedulerBackpressureStateDto;
  overlap_skip_rate_bucket: NativeSchedulerBackpressureStateDto;
  defer_low_priority_samplers: boolean;
  skip_cycle: boolean;
  pause_degraded_samplers: boolean;
  deferred_sampler_ids: string[];
  paused_sampler_ids: string[];
  emitted_topics: string[];
  provenance_id: string;
  redaction_status: string;
  automatic_llm_calls: false;
  response_execution_started: false;
}

export interface NativeTelemetryFreshnessDimensionSummaryDto {
  dimension: NativeTelemetryDimensionDto;
  sampler_id: string;
  freshness_state: NativeTelemetryFreshnessStateDto;
  last_success_monotonic_millis?: number | null;
  age_bucket: string;
  interval_bucket: NativeScheduleIntervalBucketDto;
  source_reliability_bucket: string;
  visibility_completeness_bucket: string;
  evidence_quality_bucket: string;
  degraded_reason?: string | null;
  batch_refs: string[];
  fact_refs: string[];
  audit_refs: string[];
  provenance_id: string;
  redaction_status: string;
}

export interface NativeSchedulerFreshnessSummaryDto {
  cycle_id: string;
  monotonic_elapsed_millis: number;
  dimensions: NativeTelemetryFreshnessDimensionSummaryDto[];
  fresh_dimension_count: number;
  aging_dimension_count: number;
  stale_dimension_count: number;
  missing_dimension_count: number;
  unavailable_dimension_count: number;
  revoked_dimension_count: number;
  worst_freshness_state: NativeTelemetryFreshnessStateDto;
  emitted_topics: string[];
  provenance_id: string;
  redaction_status: string;
  attack_finding_generation_started: false;
  automatic_llm_calls: false;
  response_execution_started: false;
}

export interface NativeMissedSampleDimensionSummaryDto {
  dimension: NativeTelemetryDimensionDto;
  sampler_id: string;
  missed_sample_state: NativeMissedSampleStateDto;
  expected_interval_bucket: NativeScheduleIntervalBucketDto;
  last_success_monotonic_millis?: number | null;
  missed_expected_count_bucket: string;
  blocked_reason?: string | null;
  provenance_id: string;
  redaction_status: string;
}

export interface NativeSchedulerMissedSampleSummaryDto {
  cycle_id: string;
  monotonic_elapsed_millis: number;
  dimensions: NativeMissedSampleDimensionSummaryDto[];
  delayed_dimension_count: number;
  missed_once_dimension_count: number;
  repeatedly_missed_dimension_count: number;
  paused_dimension_count: number;
  blocked_dimension_count: number;
  revoked_dimension_count: number;
  emitted_topics: string[];
  provenance_id: string;
  redaction_status: string;
  attack_finding_generation_started: false;
  automatic_llm_calls: false;
  response_execution_started: false;
}

export interface NativeSchedulerCycleSummaryDto {
  cycle_id: string;
  cycle_state: NativeSchedulerCycleStateDto;
  monotonic_elapsed_millis: number;
  selected_sampler_ids: string[];
  sampler_results: NativeSchedulerSamplerCycleResultDto[];
  skip_reason?: string | null;
  completed_sampler_count: number;
  skipped_sampler_count: number;
  execution_control?: NativeSchedulerExecutionControlSummaryDto | null;
  backpressure?: NativeSchedulerBackpressureSummaryDto | null;
  freshness?: NativeSchedulerFreshnessSummaryDto | null;
  missed_sample?: NativeSchedulerMissedSampleSummaryDto | null;
  emitted_topics: string[];
  audit_refs: string[];
  provenance_id: string;
  redaction_status: string;
  graceful_shutdown_requested: boolean;
  retry_execution_started: false;
  automatic_llm_calls: false;
  response_execution_started: false;
}

export interface NativeSamplerScheduleContractDto {
  sampler_id: string;
  sampler_category: string;
  schedule_enabled: boolean;
  interval_bucket: NativeScheduleIntervalBucketDto;
  timeout_bucket: NativeScheduleTimeoutBucketDto;
  retry_budget_bucket: NativeScheduleRetryBudgetBucketDto;
  max_records: number;
  max_bytes: number;
  declared_topics: string[];
  retention_mode: "no_raw_retention";
  provenance_id: string;
  redaction_status: string;
}

export interface NativeSamplerScheduleStatusDto {
  contract: NativeSamplerScheduleContractDto;
  permission_state: string;
  runtime_state: string;
  authorized: boolean;
  activated: boolean;
  schedule_eligible: boolean;
  blocked_reason?: string | null;
  audit_refs: string[];
}

export interface NativeSchedulerStatusDto {
  controller_state: NativeSchedulerControllerStateDto;
  periodic_sampling_enabled: boolean;
  enabled_schedule_count: number;
  eligible_schedule_count: number;
  revoked_schedule_count: number;
  scheduling_loop_implemented: boolean;
  scheduling_loop_active: boolean;
  backpressure_state: NativeSchedulerBackpressureStateDto;
  backpressure_cycle_count: number;
  latest_backpressure_cycle_id?: string | null;
  freshness_stale_dimension_count: number;
  freshness_missing_dimension_count: number;
  missed_sample_dimension_count: number;
  latest_freshness_cycle_id?: string | null;
  latest_missed_sample_cycle_id?: string | null;
  periodic_execution_started: false;
  sample_requested: false;
  retry_execution_started: false;
  graceful_shutdown_requested: boolean;
  cycle_count: number;
  completed_cycle_count: number;
  skipped_cycle_count: number;
  latest_cycle_id?: string | null;
  last_tick_monotonic_millis?: number | null;
  automatic_llm_calls: false;
  response_execution_started: false;
  emitted_topics: string[];
  audit_refs: string[];
  provenance_id: string;
  redaction_status: string;
  generated_at: string;
}

export interface NativeSchedulerSummaryDto {
  status: NativeSchedulerStatusDto;
  schedules: NativeSamplerScheduleStatusDto[];
  authorization_independent: true;
  activation_independent: true;
  enablement_independent: true;
  startup_auto_enablement: false;
  latest_cycle?: NativeSchedulerCycleSummaryDto | null;
  generated_at: string;
}

export type NativeSchedulerHealthStateDto =
  | "healthy"
  | "idle"
  | "paused"
  | "degraded"
  | "backpressure"
  | "stopped"
  | "revoked"
  | "failed";

export interface NativeSchedulerSafePersistedScheduleDto {
  sampler_id: string;
  sampler_category: string;
  schedule_enabled: boolean;
  interval_bucket: NativeScheduleIntervalBucketDto;
  timeout_bucket: NativeScheduleTimeoutBucketDto;
  retry_budget_bucket: NativeScheduleRetryBudgetBucketDto;
  provenance_id: string;
  redaction_status: string;
}

export interface NativeSchedulerRetrySummaryDto {
  retry_scheduled_count: number;
  retry_exhausted_count: number;
  retry_pending_sampler_count: number;
  latest_execution_control_cycle_id?: string | null;
  retrying_sampler_ids: string[];
  provenance_id: string;
  redaction_status: string;
  automatic_llm_calls: false;
  response_execution_started: false;
}

export interface NativeSchedulerOperationalSummaryDto {
  status: NativeSchedulerStatusDto;
  scheduler_health: NativeSchedulerHealthStateDto;
  safe_persisted_schedules: NativeSchedulerSafePersistedScheduleDto[];
  freshness_summary?: NativeSchedulerFreshnessSummaryDto | null;
  missed_sample_summary?: NativeSchedulerMissedSampleSummaryDto | null;
  retry_summary: NativeSchedulerRetrySummaryDto;
  backpressure_summary?: NativeSchedulerBackpressureSummaryDto | null;
  scheduler_refs: string[];
  freshness_refs: string[];
  missed_sample_refs: string[];
  quality_refs: string[];
  safe_persistence_only: true;
  raw_native_data_persisted: false;
  runtime_subject_persisted: false;
  source_location_persisted: false;
  launch_text_persisted: false;
  machine_identifier_persisted: false;
  scheduler_enablement_started: false;
  provider_refresh_started: false;
  automatic_llm_calls: false;
  response_execution_started: false;
  generated_at: string;
}

export interface NativeSchedulerEnablementPreviewDto {
  sampler_id: string;
  controller_state: NativeSchedulerControllerStateDto;
  permission_state: string;
  runtime_state: string;
  schedule_eligible: boolean;
  blocked_reason?: string | null;
  state_change_performed: false;
  periodic_execution_started: false;
  sample_requested: false;
  boundary_summary_redacted: string;
}

export interface NativeSchedulerActionRequestDto {
  sampler_id?: string | null;
  action: NativeSchedulerActionDto;
  explicit_user_action: boolean;
  interval_bucket: NativeScheduleIntervalBucketDto;
  timeout_bucket: NativeScheduleTimeoutBucketDto;
  retry_budget_bucket: NativeScheduleRetryBudgetBucketDto;
  max_records: number;
  max_bytes: number;
  reason_redacted: string;
}

export interface NativeSchedulerTickRequestDto {
  monotonic_elapsed_millis: number;
  max_samplers_per_tick: number;
  global_concurrency_limit: number;
  per_category_concurrency_limit: number;
  provider_timeout_millis: number;
  execution_timeout_millis: number;
  global_cycle_timeout_millis: number;
  retry_delay_millis: number;
  event_bus_backlog_count: number;
  dag_backlog_count: number;
  cancellation_requested: boolean;
  reason_redacted: string;
}

export interface NativeSchedulerAuditEntryDto {
  audit_id: string;
  sampler_id?: string | null;
  action: NativeSchedulerActionDto;
  resulting_controller_state: NativeSchedulerControllerStateDto;
  time_bucket: string;
  provenance_id: string;
  summary_redacted: string;
}

export interface NativeSchedulerActionResultDto {
  status: NativeSchedulerStatusDto;
  sampler_status?: NativeSamplerScheduleStatusDto | null;
  audit_entry: NativeSchedulerAuditEntryDto;
  emitted_topics: string[];
  preview_only: false;
  periodic_execution_started: false;
  sample_requested: false;
  automatic_llm_calls: false;
  response_execution_started: false;
}
