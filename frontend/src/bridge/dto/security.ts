import type { Id, JsonValue, MutationReasonDto } from "./common";
import type { GraphViewModelDto } from "./graph";
import type { ReportDto } from "./report";
import type { ResponsePlanDto } from "./response";

export type SecuritySeverityDto =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical"
  | string;

export interface FindingDto {
  finding_id?: Id;
  finding_type?: string;
  state?: string;
  severity?: SecuritySeverityDto;
  summary_redacted?: string;
  [key: string]: JsonValue | undefined;
}

export interface AlertDto {
  alert_id?: Id;
  state?: string;
  severity?: SecuritySeverityDto;
  summary_redacted?: string;
  finding_refs?: Id[];
  [key: string]: JsonValue | undefined;
}

export interface IncidentDto {
  incident_id?: Id;
  state?: string;
  severity?: SecuritySeverityDto;
  summary_redacted?: string;
  alert_refs?: Id[];
  [key: string]: JsonValue | undefined;
}

export interface IncidentDetailViewDto {
  incident: IncidentDto;
  related_alerts: AlertDto[];
  related_findings: FindingDto[];
  graph: GraphViewModelDto;
  response_plans: ResponsePlanDto[];
  reports: ReportDto[];
}

export type AttackCoverageStateDto =
  | "covered"
  | "observed"
  | "evidence_backed"
  | "degraded"
  | "unsupported"
  | "requires_authorized_native_extension"
  | string;

export type AttackCoverageConfidenceBucketDto =
  | "unknown"
  | "low"
  | "medium"
  | "high"
  | string;

export type AttackObservedCountBucketDto =
  | "none"
  | "single"
  | "low"
  | "medium"
  | "high"
  | string;

export type AttackLastObservedBucketDto =
  | "none"
  | "current_session"
  | "recent_session"
  | "stale"
  | "unknown"
  | string;

export type AttackRequiredVisibilityDto =
  | "portable_network_metadata"
  | "portable_auth_metadata"
  | "portable_provider_metadata"
  | "portable_deception_metadata"
  | "authorized_native_process_visibility"
  | "authorized_native_extension"
  | "unsupported"
  | string;

export interface AttackCoverageCountDto {
  label: string;
  count: number;
}

export interface AttackCoverageTechniqueRowDto {
  tactic_id: string;
  technique_id: string;
  attack_version: string;
  rule_detector_ids: string[];
  finding_refs: Id[];
  evidence_refs: Id[];
  risk_refs: Id[];
  confidence_bucket: AttackCoverageConfidenceBucketDto;
  degraded_reason?: string | null;
  required_visibility: AttackRequiredVisibilityDto;
  package_category: string;
  observed_count_bucket: AttackObservedCountBucketDto;
  last_observed_bucket: AttackLastObservedBucketDto;
  states: AttackCoverageStateDto[];
  quality?: QualityBreakdownDto;
  native_required?: boolean;
  metadata_only?: boolean;
}

export interface AttackCoverageSummaryDto {
  attack_version: string;
  generated_at: string;
  complete_coverage_claimed: boolean;
  technique_rows: AttackCoverageTechniqueRowDto[];
  top_tactics: AttackCoverageCountDto[];
  package_coverage: AttackCoverageCountDto[];
  state_counts: AttackCoverageCountDto[];
  finding_refs: Id[];
  evidence_refs: Id[];
  risk_refs: Id[];
  degraded_reason?: string | null;
}

export type SecurityLayerDto =
  | "dns"
  | "cdn_edge"
  | "waf"
  | "api"
  | "http"
  | "auth_identity"
  | "saas_cloud"
  | "deception"
  | "local_metadata_proxy"
  | "sdn_placeholder"
  | "authorized_native_host_placeholder"
  | string;

export type FusionConfidenceBucketDto = "unknown" | "low" | "medium" | string;

export type EvidenceQualityBucketDto = string;
export type SourceReliabilityQualityBucketDto = string;
export type RedactionCompletenessBucketDto = string;
export type ProvenanceQualityBucketDto = string;
export type CorrelationQualityBucketDto = string;
export type VisibilityCompletenessBucketDto = string;
export type FreshnessBucketDto = string;
export type DuplicationStatusBucketDto = string;
export type OperationalInfluenceBucketDto = string;
export type NativeVisibilityStateCategoryDto = string;
export type IntelligenceFreshnessCategoryDto = string;
export type EvidenceStrengthBucketDto = string;
export type UncertaintyBucketDto = string;
export type SuitabilityBucketDto = string;
export type EvidenceQualityTargetKindDto = string;

export interface QualityBreakdownDto {
  evidence_quality_bucket: EvidenceQualityBucketDto;
  source_reliability_bucket: SourceReliabilityQualityBucketDto;
  redaction_completeness_bucket: RedactionCompletenessBucketDto;
  provenance_quality_bucket: ProvenanceQualityBucketDto;
  correlation_quality_bucket: CorrelationQualityBucketDto;
  visibility_completeness_bucket: VisibilityCompletenessBucketDto;
  freshness_bucket: FreshnessBucketDto;
  duplication_status_bucket: DuplicationStatusBucketDto;
  operational_influence_bucket: OperationalInfluenceBucketDto;
  native_visibility_state: NativeVisibilityStateCategoryDto;
  intelligence_freshness: IntelligenceFreshnessCategoryDto;
  evidence_strength_bucket: EvidenceStrengthBucketDto;
  uncertainty_bucket: UncertaintyBucketDto;
  report_suitability_bucket: SuitabilityBucketDto;
  export_suitability_bucket: SuitabilityBucketDto;
  degraded_reasons: string[];
  missing_visibility_flags: string[];
  quality_refs: Id[];
}

export interface LayeredSamplerDeclarationDto {
  sampler_id: string;
  layer: SecurityLayerDto;
  source_kind: string;
  state: string;
  sampling_mode: string;
  checkpoint_state: string;
  health_reason?: string | null;
  output_fact_categories: string[];
  event_bus_topics: string[];
  privacy_boundary: string;
  visibility_requirements: string[];
  portable_default_available: boolean;
}

export interface SecurityFactDto {
  fact_id: Id;
  layer: SecurityLayerDto;
  category: string;
  sampler_id: string;
  confidence_hint: number;
  evidence_refs: Id[];
  provenance_id?: Id | null;
  missing_visibility_flags: string[];
  degraded_reason?: string | null;
}

export interface AttackHypothesisRecordDto {
  hypothesis_record_id: Id;
  definition_id: string;
  version: string;
  category: string;
  fact_refs: Id[];
  correlated_layers: SecurityLayerDto[];
  correlation_count: number;
  confidence_bucket: FusionConfidenceBucketDto;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  evidence_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  graph_hint_refs: Id[];
  optional_llm_story_marker: boolean;
  quality?: QualityBreakdownDto;
}

export interface FusionCountDto {
  label: string;
  count: number;
}

export interface FusionSummaryDto {
  generated_at: string;
  sampler_health: LayeredSamplerDeclarationDto[];
  fact_count: number;
  hypothesis_count: number;
  facts: SecurityFactDto[];
  hypotheses: AttackHypothesisRecordDto[];
  top_correlated_layers: FusionCountDto[];
  top_hypothesis_categories: FusionCountDto[];
  degraded_visibility_context: string[];
  fact_refs: Id[];
  hypothesis_refs: Id[];
  evidence_refs: Id[];
  finding_refs: Id[];
  graph_hint_refs: Id[];
  privacy_class: string;
  automatic_llm_calls: boolean;
  quality?: QualityBreakdownDto;
}

export type BaselineScopeDto =
  | "current_session"
  | "source_id"
  | "sampler_layer"
  | "provider_category"
  | "destination_service_category"
  | "route_endpoint_fingerprint"
  | "redacted_identity_session_category"
  | "source_session_label"
  | "decoy_sensor_ref"
  | "hypothesis_family"
  | "attack_technique_ref"
  | string;

export type BaselineBucketDto = string;
export type BaselineIndicatorKindDto = string;

export interface BaselineAttackTechniqueRefDto {
  tactic_id: string;
  technique_id: string;
  attack_version: string;
  confidence_bucket: FusionConfidenceBucketDto;
  required_visibility: string;
}

export interface BaselineRecordDto {
  baseline_id: Id;
  scope: BaselineScopeDto;
  category: string;
  scope_key_hash: string;
  safe_label: string;
  count_bucket: BaselineBucketDto;
  first_seen_time_bucket?: string | null;
  last_seen_time_bucket?: string | null;
  recurrence_bucket: BaselineBucketDto;
  rarity_bucket: BaselineBucketDto;
  trend_bucket: BaselineBucketDto;
  confidence_trend_bucket: BaselineBucketDto;
  source_reliability_bucket: BaselineBucketDto;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  evidence_refs: Id[];
  fact_refs: Id[];
  hypothesis_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  provenance_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  redaction_status: string;
  quality?: QualityBreakdownDto;
}

export interface BaselineIndicatorDto {
  indicator_id: Id;
  kind: BaselineIndicatorKindDto;
  baseline_refs: Id[];
  evidence_refs: Id[];
  fact_refs: Id[];
  hypothesis_refs: Id[];
  confidence_bucket: FusionConfidenceBucketDto;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  summary_redacted: string;
  quality?: QualityBreakdownDto;
}

export interface SourceReliabilitySummaryDto {
  source_id: Id;
  source_health_state: string;
  reliability_bucket: BaselineBucketDto;
  sampled_count_bucket: BaselineBucketDto;
  malformed_count_bucket: BaselineBucketDto;
  backpressure_count_bucket: BaselineBucketDto;
  degraded_reason?: string | null;
  evidence_refs: Id[];
  quality?: QualityBreakdownDto;
}

export interface IncidentLinkedHypothesisGroupDto {
  group_id: Id;
  incident_id?: Id | null;
  group_key_hash: string;
  hypothesis_refs: Id[];
  evidence_refs: Id[];
  fact_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  baseline_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  graph_refs: Id[];
  confidence_trend: BaselineBucketDto;
  severity_trend: BaselineBucketDto;
  first_seen_bucket?: string | null;
  last_updated_bucket?: string | null;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  report_section_refs: Id[];
  quality?: QualityBreakdownDto;
  weak_merge_warning?: boolean;
  broad_provider_only_merge_rejected?: boolean;
}

export interface IncidentTimelineEntryDto {
  timeline_entry_id: Id;
  incident_id?: Id | null;
  group_id: Id;
  time_bucket: string;
  event_category: string;
  hypothesis_refs: Id[];
  evidence_refs: Id[];
  fact_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  baseline_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  source_health_refs: Id[];
  confidence_bucket: FusionConfidenceBucketDto;
  degraded_reason?: string | null;
  summary_redacted: string;
  quality?: QualityBreakdownDto;
}

export interface BaselinePersistenceStatusDto {
  mode: string;
  automatic_durable_persistence: boolean;
  explicit_export_allowed: boolean;
  durable_security_history_written: boolean;
  storage_boundary: string;
  degraded_reason?: string | null;
}

export interface DurableBaselineSummaryDto {
  generated_at: string;
  scope: BaselineScopeDto;
  persistence_status: BaselinePersistenceStatusDto;
  baseline_count: number;
  indicator_count: number;
  incident_group_count: number;
  timeline_entry_count: number;
  source_reliability_count: number;
  records: BaselineRecordDto[];
  indicators: BaselineIndicatorDto[];
  incident_groups: IncidentLinkedHypothesisGroupDto[];
  incident_timeline: IncidentTimelineEntryDto[];
  source_reliability: SourceReliabilitySummaryDto[];
  baseline_refs: Id[];
  evidence_refs: Id[];
  fact_refs: Id[];
  hypothesis_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  provenance_refs: Id[];
  degraded_visibility_context: string[];
  missing_visibility_flags: string[];
  report_ref_count: number;
  export_ref_count: number;
  automatic_llm_calls: boolean;
  response_execution: boolean;
  quality?: QualityBreakdownDto;
}

export type InvestigationRequirementStatusDto =
  | "matched"
  | "missing"
  | "not_observed"
  | "disqualified";

export interface InvestigationSuggestionDto {
  kind: string;
  summary_redacted: string;
  advisory_only: boolean;
  automatic_action: boolean;
}

export interface FactRequirementExplanationDto {
  layer: SecurityLayerDto;
  categories: string[];
  required: boolean;
  status: InvestigationRequirementStatusDto;
  matched_count_bucket: BaselineBucketDto;
}

export interface LlmStoryAvailabilityDetailDto {
  story_refs: Id[];
  alert_ref?: Id | null;
  incident_ref?: Id | null;
  bounded_input_available: boolean;
  existing_story_available: boolean;
  explicit_user_action_required: boolean;
  automatic_generation: boolean;
}

export interface HypothesisExplanationDetailDto {
  hypothesis_id: Id;
  family: string;
  version: string;
  confidence_bucket: FusionConfidenceBucketDto;
  confidence_trend: BaselineBucketDto;
  supporting_fact_categories: string[];
  required_fact_status: FactRequirementExplanationDto[];
  optional_fact_status: FactRequirementExplanationDto[];
  disqualifier_status: InvestigationRequirementStatusDto;
  evidence_count_bucket: BaselineBucketDto;
  source_count_bucket: BaselineBucketDto;
  correlation_time_bucket: string;
  provider_category_relation: string;
  route_endpoint_relation: string;
  baseline_refs: Id[];
  indicator_refs: Id[];
  evidence_refs: Id[];
  fact_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  graph_refs: Id[];
  report_refs: Id[];
  export_refs: Id[];
  story_availability: LlmStoryAvailabilityDetailDto;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  suggested_questions: string[];
  suggestions: InvestigationSuggestionDto[];
  summary_redacted: string;
  quality?: QualityBreakdownDto;
}

export interface BaselineDrillDownDetailDto {
  baseline_id: Id;
  scope: BaselineScopeDto;
  scope_category: string;
  indicator_kinds: BaselineIndicatorKindDto[];
  indicator_refs: Id[];
  count_bucket: BaselineBucketDto;
  rarity_bucket: BaselineBucketDto;
  recurrence_bucket: BaselineBucketDto;
  first_seen_bucket?: string | null;
  last_seen_bucket?: string | null;
  trend_bucket: BaselineBucketDto;
  confidence_trend: BaselineBucketDto;
  confidence_bucket: FusionConfidenceBucketDto;
  source_reliability_bucket: BaselineBucketDto;
  hypothesis_refs: Id[];
  incident_group_refs: Id[];
  evidence_refs: Id[];
  fact_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  provenance_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  report_refs: Id[];
  export_refs: Id[];
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  suggestions: InvestigationSuggestionDto[];
  summary_redacted: string;
  quality?: QualityBreakdownDto;
}

export interface IncidentGroupInvestigationDetailDto {
  group_id: Id;
  incident_id?: Id | null;
  hypothesis_refs: Id[];
  baseline_refs: Id[];
  indicator_refs: Id[];
  timeline_refs: Id[];
  evidence_refs: Id[];
  fact_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  graph_refs: Id[];
  report_refs: Id[];
  export_refs: Id[];
  source_reliability_refs: Id[];
  source_reliability_buckets: BaselineBucketDto[];
  confidence_trend: BaselineBucketDto;
  severity_risk_trend: BaselineBucketDto;
  first_seen_bucket?: string | null;
  last_updated_bucket?: string | null;
  story_availability: LlmStoryAvailabilityDetailDto;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  suggestions: InvestigationSuggestionDto[];
  summary_redacted: string;
  quality?: QualityBreakdownDto;
  weak_merge_warning?: boolean;
  broad_provider_only_merge_rejected?: boolean;
}

export interface TimelineDrillDownDetailDto {
  timeline_entry_id: Id;
  incident_id?: Id | null;
  group_id: Id;
  time_bucket: string;
  event_category: string;
  hypothesis_refs: Id[];
  baseline_refs: Id[];
  evidence_refs: Id[];
  finding_refs: Id[];
  risk_refs: Id[];
  attack_refs: BaselineAttackTechniqueRefDto[];
  source_health_refs: Id[];
  report_refs: Id[];
  confidence_bucket: FusionConfidenceBucketDto;
  degraded_reason?: string | null;
  summary_redacted: string;
  quality?: QualityBreakdownDto;
}

export interface SourceReliabilityExplanationDto {
  source_id: Id;
  source_health_state: string;
  reliability_bucket: BaselineBucketDto;
  sampled_count_bucket: BaselineBucketDto;
  malformed_count_bucket: BaselineBucketDto;
  backpressure_count_bucket: BaselineBucketDto;
  confidence_impact: BaselineBucketDto;
  baseline_refs: Id[];
  incident_group_refs: Id[];
  timeline_refs: Id[];
  evidence_refs: Id[];
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  suggestions: InvestigationSuggestionDto[];
  summary_redacted: string;
  quality?: QualityBreakdownDto;
}

export interface InvestigationDrillDownSummaryDto {
  generated_at: string;
  hypothesis_count: number;
  baseline_count: number;
  incident_group_count: number;
  timeline_count: number;
  source_reliability_count: number;
  hypotheses: HypothesisExplanationDetailDto[];
  baselines: BaselineDrillDownDetailDto[];
  incident_groups: IncidentGroupInvestigationDetailDto[];
  timeline: TimelineDrillDownDetailDto[];
  source_reliability: SourceReliabilityExplanationDto[];
  report_refs: Id[];
  export_refs: Id[];
  suggestions: InvestigationSuggestionDto[];
  portable_no_retention: boolean;
  metadata_only: boolean;
  automatic_llm_calls: boolean;
  response_execution: boolean;
  quality?: QualityBreakdownDto;
}

export interface EvidenceQualityRecordDto {
  evidence_quality_id: Id;
  target_kind: EvidenceQualityTargetKindDto;
  evidence_ref?: Id | null;
  finding_ref?: Id | null;
  hypothesis_ref?: Id | null;
  risk_ref?: Id | null;
  baseline_ref?: Id | null;
  baseline_indicator_ref?: Id | null;
  attack_ref?: string | null;
  graph_ref?: Id | null;
  incident_group_ref?: Id | null;
  report_section_ref?: Id | null;
  export_result_ref?: Id | null;
  fact_refs: Id[];
  source_kind_category: string;
  parser_family: string;
  detector_id?: string | null;
  detector_confidence_bucket: EvidenceQualityBucketDto;
  unsafe_field_rejection_bucket: EvidenceQualityBucketDto;
  malformed_skipped_backpressure_bucket: OperationalInfluenceBucketDto;
  redaction_status: string;
  provenance_id?: Id | null;
  time_bucket: string;
  quality: QualityBreakdownDto;
}

export interface EvidenceQualitySummaryDto {
  generated_at: string;
  record_count: number;
  weak_single_signal_count: number;
  corroborated_count: number;
  report_suitable_count: number;
  export_suitable_count: number;
  blocked_count: number;
  records: EvidenceQualityRecordDto[];
  quality_refs: Id[];
  evidence_refs: Id[];
  finding_refs: Id[];
  hypothesis_refs: Id[];
  risk_refs: Id[];
  baseline_refs: Id[];
  incident_group_refs: Id[];
  report_section_refs: Id[];
  export_result_refs: Id[];
  degraded_reason_summary: string[];
  missing_visibility_flags: string[];
  portable_no_retention: boolean;
  metadata_only: boolean;
  automatic_llm_calls: boolean;
  response_execution: boolean;
}

export interface FindingStateMutationRequestDto extends MutationReasonDto {
  finding_id: Id;
}

export interface FindingStateMutationResultDto {
  finding: FindingDto;
  applied_state: string;
}

export interface EscalateAlertRequestDto {
  alert_id: Id;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface AlertEscalationResultDto {
  alert: AlertDto;
  routed_to_incident_stage: boolean;
  incident_created?: IncidentDto | null;
}

export interface IncidentStatusMutationRequestDto {
  incident_id: Id;
  state: string;
  reason_redacted: string;
  requested_by_redacted?: string | null;
}

export interface IncidentStatusMutationResultDto {
  incident: IncidentDto;
  applied_state: string;
}
