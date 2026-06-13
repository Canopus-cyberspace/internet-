import type { Id, Timestamp } from "./common";

export type NavigationTargetKindDto =
  | "hypothesis"
  | "baseline"
  | "baseline_indicator"
  | "incident_linked_group"
  | "timeline_entry"
  | "source_reliability_summary"
  | "evidence"
  | "finding"
  | "risk"
  | "attack_technique_row"
  | "graph_hint"
  | "graph_node_summary"
  | "graph_edge_summary"
  | "graph_path_summary"
  | "report_section"
  | "export_history_entry"
  | "llm_story_record"
  | "evidence_quality_detail";

export type NavigationViewKindDto =
  | "investigation"
  | "evidence"
  | "graph"
  | "attack_coverage"
  | "timeline"
  | "report"
  | "export"
  | "story";

export type NavigationResolutionStatusDto = "resolved" | "degraded" | "missing";

export interface NavigationResolveRequestDto {
  session_id?: Id | null;
  source_view: NavigationViewKindDto;
  target_kind: NavigationTargetKindDto;
  target_id: Id | string;
}

export interface NavigationBreadcrumbDto {
  view_kind: NavigationViewKindDto;
  target_kind: NavigationTargetKindDto;
  target_id: string;
  display_label_category: string;
  time_bucket?: Timestamp | null;
  confidence_bucket?: string | null;
  degraded_reason?: string | null;
  redaction_status: string;
}

export interface NavigationReferenceDto {
  ref_id: string;
  ref_kind: NavigationTargetKindDto;
  target_kind: NavigationTargetKindDto;
  target_id: string;
  source_view: NavigationViewKindDto;
  target_view: NavigationViewKindDto;
  display_label_category: string;
  confidence_bucket?: string | null;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  redacted_summary: string;
  created_time_bucket?: Timestamp | null;
  provenance_id?: Id | null;
  redaction_status: string;
}

export interface NavigationTargetSummaryDto {
  target_kind: NavigationTargetKindDto;
  target_id: string;
  status: NavigationResolutionStatusDto;
  category: string;
  severity_risk_bucket?: string | null;
  confidence_bucket?: string | null;
  evidence_quality_bucket?: string | null;
  evidence_refs: string[];
  fact_refs: string[];
  hypothesis_refs: string[];
  finding_refs: string[];
  risk_refs: string[];
  baseline_refs: string[];
  incident_group_refs: string[];
  timeline_refs: string[];
  attack_refs: string[];
  graph_refs: string[];
  report_refs: string[];
  export_refs: string[];
  story_refs: string[];
  quality_refs?: string[];
  provenance_refs: string[];
  redacted_summary: string;
  created_time_bucket?: Timestamp | null;
  degraded_reason?: string | null;
  missing_visibility_flags: string[];
  redaction_status: string;
  metadata_only: boolean;
  session_scoped: boolean;
  automatic_llm_calls: boolean;
  response_execution: boolean;
}

export interface NavigationResolutionDto {
  session_id?: Id | null;
  status: NavigationResolutionStatusDto;
  breadcrumb: NavigationBreadcrumbDto;
  target: NavigationTargetSummaryDto;
  outgoing_refs: NavigationReferenceDto[];
  portable_no_retention: boolean;
  automatic_llm_calls: boolean;
  response_execution: boolean;
}
