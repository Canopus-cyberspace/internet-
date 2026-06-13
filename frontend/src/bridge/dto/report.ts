import type { Id, JsonValue, PageRequestDto, Timestamp } from "./common";

export interface ReportDto {
  report_id: Id;
  report_type?: string;
  title_redacted?: string;
  summary_redacted?: string;
  redaction_summary?: JsonValue;
  sections?: JsonValue[];
  [key: string]: JsonValue | undefined;
}

export interface GenerateIncidentReportRequestDto {
  incident_id: Id;
  requested_by_redacted?: string | null;
  reason_redacted: string;
}

export interface ReportGenerationResultDto {
  report: ReportDto;
}

export interface ExportReportRequestDto {
  report_id: Id;
  format: string;
  destination_metadata_redacted?: string | null;
  requested_by_redacted?: string | null;
  user_confirmed: boolean;
}

export interface ExportReportMutationResultDto {
  export_result: JsonValue;
  export_performed: boolean;
}

export interface ExportDestinationMetadataDto {
  destination_metadata_redacted?: string | null;
  local_export_only: boolean;
}

export interface ExportFileHashDto {
  algorithm: string;
  value: string;
  calculated_at: Timestamp;
}

export interface ExportHistoryRecordDto {
  export_result_id: Id;
  report_id: Id;
  format: string;
  destination: ExportDestinationMetadataDto;
  file_hash?: ExportFileHashDto | null;
  redaction_summary: JsonValue;
  graph_snapshot_refs?: Id[];
  evidence_refs?: Id[];
  response_result_refs?: Id[];
  rollback_result_refs?: Id[];
  llm_story_refs?: Id[];
  actor_redacted: string;
  exported_at: Timestamp;
  trace_id?: Id | null;
  audit_id: Id;
  success: boolean;
}

export interface ExportPolicyViolationDto {
  violation_id: Id;
  report_id: Id;
  format: string;
  destination: ExportDestinationMetadataDto;
  actor_redacted: string;
  reason_redacted: string;
  redaction_summary: JsonValue;
  occurred_at: Timestamp;
  trace_id?: Id | null;
  audit_id: Id;
  export_audit_id?: Id | null;
}

export interface ReportExportHistoryQueryDto {
  page?: PageRequestDto;
  report_id?: Id | null;
  format?: string | null;
  actor_redacted?: string | null;
  time_range?: JsonValue | null;
  success?: boolean | null;
}

export type ExplicitSaveActionDto =
  | { kind: "save_session" }
  | { kind: "export_report"; incident_id: Id }
  | { kind: "export_graph" };

export type ExplicitExportFormatDto = "sg_session" | "sg_report" | "sg_graph";

export interface ExplicitRedactionOptionsDto {
  strict: boolean;
  include_hostnames: boolean;
  include_process_names: boolean;
}

export interface ExplicitExportRequestDto {
  export_id: Id;
  session_id: Id;
  action: ExplicitSaveActionDto;
  format: ExplicitExportFormatDto;
  destination_path: string;
  redaction_options: ExplicitRedactionOptionsDto;
  requested_by_redacted: string;
  requested_at: Timestamp;
  user_initiated: boolean;
}

export interface ExplicitExportRedactionSummaryDto {
  redacted_field_count: number;
  tokenized_field_count: number;
  removed_field_count: number;
  summarized_field_count: number;
  passed: boolean;
  methods: string[];
  manifest: Record<string, string>;
}

export interface ExplicitExportSummaryDto {
  observation_count: number;
  finding_count: number;
  alert_count: number;
  incident_count: number;
  graph_node_count: number;
  graph_edge_count: number;
  response_recommendation_count: number;
  report_count: number;
  quality_record_count?: number;
  report_suitable_quality_count?: number;
  export_suitable_quality_count?: number;
  blocked_quality_count?: number;
  native_sampler_contract_count?: number;
  native_sampler_ready_count?: number;
  native_sampler_blocked_count?: number;
  edr_active_sampler_count?: number;
  included_sections: string[];
  excluded_sections: string[];
}

export interface ExplicitExportFormatContractDto {
  format: ExplicitExportFormatDto;
  extension: string;
  schema_name: string;
  content_type: string;
  redaction_rules: JsonValue[];
  excluded_data_classes: string[];
}

export interface ExplicitExportPreviewDto {
  export_id: Id;
  summary: ExplicitExportSummaryDto;
  redaction_summary: ExplicitExportRedactionSummaryDto;
  estimated_size_bytes: number;
  destination_path: string;
  format_contract: ExplicitExportFormatContractDto;
  generated_at: Timestamp;
}

export interface ExplicitExportConfirmationDto {
  export_id: Id;
  user_confirmed: boolean;
  confirmed_at?: Timestamp | null;
}

export interface ExplicitExportResultDto {
  export_result_id: Id;
  export_id: Id;
  file_hash: string;
  file_size_bytes: number;
  written_at: Timestamp;
  redaction_summary_applied: ExplicitExportRedactionSummaryDto;
  format: ExplicitExportFormatDto;
  destination_path: string;
}
