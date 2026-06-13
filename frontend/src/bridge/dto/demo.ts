import type { Id, JsonValue, Timestamp } from "./common";

export type StoryStageDto =
  | "metadata_input"
  | "observation"
  | "enrichment_context"
  | "finding_evidence"
  | "risk_alert_incident"
  | "graph"
  | "response_recommendation"
  | "redacted_report"
  | string;

export interface StoryStageResultDto {
  stage: StoryStageDto;
  summary_redacted: string;
  started_at: Timestamp;
  completed_at: Timestamp;
  duration_millis: number;
  input_artifact_count: number;
  produced_artifact_count: number;
  evidence_ref_count: number;
  replay_only: boolean;
  safe_replay_note_redacted: string;
}

export interface DemoStoryResultDto {
  story_id: string;
  fixture_mode: "DEMO_ONLY" | "FIXTURE_ONLY" | string;
  title_redacted: string;
  replay_only: boolean;
  execution_disabled: boolean;
  started_at: Timestamp;
  completed_at: Timestamp;
  stage_count: number;
  stages: StoryStageResultDto[];
  flow_count: number;
  dns_observation_count: number;
  tls_observation_count: number;
  evidence_item_count: number;
  finding_count: number;
  risk_event_count: number;
  alert_count: number;
  incident_count: number;
  graph_view_count: number;
  graph_node_count: number;
  graph_edge_count: number;
  graph_path_count: number;
  response_plan_count: number;
  recommended_action_count: number;
  policy_decision_count: number;
  report_count: number;
  report_section_count: number;
  export_history_count: number;
  incident_id: Id;
  report_id: Id;
  export_result_id: Id;
  graph_view_id: Id;
  response_plan_id: Id;
  redaction_summary: JsonValue;
}
