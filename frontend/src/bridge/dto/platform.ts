import type { Id, JsonValue, PrivacyClass, Timestamp } from "./common";

export type HealthStatusDto =
  | "unknown"
  | "healthy"
  | "degraded"
  | "failed"
  | "stale"
  | "unavailable"
  | "disconnected"
  | "unauthorized"
  | string;

export interface ComponentSummaryDto {
  component_id: Id;
  component_type: string;
  name: string;
  version: string;
  state: string;
  health_status: string;
  runtime_mode: string;
  plugin_id?: Id | null;
  capability_domain?: string | null;
  capability_tags: string[];
}

export interface ComponentDetailDto {
  definition: JsonValue;
  instance?: JsonValue | null;
  runtime?: JsonValue | null;
  plugin_manifest?: JsonValue | null;
  health?: HealthSnapshotDto | null;
  ui_contributions: JsonValue[];
}

export interface HealthSnapshotDto {
  subject: JsonValue;
  status: HealthStatusDto;
  liveness: HealthStatusDto;
  readiness: HealthStatusDto;
  message_redacted?: string | null;
  observed_at: Timestamp;
  privacy_class: PrivacyClass;
}

export interface MetricSampleDto {
  metric_name: string;
  value: JsonValue;
  labels: Record<string, string>;
  observed_at: Timestamp;
  privacy_class: PrivacyClass;
}

export interface ServiceStatusViewDto {
  connected: boolean;
  degraded: boolean;
  reason?: string | null;
  profile_mode: string;
  active_session_id?: Id | null;
  local_core_status: HealthStatusDto;
  elevated_service_status: HealthStatusDto;
  ipc_status: HealthStatusDto;
  storage_status: HealthStatusDto;
  reduced_visibility: boolean;
  privileged_actions_available: boolean;
  capture_available: boolean;
  machine_local_capability_status?: CapabilityStatusSummaryDto | null;
  mutation_authorization_status?: MutationAuthorizationStatusDto | null;
  message_redacted: string;
  generated_at: Timestamp;
}

export interface MutationAuthorizationStatusDto {
  schema_version: JsonValue;
  framework_state: string;
  policy_catalog_version: JsonValue;
  supported_command_count: number;
  dry_run_only: boolean;
  production_execution_enabled: boolean;
  last_decision_category?: string | null;
  denied_count_bucket: string;
  expired_count_bucket: string;
  replay_count_bucket: string;
  caller_trust_ready: boolean;
  ownership_runtime_ready: boolean;
  degraded_reasons: string[];
  audit_refs: string[];
  provenance_id: string;
  redaction_status: string;
}

export type CapabilityStatusDto =
  | "available"
  | "degraded"
  | "unavailable"
  | "requires_setup"
  | "requires_admin"
  | "unsupported"
  | "blocked_by_env"
  | string;

export interface MachineLocalCapabilityStatusDto {
  capability: string;
  status: CapabilityStatusDto;
  reason?: string | null;
  action?: string | null;
}

export interface CapabilityStatusSummaryDto {
  capabilities: MachineLocalCapabilityStatusDto[];
  all_available: boolean;
  degraded_count: number;
  unavailable_count: number;
  requires_setup_count: number;
  detected_at: Timestamp;
}

export type PortablePreferencesDto = Record<string, JsonValue>;
