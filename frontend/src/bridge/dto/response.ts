import type { Id, JsonValue, MutationReasonDto } from "./common";

export interface ResponsePlanDto {
  plan_id?: Id;
  source?: JsonValue;
  recommended_actions: JsonValue[];
  approval_required?: boolean;
  [key: string]: JsonValue | undefined;
}

export interface ResponseActionDto {
  action_id: Id;
  plan_id?: Id;
  approval_state?: string;
  rollback_plan?: JsonValue;
  [key: string]: JsonValue | undefined;
}

export interface CreateResponsePlanRequestDto {
  source: JsonValue;
  reason_redacted: string;
  created_by_redacted?: string | null;
}

export interface ResponsePlanMutationResultDto {
  plan: ResponsePlanDto;
  actions: ResponseActionDto[];
  execution_started: boolean;
}

export interface ResponseApprovalMutationRequestDto {
  action_id: Id;
  actor_redacted?: string | null;
  reason_redacted?: string | null;
}

export interface ResponseApprovalMutationResultDto {
  action: ResponseActionDto;
  approval_result: JsonValue;
  execution_started: boolean;
}

export interface RollbackResponseActionRequestDto extends MutationReasonDto {
  action_id: Id;
  actor_redacted?: string | null;
}

export interface RollbackResponseActionResultDto {
  rollback_result: JsonValue;
  execution_performed: boolean;
}
