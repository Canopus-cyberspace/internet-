export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { readonly [key: string]: JsonValue };

export type Id = string;
export type Timestamp = string;
export type PrivacyClass =
  | "public"
  | "internal"
  | "sensitive"
  | "secret"
  | string;

export interface PageRequestDto {
  cursor?: string | null;
  limit?: number;
}

export interface PageResponseDto<T> {
  items: T[];
  limit: number;
  cursor?: string | null;
  next_cursor?: string | null;
  has_more: boolean;
}

export interface QueryRequestDto {
  scope?: JsonValue;
  filters?: JsonValue[];
  sort?: JsonValue[];
  page?: PageRequestDto;
  time_range?: JsonValue | null;
}

export interface RedactedLabelDto {
  value_redacted: string;
  privacy_class: PrivacyClass;
}

export interface CommandReceiptDto<T> {
  command: string;
  result: T;
  permission_decision?: JsonValue;
  audit_receipt?: JsonValue;
  trace_id: Id;
  rollback?: JsonValue | null;
  generated_at: Timestamp;
}

export interface MutationReasonDto {
  reason_redacted: string;
  requested_by_redacted?: string | null;
}
