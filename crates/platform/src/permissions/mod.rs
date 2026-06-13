use crate::component::ComponentId;
use crate::registry::PluginRegistry;
use crate::resolver::{
    ResolutionIssue, ResolutionIssueKind, ResolutionReport, ResolutionSeverity, ResolutionStatus,
};
use sentinel_contracts::{
    AuditId, PermissionCategory, PermissionDescriptor, PermissionKey, PermissionRiskLevel,
    PluginId, PluginManifest, ResponseActionType, ResponseMode, ResponsePolicy, RuntimeProfile,
    SchemaVersion, SettingsChangeKind, Timestamp, UiContribution, UiContributionId,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDomain {
    Data,
    System,
    Response,
    Export,
    Desktop,
    Policy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    pub key: PermissionKey,
    pub domain: PermissionDomain,
    pub category: PermissionCategory,
    pub risk_level: PermissionRiskLevel,
    pub description_redacted: String,
    pub default_grant: bool,
    pub audit_required: bool,
    pub approval_required: bool,
}

impl Permission {
    pub fn from_descriptor(descriptor: &PermissionDescriptor) -> Self {
        let domain = PermissionDomain::from_category(&descriptor.category);
        let sensitive = is_sensitive_permission_key(&descriptor.permission)
            || matches!(
                descriptor.risk_level,
                PermissionRiskLevel::High | PermissionRiskLevel::Critical
            );

        Self {
            key: descriptor.permission.clone(),
            domain,
            category: descriptor.category.clone(),
            risk_level: descriptor.risk_level.clone(),
            description_redacted: descriptor.description.clone(),
            default_grant: !sensitive,
            audit_required: sensitive,
            approval_required: matches!(
                descriptor.risk_level,
                PermissionRiskLevel::High | PermissionRiskLevel::Critical
            ),
        }
    }
}

impl PermissionDomain {
    pub fn from_category(category: &PermissionCategory) -> Self {
        match category {
            PermissionCategory::DataAccess => Self::Data,
            PermissionCategory::SystemAccess => Self::System,
            PermissionCategory::ResponseAccess => Self::Response,
            PermissionCategory::ExportAccess => Self::Export,
            PermissionCategory::DesktopAccess => Self::Desktop,
            PermissionCategory::PolicyAccess => Self::Policy,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PermissionSubject {
    Plugin(PluginId),
    Component(ComponentId),
    TauriCommand(String),
    ServiceIpcCommand(String),
    UiContribution(UiContributionId),
    LocalCore,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope_type", rename_all = "snake_case")]
pub enum PermissionScope {
    Data {
        resource: String,
        operation: String,
        metadata_only: bool,
    },
    System {
        command: String,
        elevated_service_required: bool,
    },
    Response {
        action_type: ResponseActionType,
        execute: bool,
    },
    Export {
        export_kind: String,
        redaction_required: bool,
    },
    Desktop {
        surface: String,
    },
    Policy {
        policy_key: String,
        mutation: bool,
    },
}

impl PermissionScope {
    pub fn domain(&self) -> PermissionDomain {
        match self {
            Self::Data { .. } => PermissionDomain::Data,
            Self::System { .. } => PermissionDomain::System,
            Self::Response { .. } => PermissionDomain::Response,
            Self::Export { .. } => PermissionDomain::Export,
            Self::Desktop { .. } => PermissionDomain::Desktop,
            Self::Policy { .. } => PermissionDomain::Policy,
        }
    }

    pub fn requires_audit(&self) -> bool {
        match self {
            Self::System { .. } | Self::Response { .. } | Self::Export { .. } => true,
            Self::Policy { mutation, .. } => *mutation,
            Self::Data { metadata_only, .. } => !metadata_only,
            Self::Desktop { .. } => false,
        }
    }

    pub fn requires_policy_evaluation(&self) -> bool {
        matches!(
            self,
            Self::Response { execute: true, .. }
                | Self::Export { .. }
                | Self::Policy { mutation: true, .. }
                | Self::System {
                    elevated_service_required: true,
                    ..
                }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyScope {
    Plugin,
    TauriReadCommand,
    TauriMutationCommand,
    ServiceIpc,
    ResponsePlanning,
    ResponseExecution,
    Export,
    SettingsMutation,
    UiContribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecisionKind {
    Allow,
    Deny,
    NeedsApproval,
    Unavailable,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedReasonCode {
    MissingPermission,
    SensitiveDataForbidden,
    RawPacketForbidden,
    PayloadForbidden,
    HttpBodyForbidden,
    CredentialSecretForbidden,
    FrontendServiceBypassForbidden,
    FrontendSqliteBypassForbidden,
    DirectResponseExecutionForbidden,
    ResponsePolicyRequired,
    ApprovalRequired,
    AuditRequired,
    RollbackRequired,
    ServiceUnavailable,
    ExportRedactionRequired,
    SettingsPolicyViolation,
    PermissionUnavailable,
    NotApplicable,
    UnknownPermission,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeniedReason {
    pub code: DeniedReasonCode,
    pub reason_redacted: String,
    pub detail_redacted: Option<String>,
}

impl DeniedReason {
    pub fn new(code: DeniedReasonCode, reason_redacted: impl Into<String>) -> Self {
        Self {
            code,
            reason_redacted: reason_redacted.into(),
            detail_redacted: None,
        }
    }

    pub fn with_detail(mut self, detail_redacted: impl Into<String>) -> Self {
        self.detail_redacted = Some(detail_redacted.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRequirement {
    pub audit_required: bool,
    pub event_type: String,
    pub reason_codes: Vec<DeniedReasonCode>,
    pub sensitive_data_touched: bool,
    pub rollback_required: bool,
    pub approval_required: bool,
    pub audit_ref: Option<AuditId>,
}

impl AuditRequirement {
    pub fn none() -> Self {
        Self {
            audit_required: false,
            event_type: "permission.no_audit_required".to_string(),
            reason_codes: Vec::new(),
            sensitive_data_touched: false,
            rollback_required: false,
            approval_required: false,
            audit_ref: None,
        }
    }

    pub fn required(event_type: impl Into<String>) -> Self {
        Self {
            audit_required: true,
            event_type: event_type.into(),
            reason_codes: Vec::new(),
            sensitive_data_touched: false,
            rollback_required: false,
            approval_required: false,
            audit_ref: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub subject: PermissionSubject,
    pub permission: PermissionKey,
    pub scope: PermissionScope,
    pub policy_scope: PolicyScope,
    pub reason_redacted: String,
    pub requested_at: Timestamp,
    pub policy_evaluation_required: bool,
    pub audit_requested: bool,
}

impl PermissionRequest {
    pub fn new(
        subject: PermissionSubject,
        permission: PermissionKey,
        scope: PermissionScope,
        policy_scope: PolicyScope,
        reason_redacted: impl Into<String>,
    ) -> Self {
        let policy_evaluation_required = scope.requires_policy_evaluation();
        let audit_requested = scope.requires_audit();

        Self {
            subject,
            permission,
            scope,
            policy_scope,
            reason_redacted: reason_redacted.into(),
            requested_at: Timestamp::now(),
            policy_evaluation_required,
            audit_requested,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionDecision {
    pub decision: PermissionDecisionKind,
    pub permission: PermissionKey,
    pub subject: PermissionSubject,
    pub scope: PermissionScope,
    pub policy_scope: PolicyScope,
    pub reasons: Vec<DeniedReason>,
    pub audit_requirement: AuditRequirement,
    pub policy_evaluation_required: bool,
    pub policy_evaluated: bool,
    pub created_at: Timestamp,
}

impl PermissionDecision {
    pub fn is_ready(&self) -> bool {
        matches!(self.decision, PermissionDecisionKind::Allow)
    }

    pub fn resolution_status(&self) -> ResolutionStatus {
        match self.decision {
            PermissionDecisionKind::Allow | PermissionDecisionKind::NotApplicable => {
                ResolutionStatus::Compatible
            }
            PermissionDecisionKind::NeedsApproval | PermissionDecisionKind::Unavailable => {
                ResolutionStatus::Degraded
            }
            PermissionDecisionKind::Deny => ResolutionStatus::Incompatible,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationContext {
    pub policy_scope: PolicyScope,
    pub subject: PermissionSubject,
    pub permission: PermissionKey,
    pub permission_scope: PermissionScope,
    pub runtime_profile: RuntimeProfile,
    pub response_policy: ResponsePolicy,
    pub policy_version: SchemaVersion,
    pub service_available: bool,
    pub policy_hook_available: bool,
    pub approval_already_granted: bool,
    pub rollback_available: bool,
    pub redaction_confirmed: bool,
    pub is_replay: bool,
    pub detail_redacted: Option<String>,
}

impl PolicyEvaluationContext {
    pub fn new(
        policy_scope: PolicyScope,
        subject: PermissionSubject,
        permission: PermissionKey,
        permission_scope: PermissionScope,
        runtime_profile: RuntimeProfile,
    ) -> Self {
        Self {
            response_policy: runtime_profile.response_policy.clone(),
            policy_version: runtime_profile.schema_version.clone(),
            policy_scope,
            subject,
            permission,
            permission_scope,
            runtime_profile,
            service_available: true,
            policy_hook_available: true,
            approval_already_granted: false,
            rollback_available: false,
            redaction_confirmed: false,
            is_replay: false,
            detail_redacted: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub decision: PermissionDecisionKind,
    pub status: ResolutionStatus,
    pub reasons: Vec<DeniedReason>,
    pub audit_requirement: AuditRequirement,
    pub policy_version: SchemaVersion,
    pub evaluated_at: Timestamp,
}

impl PolicyEvaluationResult {
    pub fn from_decision(
        decision: PermissionDecisionKind,
        reasons: Vec<DeniedReason>,
        audit_requirement: AuditRequirement,
        policy_version: SchemaVersion,
    ) -> Self {
        let status = match decision {
            PermissionDecisionKind::Allow | PermissionDecisionKind::NotApplicable => {
                ResolutionStatus::Compatible
            }
            PermissionDecisionKind::NeedsApproval | PermissionDecisionKind::Unavailable => {
                ResolutionStatus::Degraded
            }
            PermissionDecisionKind::Deny => ResolutionStatus::Incompatible,
        };

        Self {
            decision,
            status,
            reasons,
            audit_requirement,
            policy_version,
            evaluated_at: Timestamp::now(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PermissionResolver {
    permissions: HashMap<PermissionKey, Permission>,
    grants: HashMap<PermissionSubject, HashSet<PermissionKey>>,
    unavailable_permissions: HashSet<PermissionKey>,
}

impl PermissionResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission.key.clone(), permission);
    }

    pub fn register_descriptor(&mut self, descriptor: &PermissionDescriptor) {
        self.register_permission(Permission::from_descriptor(descriptor));
    }

    pub fn grant(&mut self, subject: PermissionSubject, permission: PermissionKey) {
        self.grants.entry(subject).or_default().insert(permission);
    }

    pub fn mark_unavailable(&mut self, permission: PermissionKey) {
        self.unavailable_permissions.insert(permission);
    }

    pub fn register_plugin_manifest_permissions(&mut self, manifest: &PluginManifest) {
        let subject = PermissionSubject::Plugin(manifest.plugin_id.clone());
        for descriptor in &manifest.required_permissions {
            self.register_descriptor(descriptor);
            if Permission::from_descriptor(descriptor).default_grant {
                self.grant(subject.clone(), descriptor.permission.clone());
            }
        }
    }

    pub fn register_ui_contribution_permissions(&mut self, contribution: &UiContribution) {
        let subject = PermissionSubject::UiContribution(contribution.contribution_id.clone());
        for descriptor in &contribution.permissions {
            self.register_descriptor(descriptor);
            if Permission::from_descriptor(descriptor).default_grant {
                self.grant(subject.clone(), descriptor.permission.clone());
            }
        }
    }

    pub fn evaluate_permission(
        &self,
        request: PermissionRequest,
        policy_result: Option<&PolicyEvaluationResult>,
    ) -> PermissionDecision {
        let mut reasons = Vec::new();
        let mut audit_requirement = if request.audit_requested {
            AuditRequirement::required(audit_event_type(&request.policy_scope))
        } else {
            AuditRequirement::none()
        };

        if self.unavailable_permissions.contains(&request.permission) {
            reasons.push(DeniedReason::new(
                DeniedReasonCode::PermissionUnavailable,
                "permission is currently unavailable",
            ));
            return self.make_decision(
                request,
                PermissionDecisionKind::Unavailable,
                reasons,
                audit_requirement,
                false,
            );
        }

        let Some(permission) = self.permissions.get(&request.permission) else {
            reasons.push(DeniedReason::new(
                DeniedReasonCode::UnknownPermission,
                "permission is not registered",
            ));
            return self.make_decision(
                request,
                PermissionDecisionKind::Deny,
                reasons,
                audit_requirement,
                false,
            );
        };

        if permission.domain != request.scope.domain() {
            reasons.push(DeniedReason::new(
                DeniedReasonCode::NotApplicable,
                "permission domain does not apply to requested scope",
            ));
            return self.make_decision(
                request,
                PermissionDecisionKind::NotApplicable,
                reasons,
                audit_requirement,
                false,
            );
        }

        audit_requirement.audit_required |= permission.audit_required;
        audit_requirement.approval_required |= permission.approval_required;

        reasons.extend(static_guardrails(&request));
        if !reasons.is_empty() {
            audit_requirement.reason_codes =
                reasons.iter().map(|reason| reason.code.clone()).collect();
            return self.make_decision(
                request,
                PermissionDecisionKind::Deny,
                reasons,
                audit_requirement,
                false,
            );
        }

        let granted = self
            .grants
            .get(&request.subject)
            .is_some_and(|grants| grants.contains(&request.permission));

        if !granted {
            reasons.push(DeniedReason::new(
                DeniedReasonCode::MissingPermission,
                "required permission has not been granted",
            ));
            audit_requirement.reason_codes =
                reasons.iter().map(|reason| reason.code.clone()).collect();
            return self.make_decision(
                request,
                PermissionDecisionKind::Deny,
                reasons,
                audit_requirement,
                false,
            );
        }

        if request.policy_evaluation_required {
            let Some(policy_result) = policy_result else {
                reasons.push(DeniedReason::new(
                    DeniedReasonCode::ResponsePolicyRequired,
                    "policy evaluation is required before this permission can be used",
                ));
                audit_requirement.reason_codes =
                    reasons.iter().map(|reason| reason.code.clone()).collect();
                return self.make_decision(
                    request,
                    PermissionDecisionKind::NeedsApproval,
                    reasons,
                    audit_requirement,
                    false,
                );
            };

            audit_requirement.audit_required |= policy_result.audit_requirement.audit_required;
            audit_requirement.approval_required |=
                policy_result.audit_requirement.approval_required;
            audit_requirement.rollback_required |=
                policy_result.audit_requirement.rollback_required;
            audit_requirement.sensitive_data_touched |=
                policy_result.audit_requirement.sensitive_data_touched;

            if !matches!(policy_result.decision, PermissionDecisionKind::Allow) {
                reasons.extend(policy_result.reasons.clone());
                audit_requirement.reason_codes =
                    reasons.iter().map(|reason| reason.code.clone()).collect();
                return self.make_decision(
                    request,
                    policy_result.decision.clone(),
                    reasons,
                    audit_requirement,
                    true,
                );
            }
        }

        self.make_decision(
            request,
            PermissionDecisionKind::Allow,
            reasons,
            audit_requirement,
            policy_result.is_some(),
        )
    }

    pub fn evaluate_policy(&self, context: PolicyEvaluationContext) -> PolicyEvaluationResult {
        let mut reasons = Vec::new();
        let mut audit_requirement = if context.permission_scope.requires_audit() {
            AuditRequirement::required(audit_event_type(&context.policy_scope))
        } else {
            AuditRequirement::none()
        };

        if !context.policy_hook_available {
            reasons.push(DeniedReason::new(
                DeniedReasonCode::ResponsePolicyRequired,
                "policy hook is unavailable",
            ));
            return PolicyEvaluationResult::from_decision(
                PermissionDecisionKind::Unavailable,
                reasons,
                audit_requirement,
                context.policy_version,
            );
        }

        reasons.extend(profile_guardrails(&context));

        match &context.permission_scope {
            PermissionScope::Response {
                action_type,
                execute,
            } => {
                audit_requirement.audit_required = true;
                audit_requirement.rollback_required = *execute;
                evaluate_response_policy(
                    action_type,
                    *execute,
                    &context,
                    &mut reasons,
                    &mut audit_requirement,
                );
            }
            PermissionScope::Export {
                redaction_required, ..
            } => {
                audit_requirement.audit_required = true;
                audit_requirement.sensitive_data_touched = true;
                if *redaction_required && !context.redaction_confirmed {
                    reasons.push(DeniedReason::new(
                        DeniedReasonCode::ExportRedactionRequired,
                        "export requires redaction confirmation",
                    ));
                }
            }
            PermissionScope::System {
                elevated_service_required,
                ..
            } => {
                audit_requirement.audit_required = true;
                if *elevated_service_required && !context.service_available {
                    reasons.push(DeniedReason::new(
                        DeniedReasonCode::ServiceUnavailable,
                        "required elevated service is unavailable",
                    ));
                }
            }
            PermissionScope::Policy { mutation, .. } => {
                if *mutation {
                    audit_requirement.audit_required = true;
                }
            }
            PermissionScope::Data { metadata_only, .. } => {
                audit_requirement.sensitive_data_touched = !metadata_only;
            }
            PermissionScope::Desktop { .. } => {}
        }

        audit_requirement.reason_codes = reasons.iter().map(|reason| reason.code.clone()).collect();

        let decision = if reasons
            .iter()
            .any(|reason| !matches!(reason.code, DeniedReasonCode::ApprovalRequired))
        {
            PermissionDecisionKind::Deny
        } else if reasons
            .iter()
            .any(|reason| reason.code == DeniedReasonCode::ApprovalRequired)
        {
            PermissionDecisionKind::NeedsApproval
        } else {
            PermissionDecisionKind::Allow
        };

        PolicyEvaluationResult::from_decision(
            decision,
            reasons,
            audit_requirement,
            context.policy_version,
        )
    }

    pub fn resolve_plugin_manifest(
        &self,
        manifest: &PluginManifest,
        plugin_registry: &PluginRegistry,
    ) -> ResolutionReport {
        let mut issues = Vec::new();

        if plugin_registry.get(&manifest.plugin_id).is_none() {
            issues.push(
                ResolutionIssue::warning(
                    ResolutionIssueKind::InvalidManifest,
                    "plugin manifest has not been registered before permission resolution",
                )
                .for_plugin(manifest.plugin_id.clone()),
            );
        }

        for descriptor in &manifest.required_permissions {
            if !self.permissions.contains_key(&descriptor.permission) {
                issues.push(ResolutionIssue {
                    severity: ResolutionSeverity::Blocker,
                    kind: ResolutionIssueKind::MissingPermission,
                    component_id: None,
                    plugin_id: Some(manifest.plugin_id.clone()),
                    capability_id: None,
                    contract_name: None,
                    dependency_name: Some(descriptor.permission.to_string()),
                    message: "required permission is not registered".to_string(),
                });
            }

            if descriptor.required {
                let subject = PermissionSubject::Plugin(manifest.plugin_id.clone());
                let granted = self
                    .grants
                    .get(&subject)
                    .is_some_and(|grants| grants.contains(&descriptor.permission));
                if !granted {
                    issues.push(ResolutionIssue {
                        severity: ResolutionSeverity::Blocker,
                        kind: ResolutionIssueKind::MissingPermission,
                        component_id: None,
                        plugin_id: Some(manifest.plugin_id.clone()),
                        capability_id: None,
                        contract_name: None,
                        dependency_name: Some(descriptor.permission.to_string()),
                        message: "required permission has not been granted".to_string(),
                    });
                }
            }
        }

        ResolutionReport::from_issues(issues)
    }

    fn make_decision(
        &self,
        request: PermissionRequest,
        decision: PermissionDecisionKind,
        reasons: Vec<DeniedReason>,
        mut audit_requirement: AuditRequirement,
        policy_evaluated: bool,
    ) -> PermissionDecision {
        if audit_requirement.reason_codes.is_empty() {
            audit_requirement.reason_codes =
                reasons.iter().map(|reason| reason.code.clone()).collect();
        }

        PermissionDecision {
            decision,
            permission: request.permission,
            subject: request.subject,
            scope: request.scope,
            policy_scope: request.policy_scope,
            reasons,
            audit_requirement,
            policy_evaluation_required: request.policy_evaluation_required,
            policy_evaluated,
            created_at: Timestamp::now(),
        }
    }
}

fn static_guardrails(request: &PermissionRequest) -> Vec<DeniedReason> {
    let mut reasons = Vec::new();
    let key = request.permission.as_str();

    if matches!(request.subject, PermissionSubject::TauriCommand(_))
        && key.contains("elevated_service.direct")
    {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::FrontendServiceBypassForbidden,
            "frontend must not directly call the elevated service",
        ));
    }

    if matches!(request.subject, PermissionSubject::TauriCommand(_))
        && key.contains("sqlite.direct")
    {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::FrontendSqliteBypassForbidden,
            "frontend must not directly read SQLite",
        ));
    }

    if is_sensitive_permission_key(&request.permission) {
        reasons.push(sensitive_permission_reason(&request.permission));
    }

    if matches!(
        request.scope,
        PermissionScope::Response { execute: true, .. }
    ) && !request.policy_evaluation_required
    {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::DirectResponseExecutionForbidden,
            "response execution requires policy evaluation",
        ));
    }

    reasons
}

fn profile_guardrails(context: &PolicyEvaluationContext) -> Vec<DeniedReason> {
    let mut reasons = Vec::new();
    let profile = &context.runtime_profile;
    let key = context.permission.as_str();

    if key.contains("raw_packet") || profile.privacy_policy.raw_packet_storage_enabled {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::RawPacketForbidden,
            "raw packet access or persistence is forbidden in normal mode",
        ));
    }
    if key.contains("payload") || profile.privacy_policy.payload_storage_enabled {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::PayloadForbidden,
            "payload access or persistence is forbidden in normal mode",
        ));
    }
    if key.contains("http_body") || profile.privacy_policy.http_body_storage_enabled {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::HttpBodyForbidden,
            "HTTP body access or persistence is forbidden in normal mode",
        ));
    }
    if profile
        .privacy_policy
        .cookie_token_credential_storage_enabled
        || profile.privacy_policy.authorization_header_storage_enabled
        || profile.privacy_policy.api_key_storage_enabled
        || contains_secret_token(key)
    {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::CredentialSecretForbidden,
            "cookies, tokens, credentials, Authorization headers, API keys, and secrets are forbidden",
        ));
    }

    if matches!(context.policy_scope, PolicyScope::SettingsMutation)
        && context.runtime_profile.validate().is_err()
    {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::SettingsPolicyViolation,
            "requested settings profile violates safe policy defaults",
        ));
    }

    reasons
}

fn evaluate_response_policy(
    action_type: &ResponseActionType,
    execute: bool,
    context: &PolicyEvaluationContext,
    reasons: &mut Vec<DeniedReason>,
    audit_requirement: &mut AuditRequirement,
) {
    if !execute {
        return;
    }

    audit_requirement.audit_required = true;
    audit_requirement.rollback_required = true;

    if context.is_replay && context.response_policy.replay_execution_disabled {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::DirectResponseExecutionForbidden,
            "response execution is disabled in replay mode",
        ));
    }

    if !context.rollback_available || !context.response_policy.rollback_required {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::RollbackRequired,
            "response execution requires rollback metadata",
        ));
    }

    if !context.response_policy.audit_required {
        reasons.push(DeniedReason::new(
            DeniedReasonCode::AuditRequired,
            "response execution requires audit metadata",
        ));
    }

    match context.response_policy.mode {
        ResponseMode::RecommendOnly => {
            reasons.push(DeniedReason::new(
                DeniedReasonCode::ResponsePolicyRequired,
                "current response policy is recommend-only",
            ));
        }
        ResponseMode::ApprovalRequired => {
            if !context.approval_already_granted {
                audit_requirement.approval_required = true;
                reasons.push(DeniedReason::new(
                    DeniedReasonCode::ApprovalRequired,
                    "response policy requires approval",
                ));
            }
        }
        ResponseMode::AutoContainmentLite => {
            if !is_allowed_auto_action(action_type, &context.response_policy) {
                if context.approval_already_granted {
                    audit_requirement.approval_required = true;
                } else {
                    audit_requirement.approval_required = true;
                    reasons.push(DeniedReason::new(
                        DeniedReasonCode::ApprovalRequired,
                        "response action is outside auto-containment allowlist",
                    ));
                }
            }
        }
    }
}

fn is_allowed_auto_action(action_type: &ResponseActionType, policy: &ResponsePolicy) -> bool {
    let key = match action_type {
        ResponseActionType::MaliciousDestinationAutoBlock => "malicious_destination_auto_block",
        ResponseActionType::ExfiltrationAutoThrottle => "exfiltration_auto_throttle",
        ResponseActionType::DecoyOutboundAutoBlock => "decoy_outbound_auto_block",
        _ => return false,
    };

    policy.allowed_auto_actions.iter().any(|value| value == key)
}

fn audit_event_type(policy_scope: &PolicyScope) -> String {
    match policy_scope {
        PolicyScope::Plugin => "permission.plugin.evaluate",
        PolicyScope::TauriReadCommand => "permission.tauri.read.evaluate",
        PolicyScope::TauriMutationCommand => "permission.tauri.mutation.evaluate",
        PolicyScope::ServiceIpc => "permission.service_ipc.evaluate",
        PolicyScope::ResponsePlanning => "permission.response.plan.evaluate",
        PolicyScope::ResponseExecution => "permission.response.execute.evaluate",
        PolicyScope::Export => "permission.export.evaluate",
        PolicyScope::SettingsMutation => "permission.settings.evaluate",
        PolicyScope::UiContribution => "permission.ui_contribution.evaluate",
    }
    .to_string()
}

fn is_sensitive_permission_key(permission: &PermissionKey) -> bool {
    let key = permission.as_str();
    key.contains("raw_packet")
        || key.contains("payload")
        || key.contains("http_body")
        || key.contains("raw_event")
        || key.contains("firewall.write")
        || key.contains("qos.write")
        || key.contains("process.control")
        || key.contains("export.raw")
        || contains_secret_token(key)
}

fn sensitive_permission_reason(permission: &PermissionKey) -> DeniedReason {
    let key = permission.as_str();

    if key.contains("raw_packet") {
        DeniedReason::new(
            DeniedReasonCode::RawPacketForbidden,
            "raw packet permission is not granted by default",
        )
    } else if key.contains("payload") {
        DeniedReason::new(
            DeniedReasonCode::PayloadForbidden,
            "payload permission is not granted by default",
        )
    } else if key.contains("http_body") {
        DeniedReason::new(
            DeniedReasonCode::HttpBodyForbidden,
            "HTTP body permission is not granted by default",
        )
    } else if contains_secret_token(key) {
        DeniedReason::new(
            DeniedReasonCode::CredentialSecretForbidden,
            "secret-bearing permission is not granted by default",
        )
    } else if key.contains("firewall.write")
        || key.contains("qos.write")
        || key.contains("process.control")
    {
        DeniedReason::new(
            DeniedReasonCode::DirectResponseExecutionForbidden,
            "sensitive response or system action requires policy evaluation",
        )
    } else {
        DeniedReason::new(
            DeniedReasonCode::SensitiveDataForbidden,
            "sensitive permission is not granted by default",
        )
    }
}

fn contains_secret_token(value: &str) -> bool {
    value.contains("cookie")
        || value.contains("token")
        || value.contains("credential")
        || value.contains("authorization_header")
        || value.contains("api_key")
        || value.contains("secret")
}

pub fn permission_scope_for_descriptor(descriptor: &PermissionDescriptor) -> PermissionScope {
    match descriptor.category {
        PermissionCategory::DataAccess => PermissionScope::Data {
            resource: descriptor.permission.to_string(),
            operation: "metadata".to_string(),
            metadata_only: !is_sensitive_permission_key(&descriptor.permission),
        },
        PermissionCategory::SystemAccess => PermissionScope::System {
            command: descriptor.permission.to_string(),
            elevated_service_required: true,
        },
        PermissionCategory::ResponseAccess => PermissionScope::Response {
            action_type: ResponseActionType::Custom(descriptor.permission.to_string()),
            execute: descriptor.permission.as_str().contains("execute"),
        },
        PermissionCategory::ExportAccess => PermissionScope::Export {
            export_kind: descriptor.permission.to_string(),
            redaction_required: true,
        },
        PermissionCategory::DesktopAccess => PermissionScope::Desktop {
            surface: descriptor.permission.to_string(),
        },
        PermissionCategory::PolicyAccess => PermissionScope::Policy {
            policy_key: descriptor.permission.to_string(),
            mutation: descriptor.permission.as_str().contains("write")
                || descriptor.permission.as_str().contains("update")
                || descriptor.permission.as_str().contains("change"),
        },
    }
}

pub fn policy_scope_for_settings_change(change_kind: &SettingsChangeKind) -> PolicyScope {
    match change_kind {
        SettingsChangeKind::RuntimeProfile
        | SettingsChangeKind::PrivacyPolicy
        | SettingsChangeKind::CaptureSettings
        | SettingsChangeKind::AttributionSettings
        | SettingsChangeKind::IntelligenceSettings
        | SettingsChangeKind::ApiSecuritySettings
        | SettingsChangeKind::WafIntegrationSettings
        | SettingsChangeKind::ResponsePolicy
        | SettingsChangeKind::ReportExportPolicy
        | SettingsChangeKind::RetentionPolicy
        | SettingsChangeKind::ServiceStatusSettings => PolicyScope::SettingsMutation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        PermissionCategory, PermissionDescriptor, PermissionRiskLevel, PluginType, RuntimeMode,
    };

    fn descriptor(
        key: &str,
        category: PermissionCategory,
        risk_level: PermissionRiskLevel,
    ) -> PermissionDescriptor {
        PermissionDescriptor::new(
            PermissionKey::new(key).expect("permission key"),
            category,
            risk_level,
            "test permission",
        )
        .expect("permission descriptor")
    }

    fn manifest_with_permission(descriptor: PermissionDescriptor) -> PluginManifest {
        let mut manifest = PluginManifest::new(
            PluginId::new_v4(),
            "permission-test-plugin",
            "0.1.0",
            "test.permissions",
            PluginType::Utility,
            RuntimeMode::OnDemand,
        )
        .expect("manifest");
        manifest.output_contracts.push(
            sentinel_contracts::ContractDescriptor::new(
                "test.permission.output",
                SchemaVersion::new(1, 0, 0),
            )
            .expect("contract"),
        );
        manifest.required_permissions.push(descriptor);
        manifest
    }

    #[test]
    fn resolver_allows_granted_metadata_data_permission() {
        let descriptor = descriptor(
            "read.event.flow",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        );
        let subject = PermissionSubject::Plugin(PluginId::new_v4());
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&descriptor);
        resolver.grant(subject.clone(), descriptor.permission.clone());

        let request = PermissionRequest::new(
            subject,
            descriptor.permission,
            PermissionScope::Data {
                resource: "network.flow.record".to_string(),
                operation: "read".to_string(),
                metadata_only: true,
            },
            PolicyScope::Plugin,
            "read flow metadata",
        );
        let decision = resolver.evaluate_permission(request, None);

        assert_eq!(decision.decision, PermissionDecisionKind::Allow);
        assert!(decision.is_ready());
    }

    #[test]
    fn missing_permission_yields_structured_denial_and_incompatible_status() {
        let descriptor = descriptor(
            "read.event.flow",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        );
        let subject = PermissionSubject::Plugin(PluginId::new_v4());
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&descriptor);

        let request = PermissionRequest::new(
            subject,
            descriptor.permission,
            PermissionScope::Data {
                resource: "network.flow.record".to_string(),
                operation: "read".to_string(),
                metadata_only: true,
            },
            PolicyScope::Plugin,
            "read flow metadata",
        );
        let decision = resolver.evaluate_permission(request, None);

        assert_eq!(decision.decision, PermissionDecisionKind::Deny);
        assert_eq!(decision.resolution_status(), ResolutionStatus::Incompatible);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.code == DeniedReasonCode::MissingPermission));
    }

    #[test]
    fn sensitive_raw_permissions_are_not_granted_by_default() {
        let descriptor = descriptor(
            "read.raw_packet",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Critical,
        );
        let subject = PermissionSubject::Plugin(PluginId::new_v4());
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&descriptor);
        resolver.grant(subject.clone(), descriptor.permission.clone());

        let request = PermissionRequest::new(
            subject,
            descriptor.permission,
            PermissionScope::Data {
                resource: "raw.packet".to_string(),
                operation: "read".to_string(),
                metadata_only: false,
            },
            PolicyScope::Plugin,
            "attempt raw packet read",
        );
        let decision = resolver.evaluate_permission(request, None);

        assert_eq!(decision.decision, PermissionDecisionKind::Deny);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.code == DeniedReasonCode::RawPacketForbidden));
    }

    #[test]
    fn response_execution_requires_policy_hook_before_permission_grant() {
        let descriptor = descriptor(
            "response.execute.firewall",
            PermissionCategory::ResponseAccess,
            PermissionRiskLevel::Critical,
        );
        let subject = PermissionSubject::Plugin(PluginId::new_v4());
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&descriptor);
        resolver.grant(subject.clone(), descriptor.permission.clone());

        let request = PermissionRequest::new(
            subject,
            descriptor.permission,
            PermissionScope::Response {
                action_type: ResponseActionType::MaliciousDestinationAutoBlock,
                execute: true,
            },
            PolicyScope::ResponseExecution,
            "evaluate response execution",
        );
        let decision = resolver.evaluate_permission(request, None);

        assert_eq!(decision.decision, PermissionDecisionKind::NeedsApproval);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.code == DeniedReasonCode::ResponsePolicyRequired));
    }

    #[test]
    fn response_policy_can_require_approval_without_executing_action() {
        let descriptor = descriptor(
            "response.execute.firewall",
            PermissionCategory::ResponseAccess,
            PermissionRiskLevel::Medium,
        );
        let subject = PermissionSubject::Plugin(PluginId::new_v4());
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&descriptor);
        resolver.grant(subject.clone(), descriptor.permission.clone());

        let mut profile = RuntimeProfile::safe_default();
        profile.response_policy = ResponsePolicy::auto_containment_lite();
        let request = PermissionRequest::new(
            subject.clone(),
            descriptor.permission.clone(),
            PermissionScope::Response {
                action_type: ResponseActionType::RecommendFirewallBlock,
                execute: true,
            },
            PolicyScope::ResponseExecution,
            "evaluate non-auto action",
        );
        let mut context = PolicyEvaluationContext::new(
            PolicyScope::ResponseExecution,
            subject,
            descriptor.permission,
            PermissionScope::Response {
                action_type: ResponseActionType::RecommendFirewallBlock,
                execute: true,
            },
            profile,
        );
        context.rollback_available = true;

        let policy_result = resolver.evaluate_policy(context);
        assert_eq!(
            policy_result.decision,
            PermissionDecisionKind::NeedsApproval
        );
        assert!(policy_result.audit_requirement.approval_required);

        let decision = resolver.evaluate_permission(request, Some(&policy_result));
        assert_eq!(decision.decision, PermissionDecisionKind::NeedsApproval);
        assert!(decision.audit_requirement.rollback_required);
    }

    #[test]
    fn auto_containment_allowlist_can_allow_policy_when_rollback_is_available() {
        let descriptor = descriptor(
            "response.recommend.firewall",
            PermissionCategory::ResponseAccess,
            PermissionRiskLevel::Medium,
        );
        let subject = PermissionSubject::Plugin(PluginId::new_v4());
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&descriptor);
        resolver.grant(subject.clone(), descriptor.permission.clone());

        let mut profile = RuntimeProfile::safe_default();
        profile.response_policy = ResponsePolicy::auto_containment_lite();
        let scope = PermissionScope::Response {
            action_type: ResponseActionType::MaliciousDestinationAutoBlock,
            execute: true,
        };
        let mut context = PolicyEvaluationContext::new(
            PolicyScope::ResponseExecution,
            subject.clone(),
            descriptor.permission.clone(),
            scope.clone(),
            profile,
        );
        context.rollback_available = true;

        let policy_result = resolver.evaluate_policy(context);
        assert_eq!(policy_result.decision, PermissionDecisionKind::Allow);

        let decision = resolver.evaluate_permission(
            PermissionRequest::new(
                subject,
                descriptor.permission,
                scope,
                PolicyScope::ResponseExecution,
                "auto containment policy check",
            ),
            Some(&policy_result),
        );
        assert_eq!(decision.decision, PermissionDecisionKind::Allow);
        assert!(decision.audit_requirement.audit_required);
        assert!(decision.audit_requirement.rollback_required);
    }

    #[test]
    fn export_requires_redaction_and_audit() {
        let descriptor = descriptor(
            "export.report",
            PermissionCategory::ExportAccess,
            PermissionRiskLevel::High,
        );
        let subject = PermissionSubject::LocalCore;
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&descriptor);
        resolver.grant(subject.clone(), descriptor.permission.clone());

        let profile = RuntimeProfile::safe_default();
        let scope = PermissionScope::Export {
            export_kind: "report".to_string(),
            redaction_required: true,
        };
        let context = PolicyEvaluationContext::new(
            PolicyScope::Export,
            subject.clone(),
            descriptor.permission.clone(),
            scope.clone(),
            profile,
        );
        let result = resolver.evaluate_policy(context);

        assert_eq!(result.decision, PermissionDecisionKind::Deny);
        assert!(result.audit_requirement.audit_required);
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.code == DeniedReasonCode::ExportRedactionRequired));
    }

    #[test]
    fn frontend_direct_service_and_sqlite_permissions_are_denied() {
        let service = descriptor(
            "frontend.elevated_service.direct",
            PermissionCategory::SystemAccess,
            PermissionRiskLevel::High,
        );
        let sqlite = descriptor(
            "frontend.sqlite.direct",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::High,
        );
        let subject = PermissionSubject::TauriCommand("unsafe_command".to_string());
        let mut resolver = PermissionResolver::new();
        resolver.register_descriptor(&service);
        resolver.register_descriptor(&sqlite);
        resolver.grant(subject.clone(), service.permission.clone());
        resolver.grant(subject.clone(), sqlite.permission.clone());

        let service_decision = resolver.evaluate_permission(
            PermissionRequest::new(
                subject.clone(),
                service.permission,
                PermissionScope::System {
                    command: "call service directly".to_string(),
                    elevated_service_required: true,
                },
                PolicyScope::TauriMutationCommand,
                "unsafe direct service",
            ),
            None,
        );
        assert!(service_decision
            .reasons
            .iter()
            .any(|reason| reason.code == DeniedReasonCode::FrontendServiceBypassForbidden));

        let sqlite_decision = resolver.evaluate_permission(
            PermissionRequest::new(
                subject,
                sqlite.permission,
                PermissionScope::Data {
                    resource: "sqlite".to_string(),
                    operation: "read".to_string(),
                    metadata_only: true,
                },
                PolicyScope::TauriReadCommand,
                "unsafe direct sqlite",
            ),
            None,
        );
        assert!(sqlite_decision
            .reasons
            .iter()
            .any(|reason| reason.code == DeniedReasonCode::FrontendSqliteBypassForbidden));
    }

    #[test]
    fn manifest_permission_resolution_reports_missing_required_grant_without_panic() {
        let descriptor = descriptor(
            "write.finding",
            PermissionCategory::DataAccess,
            PermissionRiskLevel::Low,
        );
        let manifest = manifest_with_permission(descriptor.clone());
        let resolver = PermissionResolver::new();
        let plugin_registry = PluginRegistry::new();

        let report = resolver.resolve_plugin_manifest(&manifest, &plugin_registry);

        assert_eq!(report.status, ResolutionStatus::Incompatible);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.kind == ResolutionIssueKind::MissingPermission));
    }
}
