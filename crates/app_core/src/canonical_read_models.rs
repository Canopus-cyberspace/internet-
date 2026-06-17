use sentinel_contracts::{
    read_model_snapshot::{
        CanonicalReadModelCategory, CanonicalReadModelSnapshotItem, ReadModelSnapshotFreshness,
    },
    runtime_ownership::{RuntimeComponentLifecycle, RuntimeHealthState},
    RedactionStatus,
};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanonicalOwnerClassification {
    IntendedServiceHostOwner,
    PresentationCacheOnly,
    TestHarnessOnly,
    CanonicalOwnershipViolation,
    Unknown,
}

impl CanonicalOwnerClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntendedServiceHostOwner => "intended_service_host_owner",
            Self::PresentationCacheOnly => "presentation_cache_only",
            Self::TestHarnessOnly => "test_harness_only",
            Self::CanonicalOwnershipViolation => "canonical_ownership_violation",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for CanonicalOwnerClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalReadModelOwnershipEntry {
    pub model_category: CanonicalReadModelCategory,
    pub current_producer: &'static str,
    pub current_mutable_owner: &'static str,
    pub current_cache_owner: &'static str,
    pub current_persistence: &'static str,
    pub required_service_host_owner: &'static str,
    pub snapshot_contract: &'static str,
    pub freshness_policy: ReadModelSnapshotFreshness,
    pub migration_action: &'static str,
    pub blocker: &'static str,
    pub classification: CanonicalOwnerClassification,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalReadModelInventoryError {
    DuplicateCanonicalOwner(CanonicalReadModelCategory),
    MissingCanonicalOwner(CanonicalReadModelCategory),
    CanonicalOwnershipViolation(CanonicalReadModelCategory),
    AmbiguousCanonicalOwner(CanonicalReadModelCategory),
}

impl fmt::Display for CanonicalReadModelInventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCanonicalOwner(category) => {
                write!(f, "duplicate canonical owner for {category:?}")
            }
            Self::MissingCanonicalOwner(category) => {
                write!(f, "missing canonical owner for {category:?}")
            }
            Self::CanonicalOwnershipViolation(category) => {
                write!(f, "canonical ownership violation for {category:?}")
            }
            Self::AmbiguousCanonicalOwner(category) => {
                write!(f, "ambiguous canonical owner for {category:?}")
            }
        }
    }
}

impl std::error::Error for CanonicalReadModelInventoryError {}

macro_rules! owner {
    (
        $category:expr,
        $producer:expr,
        $mutable:expr,
        $cache:expr,
        $persistence:expr,
        $owner:expr,
        $freshness:expr,
        $action:expr,
        $blocker:expr
    ) => {
        CanonicalReadModelOwnershipEntry {
            model_category: $category,
            current_producer: $producer,
            current_mutable_owner: $mutable,
            current_cache_owner: $cache,
            current_persistence: $persistence,
            required_service_host_owner: $owner,
            snapshot_contract: "CanonicalReadModelSnapshot",
            freshness_policy: $freshness,
            migration_action: $action,
            blocker: $blocker,
            classification: CanonicalOwnerClassification::IntendedServiceHostOwner,
        }
    };
}

pub const CANONICAL_READ_MODEL_OWNERSHIP_INVENTORY: &[CanonicalReadModelOwnershipEntry] = &[
    owner!(
        CanonicalReadModelCategory::RuntimeOwnership,
        "RuntimeContainer::summary",
        "RuntimeContainer",
        "DesktopRuntimeOwnershipStatus presentation cache",
        "memory-only status",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Fresh,
        "publish bounded snapshot after ServiceHost IPC read-model migration",
        "servicehost_read_model_ipc_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::ComponentLifecycleHealth,
        "RuntimeContainer component_summaries",
        "RuntimeContainer",
        "Desktop presentation cache",
        "memory-only status",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Fresh,
        "snapshot component lifecycle and health refs only",
        "servicehost_read_model_ipc_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::RuntimeHealth,
        "RuntimeContainer runtime_health",
        "RuntimeContainer",
        "Desktop presentation cache",
        "memory-only runtime health status",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Fresh,
        "snapshot runtime health buckets only",
        "servicehost_read_model_ipc_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::StorageOwnerSummary,
        "RuntimeContainer storage ownership status",
        "RuntimeContainer storage writer lease",
        "Desktop presentation cache",
        "safe storage owner buckets only",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Fresh,
        "snapshot storage owner state without paths",
        "durable_storage_migration_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::CapabilityHealth,
        "ReadOnlyCommandState plugin health summaries",
        "ServiceHost-owned ReadOnlyCommandState",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "move canonical health reads behind ServiceHost snapshots",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::Scheduler,
        "NativeSchedulerController",
        "ServiceHost-owned MutationCommandState",
        "Desktop presentation cache",
        "safe scheduler buckets only",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Fresh,
        "snapshot scheduler state without enabling scheduling",
        "servicehost_read_model_ipc_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::SchedulerHost,
        "NativeSchedulerHostController",
        "ServiceHost-owned MutationCommandState",
        "Desktop presentation cache",
        "safe scheduler-host buckets only",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Fresh,
        "snapshot stopped host state without starting host task",
        "servicehost_read_model_ipc_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::SamplerState,
        "NativeSamplerRuntime",
        "ServiceHost-owned MutationCommandState",
        "Desktop presentation cache",
        "safe sampler buckets only",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot inactive sampler state without provider calls",
        "servicehost_read_model_ipc_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::NativePermissionReadiness,
        "AuthorizedNativePermissionRuntime and readiness summaries",
        "ServiceHost-owned MutationCommandState",
        "Desktop presentation cache",
        "safe permission/readiness buckets only",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot authorization/readiness categories only",
        "servicehost_read_model_ipc_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::EndpointThreat,
        "ServiceOwnedEndpointThreatRuntime",
        "RuntimeContainer endpoint threat runtime",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot finding/evidence/risk refs only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::Fusion,
        "ServiceOwnedFusionRuntime",
        "RuntimeContainer fusion runtime",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot fusion refs and quality buckets only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::EvidenceQuality,
        "ServiceOwnedEvidenceQualityRuntime",
        "RuntimeContainer evidence-quality runtime",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot evidence quality buckets only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::Risk,
        "ServiceOwnedRiskRuntime",
        "RuntimeContainer risk runtime",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot risk refs and severity buckets only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::AttackContext,
        "ServiceOwnedAttackContextRuntime",
        "RuntimeContainer ATT&CK context runtime",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot ATT&CK refs and degraded reasons only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::Graph,
        "ServiceOwnedGraphRuntime",
        "RuntimeContainer graph runtime",
        "Desktop GraphViewModel presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot graph refs only; canonical graph store remains ServiceHost-owned",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::Baseline,
        "ServiceOwnedBaselineRuntime",
        "RuntimeContainer baseline runtime",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot baseline refs and buckets only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::IncidentLinkedGroups,
        "ServiceOwnedIncidentLinkingRuntime",
        "RuntimeContainer incident-linking runtime",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Aging,
        "snapshot incident-linked group refs only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::ReportTraceability,
        "ServiceOwnedReportExportTraceability",
        "RuntimeContainer report traceability state",
        "Desktop presentation cache",
        "canonical persistence deferred",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Stale,
        "snapshot report refs only; reports remain side-effect-free",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::ExportTraceabilityHistory,
        "ServiceOwnedReportExportTraceability",
        "RuntimeContainer export traceability state",
        "Desktop file-picker/export destination state is non-canonical",
        "export history metadata only",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Stale,
        "snapshot export refs and history metadata refs only",
        "canonical_servicehost_read_model_storage_deferred"
    ),
    owner!(
        CanonicalReadModelCategory::ProviderControllerStatus,
        "ProviderControllerShell::inactive",
        "RuntimeContainer inactive ProviderControllerShell",
        "Desktop presentation cache",
        "memory-only inactive status",
        "ServiceHost RuntimeContainer",
        ReadModelSnapshotFreshness::Fresh,
        "snapshot inactive/deferred provider state; provider call count remains zero",
        "provider_execution_deferred"
    ),
];

pub fn canonical_read_model_ownership_inventory() -> &'static [CanonicalReadModelOwnershipEntry] {
    CANONICAL_READ_MODEL_OWNERSHIP_INVENTORY
}

pub fn validate_canonical_read_model_ownership_inventory(
    entries: &[CanonicalReadModelOwnershipEntry],
) -> Result<(), CanonicalReadModelInventoryError> {
    let mut owner_counts: BTreeMap<CanonicalReadModelCategory, usize> = BTreeMap::new();
    for entry in entries {
        if entry.classification == CanonicalOwnerClassification::CanonicalOwnershipViolation {
            return Err(
                CanonicalReadModelInventoryError::CanonicalOwnershipViolation(entry.model_category),
            );
        }
        if entry.classification == CanonicalOwnerClassification::Unknown {
            return Err(CanonicalReadModelInventoryError::AmbiguousCanonicalOwner(
                entry.model_category,
            ));
        }
        if entry.classification == CanonicalOwnerClassification::IntendedServiceHostOwner {
            *owner_counts.entry(entry.model_category).or_default() += 1;
        }
        if entry.current_producer.trim().is_empty()
            || entry.current_mutable_owner.trim().is_empty()
            || entry.current_cache_owner.trim().is_empty()
            || entry.current_persistence.trim().is_empty()
            || entry.required_service_host_owner.trim().is_empty()
            || entry.snapshot_contract.trim().is_empty()
            || entry.migration_action.trim().is_empty()
            || entry.blocker.trim().is_empty()
        {
            return Err(CanonicalReadModelInventoryError::AmbiguousCanonicalOwner(
                entry.model_category,
            ));
        }
    }
    for category in required_canonical_read_model_categories() {
        match owner_counts.get(category).copied().unwrap_or_default() {
            1 => {}
            0 => {
                return Err(CanonicalReadModelInventoryError::MissingCanonicalOwner(
                    *category,
                ))
            }
            _ => {
                return Err(CanonicalReadModelInventoryError::DuplicateCanonicalOwner(
                    *category,
                ))
            }
        }
    }
    Ok(())
}

pub fn canonical_read_model_snapshot_contract_items() -> Vec<CanonicalReadModelSnapshotItem> {
    canonical_read_model_ownership_inventory()
        .iter()
        .map(|entry| CanonicalReadModelSnapshotItem {
            model_category: entry.model_category,
            lifecycle_state: RuntimeComponentLifecycle::Ready,
            health_state: match entry.freshness_policy {
                ReadModelSnapshotFreshness::Unavailable => RuntimeHealthState::Degraded,
                _ => RuntimeHealthState::Ready,
            },
            bounded_categories: vec![entry.classification.as_str().to_string()],
            bounded_buckets: vec![format!("{:?}", entry.freshness_policy).to_ascii_lowercase()],
            bounded_refs: vec![entry.snapshot_contract.to_string()],
            degraded_reason: (entry.blocker != "none").then(|| entry.blocker.to_string()),
            missing_visibility_flags: vec![entry.blocker.to_string()],
            provenance_id: "canonical_read_model_ownership_inventory".to_string(),
            redaction_status: RedactionStatus::Redacted,
        })
        .collect()
}

fn required_canonical_read_model_categories() -> &'static [CanonicalReadModelCategory] {
    &[
        CanonicalReadModelCategory::RuntimeOwnership,
        CanonicalReadModelCategory::ComponentLifecycleHealth,
        CanonicalReadModelCategory::RuntimeHealth,
        CanonicalReadModelCategory::StorageOwnerSummary,
        CanonicalReadModelCategory::CapabilityHealth,
        CanonicalReadModelCategory::Scheduler,
        CanonicalReadModelCategory::SchedulerHost,
        CanonicalReadModelCategory::SamplerState,
        CanonicalReadModelCategory::NativePermissionReadiness,
        CanonicalReadModelCategory::EndpointThreat,
        CanonicalReadModelCategory::Fusion,
        CanonicalReadModelCategory::EvidenceQuality,
        CanonicalReadModelCategory::Risk,
        CanonicalReadModelCategory::AttackContext,
        CanonicalReadModelCategory::Graph,
        CanonicalReadModelCategory::Baseline,
        CanonicalReadModelCategory::IncidentLinkedGroups,
        CanonicalReadModelCategory::ReportTraceability,
        CanonicalReadModelCategory::ExportTraceabilityHistory,
        CanonicalReadModelCategory::ProviderControllerStatus,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        read_model_snapshot::{CanonicalReadModelSnapshot, READ_MODEL_SNAPSHOT_SCHEMA_VERSION},
        runtime_ownership::{RuntimeMode, RuntimeOwnerCategory},
        ReadModelSnapshotId,
    };

    #[test]
    fn canonical_read_models_inventory_has_exactly_one_intended_owner_per_model() {
        validate_canonical_read_model_ownership_inventory(
            canonical_read_model_ownership_inventory(),
        )
        .expect("canonical inventory is unambiguous");
        assert_eq!(
            canonical_read_model_ownership_inventory().len(),
            required_canonical_read_model_categories().len()
        );
        assert!(canonical_read_model_ownership_inventory()
            .iter()
            .all(|entry| {
                entry.classification == CanonicalOwnerClassification::IntendedServiceHostOwner
                    && entry.required_service_host_owner == "ServiceHost RuntimeContainer"
            }));
    }

    #[test]
    fn canonical_read_models_duplicate_owner_is_detected() {
        let mut entries = canonical_read_model_ownership_inventory().to_vec();
        entries.push(entries[0]);
        assert!(matches!(
            validate_canonical_read_model_ownership_inventory(&entries),
            Err(CanonicalReadModelInventoryError::DuplicateCanonicalOwner(
                CanonicalReadModelCategory::RuntimeOwnership
            ))
        ));
    }

    #[test]
    fn canonical_read_models_violation_is_detected() {
        let mut entries = canonical_read_model_ownership_inventory().to_vec();
        entries[0].classification = CanonicalOwnerClassification::CanonicalOwnershipViolation;
        assert!(matches!(
            validate_canonical_read_model_ownership_inventory(&entries),
            Err(
                CanonicalReadModelInventoryError::CanonicalOwnershipViolation(
                    CanonicalReadModelCategory::RuntimeOwnership
                )
            )
        ));
    }

    #[test]
    fn canonical_read_models_snapshot_contract_items_validate() {
        for item in canonical_read_model_snapshot_contract_items() {
            item.validate().expect("snapshot inventory item is safe");
        }
    }

    #[test]
    fn canonical_read_models_snapshot_envelope_requires_epoch_and_bounded_freshness() {
        let snapshot = CanonicalReadModelSnapshot {
            snapshot_id: ReadModelSnapshotId::new_v4(),
            ownership_ref: "runtime-owner-ref".to_string(),
            ownership_epoch: 1,
            runtime_owner: RuntimeOwnerCategory::ServiceHost,
            runtime_mode: RuntimeMode::ServiceOwned,
            schema_version: READ_MODEL_SNAPSHOT_SCHEMA_VERSION,
            generation_bucket: "generation_current".to_string(),
            generated_time_bucket: sentinel_contracts::Timestamp::now(),
            freshness_state: ReadModelSnapshotFreshness::Fresh,
            partial_state: true,
            items: canonical_read_model_snapshot_contract_items(),
            degraded_reason: Some("servicehost_read_model_ipc_deferred".to_string()),
            missing_visibility_flags: vec!["durable_storage_migration_deferred".to_string()],
            provenance_id: "canonical_read_model_ownership_inventory".to_string(),
            redaction_status: RedactionStatus::Redacted,
        };
        snapshot.validate().expect("snapshot validates");

        let mut missing_epoch = snapshot;
        missing_epoch.ownership_epoch = 0;
        assert!(missing_epoch.validate().is_err());
    }

    #[test]
    fn canonical_read_models_provider_requirements_remain_zero_call() {
        let provider = canonical_read_model_ownership_inventory()
            .iter()
            .find(|entry| {
                entry.model_category == CanonicalReadModelCategory::ProviderControllerStatus
            })
            .expect("provider controller inventory row");
        assert_eq!(
            provider.current_producer,
            "ProviderControllerShell::inactive"
        );
        assert!(provider
            .migration_action
            .contains("provider call count remains zero"));
        assert_eq!(provider.blocker, "provider_execution_deferred");
    }
}
