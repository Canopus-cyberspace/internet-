use sentinel_contracts::{
    EtwArchitectureInventory, EtwProbeAuditRecord, EtwProbeContractError, EtwProbeReadModel,
    RedactionStatus, Timestamp,
};
use sentinel_infrastructure::{EtwCapabilityProbeAdapter, EtwCapabilityProbeSource};

pub fn build_etw_probe_read_model() -> Result<EtwProbeReadModel, EtwProbeContractError> {
    build_etw_probe_read_model_with(&EtwCapabilityProbeAdapter::new())
}

pub fn build_etw_probe_read_model_with<P>(
    probe_source: &P,
) -> Result<EtwProbeReadModel, EtwProbeContractError>
where
    P: EtwCapabilityProbeSource,
{
    let probe = probe_source.probe_etw_capability();
    probe.validate()?;
    let audit = EtwProbeAuditRecord::from_probe(&probe);
    let read_model = EtwProbeReadModel {
        read_model_ref: "etw_probe_read_model_ref".to_string(),
        architecture: EtwArchitectureInventory::probe_only(),
        probe,
        audit,
        generated_at: Timestamp::now(),
        redaction_status: RedactionStatus::Redacted,
    };
    read_model.validate()?;
    Ok(read_model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{
        EtwApiSurfaceState, EtwCapabilityProbeSnapshot, EtwCapabilityState, EtwCollectionState,
        EtwNetworkSchemaDeclaration, EtwSchemaSupportState, EtwSessionState, NetworkProviderKind,
        ETW_PROBE_SCHEMA_VERSION,
    };

    #[derive(Clone)]
    struct FixedProbe {
        snapshot: EtwCapabilityProbeSnapshot,
    }

    impl EtwCapabilityProbeSource for FixedProbe {
        fn probe_etw_capability(&self) -> EtwCapabilityProbeSnapshot {
            self.snapshot.clone()
        }
    }

    fn fixed_available_probe() -> FixedProbe {
        FixedProbe {
            snapshot: EtwCapabilityProbeSnapshot {
                probe_ref: "etw_capability_probe_ref".to_string(),
                schema_version: ETW_PROBE_SCHEMA_VERSION,
                provider_kind: NetworkProviderKind::EtwNetwork,
                capability_state: EtwCapabilityState::Available,
                api_surface_state: EtwApiSurfaceState::Complete,
                schema_support_state: EtwSchemaSupportState::RuntimeMetadataAvailable,
                session_state: EtwSessionState::NotCreated,
                collection_state: EtwCollectionState::Inactive,
                activation_allowed: false,
                event_session_created: false,
                collection_started: false,
                provider_execution_count: 0,
                events_observed_count: 0,
                eventbus_publication_count: 0,
                finding_count: 0,
                degraded_reason: None,
                schema_declaration: EtwNetworkSchemaDeclaration::metadata_only_v1(),
                audit_refs: vec!["audit_etw_capability_probe_ref".to_string()],
                provenance_refs: vec!["etw_test_probe".to_string()],
                probed_at: Timestamp::now(),
                redaction_status: RedactionStatus::Redacted,
            },
        }
    }

    #[test]
    fn etw_probe_read_model_is_safe_audited_and_side_effect_free() {
        let model =
            build_etw_probe_read_model_with(&fixed_available_probe()).expect("ETW read model");

        assert!(model.validate().is_ok());
        assert_eq!(model.audit.probe_ref, model.probe.probe_ref);
        assert_eq!(model.probe.session_state, EtwSessionState::NotCreated);
        assert_eq!(model.probe.collection_state, EtwCollectionState::Inactive);
        assert_eq!(model.probe.provider_execution_count, 0);
        assert_eq!(model.probe.eventbus_publication_count, 0);
        assert_eq!(model.probe.finding_count, 0);
        assert!(!model.audit.response_execution_allowed);
        assert!(!model.audit.automatic_llm_calls_allowed);
        assert!(model.architecture.probe_only);
        assert!(!model.architecture.event_session_implemented);
        assert!(!model.architecture.collection_implemented);
    }

    #[test]
    fn etw_probe_read_model_rejects_collection_or_activation_claims() {
        let mut fixed = fixed_available_probe();
        fixed.snapshot.activation_allowed = true;
        assert_eq!(
            build_etw_probe_read_model_with(&fixed),
            Err(EtwProbeContractError::ProbeCreatedRuntimeState)
        );
    }

    #[test]
    fn etw_probe_read_model_contains_no_raw_provider_values() {
        let model = build_etw_probe_read_model().expect("system ETW probe read model");
        let serialized = serde_json::to_string(&model).expect("serialize");
        for marker in [
            "203.0.113.77",
            "65000",
            "process_name_value",
            "c:\\unsafe\\binary.exe",
            "username_value",
            "sid_value",
            "token_value",
            "credential_value",
            "secret_value",
        ] {
            assert!(!serialized.contains(marker));
        }
    }
}
