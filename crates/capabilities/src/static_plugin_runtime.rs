use crate::asset_exposure::{
    AssetExposureError, AssetExposureInput, AssetExposureObservation, AssetExposureOutput,
    AssetExposurePlugin, AssetRecord, AssetRiskFinding, PortExposureRecord, ServiceInventoryInput,
    ServiceInventoryPlugin, ServiceRecord, ASSET_EXPOSURE_SCHEMA_VERSION,
};
use crate::c2_detection::{
    C2DetectionError, C2DetectionInput, C2DetectionOutput, C2DetectionPlugin,
    C2_DETECTION_SCHEMA_VERSION,
};
use crate::endpoint_threat_detection::{
    EndpointDetectorEvidenceCategory, EndpointDetectorEvidenceLayer,
    EndpointDetectorEvidenceRecord, EndpointDetectorFactRecord, EndpointThreatDetectionError,
    EndpointThreatDetectionInput, EndpointThreatDetectorPack, EndpointThreatDetectorPackOutput,
    EndpointThreatIntelligenceInput, EndpointThreatIntelligenceIntegrator,
};
use crate::evidence_management::CollectedEvidence;
use crate::exfiltration_detection::{
    ExfiltrationDetectionError, ExfiltrationDetectionInput, ExfiltrationDetectionOutput,
    ExfiltrationDetectionPlugin, EXFILTRATION_DETECTION_SCHEMA_VERSION,
};
use crate::lateral_movement_lite::{
    LateralMovementError, LateralMovementLiteInput, LateralMovementLiteOutput,
    LateralMovementLitePlugin, LATERAL_MOVEMENT_SCHEMA_VERSION,
};
use crate::multi_layer_fusion::{
    MultiLayerFusionInput, MultiLayerFusionOutput, MultiLayerSecurityFusionPlugin,
    MULTI_LAYER_FUSION_SCHEMA_VERSION, SECURITY_FACT_CONTRACT, SECURITY_HYPOTHESIS_CONTRACT,
};
use crate::native_network_fact::{
    NativeNetworkFactPlugin, NATIVE_ETW_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT,
    NATIVE_ETW_NETWORK_VISIBILITY_FACT_CONTRACT, NATIVE_NETWORK_FACT_CONTRACT,
    NATIVE_NETWORK_FACT_SCHEMA_VERSION, NATIVE_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT,
    NATIVE_NETWORK_VISIBILITY_FACT_CONTRACT,
};
use crate::native_sampler_runtime::{
    NativeSamplerFactPlugin, ENDPOINT_NATIVE_HEALTH_FACT_CONTRACT,
    ENDPOINT_PROCESS_CATEGORY_FACT_CONTRACT, ENDPOINT_PROCESS_PARENT_CATEGORY_FACT_CONTRACT,
    ENDPOINT_SERVICE_CATEGORY_FACT_CONTRACT, NATIVE_SAMPLER_RUNTIME_SCHEMA_VERSION,
};
use crate::network_observations::{
    FlowSessionizationInput, FlowSessionizationOutput, FlowSessionizationPlugin,
    NetworkObservationError, NETWORK_OBSERVATION_SCHEMA_VERSION,
};
use crate::portable_network_web::{
    PortableApiSecurityLiteInput, PortableApiSecurityLitePlugin,
    PortableAuthIdentityAnalysisLiteInput, PortableAuthIdentityAnalysisLitePlugin,
    PortableDeceptionEventLiteInput, PortableDeceptionEventLitePlugin, PortableDnsSecurityV2Plugin,
    PortableHttpAnalysisInput, PortableHttpAnalysisV1Plugin, PortableNetworkWebAnalysisError,
    PortableNetworkWebOutput, PortableQuicHttp3SecurityLiteInput,
    PortableQuicHttp3SecurityLitePlugin, PortableRemoteAdminObservationLiteInput,
    PortableRemoteAdminObservationLitePlugin, PortableSaasCloudAbuseLiteInput,
    PortableSaasCloudAbuseLitePlugin, PortableWafSecurityLiteInput, PortableWafSecurityLitePlugin,
    PORTABLE_NETWORK_WEB_SCHEMA_VERSION,
};
use crate::response_planning::{
    ResponsePlanningError, ResponsePlanningInput, ResponsePlanningOutput, ResponsePlanningPlugin,
    ResponsePolicyRule, RESPONSE_PLANNING_SCHEMA_VERSION, RESPONSE_POLICY_RULE_CONTRACT,
    RESPONSE_POLICY_SETTINGS_CONTRACT,
};
use crate::risk_alerting::{
    RiskAlertingError, RiskBasedAlertingInput, RiskBasedAlertingOutput, RiskBasedAlertingPlugin,
    ALERT_CANDIDATE_CONTRACT, INCIDENT_CANDIDATE_CONTRACT, RISK_ALERTING_SCHEMA_VERSION,
};
use sentinel_contracts::{
    Alert, ApprovalRequest, AttackHypothesisRecord, BaselineRecordId, CertificateContext,
    CloudContext, DataSourceId, DnsFeatures, DnsObservation, DomainContext, EndpointAnalysisInput,
    EndpointAnalysisInputId, EndpointAttackRef, EndpointCorrelationQualityBucket,
    EndpointCountChangeBucket, EndpointEvidenceQualityBucket, EndpointExecutionContextCategory,
    EndpointFreshnessCategory, EndpointLifecycleBucket, EndpointMissingVisibilityFlag,
    EndpointOccurrenceIndicator, EndpointPrivilegeIntegrityCategory, EndpointProcessCategory,
    EndpointRelationCategory, EndpointServiceCategory, EndpointServiceStateBucket,
    EndpointSourceReliabilityBucket, EndpointStartupTypeBucket, EndpointThreatEvidence,
    EndpointThreatEvidenceCategory, EndpointThreatEvidenceId, EndpointThreatFinding,
    EndpointThreatFindingCategory, EndpointThreatRiskCategory, EndpointThreatRiskHint,
    EndpointThreatRiskHintId, EndpointTrustSignednessBucket, EtwNormalizedNetworkBatch,
    EventEnvelope, EventId, EventType, EvidenceId, Finding, FlowRecord, FusionSummary, GraphHint,
    GraphPath, HttpMetadata, Incident, IpContext, NativeIpHelperMetadataBatch, PacketRecord,
    PluginId, PluginManifest, PortableAuthMetadata, PortableCaptureProvenance,
    PortableDeceptionEventMetadata, PortableSaasCloudMetadata, PortableSdnControlPlaneMetadata,
    PrivacyClass, ProcessContext, QualityScore, RedactionStatus, ResponsePolicy, RiskHint,
    SchemaVersion, SecurityFact, SecurityFactId, SecurityLayer, ServiceCapabilityContext,
    SessionId, SessionRecord, Timestamp, TlsObservation, WindowsAuthRemoteObservationBatch,
    WindowsDnsAnswerCountBucket, WindowsDnsDepthBucket, WindowsDnsEntropyBucket,
    WindowsDnsLengthBucket, WindowsDnsObservation, WindowsDnsQueryTypeCategory,
    WindowsDnsResultCategory,
};
use sentinel_platform::{
    BuiltInPluginCatalog, HealthSnapshot, HealthSubject, InternalPlugin, ObservabilityHealthStatus,
    PluginContext, PluginEventBatch, PluginLifecycle, PluginOutput, PluginResult, PluginRuntime,
    PluginRuntimeError, ASSET_EXPOSURE, AUDIT_ENDPOINT_THREAT_ANALYSIS, CLOUD_SAAS_METADATA,
    DECEPTION_EVENT_METADATA, ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT, ENDPOINT_PROCESS_CATEGORY_FACT,
    ENDPOINT_PROCESS_PARENT_CATEGORY_FACT, ENDPOINT_SERVICE_CATEGORY_FACT,
    ENDPOINT_THREAT_CANDIDATE, ENDPOINT_THREAT_EVIDENCE, ENDPOINT_THREAT_FINDING,
    ENDPOINT_THREAT_REJECTED, ENDPOINT_THREAT_RISK_HINT, ENDPOINT_VISIBILITY_ADVISORY, GRAPH_HINT,
    GRAPH_PATH, IDENTITY_AUTH_METADATA, IDENTITY_PROCESS_CONTEXT,
    IDENTITY_SMB_OPERATIONAL_METADATA, IDENTITY_SSH_OPERATIONAL_METADATA,
    INTEL_CERTIFICATE_CONTEXT, INTEL_CLOUD_CONTEXT, INTEL_DOMAIN_CONTEXT, INTEL_IP_CONTEXT,
    NATIVE_CONNECTION_CATEGORY_FACT, NATIVE_ETW_NETWORK_METADATA, NATIVE_HEALTH_METADATA,
    NATIVE_IP_HELPER_METADATA, NATIVE_PROCESS_METADATA, NATIVE_PROCESS_PARENT_METADATA,
    NATIVE_SERVICE_METADATA, NETWORK_DNS_OBSERVATION, NETWORK_FLOW_RECORD, NETWORK_HTTP_METADATA,
    NETWORK_PACKET_RECORD, NETWORK_SDN_CONTROL_PLANE_METADATA, NETWORK_SESSION_RECORD,
    NETWORK_TLS_OBSERVATION, RESPONSE_APPROVAL_REQUEST, RESPONSE_PLAN, RESPONSE_POLICY_DECISION,
    SECURITY_ALERT, SECURITY_EVIDENCE, SECURITY_FINDING, SECURITY_FUSION_CONTEXT,
    SECURITY_FUSION_SUMMARY, SECURITY_HYPOTHESIS, SECURITY_INCIDENT, SECURITY_OBSERVATION,
    SECURITY_RISK, SERVICE_CAPABILITY_STATUS,
};
use serde::Serialize;

pub const FLOW_SESSIONIZATION_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000193";
pub const ASSET_EXPOSURE_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019a";
pub const C2_DETECTION_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019d";
pub const EXFILTRATION_DETECTION_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019b";
pub const LATERAL_MOVEMENT_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019c";
pub const RISK_ALERTING_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a0";
pub const RESPONSE_PLANNING_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a2";
pub const DNS_SECURITY_V2_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a4";
pub const HTTP_ANALYSIS_V1_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a5";
pub const API_SECURITY_LITE_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a6";
pub const WAF_SECURITY_LITE_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a7";
pub const QUIC_HTTP3_SECURITY_LITE_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001a8";
pub const REMOTE_ADMIN_PROTOCOL_LITE_STATIC_PLUGIN_ID: &str =
    "00000000-0000-0000-0000-0000000001a9";
pub const AUTH_IDENTITY_ANALYSIS_LITE_STATIC_PLUGIN_ID: &str =
    "00000000-0000-0000-0000-0000000001aa";
pub const SAAS_CLOUD_ABUSE_LITE_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001ab";
pub const DECEPTION_EVENT_LITE_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001ac";
pub const MULTI_LAYER_SECURITY_FUSION_STATIC_PLUGIN_ID: &str =
    "00000000-0000-0000-0000-0000000001ad";
pub const NATIVE_SAMPLER_FACT_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001ae";
pub const NATIVE_NETWORK_FACT_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-0000000001b0";
pub const ENDPOINT_THREAT_ANALYSIS_LITE_STATIC_PLUGIN_ID: &str =
    "00000000-0000-0000-0000-0000000001af";

const ASSET_RECORD_CONTRACT: &str = "asset.record";
const ASSET_SERVICE_RECORD_CONTRACT: &str = "asset.service_record";
const ASSET_PORT_EXPOSURE_CONTRACT: &str = "asset.port_exposure";
const ASSET_EXPOSURE_OBSERVATION_CONTRACT: &str = "asset.exposure.observation";
const ASSET_RISK_FINDING_CONTRACT: &str = "security.finding.asset_risk";
const ASSET_SERVICE_INVENTORY_CONTRACT: &str = "asset.service_inventory";
const SECURITY_RISK_HINT: &str = "security.risk_hint";

#[derive(Clone, Debug)]
struct StaticFlowSessionizationRuntimePlugin {
    manifest: PluginManifest,
    capability: FlowSessionizationPlugin,
}

impl StaticFlowSessionizationRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(FLOW_SESSIONIZATION_STATIC_PLUGIN_ID)?,
            capability: FlowSessionizationPlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticFlowSessionizationRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "flow sessionization")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal flow sessionization runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticFlowSessionizationRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "flow sessionization")?;
        let mut packets = Vec::new();
        for event in &batch.events {
            if event.event_type.as_str() == NETWORK_PACKET_RECORD {
                packets.push(parse_event_payload::<PacketRecord>(
                    &self.manifest.plugin_id,
                    event,
                    NETWORK_PACKET_RECORD,
                )?);
            }
        }
        if packets.is_empty() {
            return empty_output(&self.manifest.plugin_id, context, "flow sessionization");
        }

        let output = self
            .capability
            .process(FlowSessionizationInput::new(packets))
            .map_err(|error| capability_error(&self.manifest.plugin_id, error))?;
        plugin_output_from_flow_sessionization(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_flow_sessionization_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticFlowSessionizationRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticAssetExposureRuntimePlugin {
    manifest: PluginManifest,
    inventory: ServiceInventoryPlugin,
    capability: AssetExposurePlugin,
}

impl StaticAssetExposureRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(ASSET_EXPOSURE_STATIC_PLUGIN_ID)?,
            inventory: ServiceInventoryPlugin::new(),
            capability: AssetExposurePlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticAssetExposureRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "asset exposure")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal asset exposure runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticAssetExposureRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "asset exposure")?;
        let mut events = Vec::new();

        for event in &batch.events {
            if event.event_type.as_str() != ASSET_SERVICE_INVENTORY_CONTRACT {
                continue;
            }
            let inventory_input: ServiceInventoryInput = parse_event_payload(
                &self.manifest.plugin_id,
                event,
                ASSET_SERVICE_INVENTORY_CONTRACT,
            )?;
            let inventory = self
                .inventory
                .inventory(inventory_input)
                .map_err(|error| asset_capability_error(&self.manifest.plugin_id, error))?;
            let mut input =
                AssetExposureInput::from_inventory(inventory, self.manifest.plugin_id.clone())
                    .map_err(|error| asset_capability_error(&self.manifest.plugin_id, error))?;
            input.source_event_refs = vec![event.event_id.clone()];
            let mut output = self
                .capability
                .observe(input)
                .map_err(|error| asset_capability_error(&self.manifest.plugin_id, error))?;
            attach_asset_source_refs(&mut output, &event.event_id);
            events.extend(asset_output_events(
                &self.manifest.plugin_id,
                &output,
                context,
            )?);
        }

        Ok(PluginOutput {
            events,
            health: vec![self.health_snapshot(context)?],
            metrics: Vec::new(),
            audit_events: Vec::new(),
        })
    }
}

pub fn register_static_asset_exposure_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticAssetExposureRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableDnsSecurityV2RuntimePlugin {
    manifest: PluginManifest,
    capability: PortableDnsSecurityV2Plugin,
}

impl StaticPortableDnsSecurityV2RuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(DNS_SECURITY_V2_STATIC_PLUGIN_ID)?,
            capability: PortableDnsSecurityV2Plugin,
        })
    }
}

impl PluginLifecycle for StaticPortableDnsSecurityV2RuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "dns security v2")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal dns security v2 runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableDnsSecurityV2RuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "dns security v2")?;
        let mut observations = Vec::new();
        let mut source_event_refs = Vec::new();
        for event in &batch.events {
            if event.event_type.as_str() == NETWORK_DNS_OBSERVATION {
                let observation = match serde_json::from_value::<DnsObservation>(
                    event.payload.clone(),
                ) {
                    Ok(observation) => observation,
                    Err(_) => {
                        let native = serde_json::from_value::<WindowsDnsObservation>(
                            event.payload.clone(),
                        )
                        .map_err(|error| {
                            process_error(
                                &self.manifest.plugin_id,
                                format!(
                                    "{NETWORK_DNS_OBSERVATION} payload deserialization failed: {error}"
                                ),
                            )
                        })?;
                        windows_dns_detector_observation(native)
                            .map_err(|error| process_error(&self.manifest.plugin_id, error))?
                    }
                };
                observations.push(observation);
                source_event_refs.push(event.event_id.clone());
            }
        }
        let mut output = match self
            .capability
            .analyze(&self.manifest.plugin_id, &observations)
        {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(&self.manifest.plugin_id, context, "dns security v2");
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

fn windows_dns_detector_observation(
    native: WindowsDnsObservation,
) -> Result<DnsObservation, String> {
    native.validate().map_err(|error| error.to_string())?;
    let unspecified =
        sentinel_contracts::IpAddress::parse_str("0.0.0.0").map_err(|error| error.to_string())?;
    let query_type = match native.query_type_category {
        WindowsDnsQueryTypeCategory::Address => "address",
        WindowsDnsQueryTypeCategory::Alias => "alias",
        WindowsDnsQueryTypeCategory::Mail => "mail",
        WindowsDnsQueryTypeCategory::Service => "service",
        WindowsDnsQueryTypeCategory::Reverse => "reverse",
        WindowsDnsQueryTypeCategory::Text => "text",
        WindowsDnsQueryTypeCategory::Other => "other",
    };
    let mut observation =
        DnsObservation::new(native.query_ref, query_type, unspecified, unspecified)
            .map_err(|error| error.to_string())?;
    observation.timestamp = native.observed_at;
    observation.response_code = Some(
        match native.result_category {
            WindowsDnsResultCategory::Pending => "PENDING",
            WindowsDnsResultCategory::Success => "NOERROR",
            WindowsDnsResultCategory::NameError => "NAME_ERROR",
            WindowsDnsResultCategory::Timeout => "TIMEOUT",
            WindowsDnsResultCategory::Refused => "REFUSED",
            WindowsDnsResultCategory::ServerFailure => "SERVER_FAILURE",
            WindowsDnsResultCategory::Cancelled => "CANCELLED",
            WindowsDnsResultCategory::OtherFailure => "OTHER_FAILURE",
        }
        .to_string(),
    );
    observation.features = DnsFeatures {
        query_length: match native.query_length_bucket {
            WindowsDnsLengthBucket::Short => 12,
            WindowsDnsLengthBucket::Medium => 32,
            WindowsDnsLengthBucket::Long => 72,
        },
        label_count: match native.subdomain_depth_bucket {
            WindowsDnsDepthBucket::Shallow => 2,
            WindowsDnsDepthBucket::Moderate => 4,
            WindowsDnsDepthBucket::Deep => 6,
        },
        subdomain_depth: match native.subdomain_depth_bucket {
            WindowsDnsDepthBucket::Shallow => 1,
            WindowsDnsDepthBucket::Moderate => 3,
            WindowsDnsDepthBucket::Deep => 5,
        },
        character_entropy: Some(match native.entropy_bucket {
            WindowsDnsEntropyBucket::Low => 2.0,
            WindowsDnsEntropyBucket::Medium => 3.3,
            WindowsDnsEntropyBucket::High => 4.0,
        }),
        answer_count: match native.answer_count_bucket {
            WindowsDnsAnswerCountBucket::Unknown | WindowsDnsAnswerCountBucket::Zero => 0,
            WindowsDnsAnswerCountBucket::One => 1,
            WindowsDnsAnswerCountBucket::Few => 3,
            WindowsDnsAnswerCountBucket::Many => 10,
        },
    };
    observation.privacy_class = PrivacyClass::Internal;
    observation.quality_score = quality(0.62).map_err(|error| error.to_string())?;
    Ok(observation)
}

#[cfg(test)]
mod windows_dns_adapter_tests {
    use super::*;
    use sentinel_contracts::{WindowsDnsRecurrenceBucket, WINDOWS_DNS_SENSING_SCHEMA_VERSION};

    #[test]
    fn native_dns_adapter_preserves_only_protected_query_ref() {
        let observation = windows_dns_detector_observation(WindowsDnsObservation {
            schema_version: WINDOWS_DNS_SENSING_SCHEMA_VERSION,
            observation_ref: "dns_observation_1".to_string(),
            query_ref: "dns_query_0123456789abcdef".to_string(),
            query_type_category: WindowsDnsQueryTypeCategory::Address,
            result_category: WindowsDnsResultCategory::Success,
            query_length_bucket: WindowsDnsLengthBucket::Medium,
            subdomain_depth_bucket: WindowsDnsDepthBucket::Shallow,
            entropy_bucket: WindowsDnsEntropyBucket::Low,
            answer_count_bucket: WindowsDnsAnswerCountBucket::Unknown,
            recurrence_bucket: WindowsDnsRecurrenceBucket::One,
            observed_at: Timestamp::now(),
            provenance_refs: vec!["windows_dns_client_etw".to_string()],
            redaction_status: RedactionStatus::Redacted,
        })
        .expect("adapt");
        assert_eq!(
            observation.query_name_protected,
            "dns_query_0123456789abcdef"
        );
        assert!(observation.client_ip.as_ip_addr().is_unspecified());
        assert!(observation.resolver_ip.as_ip_addr().is_unspecified());
        assert!(observation.answers.is_empty());
        assert!(observation.process_ref.is_none());
    }
}

pub fn register_static_dns_security_v2_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableDnsSecurityV2RuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableHttpAnalysisV1RuntimePlugin {
    manifest: PluginManifest,
    capability: PortableHttpAnalysisV1Plugin,
}

impl StaticPortableHttpAnalysisV1RuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(HTTP_ANALYSIS_V1_STATIC_PLUGIN_ID)?,
            capability: PortableHttpAnalysisV1Plugin,
        })
    }
}

impl PluginLifecycle for StaticPortableHttpAnalysisV1RuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "http analysis v1")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal http analysis v1 runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableHttpAnalysisV1RuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "http analysis v1")?;
        let mut flows = Vec::new();
        let mut sessions = Vec::new();
        let mut http_metadata = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_SESSION_RECORD => {
                    sessions.push(parse_event_payload::<SessionRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_SESSION_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_HTTP_METADATA => {
                    http_metadata.push(parse_event_payload::<HttpMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_HTTP_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableHttpAnalysisInput {
                flow_records: &flows,
                session_records: &sessions,
                http_metadata: &http_metadata,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(&self.manifest.plugin_id, context, "http analysis v1");
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_http_analysis_v1_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableHttpAnalysisV1RuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableApiSecurityLiteRuntimePlugin {
    manifest: PluginManifest,
    capability: PortableApiSecurityLitePlugin,
}

impl StaticPortableApiSecurityLiteRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(API_SECURITY_LITE_STATIC_PLUGIN_ID)?,
            capability: PortableApiSecurityLitePlugin,
        })
    }
}

impl PluginLifecycle for StaticPortableApiSecurityLiteRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "api security lite")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal api security lite runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableApiSecurityLiteRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "api security lite")?;
        let mut flows = Vec::new();
        let mut http_metadata = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_HTTP_METADATA => {
                    http_metadata.push(parse_event_payload::<HttpMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_HTTP_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableApiSecurityLiteInput {
                flow_records: &flows,
                http_metadata: &http_metadata,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(&self.manifest.plugin_id, context, "api security lite");
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_api_security_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableApiSecurityLiteRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableWafSecurityLiteRuntimePlugin {
    manifest: PluginManifest,
    capability: PortableWafSecurityLitePlugin,
}

impl StaticPortableWafSecurityLiteRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(WAF_SECURITY_LITE_STATIC_PLUGIN_ID)?,
            capability: PortableWafSecurityLitePlugin,
        })
    }
}

impl PluginLifecycle for StaticPortableWafSecurityLiteRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "waf security lite")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal waf security lite runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableWafSecurityLiteRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "waf security lite")?;
        let mut flows = Vec::new();
        let mut http_metadata = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_HTTP_METADATA => {
                    http_metadata.push(parse_event_payload::<HttpMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_HTTP_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableWafSecurityLiteInput {
                flow_records: &flows,
                http_metadata: &http_metadata,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(&self.manifest.plugin_id, context, "waf security lite");
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_waf_security_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableWafSecurityLiteRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableQuicHttp3SecurityLiteRuntimePlugin {
    manifest: PluginManifest,
    capability: PortableQuicHttp3SecurityLitePlugin,
}

impl StaticPortableQuicHttp3SecurityLiteRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(QUIC_HTTP3_SECURITY_LITE_STATIC_PLUGIN_ID)?,
            capability: PortableQuicHttp3SecurityLitePlugin,
        })
    }
}

impl PluginLifecycle for StaticPortableQuicHttp3SecurityLiteRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "quic http3 security lite",
        )
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal quic http3 security lite runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableQuicHttp3SecurityLiteRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "quic http3 security lite",
        )?;
        let mut flows = Vec::new();
        let mut tls_observations = Vec::new();
        let mut http_metadata = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_TLS_OBSERVATION => {
                    tls_observations.push(parse_event_payload::<TlsObservation>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_TLS_OBSERVATION,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_HTTP_METADATA => {
                    http_metadata.push(parse_event_payload::<HttpMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_HTTP_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableQuicHttp3SecurityLiteInput {
                flow_records: &flows,
                tls_observations: &tls_observations,
                http_metadata: &http_metadata,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(
                    &self.manifest.plugin_id,
                    context,
                    "quic http3 security lite",
                );
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_quic_http3_security_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableQuicHttp3SecurityLiteRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableRemoteAdminObservationLiteRuntimePlugin {
    manifest: PluginManifest,
    capability: PortableRemoteAdminObservationLitePlugin,
}

impl StaticPortableRemoteAdminObservationLiteRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(REMOTE_ADMIN_PROTOCOL_LITE_STATIC_PLUGIN_ID)?,
            capability: PortableRemoteAdminObservationLitePlugin,
        })
    }
}

impl PluginLifecycle for StaticPortableRemoteAdminObservationLiteRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "remote admin protocol lite",
        )
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal remote admin protocol lite runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableRemoteAdminObservationLiteRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "remote admin protocol lite",
        )?;
        let mut flows = Vec::new();
        let mut sessions = Vec::new();
        let mut remote_auth_metadata = Vec::new();
        let mut smb_operational_observations = 0_usize;
        let mut ssh_operational_observations = 0_usize;
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_SESSION_RECORD => {
                    sessions.push(parse_event_payload::<SessionRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_SESSION_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                IDENTITY_AUTH_METADATA => {
                    let metadata = parse_event_payload::<PortableAuthMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        IDENTITY_AUTH_METADATA,
                    )?;
                    if metadata
                        .destination_service_category
                        .as_deref()
                        .is_some_and(|service| matches!(service, "rdp" | "smb" | "ssh"))
                    {
                        remote_auth_metadata.push(metadata);
                        source_event_refs.push(event.event_id.clone());
                    }
                }
                IDENTITY_SMB_OPERATIONAL_METADATA => {
                    let batch = parse_event_payload::<WindowsAuthRemoteObservationBatch>(
                        &self.manifest.plugin_id,
                        event,
                        IDENTITY_SMB_OPERATIONAL_METADATA,
                    )?;
                    let consumed = batch
                        .observations
                        .iter()
                        .filter(|observation| {
                            observation.remote_protocol_category
                                == Some(sentinel_contracts::WindowsRemoteProtocolCategory::Smb)
                        })
                        .count();
                    if consumed > 0 {
                        smb_operational_observations =
                            smb_operational_observations.saturating_add(consumed);
                        source_event_refs.push(event.event_id.clone());
                    }
                }
                IDENTITY_SSH_OPERATIONAL_METADATA => {
                    let batch = parse_event_payload::<WindowsAuthRemoteObservationBatch>(
                        &self.manifest.plugin_id,
                        event,
                        IDENTITY_SSH_OPERATIONAL_METADATA,
                    )?;
                    let consumed = batch
                        .observations
                        .iter()
                        .filter(|observation| {
                            observation.remote_protocol_category
                                == Some(sentinel_contracts::WindowsRemoteProtocolCategory::Ssh)
                        })
                        .count();
                    if consumed > 0 {
                        ssh_operational_observations =
                            ssh_operational_observations.saturating_add(consumed);
                        source_event_refs.push(event.event_id.clone());
                    }
                }
                _ => {}
            }
        }

        if flows.is_empty()
            && sessions.is_empty()
            && (!remote_auth_metadata.is_empty()
                || smb_operational_observations > 0
                || ssh_operational_observations > 0)
        {
            return empty_output(
                &self.manifest.plugin_id,
                context,
                "remote admin protocol lite operational metadata without flow/session visibility",
            );
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableRemoteAdminObservationLiteInput {
                flow_records: &flows,
                session_records: &sessions,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(
                    &self.manifest.plugin_id,
                    context,
                    "remote admin protocol lite",
                );
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_remote_admin_protocol_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableRemoteAdminObservationLiteRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableAuthIdentityAnalysisLiteRuntimePlugin {
    manifest: PluginManifest,
    capability: PortableAuthIdentityAnalysisLitePlugin,
}

impl StaticPortableAuthIdentityAnalysisLiteRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(AUTH_IDENTITY_ANALYSIS_LITE_STATIC_PLUGIN_ID)?,
            capability: PortableAuthIdentityAnalysisLitePlugin,
        })
    }
}

impl PluginLifecycle for StaticPortableAuthIdentityAnalysisLiteRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "auth identity analysis lite",
        )
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal auth identity analysis lite runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableAuthIdentityAnalysisLiteRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "auth identity analysis lite",
        )?;
        let mut flows = Vec::new();
        let mut sessions = Vec::new();
        let mut auth_metadata = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_SESSION_RECORD => {
                    sessions.push(parse_event_payload::<SessionRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_SESSION_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                IDENTITY_AUTH_METADATA => {
                    auth_metadata.push(parse_event_payload::<PortableAuthMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        IDENTITY_AUTH_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableAuthIdentityAnalysisLiteInput {
                flow_records: &flows,
                session_records: &sessions,
                auth_metadata: &auth_metadata,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(
                    &self.manifest.plugin_id,
                    context,
                    "auth identity analysis lite",
                );
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_auth_identity_analysis_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableAuthIdentityAnalysisLiteRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticPortableSaasCloudAbuseLiteRuntimePlugin {
    manifest: PluginManifest,
    capability: PortableSaasCloudAbuseLitePlugin,
}

impl StaticPortableSaasCloudAbuseLiteRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(SAAS_CLOUD_ABUSE_LITE_STATIC_PLUGIN_ID)?,
            capability: PortableSaasCloudAbuseLitePlugin,
        })
    }
}

impl PluginLifecycle for StaticPortableSaasCloudAbuseLiteRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "saas cloud abuse lite")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal saas cloud abuse lite runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticPortableSaasCloudAbuseLiteRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "saas cloud abuse lite")?;
        let mut saas_cloud_metadata = Vec::new();
        let mut auth_metadata = Vec::new();
        let mut http_metadata = Vec::new();
        let mut related_findings = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                CLOUD_SAAS_METADATA => {
                    saas_cloud_metadata.push(parse_event_payload::<PortableSaasCloudMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        CLOUD_SAAS_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                IDENTITY_AUTH_METADATA => {
                    auth_metadata.push(parse_event_payload::<PortableAuthMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        IDENTITY_AUTH_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_HTTP_METADATA => {
                    http_metadata.push(parse_event_payload::<HttpMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_HTTP_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                SECURITY_FINDING => {
                    related_findings.push(parse_event_payload::<Finding>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_FINDING,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableSaasCloudAbuseLiteInput {
                saas_cloud_metadata: &saas_cloud_metadata,
                auth_metadata: &auth_metadata,
                http_metadata: &http_metadata,
                related_findings: &related_findings,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(&self.manifest.plugin_id, context, "saas cloud abuse lite");
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_portable_saas_cloud_abuse_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticPortableSaasCloudAbuseLiteRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticDeceptionEventLiteRuntimePlugin {
    manifest: PluginManifest,
    capability: PortableDeceptionEventLitePlugin,
}

impl StaticDeceptionEventLiteRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(DECEPTION_EVENT_LITE_STATIC_PLUGIN_ID)?,
            capability: PortableDeceptionEventLitePlugin,
        })
    }
}

impl PluginLifecycle for StaticDeceptionEventLiteRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "deception event lite")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal deception event lite runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticDeceptionEventLiteRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "deception event lite")?;
        let mut deception_events = Vec::new();
        let mut related_findings = Vec::new();
        let mut related_risk_hints = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                DECEPTION_EVENT_METADATA => {
                    deception_events.push(parse_event_payload::<PortableDeceptionEventMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        DECEPTION_EVENT_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                SECURITY_FINDING => {
                    related_findings.push(parse_event_payload::<Finding>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_FINDING,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                SECURITY_RISK_HINT => {
                    related_risk_hints.push(parse_event_payload::<RiskHint>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_RISK_HINT,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }

        let mut output = match self.capability.analyze(
            &self.manifest.plugin_id,
            PortableDeceptionEventLiteInput {
                deception_events: &deception_events,
                related_findings: &related_findings,
                related_risk_hints: &related_risk_hints,
            },
        ) {
            Ok(output) => output,
            Err(
                PortableNetworkWebAnalysisError::EmptyInput(_)
                | PortableNetworkWebAnalysisError::NoSignals,
            ) => {
                return empty_output(&self.manifest.plugin_id, context, "deception event lite");
            }
            Err(error) => return Err(portable_network_web_error(&self.manifest.plugin_id, error)),
        };
        attach_portable_web_source_refs(&mut output, &source_event_refs);
        portable_network_web_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_deception_event_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticDeceptionEventLiteRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticMultiLayerSecurityFusionRuntimePlugin {
    manifest: PluginManifest,
    capability: MultiLayerSecurityFusionPlugin,
}

impl StaticMultiLayerSecurityFusionRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(MULTI_LAYER_SECURITY_FUSION_STATIC_PLUGIN_ID)?,
            capability: MultiLayerSecurityFusionPlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticMultiLayerSecurityFusionRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "multi-layer fusion")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal multi-layer fusion runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticMultiLayerSecurityFusionRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "multi-layer fusion")?;
        let mut provenance = None;
        let mut dns_observations = Vec::new();
        let mut http_metadata = Vec::new();
        let mut auth_metadata = Vec::new();
        let mut saas_cloud_metadata = Vec::new();
        let mut deception_events = Vec::new();
        let mut sdn_control_plane_metadata = Vec::new();
        let mut findings = Vec::new();
        let mut source_event_refs = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                SECURITY_FUSION_CONTEXT => {
                    provenance = Some(parse_event_payload::<PortableCaptureProvenance>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_FUSION_CONTEXT,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_DNS_OBSERVATION => {
                    dns_observations.push(parse_event_payload::<DnsObservation>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_DNS_OBSERVATION,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_HTTP_METADATA => {
                    http_metadata.push(parse_event_payload::<HttpMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_HTTP_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                IDENTITY_AUTH_METADATA => {
                    auth_metadata.push(parse_event_payload::<PortableAuthMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        IDENTITY_AUTH_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                CLOUD_SAAS_METADATA => {
                    saas_cloud_metadata.push(parse_event_payload::<PortableSaasCloudMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        CLOUD_SAAS_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                DECEPTION_EVENT_METADATA => {
                    deception_events.push(parse_event_payload::<PortableDeceptionEventMetadata>(
                        &self.manifest.plugin_id,
                        event,
                        DECEPTION_EVENT_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_SDN_CONTROL_PLANE_METADATA => {
                    sdn_control_plane_metadata.push(parse_event_payload::<
                        PortableSdnControlPlaneMetadata,
                    >(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_SDN_CONTROL_PLANE_METADATA,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                SECURITY_FINDING => {
                    findings.push(parse_event_payload::<Finding>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_FINDING,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }
        let Some(provenance) = provenance else {
            return empty_output(&self.manifest.plugin_id, context, "multi-layer fusion");
        };
        let mut output = self
            .capability
            .analyze(
                &self.manifest.plugin_id,
                MultiLayerFusionInput {
                    provenance: &provenance,
                    dns_observations: &dns_observations,
                    http_metadata: &http_metadata,
                    auth_metadata: &auth_metadata,
                    saas_cloud_metadata: &saas_cloud_metadata,
                    deception_events: &deception_events,
                    sdn_control_plane_metadata: &sdn_control_plane_metadata,
                    findings: &findings,
                },
            )
            .map_err(|error| process_error(&self.manifest.plugin_id, error.to_string()))?;
        for evidence in &mut output.evidence {
            if evidence.source_event_refs.is_empty() {
                evidence.source_event_refs = source_event_refs.clone();
            }
        }
        multi_layer_fusion_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_multi_layer_security_fusion_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticMultiLayerSecurityFusionRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticNativeSamplerFactRuntimePlugin {
    manifest: PluginManifest,
    capability: NativeSamplerFactPlugin,
}

impl StaticNativeSamplerFactRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(NATIVE_SAMPLER_FACT_STATIC_PLUGIN_ID)?,
            capability: NativeSamplerFactPlugin,
        })
    }
}

impl PluginLifecycle for StaticNativeSamplerFactRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "native sampler facts")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal native sampler fact runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticNativeSamplerFactRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "native sampler facts")?;
        let mut events = Vec::new();
        for event in &batch.events {
            if !matches!(
                event.event_type.as_str(),
                NATIVE_HEALTH_METADATA
                    | NATIVE_SERVICE_METADATA
                    | NATIVE_PROCESS_METADATA
                    | NATIVE_PROCESS_PARENT_METADATA
            ) {
                continue;
            }
            let native_batch = parse_event_payload::<sentinel_contracts::NativeSamplerRuntimeBatch>(
                &self.manifest.plugin_id,
                event,
                event.event_type.as_str(),
            )?;
            let facts = self
                .capability
                .process_batch(&native_batch)
                .map_err(|error| process_error(&self.manifest.plugin_id, error.to_string()))?;
            for fact in facts {
                let topic = match fact.layer {
                    sentinel_contracts::SecurityLayer::AuthorizedNativeHealth => {
                        ENDPOINT_NATIVE_HEALTH_FACT_CONTRACT
                    }
                    sentinel_contracts::SecurityLayer::AuthorizedNativeService => {
                        ENDPOINT_SERVICE_CATEGORY_FACT_CONTRACT
                    }
                    sentinel_contracts::SecurityLayer::AuthorizedNativeProcess => {
                        if fact.category == ENDPOINT_PROCESS_PARENT_CATEGORY_FACT_CONTRACT {
                            ENDPOINT_PROCESS_PARENT_CATEGORY_FACT_CONTRACT
                        } else {
                            ENDPOINT_PROCESS_CATEGORY_FACT_CONTRACT
                        }
                    }
                    _ => {
                        return Err(process_error(
                            &self.manifest.plugin_id,
                            "native sampler fact plugin produced an undeclared layer",
                        ));
                    }
                };
                events.push(envelope(
                    &self.manifest.plugin_id,
                    topic,
                    &fact,
                    NATIVE_SAMPLER_RUNTIME_SCHEMA_VERSION,
                    fact.confidence_hint.clone(),
                    context,
                )?);
            }
        }
        Ok(PluginOutput {
            events,
            health: vec![self.health_snapshot(context)?],
            metrics: Vec::new(),
            audit_events: Vec::new(),
        })
    }
}

pub fn register_static_native_sampler_fact_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticNativeSamplerFactRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticNativeNetworkFactRuntimePlugin {
    manifest: PluginManifest,
    capability: NativeNetworkFactPlugin,
}

impl StaticNativeNetworkFactRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(NATIVE_NETWORK_FACT_STATIC_PLUGIN_ID)?,
            capability: NativeNetworkFactPlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticNativeNetworkFactRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "native network facts")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal native network fact runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticNativeNetworkFactRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "native network facts")?;
        let mut events = Vec::new();
        for event in &batch.events {
            let facts = match event.event_type.as_str() {
                NATIVE_IP_HELPER_METADATA => {
                    let native_batch = parse_event_payload::<NativeIpHelperMetadataBatch>(
                        &self.manifest.plugin_id,
                        event,
                        NATIVE_IP_HELPER_METADATA,
                    )?;
                    self.capability
                        .process_batch(&native_batch)
                        .map_err(|error| {
                            process_error(&self.manifest.plugin_id, error.to_string())
                        })?
                }
                NATIVE_ETW_NETWORK_METADATA => {
                    let etw_batch = parse_event_payload::<EtwNormalizedNetworkBatch>(
                        &self.manifest.plugin_id,
                        event,
                        NATIVE_ETW_NETWORK_METADATA,
                    )?;
                    self.capability
                        .process_etw_batch(&etw_batch)
                        .map_err(|error| {
                            process_error(&self.manifest.plugin_id, error.to_string())
                        })?
                }
                _ => continue,
            };
            for fact in facts {
                if fact.layer != SecurityLayer::AuthorizedNativeNetwork {
                    return Err(process_error(
                        &self.manifest.plugin_id,
                        "native network fact plugin produced an undeclared layer",
                    ));
                }
                if !matches!(
                    fact.category.as_str(),
                    NATIVE_NETWORK_FACT_CONTRACT
                        | NATIVE_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT
                        | NATIVE_NETWORK_VISIBILITY_FACT_CONTRACT
                        | NATIVE_ETW_NETWORK_PROVIDER_HEALTH_FACT_CONTRACT
                        | NATIVE_ETW_NETWORK_VISIBILITY_FACT_CONTRACT
                ) {
                    return Err(process_error(
                        &self.manifest.plugin_id,
                        "native network fact plugin produced an undeclared fact category",
                    ));
                }
                if fact.process_category.is_some()
                    || fact.parent_process_category.is_some()
                    || fact.execution_context_category.is_some()
                {
                    return Err(process_error(
                        &self.manifest.plugin_id,
                        "native network fact plugin must not emit process attribution",
                    ));
                }
                events.push(envelope(
                    &self.manifest.plugin_id,
                    NATIVE_CONNECTION_CATEGORY_FACT,
                    &fact,
                    NATIVE_NETWORK_FACT_SCHEMA_VERSION,
                    fact.confidence_hint.clone(),
                    context,
                )?);
            }
        }
        Ok(PluginOutput {
            events,
            health: vec![self.health_snapshot(context)?],
            metrics: Vec::new(),
            audit_events: Vec::new(),
        })
    }
}

pub fn register_static_native_network_fact_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticNativeNetworkFactRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticEndpointThreatAnalysisRuntimePlugin {
    manifest: PluginManifest,
    detector: EndpointThreatDetectorPack,
    integrator: EndpointThreatIntelligenceIntegrator,
}

impl StaticEndpointThreatAnalysisRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(ENDPOINT_THREAT_ANALYSIS_LITE_STATIC_PLUGIN_ID)?,
            detector: EndpointThreatDetectorPack::new(),
            integrator: EndpointThreatIntelligenceIntegrator::new(),
        })
    }
}

impl PluginLifecycle for StaticEndpointThreatAnalysisRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "endpoint threat analysis",
        )
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal endpoint threat analysis runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticEndpointThreatAnalysisRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(
            context,
            &self.manifest.plugin_id,
            "endpoint threat analysis",
        )?;
        let mut facts = Vec::new();
        let mut findings = Vec::new();
        let mut risk_hints = Vec::new();
        let mut hypotheses = Vec::new();
        let mut fusion_summaries = Vec::new();

        for event in &batch.events {
            match event.event_type.as_str() {
                ENDPOINT_NATIVE_HEALTH_CATEGORY_FACT
                | ENDPOINT_SERVICE_CATEGORY_FACT
                | ENDPOINT_PROCESS_CATEGORY_FACT
                | ENDPOINT_PROCESS_PARENT_CATEGORY_FACT => {
                    facts.push(parse_event_payload::<SecurityFact>(
                        &self.manifest.plugin_id,
                        event,
                        event.event_type.as_str(),
                    )?);
                }
                SECURITY_FINDING => {
                    findings.push(parse_event_payload::<Finding>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_FINDING,
                    )?);
                }
                SECURITY_RISK_HINT => {
                    risk_hints.push(parse_event_payload::<RiskHint>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_RISK_HINT,
                    )?);
                }
                SECURITY_HYPOTHESIS => {
                    hypotheses.push(parse_event_payload::<AttackHypothesisRecord>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_HYPOTHESIS,
                    )?);
                }
                SECURITY_FUSION_SUMMARY => {
                    fusion_summaries.push(parse_event_payload::<FusionSummary>(
                        &self.manifest.plugin_id,
                        event,
                        SECURITY_FUSION_SUMMARY,
                    )?);
                }
                _ => {}
            }
        }

        let Some(input) = endpoint_detection_input_from_runtime(
            &facts,
            &findings,
            &risk_hints,
            &hypotheses,
            &fusion_summaries,
        )
        .map_err(|error| endpoint_capability_error(&self.manifest.plugin_id, error))?
        else {
            return empty_output(
                &self.manifest.plugin_id,
                context,
                "endpoint threat analysis",
            );
        };

        let detector_output = self
            .detector
            .analyze(&input)
            .map_err(|error| endpoint_capability_error(&self.manifest.plugin_id, error))?;
        let intelligence_output = self
            .integrator
            .integrate(&EndpointThreatIntelligenceInput {
                findings: detector_output.findings.clone(),
                facts: input.facts.clone(),
                evaluations: detector_output.evaluations.clone(),
            })
            .map_err(|error| endpoint_capability_error(&self.manifest.plugin_id, error))?;
        let endpoint_evidence = endpoint_runtime_evidence(&input)
            .map_err(|error| endpoint_capability_error(&self.manifest.plugin_id, error))?;
        let endpoint_risk_hints = endpoint_runtime_risk_hints(&detector_output, &input)
            .map_err(|error| endpoint_capability_error(&self.manifest.plugin_id, error))?;

        endpoint_threat_runtime_output(
            &self.manifest.plugin_id,
            &detector_output,
            &endpoint_evidence,
            &endpoint_risk_hints,
            &intelligence_output.graph_hints,
            context,
        )
    }
}

pub fn register_static_endpoint_threat_analysis_lite_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticEndpointThreatAnalysisRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticC2DetectionRuntimePlugin {
    manifest: PluginManifest,
    capability: C2DetectionPlugin,
}

impl StaticC2DetectionRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(C2_DETECTION_STATIC_PLUGIN_ID)?,
            capability: C2DetectionPlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticC2DetectionRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "c2 detection")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal c2 detection runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticC2DetectionRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "c2 detection")?;
        let mut input = C2DetectionInput::new(self.manifest.plugin_id.clone());
        input.trace_id = Some(context.trace_context.trace_id.clone());
        let mut source_event_refs = Vec::new();
        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    input.flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_SESSION_RECORD => {
                    input.sessions.push(parse_event_payload::<SessionRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_SESSION_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_DNS_OBSERVATION => {
                    input
                        .dns_observations
                        .push(parse_event_payload::<DnsObservation>(
                            &self.manifest.plugin_id,
                            event,
                            NETWORK_DNS_OBSERVATION,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_TLS_OBSERVATION => {
                    input
                        .tls_observations
                        .push(parse_event_payload::<TlsObservation>(
                            &self.manifest.plugin_id,
                            event,
                            NETWORK_TLS_OBSERVATION,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                IDENTITY_PROCESS_CONTEXT => {
                    input
                        .process_contexts
                        .push(parse_event_payload::<ProcessContext>(
                            &self.manifest.plugin_id,
                            event,
                            IDENTITY_PROCESS_CONTEXT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                INTEL_DOMAIN_CONTEXT => {
                    input
                        .domain_contexts
                        .push(parse_event_payload::<DomainContext>(
                            &self.manifest.plugin_id,
                            event,
                            INTEL_DOMAIN_CONTEXT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                INTEL_IP_CONTEXT => {
                    input.ip_contexts.push(parse_event_payload::<IpContext>(
                        &self.manifest.plugin_id,
                        event,
                        INTEL_IP_CONTEXT,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                INTEL_CLOUD_CONTEXT => {
                    input
                        .cloud_contexts
                        .push(parse_event_payload::<CloudContext>(
                            &self.manifest.plugin_id,
                            event,
                            INTEL_CLOUD_CONTEXT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                INTEL_CERTIFICATE_CONTEXT => {
                    input
                        .certificate_contexts
                        .push(parse_event_payload::<CertificateContext>(
                            &self.manifest.plugin_id,
                            event,
                            INTEL_CERTIFICATE_CONTEXT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }
        let mut output = match self.capability.detect(input) {
            Ok(output) => output,
            Err(C2DetectionError::EmptyInput | C2DetectionError::NoSignals) => {
                return empty_output(&self.manifest.plugin_id, context, "c2 detection");
            }
            Err(error) => return Err(c2_capability_error(&self.manifest.plugin_id, error)),
        };
        attach_collected_evidence_source_refs(&mut output.evidence, &source_event_refs);
        c2_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_c2_detection_plugin(runtime: &mut PluginRuntime) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticC2DetectionRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticExfiltrationDetectionRuntimePlugin {
    manifest: PluginManifest,
    capability: ExfiltrationDetectionPlugin,
}

impl StaticExfiltrationDetectionRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(EXFILTRATION_DETECTION_STATIC_PLUGIN_ID)?,
            capability: ExfiltrationDetectionPlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticExfiltrationDetectionRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "exfiltration detection")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal exfiltration runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticExfiltrationDetectionRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "exfiltration detection")?;
        let mut input = ExfiltrationDetectionInput::new(self.manifest.plugin_id.clone());
        input.trace_id = Some(context.trace_context.trace_id.clone());
        let mut source_event_refs = Vec::new();
        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    input.flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_SESSION_RECORD => {
                    input.sessions.push(parse_event_payload::<SessionRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_SESSION_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_HTTP_METADATA => {
                    input
                        .http_metadata
                        .push(parse_event_payload::<HttpMetadata>(
                            &self.manifest.plugin_id,
                            event,
                            NETWORK_HTTP_METADATA,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                IDENTITY_PROCESS_CONTEXT => {
                    input
                        .process_contexts
                        .push(parse_event_payload::<ProcessContext>(
                            &self.manifest.plugin_id,
                            event,
                            IDENTITY_PROCESS_CONTEXT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                INTEL_IP_CONTEXT => {
                    input.ip_contexts.push(parse_event_payload::<IpContext>(
                        &self.manifest.plugin_id,
                        event,
                        INTEL_IP_CONTEXT,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                INTEL_CLOUD_CONTEXT => {
                    input
                        .cloud_contexts
                        .push(parse_event_payload::<CloudContext>(
                            &self.manifest.plugin_id,
                            event,
                            INTEL_CLOUD_CONTEXT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                SECURITY_FINDING => {
                    input
                        .related_c2_findings
                        .push(parse_event_payload::<Finding>(
                            &self.manifest.plugin_id,
                            event,
                            SECURITY_FINDING,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                GRAPH_HINT => {
                    input
                        .related_c2_graph_hints
                        .push(parse_event_payload::<GraphHint>(
                            &self.manifest.plugin_id,
                            event,
                            GRAPH_HINT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }
        let mut output = match self.capability.detect(input) {
            Ok(output) => output,
            Err(ExfiltrationDetectionError::EmptyInput | ExfiltrationDetectionError::NoSignals) => {
                return empty_output(&self.manifest.plugin_id, context, "exfiltration detection");
            }
            Err(error) => {
                return Err(exfiltration_capability_error(
                    &self.manifest.plugin_id,
                    error,
                ))
            }
        };
        attach_collected_evidence_source_refs(&mut output.evidence, &source_event_refs);
        exfiltration_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_exfiltration_detection_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticExfiltrationDetectionRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticLateralMovementRuntimePlugin {
    manifest: PluginManifest,
    capability: LateralMovementLitePlugin,
}

impl StaticLateralMovementRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(LATERAL_MOVEMENT_STATIC_PLUGIN_ID)?,
            capability: LateralMovementLitePlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticLateralMovementRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "lateral movement lite")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal lateral movement runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticLateralMovementRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "lateral movement lite")?;
        let mut input = LateralMovementLiteInput::new(self.manifest.plugin_id.clone());
        input.trace_id = Some(context.trace_context.trace_id.clone());
        let mut source_event_refs = Vec::new();
        for event in &batch.events {
            match event.event_type.as_str() {
                NETWORK_FLOW_RECORD => {
                    input.flows.push(parse_event_payload::<FlowRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_FLOW_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                NETWORK_SESSION_RECORD => {
                    input.sessions.push(parse_event_payload::<SessionRecord>(
                        &self.manifest.plugin_id,
                        event,
                        NETWORK_SESSION_RECORD,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                IDENTITY_PROCESS_CONTEXT => {
                    input
                        .process_contexts
                        .push(parse_event_payload::<ProcessContext>(
                            &self.manifest.plugin_id,
                            event,
                            IDENTITY_PROCESS_CONTEXT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                ASSET_RECORD_CONTRACT => {
                    input.assets.push(parse_event_payload::<AssetRecord>(
                        &self.manifest.plugin_id,
                        event,
                        ASSET_RECORD_CONTRACT,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                ASSET_SERVICE_RECORD_CONTRACT => {
                    input.services.push(parse_event_payload::<ServiceRecord>(
                        &self.manifest.plugin_id,
                        event,
                        ASSET_SERVICE_RECORD_CONTRACT,
                    )?);
                    source_event_refs.push(event.event_id.clone());
                }
                ASSET_PORT_EXPOSURE_CONTRACT => {
                    input
                        .port_exposures
                        .push(parse_event_payload::<PortExposureRecord>(
                            &self.manifest.plugin_id,
                            event,
                            ASSET_PORT_EXPOSURE_CONTRACT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                ASSET_EXPOSURE_OBSERVATION_CONTRACT => {
                    input
                        .asset_observations
                        .push(parse_event_payload::<AssetExposureObservation>(
                            &self.manifest.plugin_id,
                            event,
                            ASSET_EXPOSURE_OBSERVATION_CONTRACT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                ASSET_RISK_FINDING_CONTRACT => {
                    input
                        .asset_findings
                        .push(parse_event_payload::<AssetRiskFinding>(
                            &self.manifest.plugin_id,
                            event,
                            ASSET_RISK_FINDING_CONTRACT,
                        )?);
                    source_event_refs.push(event.event_id.clone());
                }
                ASSET_EXPOSURE => {
                    let exposure = parse_event_payload::<AssetExposureOutput>(
                        &self.manifest.plugin_id,
                        event,
                        ASSET_EXPOSURE,
                    )?;
                    input.asset_observations.extend(exposure.observations);
                    input.asset_findings.extend(exposure.findings);
                    source_event_refs.push(event.event_id.clone());
                }
                _ => {}
            }
        }
        let has_asset_context = !input.assets.is_empty()
            || !input.services.is_empty()
            || !input.port_exposures.is_empty()
            || !input.asset_observations.is_empty()
            || !input.asset_findings.is_empty();
        if input.flows.is_empty() || input.process_contexts.is_empty() || !has_asset_context {
            return empty_output(&self.manifest.plugin_id, context, "lateral movement lite");
        }
        let mut output = match self.capability.detect(input) {
            Ok(output) => output,
            Err(LateralMovementError::EmptyInput | LateralMovementError::NoSignals) => {
                return empty_output(&self.manifest.plugin_id, context, "lateral movement lite");
            }
            Err(error) => return Err(lateral_capability_error(&self.manifest.plugin_id, error)),
        };
        attach_collected_evidence_source_refs(&mut output.evidence, &source_event_refs);
        lateral_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_lateral_movement_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticLateralMovementRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticRiskAlertingRuntimePlugin {
    manifest: PluginManifest,
    capability: RiskBasedAlertingPlugin,
}

impl StaticRiskAlertingRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(RISK_ALERTING_STATIC_PLUGIN_ID)?,
            capability: RiskBasedAlertingPlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticRiskAlertingRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "risk alerting")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal risk alerting runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticRiskAlertingRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "risk alerting")?;
        let mut input = RiskBasedAlertingInput::new(self.manifest.plugin_id.clone());
        for event in &batch.events {
            match event.event_type.as_str() {
                SECURITY_FINDING => input.findings.push(parse_event_payload::<Finding>(
                    &self.manifest.plugin_id,
                    event,
                    SECURITY_FINDING,
                )?),
                SECURITY_RISK_HINT => input.risk_hints.push(parse_event_payload::<RiskHint>(
                    &self.manifest.plugin_id,
                    event,
                    SECURITY_RISK_HINT,
                )?),
                SERVICE_CAPABILITY_STATUS => input.service_contexts.push(parse_event_payload::<
                    ServiceCapabilityContext,
                >(
                    &self.manifest.plugin_id,
                    event,
                    SERVICE_CAPABILITY_STATUS,
                )?),
                _ => {}
            }
        }
        if input.findings.is_empty() {
            return empty_output(&self.manifest.plugin_id, context, "risk alerting");
        }
        let output = self
            .capability
            .process(input)
            .map_err(|error| risk_capability_error(&self.manifest.plugin_id, error))?;
        risk_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_risk_alerting_plugin(runtime: &mut PluginRuntime) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticRiskAlertingRuntimePlugin::from_static_catalog()?,
    ))
}

#[derive(Clone, Debug)]
struct StaticResponsePlanningRuntimePlugin {
    manifest: PluginManifest,
    capability: ResponsePlanningPlugin,
}

impl StaticResponsePlanningRuntimePlugin {
    fn from_static_catalog() -> PluginResult<Self> {
        Ok(Self {
            manifest: manifest_from_static_catalog(RESPONSE_PLANNING_STATIC_PLUGIN_ID)?,
            capability: ResponsePlanningPlugin::new(),
        })
    }
}

impl PluginLifecycle for StaticResponsePlanningRuntimePlugin {
    fn start(&mut self, context: &mut PluginContext<'_>) -> PluginResult<()> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "response planning")
    }

    fn health_snapshot(&self, _context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(healthy_plugin_snapshot(
            &self.manifest.plugin_id,
            "static internal response planning runtime is bound",
        ))
    }
}

impl InternalPlugin for StaticResponsePlanningRuntimePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        ensure_metadata_only_context(context, &self.manifest.plugin_id, "response planning")?;
        let mut input = ResponsePlanningInput::new(self.manifest.plugin_id.clone());
        input.observed_at = Timestamp::now();
        input.is_replay = context.replay.context.is_some();
        input.response_policy.replay_execution_disabled = true;
        for event in &batch.events {
            match event.event_type.as_str() {
                SECURITY_FINDING => input.findings.push(parse_event_payload::<Finding>(
                    &self.manifest.plugin_id,
                    event,
                    SECURITY_FINDING,
                )?),
                SECURITY_ALERT => input.alerts.push(parse_event_payload::<Alert>(
                    &self.manifest.plugin_id,
                    event,
                    SECURITY_ALERT,
                )?),
                SECURITY_INCIDENT => input.incidents.push(parse_event_payload::<Incident>(
                    &self.manifest.plugin_id,
                    event,
                    SECURITY_INCIDENT,
                )?),
                GRAPH_PATH => input.graph_paths.push(parse_event_payload::<GraphPath>(
                    &self.manifest.plugin_id,
                    event,
                    GRAPH_PATH,
                )?),
                RESPONSE_POLICY_SETTINGS_CONTRACT => {
                    input.response_policy = parse_event_payload::<ResponsePolicy>(
                        &self.manifest.plugin_id,
                        event,
                        RESPONSE_POLICY_SETTINGS_CONTRACT,
                    )?;
                }
                RESPONSE_POLICY_RULE_CONTRACT => {
                    input
                        .policy_rules
                        .push(parse_event_payload::<ResponsePolicyRule>(
                            &self.manifest.plugin_id,
                            event,
                            RESPONSE_POLICY_RULE_CONTRACT,
                        )?);
                }
                _ => {}
            }
        }
        let output = match self.capability.process(input) {
            Ok(output) => output,
            Err(ResponsePlanningError::EmptyInput) => {
                return empty_output(&self.manifest.plugin_id, context, "response planning");
            }
            Err(error) => return Err(response_capability_error(&self.manifest.plugin_id, error)),
        };
        response_output(&self.manifest.plugin_id, &output, context)
    }
}

pub fn register_static_response_planning_plugin(
    runtime: &mut PluginRuntime,
) -> PluginResult<PluginId> {
    runtime.register_static_plugin(Box::new(
        StaticResponsePlanningRuntimePlugin::from_static_catalog()?,
    ))
}

fn manifest_from_static_catalog(expected_plugin_id: &str) -> PluginResult<PluginManifest> {
    let catalog = BuiltInPluginCatalog::static_internal()?;
    catalog
        .manifests()
        .into_iter()
        .find(|manifest| manifest.plugin_id.to_string() == expected_plugin_id)
        .cloned()
        .ok_or_else(|| {
            PluginRuntimeError::ManifestInvalid(format!(
                "static manifest {expected_plugin_id} is missing"
            ))
        })
}

fn ensure_metadata_only_context(
    context: &PluginContext<'_>,
    plugin_id: &PluginId,
    capability_name: &str,
) -> PluginResult<()> {
    if !context.privacy.raw_content_persistence_forbidden() {
        return Err(process_error(
            plugin_id,
            format!("{capability_name} refuses unsafe persistence context"),
        ));
    }
    if context.runtime.resource_quota.allow_response_execution {
        return Err(process_error(
            plugin_id,
            format!("{capability_name} must not execute response actions"),
        ));
    }
    if !context.replay_safe() {
        return Err(process_error(
            plugin_id,
            format!("{capability_name} requires replay-safe runtime context"),
        ));
    }
    Ok(())
}

fn healthy_plugin_snapshot(plugin_id: &PluginId, message: &str) -> HealthSnapshot {
    let mut snapshot = HealthSnapshot::new(
        HealthSubject::Plugin {
            plugin_id: plugin_id.clone(),
        },
        ObservabilityHealthStatus::Healthy,
    );
    snapshot.message_redacted = Some(message.to_string());
    snapshot.stale_after_ms = Some(30_000);
    snapshot
}

fn empty_output(
    plugin_id: &PluginId,
    _context: &PluginContext<'_>,
    message: &str,
) -> PluginResult<PluginOutput> {
    let _ = message;
    Ok(PluginOutput {
        events: Vec::new(),
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn plugin_output_from_flow_sessionization(
    plugin_id: &PluginId,
    output: &FlowSessionizationOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for flow in &output.flows {
        events.push(envelope(
            plugin_id,
            NETWORK_FLOW_RECORD,
            flow,
            NETWORK_OBSERVATION_SCHEMA_VERSION,
            flow.quality_score.clone(),
            context,
        )?);
    }
    for session in &output.sessions {
        events.push(envelope(
            plugin_id,
            NETWORK_SESSION_RECORD,
            session,
            NETWORK_OBSERVATION_SCHEMA_VERSION,
            session.quality_score.clone(),
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal flow sessionization runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn asset_output_events(
    plugin_id: &PluginId,
    output: &AssetExposureOutput,
    context: &PluginContext<'_>,
) -> PluginResult<Vec<EventEnvelope>> {
    let mut events = vec![envelope(
        plugin_id,
        ASSET_EXPOSURE,
        output,
        ASSET_EXPOSURE_SCHEMA_VERSION,
        quality(0.82)?,
        context,
    )?];

    for observation in &output.observations {
        events.push(envelope(
            plugin_id,
            SECURITY_OBSERVATION,
            &observation.observation,
            ASSET_EXPOSURE_SCHEMA_VERSION,
            observation.observation.confidence.clone(),
            context,
        )?);
    }
    for finding in &output.findings {
        events.push(envelope(
            plugin_id,
            SECURITY_FINDING,
            &finding.finding,
            ASSET_EXPOSURE_SCHEMA_VERSION,
            finding.finding.confidence().clone(),
            context,
        )?);
    }
    for evidence in &output.evidence {
        events.push(envelope(
            plugin_id,
            SECURITY_EVIDENCE,
            evidence,
            ASSET_EXPOSURE_SCHEMA_VERSION,
            evidence.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.graph_hints {
        events.push(envelope(
            plugin_id,
            GRAPH_HINT,
            &hint.graph_hint,
            ASSET_EXPOSURE_SCHEMA_VERSION,
            hint.graph_hint.confidence.clone(),
            context,
        )?);
    }

    Ok(events)
}

fn c2_output(
    plugin_id: &PluginId,
    output: &C2DetectionOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for finding in &output.findings {
        events.push(envelope(
            plugin_id,
            SECURITY_FINDING,
            finding,
            C2_DETECTION_SCHEMA_VERSION,
            finding.confidence().clone(),
            context,
        )?);
    }
    for collected in &output.evidence {
        events.push(envelope(
            plugin_id,
            SECURITY_EVIDENCE,
            &collected.evidence,
            C2_DETECTION_SCHEMA_VERSION,
            collected.evidence.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.risk_hints {
        events.push(envelope(
            plugin_id,
            SECURITY_RISK_HINT,
            hint,
            C2_DETECTION_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.graph_hints {
        events.push(envelope(
            plugin_id,
            GRAPH_HINT,
            hint,
            C2_DETECTION_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal c2 detection runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn exfiltration_output(
    plugin_id: &PluginId,
    output: &ExfiltrationDetectionOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for finding in &output.findings {
        events.push(envelope(
            plugin_id,
            SECURITY_FINDING,
            finding,
            EXFILTRATION_DETECTION_SCHEMA_VERSION,
            finding.confidence().clone(),
            context,
        )?);
    }
    for collected in &output.evidence {
        events.push(envelope(
            plugin_id,
            SECURITY_EVIDENCE,
            &collected.evidence,
            EXFILTRATION_DETECTION_SCHEMA_VERSION,
            collected.evidence.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.risk_hints {
        events.push(envelope(
            plugin_id,
            SECURITY_RISK_HINT,
            hint,
            EXFILTRATION_DETECTION_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.graph_hints {
        events.push(envelope(
            plugin_id,
            GRAPH_HINT,
            hint,
            EXFILTRATION_DETECTION_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal exfiltration runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn lateral_output(
    plugin_id: &PluginId,
    output: &LateralMovementLiteOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for finding in &output.findings {
        events.push(envelope(
            plugin_id,
            SECURITY_FINDING,
            finding,
            LATERAL_MOVEMENT_SCHEMA_VERSION,
            finding.confidence().clone(),
            context,
        )?);
    }
    for collected in &output.evidence {
        events.push(envelope(
            plugin_id,
            SECURITY_EVIDENCE,
            &collected.evidence,
            LATERAL_MOVEMENT_SCHEMA_VERSION,
            collected.evidence.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.risk_hints {
        events.push(envelope(
            plugin_id,
            SECURITY_RISK_HINT,
            hint,
            LATERAL_MOVEMENT_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.graph_hints {
        events.push(envelope(
            plugin_id,
            GRAPH_HINT,
            hint,
            LATERAL_MOVEMENT_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal lateral movement runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn portable_network_web_output(
    plugin_id: &PluginId,
    output: &PortableNetworkWebOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for finding in &output.findings {
        events.push(envelope(
            plugin_id,
            SECURITY_FINDING,
            finding,
            PORTABLE_NETWORK_WEB_SCHEMA_VERSION,
            finding.confidence().clone(),
            context,
        )?);
    }
    for evidence in &output.evidence {
        events.push(envelope(
            plugin_id,
            SECURITY_EVIDENCE,
            evidence,
            PORTABLE_NETWORK_WEB_SCHEMA_VERSION,
            evidence.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.risk_hints {
        events.push(envelope(
            plugin_id,
            SECURITY_RISK_HINT,
            hint,
            PORTABLE_NETWORK_WEB_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.graph_hints {
        events.push(envelope(
            plugin_id,
            GRAPH_HINT,
            hint,
            PORTABLE_NETWORK_WEB_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal portable network/web runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn multi_layer_fusion_output(
    plugin_id: &PluginId,
    output: &MultiLayerFusionOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for fact in &output.facts {
        events.push(envelope(
            plugin_id,
            SECURITY_FACT_CONTRACT,
            fact,
            MULTI_LAYER_FUSION_SCHEMA_VERSION,
            fact.confidence_hint.clone(),
            context,
        )?);
    }
    for hypothesis in &output.hypotheses {
        events.push(envelope(
            plugin_id,
            SECURITY_HYPOTHESIS_CONTRACT,
            hypothesis,
            MULTI_LAYER_FUSION_SCHEMA_VERSION,
            quality(match hypothesis.confidence_bucket {
                sentinel_contracts::FusionConfidenceBucket::Medium => 0.68,
                sentinel_contracts::FusionConfidenceBucket::Low => 0.48,
                sentinel_contracts::FusionConfidenceBucket::Unknown => 0.35,
            })?,
            context,
        )?);
    }
    if let Some(summary) = &output.summary {
        events.push(envelope(
            plugin_id,
            SECURITY_FUSION_SUMMARY,
            summary,
            MULTI_LAYER_FUSION_SCHEMA_VERSION,
            quality(0.62)?,
            context,
        )?);
    }
    for finding in &output.findings {
        events.push(envelope(
            plugin_id,
            SECURITY_FINDING,
            finding,
            MULTI_LAYER_FUSION_SCHEMA_VERSION,
            finding.confidence().clone(),
            context,
        )?);
    }
    for evidence in &output.evidence {
        events.push(envelope(
            plugin_id,
            SECURITY_EVIDENCE,
            evidence,
            MULTI_LAYER_FUSION_SCHEMA_VERSION,
            evidence.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.risk_hints {
        events.push(envelope(
            plugin_id,
            SECURITY_RISK_HINT,
            hint,
            MULTI_LAYER_FUSION_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    for hint in &output.graph_hints {
        events.push(envelope(
            plugin_id,
            GRAPH_HINT,
            hint,
            MULTI_LAYER_FUSION_SCHEMA_VERSION,
            hint.confidence.clone(),
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal multi-layer fusion runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn risk_output(
    plugin_id: &PluginId,
    output: &RiskBasedAlertingOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for risk_event in &output.risk_events {
        events.push(envelope(
            plugin_id,
            SECURITY_RISK,
            risk_event,
            RISK_ALERTING_SCHEMA_VERSION,
            risk_event.risk_score.clone(),
            context,
        )?);
    }
    for candidate in &output.alert_candidates {
        events.push(envelope(
            plugin_id,
            ALERT_CANDIDATE_CONTRACT,
            candidate,
            RISK_ALERTING_SCHEMA_VERSION,
            candidate.confidence.clone(),
            context,
        )?);
    }
    for alert in &output.alerts {
        events.push(envelope(
            plugin_id,
            SECURITY_ALERT,
            alert,
            RISK_ALERTING_SCHEMA_VERSION,
            alert.confidence().clone(),
            context,
        )?);
    }
    for candidate in &output.incident_candidates {
        events.push(envelope(
            plugin_id,
            INCIDENT_CANDIDATE_CONTRACT,
            candidate,
            RISK_ALERTING_SCHEMA_VERSION,
            candidate.confidence.clone(),
            context,
        )?);
    }
    for incident in &output.incidents {
        events.push(envelope(
            plugin_id,
            SECURITY_INCIDENT,
            incident,
            RISK_ALERTING_SCHEMA_VERSION,
            incident.confidence().clone(),
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal risk alerting runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn response_output(
    plugin_id: &PluginId,
    output: &ResponsePlanningOutput,
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    for plan in &output.response_plans {
        events.push(envelope(
            plugin_id,
            RESPONSE_PLAN,
            plan,
            RESPONSE_PLANNING_SCHEMA_VERSION,
            quality(0.9)?,
            context,
        )?);
    }
    for decision in &output.policy_decisions {
        events.push(envelope(
            plugin_id,
            RESPONSE_POLICY_DECISION,
            decision,
            RESPONSE_PLANNING_SCHEMA_VERSION,
            quality(0.9)?,
            context,
        )?);
    }
    for request in approval_requests_from_output(plugin_id, output)? {
        events.push(envelope(
            plugin_id,
            RESPONSE_APPROVAL_REQUEST,
            &request,
            RESPONSE_PLANNING_SCHEMA_VERSION,
            quality(0.88)?,
            context,
        )?);
    }
    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal response planning runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn approval_requests_from_output(
    _plugin_id: &PluginId,
    output: &ResponsePlanningOutput,
) -> PluginResult<Vec<ApprovalRequest>> {
    let _ = output;
    Ok(Vec::new())
}

#[derive(Clone, Debug, Serialize)]
struct EndpointThreatAnalysisAuditSummary {
    detector_status: String,
    candidate_count: usize,
    finding_count: usize,
    evidence_count: usize,
    risk_hint_count: usize,
    advisory_count: usize,
    rejected_count: usize,
    graph_hint_count: usize,
    automatic_llm_calls: bool,
    response_execution_started: bool,
    generated_at: Timestamp,
}

fn endpoint_detection_input_from_runtime(
    facts: &[SecurityFact],
    findings: &[Finding],
    risk_hints: &[RiskHint],
    hypotheses: &[AttackHypothesisRecord],
    fusion_summaries: &[FusionSummary],
) -> Result<Option<EndpointThreatDetectionInput>, EndpointThreatDetectionError> {
    let fact_records = endpoint_fact_records_from_security_facts(facts)?;
    let evidence_records =
        endpoint_evidence_records_from_runtime(findings, risk_hints, hypotheses, fusion_summaries)?;
    if fact_records.is_empty() || evidence_records.is_empty() {
        return Ok(None);
    }

    let mut process_fact_refs = Vec::new();
    let mut parent_relation_fact_refs = Vec::new();
    let mut service_fact_refs = Vec::new();
    let mut native_health_fact_refs = Vec::new();
    for fact in &fact_records {
        match fact.layer {
            EndpointDetectorEvidenceLayer::ProcessCategory => {
                push_unique_fact_ref(&mut process_fact_refs, fact.fact_ref.clone());
            }
            EndpointDetectorEvidenceLayer::ParentRelation => {
                push_unique_fact_ref(&mut parent_relation_fact_refs, fact.fact_ref.clone());
            }
            EndpointDetectorEvidenceLayer::ServiceCategory => {
                push_unique_fact_ref(&mut service_fact_refs, fact.fact_ref.clone());
            }
            EndpointDetectorEvidenceLayer::NativeHealth => {
                push_unique_fact_ref(&mut native_health_fact_refs, fact.fact_ref.clone());
            }
            _ => {}
        }
    }

    let evidence_refs = evidence_records
        .iter()
        .map(|record| record.evidence_ref.clone())
        .take(32)
        .collect::<Vec<_>>();
    let baseline_refs = evidence_records
        .iter()
        .filter_map(|record| record.baseline_ref.clone())
        .take(32)
        .collect::<Vec<_>>();
    let hypothesis_refs = evidence_records
        .iter()
        .filter_map(|record| record.hypothesis_ref.clone())
        .take(32)
        .collect::<Vec<_>>();
    let portable_finding_refs = evidence_records
        .iter()
        .filter_map(|record| record.finding_ref.clone())
        .take(32)
        .collect::<Vec<_>>();

    let analysis_input = EndpointAnalysisInput {
        analysis_input_id: EndpointAnalysisInputId::new_v4(),
        session_ref: SessionId::new_v4(),
        process_fact_refs,
        parent_relation_fact_refs,
        service_fact_refs,
        native_health_fact_refs,
        portable_finding_refs,
        evidence_refs,
        baseline_refs,
        hypothesis_refs,
        risk_refs: Vec::new(),
        attack_refs: Vec::<EndpointAttackRef>::new(),
        process_category: endpoint_process_category(facts),
        parent_process_category: endpoint_parent_process_category(facts),
        relation_category: EndpointRelationCategory::ParentChildObserved,
        execution_context_category: endpoint_execution_context_category(facts),
        service_category: endpoint_service_category(facts),
        process_lifecycle_bucket: EndpointLifecycleBucket::FirstObserved,
        service_state_bucket: EndpointServiceStateBucket::Running,
        startup_type_bucket: EndpointStartupTypeBucket::Manual,
        trust_signedness_bucket: EndpointTrustSignednessBucket::SignedTrusted,
        privilege_integrity_category: EndpointPrivilegeIntegrityCategory::Medium,
        occurrence_indicator: EndpointOccurrenceIndicator::Rare,
        count_change_bucket: EndpointCountChangeBucket::Single,
        time_bucket: Timestamp::now(),
        freshness_category: EndpointFreshnessCategory::Fresh,
        source_reliability_bucket: EndpointSourceReliabilityBucket::Stable,
        evidence_quality_bucket: EndpointEvidenceQualityBucket::Moderate,
        correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
        missing_visibility_flags: endpoint_missing_visibility_flags(),
        provenance_id: facts
            .iter()
            .find_map(|fact| fact.provenance_id.clone())
            .unwrap_or_else(DataSourceId::new_v4),
        redaction_status: RedactionStatus::Redacted,
    };

    let input = EndpointThreatDetectionInput {
        analysis_input,
        candidate_ref: None,
        evidence: evidence_records,
        facts: fact_records,
    };
    input.validate()?;
    Ok(Some(input))
}

fn endpoint_fact_records_from_security_facts(
    facts: &[SecurityFact],
) -> Result<Vec<EndpointDetectorFactRecord>, EndpointThreatDetectionError> {
    let mut records = Vec::new();
    for fact in facts.iter().take(32) {
        let layer = endpoint_fact_layer(fact);
        let categories = endpoint_fact_categories(fact);
        for category in categories.into_iter().take(8) {
            let record = EndpointDetectorFactRecord {
                fact_ref: fact.fact_id.clone(),
                category,
                layer: layer.clone(),
                provenance_id: fact
                    .provenance_id
                    .clone()
                    .unwrap_or_else(DataSourceId::new_v4),
                evidence_refs: fact.evidence_refs.iter().take(32).cloned().collect(),
                sample_group_ref: Some(endpoint_sample_group(fact)),
                freshness_category: EndpointFreshnessCategory::Fresh,
                redaction_status: RedactionStatus::Redacted,
            };
            record.validate()?;
            records.push(record);
        }
    }
    Ok(records)
}

fn endpoint_evidence_records_from_runtime(
    findings: &[Finding],
    risk_hints: &[RiskHint],
    hypotheses: &[AttackHypothesisRecord],
    fusion_summaries: &[FusionSummary],
) -> Result<Vec<EndpointDetectorEvidenceRecord>, EndpointThreatDetectionError> {
    let mut records = Vec::new();
    for (index, finding) in findings.iter().take(16).enumerate() {
        let Some(evidence_ref) = finding.evidence_refs().first().cloned() else {
            continue;
        };
        let category = if finding.confidence().value() >= 0.6 {
            EndpointDetectorEvidenceCategory::HighQualityFinding
        } else {
            EndpointDetectorEvidenceCategory::PortableFinding
        };
        let record = EndpointDetectorEvidenceRecord {
            evidence_ref,
            layer: EndpointDetectorEvidenceLayer::PortableFinding,
            category,
            provenance_id: DataSourceId::new_v4(),
            source_key: format!("portable_finding_source_{index}"),
            sample_group_ref: Some(format!("finding_sample_{index}")),
            parent_evidence_refs: Vec::new(),
            generated_from_candidate_ref: None,
            finding_ref: Some(finding.id().clone()),
            hypothesis_ref: None,
            baseline_ref: None,
            risk_ref: None,
            quality_bucket: if finding.confidence().value() >= 0.6 {
                EndpointEvidenceQualityBucket::Elevated
            } else {
                EndpointEvidenceQualityBucket::Moderate
            },
            reliability_bucket: EndpointSourceReliabilityBucket::Stable,
            freshness_category: EndpointFreshnessCategory::Fresh,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            redaction_status: RedactionStatus::Redacted,
        };
        record.validate()?;
        records.push(record);
    }

    for (index, hint) in risk_hints.iter().take(16).enumerate() {
        let record = EndpointDetectorEvidenceRecord {
            evidence_ref: EvidenceId::from_uuid(hint.risk_hint_id.as_uuid()),
            layer: EndpointDetectorEvidenceLayer::Risk,
            category: EndpointDetectorEvidenceCategory::RiskReference,
            provenance_id: DataSourceId::new_v4(),
            source_key: format!("risk_context_source_{index}"),
            sample_group_ref: Some(format!("risk_sample_{index}")),
            parent_evidence_refs: Vec::new(),
            generated_from_candidate_ref: None,
            finding_ref: None,
            hypothesis_ref: None,
            baseline_ref: None,
            risk_ref: None,
            quality_bucket: EndpointEvidenceQualityBucket::Moderate,
            reliability_bucket: EndpointSourceReliabilityBucket::Stable,
            freshness_category: EndpointFreshnessCategory::Fresh,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            redaction_status: RedactionStatus::Redacted,
        };
        record.validate()?;
        records.push(record);
    }

    for (index, hypothesis) in hypotheses.iter().take(16).enumerate() {
        let record = EndpointDetectorEvidenceRecord {
            evidence_ref: EvidenceId::from_uuid(hypothesis.hypothesis_record_id.as_uuid()),
            layer: EndpointDetectorEvidenceLayer::Hypothesis,
            category: EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis,
            provenance_id: DataSourceId::new_v4(),
            source_key: format!("hypothesis_source_{index}"),
            sample_group_ref: Some(format!("hypothesis_sample_{index}")),
            parent_evidence_refs: hypothesis
                .evidence_refs
                .iter()
                .skip(1)
                .take(8)
                .cloned()
                .collect(),
            generated_from_candidate_ref: None,
            finding_ref: None,
            hypothesis_ref: Some(hypothesis.hypothesis_record_id.clone()),
            baseline_ref: None,
            risk_ref: None,
            quality_bucket: EndpointEvidenceQualityBucket::Moderate,
            reliability_bucket: EndpointSourceReliabilityBucket::Stable,
            freshness_category: EndpointFreshnessCategory::Fresh,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            redaction_status: RedactionStatus::Redacted,
        };
        record.validate()?;
        records.push(record);
    }

    for (index, summary) in fusion_summaries.iter().take(8).enumerate() {
        if summary.evidence_refs.is_empty() && summary.finding_refs.is_empty() {
            continue;
        }
        let record = EndpointDetectorEvidenceRecord {
            evidence_ref: EvidenceId::new_v4(),
            layer: EndpointDetectorEvidenceLayer::Baseline,
            category: EndpointDetectorEvidenceCategory::BaselineDeviation,
            provenance_id: DataSourceId::new_v4(),
            source_key: format!("baseline_context_source_{index}"),
            sample_group_ref: Some(format!("baseline_sample_{index}")),
            parent_evidence_refs: Vec::new(),
            generated_from_candidate_ref: None,
            finding_ref: None,
            hypothesis_ref: None,
            baseline_ref: Some(BaselineRecordId::new_v4()),
            risk_ref: None,
            quality_bucket: EndpointEvidenceQualityBucket::Moderate,
            reliability_bucket: EndpointSourceReliabilityBucket::Stable,
            freshness_category: EndpointFreshnessCategory::Fresh,
            correlation_quality_bucket: EndpointCorrelationQualityBucket::Limited,
            redaction_status: RedactionStatus::Redacted,
        };
        record.validate()?;
        records.push(record);
    }

    Ok(records)
}

fn endpoint_runtime_evidence(
    input: &EndpointThreatDetectionInput,
) -> Result<Vec<EndpointThreatEvidence>, EndpointThreatDetectionError> {
    let mut evidence = Vec::new();
    for record in input.evidence.iter().take(32) {
        let endpoint_evidence = EndpointThreatEvidence {
            endpoint_evidence_id: EndpointThreatEvidenceId::new_v4(),
            analysis_input_ref: input.analysis_input.analysis_input_id.clone(),
            source_evidence_ref: record.evidence_ref.clone(),
            category: endpoint_threat_evidence_category(&record.category),
            process_fact_refs: input.analysis_input.process_fact_refs.clone(),
            parent_relation_fact_refs: input.analysis_input.parent_relation_fact_refs.clone(),
            service_fact_refs: input.analysis_input.service_fact_refs.clone(),
            native_health_fact_refs: input.analysis_input.native_health_fact_refs.clone(),
            portable_finding_refs: record.finding_ref.iter().cloned().collect(),
            baseline_refs: record.baseline_ref.iter().cloned().collect(),
            hypothesis_refs: record.hypothesis_ref.iter().cloned().collect(),
            risk_refs: record.risk_ref.iter().cloned().collect(),
            summary_redacted: "bounded_endpoint_threat_evidence_ref".to_string(),
            time_bucket: Timestamp::now(),
            freshness_category: record.freshness_category.clone(),
            source_reliability_bucket: record.reliability_bucket.clone(),
            evidence_quality_bucket: record.quality_bucket.clone(),
            correlation_quality_bucket: record.correlation_quality_bucket.clone(),
            missing_visibility_flags: endpoint_missing_visibility_flags(),
            provenance_id: record.provenance_id.clone(),
            redaction_status: RedactionStatus::Redacted,
        };
        endpoint_evidence
            .validate()
            .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        evidence.push(endpoint_evidence);
    }
    Ok(evidence)
}

fn endpoint_runtime_risk_hints(
    output: &EndpointThreatDetectorPackOutput,
    input: &EndpointThreatDetectionInput,
) -> Result<Vec<EndpointThreatRiskHint>, EndpointThreatDetectionError> {
    let mut hints = Vec::new();
    for finding in output.findings.iter().take(32) {
        let hint = EndpointThreatRiskHint {
            risk_hint_id: EndpointThreatRiskHintId::new_v4(),
            finding_ref: Some(finding.finding_id.clone()),
            candidate_ref: Some(finding.candidate_ref.clone()),
            category: endpoint_threat_risk_category(finding),
            risk_bucket: finding.severity_bucket.clone(),
            confidence_bucket: finding.confidence_bucket.clone(),
            evidence_refs: finding.evidence_refs.clone(),
            risk_refs: Vec::new(),
            summary_redacted: "bounded_endpoint_threat_risk_hint".to_string(),
            missing_visibility_flags: input.analysis_input.missing_visibility_flags.clone(),
            provenance_id: finding.provenance_id.clone(),
            redaction_status: RedactionStatus::Redacted,
        };
        hint.validate()
            .map_err(|error| EndpointThreatDetectionError::Contract(error.to_string()))?;
        hints.push(hint);
    }
    Ok(hints)
}

fn endpoint_threat_runtime_output(
    plugin_id: &PluginId,
    output: &EndpointThreatDetectorPackOutput,
    endpoint_evidence: &[EndpointThreatEvidence],
    endpoint_risk_hints: &[EndpointThreatRiskHint],
    graph_hints: &[GraphHint],
    context: &PluginContext<'_>,
) -> PluginResult<PluginOutput> {
    let mut events = Vec::new();
    let candidates = output
        .evaluations
        .iter()
        .filter_map(|evaluation| evaluation.candidate.clone())
        .collect::<Vec<_>>();
    for candidate in &candidates {
        events.push(envelope(
            plugin_id,
            ENDPOINT_THREAT_CANDIDATE,
            candidate,
            SchemaVersion::new(1, 0, 0),
            quality(0.55)?,
            context,
        )?);
    }

    for finding in &output.findings {
        let mut finding = finding.clone();
        finding.endpoint_evidence_refs = endpoint_evidence
            .iter()
            .map(|evidence| evidence.endpoint_evidence_id.clone())
            .take(32)
            .collect();
        finding.risk_hint_refs = endpoint_risk_hints
            .iter()
            .filter(|hint| hint.finding_ref.as_ref() == Some(&finding.finding_id))
            .map(|hint| hint.risk_hint_id.clone())
            .take(32)
            .collect();
        finding.validate().map_err(|error| {
            endpoint_capability_error(
                plugin_id,
                EndpointThreatDetectionError::Contract(error.to_string()),
            )
        })?;
        events.push(envelope(
            plugin_id,
            ENDPOINT_THREAT_FINDING,
            &finding,
            SchemaVersion::new(1, 0, 0),
            quality(0.6)?,
            context,
        )?);
    }

    for evidence in endpoint_evidence {
        events.push(envelope(
            plugin_id,
            ENDPOINT_THREAT_EVIDENCE,
            evidence,
            SchemaVersion::new(1, 0, 0),
            quality(0.58)?,
            context,
        )?);
    }
    for hint in endpoint_risk_hints {
        events.push(envelope(
            plugin_id,
            ENDPOINT_THREAT_RISK_HINT,
            hint,
            SchemaVersion::new(1, 0, 0),
            quality(0.52)?,
            context,
        )?);
    }
    for advisory in &output.advisories {
        events.push(envelope(
            plugin_id,
            ENDPOINT_VISIBILITY_ADVISORY,
            advisory,
            SchemaVersion::new(1, 0, 0),
            quality(0.45)?,
            context,
        )?);
    }
    for rejected in &output.rejected_candidates {
        events.push(envelope(
            plugin_id,
            ENDPOINT_THREAT_REJECTED,
            rejected,
            SchemaVersion::new(1, 0, 0),
            quality(0.4)?,
            context,
        )?);
    }
    for hint in graph_hints {
        let mut hint = hint.clone();
        hint.producer_plugin = plugin_id.clone();
        events.push(envelope(
            plugin_id,
            GRAPH_HINT,
            &hint,
            SchemaVersion::new(1, 0, 0),
            hint.confidence.clone(),
            context,
        )?);
    }
    let audit = EndpointThreatAnalysisAuditSummary {
        detector_status: "completed_metadata_only".to_string(),
        candidate_count: candidates.len(),
        finding_count: output.findings.len(),
        evidence_count: endpoint_evidence.len(),
        risk_hint_count: endpoint_risk_hints.len(),
        advisory_count: output.advisories.len(),
        rejected_count: output.rejected_candidates.len(),
        graph_hint_count: graph_hints.len(),
        automatic_llm_calls: false,
        response_execution_started: false,
        generated_at: Timestamp::now(),
    };
    events.push(envelope(
        plugin_id,
        AUDIT_ENDPOINT_THREAT_ANALYSIS,
        &audit,
        SchemaVersion::new(1, 0, 0),
        quality(0.5)?,
        context,
    )?);

    Ok(PluginOutput {
        events,
        health: vec![healthy_plugin_snapshot(
            plugin_id,
            "static internal endpoint threat analysis runtime is bound",
        )],
        metrics: Vec::new(),
        audit_events: Vec::new(),
    })
}

fn endpoint_fact_layer(fact: &SecurityFact) -> EndpointDetectorEvidenceLayer {
    match fact.layer {
        SecurityLayer::AuthorizedNativeHealth => EndpointDetectorEvidenceLayer::NativeHealth,
        SecurityLayer::AuthorizedNativeService => EndpointDetectorEvidenceLayer::ServiceCategory,
        SecurityLayer::AuthorizedNativeProcess => {
            if fact.category == ENDPOINT_PROCESS_PARENT_CATEGORY_FACT {
                EndpointDetectorEvidenceLayer::ParentRelation
            } else {
                EndpointDetectorEvidenceLayer::ProcessCategory
            }
        }
        _ => EndpointDetectorEvidenceLayer::ProcessCategory,
    }
}

fn endpoint_fact_categories(fact: &SecurityFact) -> Vec<String> {
    let mut categories = vec![fact.category.clone()];
    match fact.layer {
        SecurityLayer::AuthorizedNativeHealth => {
            categories.push("native_health".to_string());
        }
        SecurityLayer::AuthorizedNativeService => {
            categories.push("service_category".to_string());
            categories.push("service_state_change".to_string());
        }
        SecurityLayer::AuthorizedNativeProcess => {
            if fact.category == ENDPOINT_PROCESS_PARENT_CATEGORY_FACT {
                categories.push("parent_category_transition".to_string());
            } else {
                categories.push("process_category".to_string());
            }
        }
        _ => {}
    }

    for value in [
        fact.process_category.as_ref(),
        fact.parent_process_category.as_ref(),
        fact.relation_category.as_ref(),
        fact.execution_context_category.as_ref(),
        fact.lifecycle_bucket.as_ref(),
        fact.count_bucket.as_ref(),
        fact.status_category.as_ref(),
        fact.auth_category.as_ref(),
        fact.saas_cloud_category.as_ref(),
        fact.deception_category.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let lower = value.to_ascii_lowercase();
        if lower.contains("remote") || lower.contains("admin") {
            categories.push("remote_admin_endpoint_activity".to_string());
        }
        if lower.contains("auth") || lower.contains("fail") || lower.contains("denied") {
            categories.push("auth_pressure".to_string());
        }
        if lower.contains("script") || lower.contains("shell") {
            categories.push("script_capable_activity".to_string());
        }
        if lower.contains("saas") || lower.contains("cloud") || lower.contains("object_storage") {
            categories.push("saas_cloud_endpoint_context".to_string());
        }
        if lower.contains("deception") || lower.contains("decoy") {
            categories.push("deception_endpoint_probe".to_string());
        }
    }
    if fact.count_bucket.is_some() {
        categories.push("population_change".to_string());
    }
    bounded_endpoint_labels(categories)
}

fn endpoint_sample_group(fact: &SecurityFact) -> String {
    match fact.layer {
        SecurityLayer::AuthorizedNativeHealth => "native_health_sample".to_string(),
        SecurityLayer::AuthorizedNativeService => "native_service_sample".to_string(),
        SecurityLayer::AuthorizedNativeProcess => {
            if fact.category == ENDPOINT_PROCESS_PARENT_CATEGORY_FACT {
                "native_parent_sample".to_string()
            } else {
                "native_process_sample".to_string()
            }
        }
        _ => "endpoint_metadata_sample".to_string(),
    }
}

fn endpoint_process_category(facts: &[SecurityFact]) -> EndpointProcessCategory {
    for fact in facts {
        let lower = fact
            .process_category
            .as_deref()
            .unwrap_or(&fact.category)
            .to_ascii_lowercase();
        if lower.contains("script") {
            return EndpointProcessCategory::ScriptInterpreter;
        }
        if lower.contains("shell") {
            return EndpointProcessCategory::Shell;
        }
        if lower.contains("service") {
            return EndpointProcessCategory::ServiceHost;
        }
        if lower.contains("browser") {
            return EndpointProcessCategory::Browser;
        }
        if lower.contains("admin") || lower.contains("remote") {
            return EndpointProcessCategory::SystemUtility;
        }
    }
    EndpointProcessCategory::OtherRedacted
}

fn endpoint_parent_process_category(facts: &[SecurityFact]) -> EndpointProcessCategory {
    for fact in facts {
        let lower = fact
            .parent_process_category
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        if lower.contains("shell") {
            return EndpointProcessCategory::Shell;
        }
        if lower.contains("service") {
            return EndpointProcessCategory::ServiceHost;
        }
    }
    EndpointProcessCategory::Unknown
}

fn endpoint_execution_context_category(facts: &[SecurityFact]) -> EndpointExecutionContextCategory {
    for fact in facts {
        let lower = fact
            .execution_context_category
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        if lower.contains("remote") {
            return EndpointExecutionContextCategory::RemoteManagement;
        }
        if lower.contains("service") {
            return EndpointExecutionContextCategory::Service;
        }
    }
    EndpointExecutionContextCategory::MetadataOnly
}

fn endpoint_service_category(facts: &[SecurityFact]) -> EndpointServiceCategory {
    for fact in facts {
        let lower = fact.category.to_ascii_lowercase();
        if lower.contains("remote") {
            return EndpointServiceCategory::RemoteAccess;
        }
        if lower.contains("security") {
            return EndpointServiceCategory::Security;
        }
        if lower.contains("network") {
            return EndpointServiceCategory::Network;
        }
    }
    EndpointServiceCategory::System
}

fn endpoint_missing_visibility_flags() -> Vec<EndpointMissingVisibilityFlag> {
    vec![
        EndpointMissingVisibilityFlag::ProcessNetworkAttributionUnavailable,
        EndpointMissingVisibilityFlag::CommandLineVisibilityUnavailable,
        EndpointMissingVisibilityFlag::FileRegistryVisibilityUnavailable,
        EndpointMissingVisibilityFlag::PacketVisibilityUnavailable,
        EndpointMissingVisibilityFlag::SpecificProcessIdentityUnavailable,
    ]
}

fn endpoint_threat_evidence_category(
    category: &EndpointDetectorEvidenceCategory,
) -> EndpointThreatEvidenceCategory {
    match category {
        EndpointDetectorEvidenceCategory::ProcessCategoryFact => {
            EndpointThreatEvidenceCategory::ProcessCategoryMetadata
        }
        EndpointDetectorEvidenceCategory::ParentRelationFact => {
            EndpointThreatEvidenceCategory::ParentRelationMetadata
        }
        EndpointDetectorEvidenceCategory::ServiceCategoryFact => {
            EndpointThreatEvidenceCategory::ServiceCategoryMetadata
        }
        EndpointDetectorEvidenceCategory::NativeHealthFact => {
            EndpointThreatEvidenceCategory::NativeHealthMetadata
        }
        EndpointDetectorEvidenceCategory::BaselineDeviation => {
            EndpointThreatEvidenceCategory::BaselineCorrelation
        }
        EndpointDetectorEvidenceCategory::EvidenceBackedHypothesis => {
            EndpointThreatEvidenceCategory::HypothesisCorrelation
        }
        EndpointDetectorEvidenceCategory::RiskReference => {
            EndpointThreatEvidenceCategory::RiskCorrelation
        }
        _ => EndpointThreatEvidenceCategory::PortableFindingCorrelation,
    }
}

fn endpoint_threat_risk_category(finding: &EndpointThreatFinding) -> EndpointThreatRiskCategory {
    match finding.category {
        EndpointThreatFindingCategory::EvidenceBackedPrivilegeAnomaly => {
            EndpointThreatRiskCategory::RarePrivilegeContext
        }
        EndpointThreatFindingCategory::EvidenceBackedServiceAnomaly
        | EndpointThreatFindingCategory::EvidenceBackedLifecycleAnomaly => {
            EndpointThreatRiskCategory::RepeatedSuspiciousCategory
        }
        EndpointThreatFindingCategory::EvidenceBackedTrustAnomaly
        | EndpointThreatFindingCategory::DegradedVisibilityEndpointSuspicion => {
            EndpointThreatRiskCategory::CorrelatedPortableFindingContext
        }
        EndpointThreatFindingCategory::EvidenceBackedEndpointAnomaly => {
            EndpointThreatRiskCategory::VisibilityLimitedEndpointRisk
        }
    }
}

fn push_unique_fact_ref(values: &mut Vec<SecurityFactId>, value: SecurityFactId) {
    if !values.iter().any(|existing| existing == &value) && values.len() < 32 {
        values.push(value);
    }
}

fn bounded_endpoint_labels(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .take(32)
        .collect()
}

fn attach_asset_source_refs(output: &mut AssetExposureOutput, source_event_ref: &EventId) {
    for evidence in &mut output.evidence {
        if evidence.source_event_refs.is_empty() {
            evidence.source_event_refs.push(source_event_ref.clone());
        }
    }
}

fn attach_collected_evidence_source_refs(
    evidence: &mut [CollectedEvidence],
    source_event_refs: &[EventId],
) {
    for collected in evidence {
        if collected.evidence.source_event_refs.is_empty() {
            collected.evidence.source_event_refs = source_event_refs.to_vec();
        }
    }
}

fn attach_portable_web_source_refs(
    output: &mut PortableNetworkWebOutput,
    source_event_refs: &[EventId],
) {
    for evidence in &mut output.evidence {
        if evidence.source_event_refs.is_empty() {
            evidence.source_event_refs = source_event_refs.to_vec();
        }
    }
}

fn envelope(
    plugin_id: &PluginId,
    topic: &str,
    payload: &impl serde::Serialize,
    schema_version: SchemaVersion,
    quality_score: QualityScore,
    context: &PluginContext<'_>,
) -> PluginResult<EventEnvelope> {
    let mut event = EventEnvelope::new(
        EventType::new(topic).map_err(|error| process_error(plugin_id, error.to_string()))?,
        schema_version,
        plugin_id.clone(),
        context.trace_context.clone(),
    );
    event.privacy_class = PrivacyClass::Internal;
    event.quality_score = quality_score;
    event.payload = serde_json::to_value(payload)
        .map_err(|error| process_error(plugin_id, error.to_string()))?;
    Ok(event)
}

fn parse_event_payload<T: serde::de::DeserializeOwned>(
    plugin_id: &PluginId,
    event: &EventEnvelope,
    topic: &str,
) -> PluginResult<T> {
    serde_json::from_value(event.payload.clone()).map_err(|error| {
        process_error(
            plugin_id,
            format!("{topic} payload deserialization failed: {error}"),
        )
    })
}

fn quality(value: f32) -> PluginResult<QualityScore> {
    QualityScore::new(value).map_err(|error| PluginRuntimeError::ManifestInvalid(error.to_string()))
}

fn capability_error(plugin_id: &PluginId, error: NetworkObservationError) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn response_capability_error(
    plugin_id: &PluginId,
    error: ResponsePlanningError,
) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn asset_capability_error(plugin_id: &PluginId, error: AssetExposureError) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn c2_capability_error(plugin_id: &PluginId, error: C2DetectionError) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn exfiltration_capability_error(
    plugin_id: &PluginId,
    error: ExfiltrationDetectionError,
) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn lateral_capability_error(
    plugin_id: &PluginId,
    error: LateralMovementError,
) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn risk_capability_error(plugin_id: &PluginId, error: RiskAlertingError) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn portable_network_web_error(
    plugin_id: &PluginId,
    error: PortableNetworkWebAnalysisError,
) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn endpoint_capability_error(
    plugin_id: &PluginId,
    error: EndpointThreatDetectionError,
) -> PluginRuntimeError {
    process_error(plugin_id, error.to_string())
}

fn process_error(plugin_id: &PluginId, error_redacted: impl Into<String>) -> PluginRuntimeError {
    PluginRuntimeError::LifecycleFailed {
        plugin_id: plugin_id.clone(),
        phase: "process_batch",
        error_redacted: error_redacted.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use sentinel_contracts::{
        AttributionConfidence, CollectionMode, ContractDescriptor, DnsAnswer, DnsFeatures,
        IndicatorType, IntelligenceExportPolicy, IntelligenceLicenseClass,
        IntelligenceLookupStatus, IntelligenceRecord, IntelligenceSource, IntelligenceSourceClass,
        IpAddress, NetworkDirection, SignerStatus, TraceContext, TransportProtocol,
        VisibilityLevel,
    };
    use sentinel_platform::TopicName;
    use serde::Serialize;

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("test ip")
    }

    fn q(value: f32) -> QualityScore {
        QualityScore::new(value).expect("quality")
    }

    fn source() -> IntelligenceSource {
        IntelligenceSource::new(
            "runtime-test-local-intel",
            IntelligenceSourceClass::BundledLocal,
            "bounded runtime test data",
            "2026.06.01",
            IntelligenceLicenseClass::RedistributableFixture,
            PrivacyClass::Internal,
            IntelligenceExportPolicy::AllowRedactedSummary,
        )
        .expect("source")
    }

    fn record(indicator_type: IndicatorType, indicator: &str) -> IntelligenceRecord {
        IntelligenceRecord::new(
            indicator_type,
            indicator,
            &source(),
            "Bounded local context for runtime wiring.",
        )
        .expect("record")
        .with_confidence(q(0.72))
        .with_expires_at(Timestamp::from_datetime(Utc::now() + Duration::days(30)))
    }

    fn process_context() -> ProcessContext {
        let mut process = ProcessContext::new(4_242, "bounded_client");
        process.signer_status = SignerStatus::Unsigned;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn flow(process: &ProcessContext, offset_seconds: i64, src_port: u16) -> FlowRecord {
        let start = Utc::now() + Duration::seconds(offset_seconds);
        let mut flow = FlowRecord::new(
            ip("192.0.2.10"),
            src_port,
            ip("198.51.100.24"),
            443,
            TransportProtocol::Tcp,
            NetworkDirection::Outbound,
        );
        flow.start_time = Timestamp::from_datetime(start);
        flow.end_time = Some(Timestamp::from_datetime(start + Duration::seconds(1)));
        flow.duration_millis = Some(1_000);
        flow.bytes_out = 620;
        flow.bytes_in = 840;
        flow.packets_out = 3;
        flow.packets_in = 3;
        flow.process_ref = Some(process.process_context_id.clone());
        flow.attribution_confidence = AttributionConfidence::Medium;
        flow.quality_score = q(0.9);
        flow
    }

    fn session_for_flow(flow: &FlowRecord) -> SessionRecord {
        let mut session = SessionRecord::new(
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol.clone(),
            flow.direction.clone(),
        );
        session.flow_refs.push(flow.flow_id.clone());
        session.start_time = flow.start_time.clone();
        session.end_time = flow.end_time.clone();
        session.duration_millis = flow.duration_millis;
        session.bytes_out = flow.bytes_out;
        session.bytes_in = flow.bytes_in;
        session.packets_out = flow.packets_out;
        session.packets_in = flow.packets_in;
        session.quality_score = q(0.86);
        session
    }

    fn dns_observation(process: &ProcessContext, flow: &FlowRecord) -> DnsObservation {
        let domain = "beacon.example.test";
        let mut observation =
            DnsObservation::new(domain, "A", ip("203.0.113.53"), ip("192.0.2.10")).expect("dns");
        observation.flow_ref = Some(flow.flow_id.clone());
        observation.process_ref = Some(process.process_context_id.clone());
        observation.timestamp = flow.start_time.clone();
        observation.answers = vec![DnsAnswer::Ip {
            address: flow.dst_ip,
            ttl_seconds: Some(60),
        }];
        observation.features = DnsFeatures {
            query_length: domain.len() as u16,
            label_count: 3,
            subdomain_depth: 2,
            character_entropy: Some(3.2),
            answer_count: 1,
        };
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = q(0.88);
        observation
    }

    fn tls_observation(process: &ProcessContext, flow: &FlowRecord) -> TlsObservation {
        let mut observation = TlsObservation::new();
        observation.flow_ref = Some(flow.flow_id.clone());
        observation.process_ref = Some(process.process_context_id.clone());
        observation.timestamp = flow.start_time.clone();
        observation.sni_protected = Some("beacon.example.test".to_string());
        observation.alpn = vec!["h2".to_string()];
        observation.ja3 = Some("ja3-runtime-test".to_string());
        observation.ja4 = Some("ja4-runtime-test".to_string());
        observation.tls_version = Some("tls1.3".to_string());
        observation.cipher_suite = Some("tls_aes_128_gcm_sha256".to_string());
        observation.certificate_fingerprint =
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string());
        observation.issuer_summary_protected = Some("runtime-test issuer".to_string());
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = q(0.86);
        observation
    }

    fn domain_context() -> DomainContext {
        let record = record(IndicatorType::Domain, "beacon.example.test");
        DomainContext {
            domain_protected: "beacon.example.test".to_string(),
            tld_protected: Some("test".to_string()),
            suspicious_tld: true,
            allowlisted: false,
            blocklisted: false,
            user_ioc_match: false,
            lexical_score: q(0.62),
            lookup_status: IntelligenceLookupStatus::Hit,
            risk_hints: Vec::new(),
            records: vec![record],
            confidence: q(0.72),
            retrieved_at: Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn certificate_context() -> CertificateContext {
        let fingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let record = record(IndicatorType::CertificateFingerprint, fingerprint);
        CertificateContext {
            fingerprint_protected: fingerprint.to_string(),
            issuer_summary_protected: Some("runtime-test issuer profile".to_string()),
            self_signed_hint: true,
            suspicious_issuer_hint: true,
            lookup_status: IntelligenceLookupStatus::Hit,
            records: vec![record],
            risk_hints: Vec::new(),
            confidence: q(0.66),
            retrieved_at: Timestamp::now(),
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn input_event<T: Serialize>(
        producer_plugin: &PluginId,
        topic: &str,
        payload: &T,
        quality_score: QualityScore,
        trace_context: TraceContext,
    ) -> EventEnvelope {
        let mut event = EventEnvelope::new(
            EventType::new(topic).expect("event type"),
            C2_DETECTION_SCHEMA_VERSION,
            producer_plugin.clone(),
            trace_context,
        );
        event.privacy_class = PrivacyClass::Internal;
        event.quality_score = quality_score;
        event.payload = serde_json::to_value(payload).expect("payload");
        event
    }

    fn context_for_manifest(manifest: &PluginManifest) -> PluginContext<'static> {
        let mut context = PluginContext::new(
            manifest.plugin_id.clone(),
            manifest.runtime_mode.clone(),
            TraceContext::new_root(),
        );
        for contract in &manifest.input_contracts {
            context
                .topic_scope
                .subscribe_topics
                .insert(topic_for_test_contract(contract));
        }
        for contract in &manifest.output_contracts {
            context
                .topic_scope
                .publish_topics
                .insert(topic_for_test_contract(contract));
        }
        for permission in &manifest.required_permissions {
            context
                .permission_scope
                .required_permissions
                .insert(permission.permission.clone());
            context
                .permission_scope
                .granted_permissions
                .insert(permission.permission.clone());
        }
        context
    }

    fn topic_for_test_contract(contract: &ContractDescriptor) -> TopicName {
        TopicName::new(
            contract
                .topic
                .as_deref()
                .unwrap_or(contract.contract_name.as_str()),
        )
        .expect("topic")
    }

    fn start_c2_plugin() -> (
        StaticC2DetectionRuntimePlugin,
        PluginId,
        PluginContext<'static>,
    ) {
        let mut plugin =
            StaticC2DetectionRuntimePlugin::from_static_catalog().expect("static c2 plugin");
        let manifest = plugin.manifest().clone();
        let plugin_id = manifest.plugin_id.clone();
        let mut context = context_for_manifest(&manifest);
        plugin.start(&mut context).expect("start c2");
        (plugin, plugin_id, context)
    }

    #[test]
    fn static_c2_runtime_processes_bounded_metadata_to_product_topics() {
        let (mut plugin, plugin_id, mut context) = start_c2_plugin();
        let trace_context = context.trace_context.clone();
        let process = process_context();
        let flow_a = flow(&process, 0, 50_000);
        let flow_b = flow(&process, 60, 50_001);
        let flow_c = flow(&process, 120, 50_002);
        let sessions = [
            session_for_flow(&flow_a),
            session_for_flow(&flow_b),
            session_for_flow(&flow_c),
        ];
        let dns = dns_observation(&process, &flow_a);
        let tls = tls_observation(&process, &flow_a);
        let domain_context = domain_context();
        let certificate_context = certificate_context();
        let producer_plugin = PluginId::new_v4();

        let mut batch = PluginEventBatch::new(plugin_id.clone(), 11);
        batch
            .push(input_event(
                &producer_plugin,
                IDENTITY_PROCESS_CONTEXT,
                &process,
                q(0.8),
                trace_context.clone(),
            ))
            .expect("process event");
        for flow in [&flow_a, &flow_b, &flow_c] {
            batch
                .push(input_event(
                    &producer_plugin,
                    NETWORK_FLOW_RECORD,
                    flow,
                    flow.quality_score.clone(),
                    trace_context.clone(),
                ))
                .expect("flow event");
        }
        for session in &sessions {
            batch
                .push(input_event(
                    &producer_plugin,
                    NETWORK_SESSION_RECORD,
                    session,
                    session.quality_score.clone(),
                    trace_context.clone(),
                ))
                .expect("session event");
        }
        batch
            .push(input_event(
                &producer_plugin,
                NETWORK_DNS_OBSERVATION,
                &dns,
                dns.quality_score.clone(),
                trace_context.clone(),
            ))
            .expect("dns event");
        batch
            .push(input_event(
                &producer_plugin,
                NETWORK_TLS_OBSERVATION,
                &tls,
                tls.quality_score.clone(),
                trace_context.clone(),
            ))
            .expect("tls event");
        batch
            .push(input_event(
                &producer_plugin,
                INTEL_DOMAIN_CONTEXT,
                &domain_context,
                domain_context.confidence.clone(),
                trace_context.clone(),
            ))
            .expect("domain event");
        batch
            .push(input_event(
                &producer_plugin,
                INTEL_CERTIFICATE_CONTEXT,
                &certificate_context,
                certificate_context.confidence.clone(),
                trace_context,
            ))
            .expect("certificate event");

        let output = plugin
            .process_batch(&mut context, &batch)
            .expect("c2 output");
        let topics = output
            .events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>();
        assert!(topics.contains(&SECURITY_FINDING));
        assert!(topics.contains(&SECURITY_EVIDENCE));
        assert!(topics.contains(&SECURITY_RISK_HINT));
        assert!(topics.contains(&GRAPH_HINT));
        assert!(!topics.contains(&SECURITY_ALERT));
        assert!(!topics.contains(&SECURITY_INCIDENT));
        assert!(!topics.contains(&RESPONSE_PLAN));

        let output_json = serde_json::to_string(&output.events).expect("output json");
        for forbidden in [
            "198.51.100.24",
            "192.0.2.10",
            "\"dst_port\":443",
            "\"src_port\":50000",
            "os_process_id",
            "process_path",
            "command_line",
            "credential",
            "secret",
            "token",
        ] {
            assert!(
                !output_json.contains(forbidden),
                "c2 runtime output leaked forbidden marker {forbidden}"
            );
        }
    }

    #[test]
    fn static_c2_runtime_returns_empty_output_for_benign_metadata() {
        let (mut plugin, plugin_id, mut context) = start_c2_plugin();
        let trace_context = context.trace_context.clone();
        let process = process_context();
        let benign_flow = flow(&process, 0, 51_000);
        let producer_plugin = PluginId::new_v4();
        let mut batch = PluginEventBatch::new(plugin_id.clone(), 1);
        batch
            .push(input_event(
                &producer_plugin,
                NETWORK_FLOW_RECORD,
                &benign_flow,
                benign_flow.quality_score.clone(),
                trace_context,
            ))
            .expect("benign flow");

        let output = plugin
            .process_batch(&mut context, &batch)
            .expect("empty output");
        assert!(output.events.is_empty());
        assert!(output
            .health
            .iter()
            .any(|snapshot| snapshot.status == ObservabilityHealthStatus::Healthy));
    }
}
