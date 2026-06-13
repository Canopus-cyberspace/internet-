use crate::asset_exposure::{
    AssetExposureError, AssetExposureInput, AssetExposureObservation, AssetExposureOutput,
    AssetExposurePlugin, AssetRecord, AssetRiskFinding, PortExposureRecord, ServiceInventoryInput,
    ServiceInventoryPlugin, ServiceRecord, ASSET_EXPOSURE_SCHEMA_VERSION,
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
    Alert, ApprovalRequest, CloudContext, DnsObservation, EventEnvelope, EventId, EventType,
    Finding, FlowRecord, GraphHint, GraphPath, HttpMetadata, Incident, IpContext, PacketRecord,
    PluginId, PluginManifest, PortableAuthMetadata, PortableCaptureProvenance,
    PortableDeceptionEventMetadata, PortableSaasCloudMetadata, PrivacyClass, ProcessContext,
    QualityScore, ResponsePolicy, RiskHint, SchemaVersion, ServiceCapabilityContext, SessionRecord,
    Timestamp, TlsObservation,
};
use sentinel_platform::{
    BuiltInPluginCatalog, HealthSnapshot, HealthSubject, InternalPlugin, ObservabilityHealthStatus,
    PluginContext, PluginEventBatch, PluginLifecycle, PluginOutput, PluginResult, PluginRuntime,
    PluginRuntimeError, ASSET_EXPOSURE, CLOUD_SAAS_METADATA, DECEPTION_EVENT_METADATA, GRAPH_HINT,
    GRAPH_PATH, IDENTITY_AUTH_METADATA, IDENTITY_PROCESS_CONTEXT, INTEL_CLOUD_CONTEXT,
    INTEL_IP_CONTEXT, NATIVE_HEALTH_METADATA, NATIVE_PROCESS_METADATA,
    NATIVE_PROCESS_PARENT_METADATA, NATIVE_SERVICE_METADATA, NETWORK_DNS_OBSERVATION,
    NETWORK_FLOW_RECORD, NETWORK_HTTP_METADATA, NETWORK_PACKET_RECORD, NETWORK_SESSION_RECORD,
    NETWORK_TLS_OBSERVATION, RESPONSE_APPROVAL_REQUEST, RESPONSE_PLAN, RESPONSE_POLICY_DECISION,
    SECURITY_ALERT, SECURITY_EVIDENCE, SECURITY_FINDING, SECURITY_FUSION_CONTEXT,
    SECURITY_FUSION_SUMMARY, SECURITY_INCIDENT, SECURITY_OBSERVATION, SECURITY_RISK,
    SERVICE_CAPABILITY_STATUS,
};

pub const FLOW_SESSIONIZATION_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-000000000193";
pub const ASSET_EXPOSURE_STATIC_PLUGIN_ID: &str = "00000000-0000-0000-0000-00000000019a";
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
                observations.push(parse_event_payload::<sentinel_contracts::DnsObservation>(
                    &self.manifest.plugin_id,
                    event,
                    NETWORK_DNS_OBSERVATION,
                )?);
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
                _ => {}
            }
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

fn process_error(plugin_id: &PluginId, error_redacted: impl Into<String>) -> PluginRuntimeError {
    PluginRuntimeError::LifecycleFailed {
        plugin_id: plugin_id.clone(),
        phase: "process_batch",
        error_redacted: error_redacted.into(),
    }
}
