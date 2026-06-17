use crate::{
    register_static_api_security_lite_plugin, register_static_auth_identity_analysis_lite_plugin,
    register_static_c2_detection_plugin, register_static_deception_event_lite_plugin,
    register_static_dns_security_v2_plugin, register_static_exfiltration_detection_plugin,
    register_static_http_analysis_v1_plugin, register_static_lateral_movement_plugin,
    register_static_multi_layer_security_fusion_plugin,
    register_static_portable_saas_cloud_abuse_lite_plugin,
    register_static_quic_http3_security_lite_plugin,
    register_static_remote_admin_protocol_lite_plugin, register_static_risk_alerting_plugin,
    register_static_waf_security_lite_plugin, run_portable_capture_lite_with_runtime,
    PortableCaptureLiteError, PortableCaptureLitePreparedBatch, PortableCaptureLiteRunResult,
    PortableCaptureRuntimeContext,
};
use sentinel_contracts::ServiceCapabilityContext;
use sentinel_platform::{
    EventBus, PipelineDag, PipelineNode, PipelineStage, PluginRuntime, StageBinding, TopicName,
    CLOUD_SAAS_METADATA, DECEPTION_EVENT_METADATA, GRAPH_HINT, IDENTITY_AUTH_METADATA,
    NETWORK_DNS_OBSERVATION, NETWORK_FLOW_RECORD, NETWORK_HTTP_METADATA,
    NETWORK_SDN_CONTROL_PLANE_METADATA, NETWORK_SESSION_RECORD, NETWORK_TLS_OBSERVATION,
    SECURITY_ALERT, SECURITY_EVIDENCE, SECURITY_FACT, SECURITY_FINDING, SECURITY_FUSION_CONTEXT,
    SECURITY_FUSION_SUMMARY, SECURITY_HYPOTHESIS, SECURITY_INCIDENT, SECURITY_RISK,
    SERVICE_CAPABILITY_STATUS,
};

pub(crate) fn run_portable_capture_lite_for_test(
    prepared: &PortableCaptureLitePreparedBatch,
    service_contexts: &[ServiceCapabilityContext],
) -> Result<PortableCaptureLiteRunResult, PortableCaptureLiteError> {
    let mut event_bus = EventBus::with_core_topics();
    let execution_plan = test_dag()?.build_execution_plan()?;
    let mut plugin_runtime = PluginRuntime::new();
    register_plugins(&mut plugin_runtime)?;
    run_portable_capture_lite_with_runtime(
        prepared,
        service_contexts,
        &mut PortableCaptureRuntimeContext {
            event_bus: &mut event_bus,
            execution_plan: &execution_plan,
            plugin_runtime: &mut plugin_runtime,
        },
    )
}

fn register_plugins(runtime: &mut PluginRuntime) -> Result<(), PortableCaptureLiteError> {
    register_static_dns_security_v2_plugin(runtime)?;
    register_static_auth_identity_analysis_lite_plugin(runtime)?;
    register_static_http_analysis_v1_plugin(runtime)?;
    register_static_quic_http3_security_lite_plugin(runtime)?;
    register_static_remote_admin_protocol_lite_plugin(runtime)?;
    register_static_api_security_lite_plugin(runtime)?;
    register_static_waf_security_lite_plugin(runtime)?;
    register_static_portable_saas_cloud_abuse_lite_plugin(runtime)?;
    register_static_deception_event_lite_plugin(runtime)?;
    register_static_c2_detection_plugin(runtime)?;
    register_static_lateral_movement_plugin(runtime)?;
    register_static_exfiltration_detection_plugin(runtime)?;
    register_static_multi_layer_security_fusion_plugin(runtime)?;
    register_static_risk_alerting_plugin(runtime)?;
    Ok(())
}

fn test_dag() -> Result<PipelineDag, PortableCaptureLiteError> {
    let mut dag = PipelineDag::new("portable capture lite test pipeline")?;
    let source = dag.add_node(PipelineNode::new(
        "portable imported metadata source",
        PipelineStage::Source,
        StageBinding::metadata_only(
            Vec::new(),
            topics(&[
                NETWORK_FLOW_RECORD,
                NETWORK_SESSION_RECORD,
                NETWORK_DNS_OBSERVATION,
                NETWORK_TLS_OBSERVATION,
                NETWORK_HTTP_METADATA,
                IDENTITY_AUTH_METADATA,
                CLOUD_SAAS_METADATA,
                DECEPTION_EVENT_METADATA,
                NETWORK_SDN_CONTROL_PLANE_METADATA,
                SERVICE_CAPABILITY_STATUS,
                SECURITY_FUSION_CONTEXT,
            ])?,
        ),
    )?)?;
    let detection = dag.add_node(
        PipelineNode::new(
            "portable imported detection",
            PipelineStage::Detection,
            StageBinding::metadata_only(
                topics(&[
                    NETWORK_FLOW_RECORD,
                    NETWORK_SESSION_RECORD,
                    NETWORK_DNS_OBSERVATION,
                    NETWORK_TLS_OBSERVATION,
                    NETWORK_HTTP_METADATA,
                    IDENTITY_AUTH_METADATA,
                    CLOUD_SAAS_METADATA,
                    DECEPTION_EVENT_METADATA,
                    NETWORK_SDN_CONTROL_PLANE_METADATA,
                    SECURITY_FINDING,
                    SECURITY_FUSION_CONTEXT,
                ])?,
                topics(&[
                    SECURITY_FINDING,
                    SECURITY_EVIDENCE,
                    "security.risk_hint",
                    GRAPH_HINT,
                    SECURITY_FACT,
                    SECURITY_HYPOTHESIS,
                    SECURITY_FUSION_SUMMARY,
                ])?,
            ),
        )?
        .depends_on(source),
    )?;
    dag.add_node(
        PipelineNode::new(
            "portable imported risk",
            PipelineStage::Risk,
            StageBinding::metadata_only(
                topics(&[
                    SECURITY_FINDING,
                    SECURITY_EVIDENCE,
                    "security.risk_hint",
                    SERVICE_CAPABILITY_STATUS,
                ])?,
                topics(&[
                    SECURITY_RISK,
                    "security.alert_candidate",
                    SECURITY_ALERT,
                    "security.incident_candidate",
                    SECURITY_INCIDENT,
                ])?,
            ),
        )?
        .depends_on(detection),
    )?;
    Ok(dag)
}

fn topics(values: &[&str]) -> Result<Vec<TopicName>, PortableCaptureLiteError> {
    values
        .iter()
        .map(|value| {
            TopicName::new(*value).map_err(|error| {
                PortableCaptureLiteError::Runtime(format!(
                    "test runtime topic validation failed: {error}"
                ))
            })
        })
        .collect()
}
