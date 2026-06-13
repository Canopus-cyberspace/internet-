use super::*;
use crate::component::ComponentId;
use crate::event_bus::{core_v1_topics, AUDIT_EVENT, OPERATIONAL_HEALTH, OPERATIONAL_METRIC};
use sentinel_contracts::{
    report::ExportFormat, PluginId, RedactedDataCategory, RedactionSummary, TraceId,
};

#[test]
fn health_snapshots_cover_required_statuses() {
    let statuses = [
        HealthStatus::Healthy,
        HealthStatus::Degraded,
        HealthStatus::Unavailable,
        HealthStatus::Disconnected,
        HealthStatus::Unauthorized,
        HealthStatus::Stale,
        HealthStatus::Failed,
    ];

    for status in statuses {
        let snapshot = HealthSnapshot::new(
            HealthSubject::Plugin {
                plugin_id: PluginId::new_v4(),
            },
            status,
        );

        assert!(snapshot.validate().is_ok());
        assert_eq!(HealthSnapshot::event_type(), "platform.health.snapshot");
    }
}

#[test]
fn plugin_and_service_health_use_operational_event_topic() {
    let topics = core_v1_topics();
    let health_topic = topics
        .iter()
        .find(|topic| topic.name.as_str() == OPERATIONAL_HEALTH)
        .expect("health topic registered");
    let metric_topic = topics
        .iter()
        .find(|topic| topic.name.as_str() == OPERATIONAL_METRIC)
        .expect("metric topic registered");

    let plugin_snapshot = HealthSnapshot::new(
        HealthSubject::Plugin {
            plugin_id: PluginId::new_v4(),
        },
        HealthStatus::Healthy,
    );
    let service_snapshot = HealthSnapshot::new(
        HealthSubject::ServiceAdapter {
            component_id: ComponentId::new_v4(),
            adapter_name: "elevated_service".to_string(),
        },
        HealthStatus::Disconnected,
    );

    assert_eq!(HealthSnapshot::topic_name().as_str(), OPERATIONAL_HEALTH);
    assert_eq!(health_topic.name.as_str(), OPERATIONAL_HEALTH);
    assert!(health_topic.protected_delivery);
    assert_eq!(metric_topic.name.as_str(), OPERATIONAL_METRIC);
    assert_eq!(
        plugin_snapshot.priority_lane(),
        crate::event_bus::PriorityLane::P2Normal
    );
    assert_eq!(
        service_snapshot.priority_lane(),
        crate::event_bus::PriorityLane::P1High
    );
}

#[test]
fn audit_events_are_structured_privacy_safe_and_not_droppable() {
    let event = AuditEvent::response_event(
        AuditActionType::ResponseActionCompleted,
        "local operator",
        "redacted destination",
        AuditDecision::Completed,
        "policy-v1",
        TraceId::new_v4(),
        "recommendation recorded",
        "rollback-ref-1",
        false,
    )
    .expect("response audit event");

    assert_eq!(AuditEvent::topic_name().as_str(), AUDIT_EVENT);
    assert_eq!(
        event.priority_lane(),
        crate::event_bus::PriorityLane::P0Critical
    );
    assert!(!event.can_drop_under_pressure());
    assert!(event.policy_version.is_some());
    assert!(event.trace_id.is_some());
    assert!(event.rollback_ref.is_some());
    assert!(!event.sensitive_data_touched);
}

#[test]
fn audit_sink_is_append_only_and_reports_unavailable_sink() {
    let event = AuditEvent::response_event(
        AuditActionType::ResponsePolicyDecision,
        "local operator",
        "redacted scope",
        AuditDecision::Allowed,
        "policy-v1",
        TraceId::new_v4(),
        "policy allowed recommendation",
        "rollback-ref-2",
        false,
    )
    .expect("audit event");

    let mut sink = InMemoryAuditSink::new();
    let receipt = sink.append(event.clone()).expect("append audit");

    assert_eq!(receipt.sequence, 1);
    assert_eq!(sink.records().len(), 1);
    assert_eq!(sink.records()[0].audit_id, event.audit_id);

    let mut unavailable = InMemoryAuditSink::unavailable();
    let error = unavailable
        .append(event)
        .expect_err("unavailable audit sink is explicit");
    assert!(matches!(error, AuditSinkError::Unavailable { .. }));
}

#[test]
fn export_audit_includes_redaction_summary_and_metadata() {
    let redaction_summary = RedactionSummary::passed(vec![
        RedactedDataCategory::RawPacket,
        RedactedDataCategory::Payload,
        RedactedDataCategory::HttpBody,
    ]);
    let metadata = ExportAuditMetadata {
        format: ExportFormat::RedactedJson,
        destination_metadata_redacted: Some("local redacted path".to_string()),
        file_hash: Some("sha256:abc".to_string()),
    };
    let event = AuditEvent::export_event(
        AuditActionType::ExportCompleted,
        "local operator",
        "redacted report",
        AuditDecision::Completed,
        "export completed",
        redaction_summary,
        metadata,
    )
    .expect("export audit event");

    assert!(event.redaction_summary.is_some());
    assert!(event.export_metadata.is_some());
    assert!(event.sensitive_data_touched);
}

#[test]
fn metrics_catalog_covers_required_platform_metrics() {
    let metric_names = MetricDescriptor::core_v1_catalog()
        .into_iter()
        .map(|descriptor| descriptor.metric_name)
        .collect::<Vec<_>>();

    for required in [
        "plugin_throughput",
        "plugin_latency",
        "plugin_error_rate",
        "queue_lag",
        "finding_count",
        "alert_count",
        "incident_count",
        "response_success",
        "rollback_success",
    ] {
        assert!(metric_names.contains(&required.to_string()));
    }
}

#[test]
fn metrics_reject_sensitive_labels() {
    let descriptor = MetricDescriptor::new(
        "plugin_throughput",
        sentinel_contracts::MetricKind::Counter,
        "Plugin throughput",
    )
    .expect("descriptor");
    let mut sample =
        MetricSample::new("plugin_throughput", MetricValue::Counter(1)).expect("sample");
    sample
        .labels
        .insert("authorization_header".to_string(), "present".to_string());

    assert!(sample.validate(Some(&descriptor)).is_err());
}

#[test]
fn diagnostics_reject_sensitive_summaries() {
    let error = DiagnosticsSummary::new(HealthStatus::Failed, "raw packet was attached")
        .expect_err("sensitive diagnostic summary rejected");

    assert!(matches!(
        error,
        DiagnosticsValidationError::SensitiveMarker { .. }
    ));
}
