use crate::observability::{AuditEvent, HealthSnapshot, HealthStatus, MetricSample};
use crate::plugin_runtime::context::PluginContext;
use crate::plugin_runtime::policy::CheckpointSupport;
use sentinel_contracts::{
    CapabilityManifest, EventEnvelope, PluginId, PluginManifest, Timestamp, UiContribution,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub trait PluginLifecycle {
    fn initialize(&mut self, _context: &mut PluginContext<'_>) -> PluginResult<()> {
        Ok(())
    }

    fn start(&mut self, _context: &mut PluginContext<'_>) -> PluginResult<()> {
        Ok(())
    }

    fn stop(&mut self, _context: &mut PluginContext<'_>) -> PluginResult<()> {
        Ok(())
    }

    fn disable(&mut self, _context: &mut PluginContext<'_>) -> PluginResult<()> {
        Ok(())
    }

    fn health_snapshot(&self, context: &PluginContext<'_>) -> PluginResult<HealthSnapshot> {
        Ok(HealthSnapshot::new(
            crate::observability::HealthSubject::Plugin {
                plugin_id: context.runtime.plugin_id.clone(),
            },
            HealthStatus::Healthy,
        ))
    }
}

pub trait InternalPlugin: PluginLifecycle {
    fn manifest(&self) -> &PluginManifest;

    fn capability_manifest(&self) -> Option<&CapabilityManifest> {
        None
    }

    fn ui_contributions(&self) -> &[UiContribution] {
        &self.manifest().ui_contributions
    }

    fn process_event(
        &mut self,
        _context: &mut PluginContext<'_>,
        _event: &EventEnvelope,
    ) -> PluginResult<PluginOutput> {
        Ok(PluginOutput::default())
    }

    fn process_batch(
        &mut self,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        let mut output = PluginOutput::default();
        for event in &batch.events {
            output.extend(self.process_event(context, event)?);
        }
        Ok(output)
    }

    fn checkpoint_support(&self) -> CheckpointSupport {
        CheckpointSupport::from_manifest_level(self.manifest().checkpoint_support.clone())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginOutput {
    pub events: Vec<EventEnvelope>,
    pub health: Vec<HealthSnapshot>,
    pub metrics: Vec<MetricSample>,
    pub audit_events: Vec<AuditEvent>,
}

impl PluginOutput {
    pub fn extend(&mut self, other: Self) {
        self.events.extend(other.events);
        self.health.extend(other.health);
        self.metrics.extend(other.metrics);
        self.audit_events.extend(other.audit_events);
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginEventBatch {
    pub plugin_id: PluginId,
    pub events: Vec<EventEnvelope>,
    pub received_at: Timestamp,
    pub max_events: usize,
}

impl PluginEventBatch {
    pub fn new(plugin_id: PluginId, max_events: usize) -> Self {
        Self {
            plugin_id,
            events: Vec::new(),
            received_at: Timestamp::now(),
            max_events,
        }
    }

    pub fn push(&mut self, event: EventEnvelope) -> Result<(), PluginRuntimeError> {
        if self.events.len() >= self.max_events {
            return Err(PluginRuntimeError::BatchLimitExceeded {
                max_events: self.max_events,
            });
        }
        self.events.push(event);
        Ok(())
    }
}

pub type PluginResult<T> = Result<T, PluginRuntimeError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginRuntimeError {
    DuplicatePlugin(PluginId),
    MissingPlugin(PluginId),
    ManifestInvalid(String),
    StartupBlocked {
        plugin_id: PluginId,
        reasons: Vec<String>,
    },
    LifecycleFailed {
        plugin_id: PluginId,
        phase: &'static str,
        error_redacted: String,
    },
    BatchLimitExceeded {
        max_events: usize,
    },
}

impl fmt::Display for PluginRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePlugin(plugin_id) => write!(f, "duplicate plugin: {plugin_id}"),
            Self::MissingPlugin(plugin_id) => write!(f, "missing plugin: {plugin_id}"),
            Self::ManifestInvalid(error) => write!(f, "plugin manifest is invalid: {error}"),
            Self::StartupBlocked { plugin_id, reasons } => {
                write!(
                    f,
                    "plugin startup blocked for {plugin_id}: {}",
                    reasons.join("; ")
                )
            }
            Self::LifecycleFailed {
                plugin_id,
                phase,
                error_redacted,
            } => write!(
                f,
                "plugin lifecycle phase {phase} failed for {plugin_id}: {error_redacted}"
            ),
            Self::BatchLimitExceeded { max_events } => {
                write!(f, "plugin event batch exceeded max_events={max_events}")
            }
        }
    }
}

impl std::error::Error for PluginRuntimeError {}
