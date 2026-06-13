use crate::plugin_runtime::context::{PluginContext, PluginLifecycleState};
use crate::plugin_runtime::registry::{
    PluginRuntimeDescriptor, PluginRuntimeRegistry, PluginStartupValidation,
};
use crate::plugin_runtime::traits::{
    InternalPlugin, PluginEventBatch, PluginOutput, PluginResult, PluginRuntimeError,
};
use crate::TopicName;
use sentinel_contracts::{ContractDescriptor, PluginId, PluginManifest};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct PluginRuntime {
    registry: PluginRuntimeRegistry,
    plugins: HashMap<PluginId, Box<dyn InternalPlugin>>,
}

impl PluginRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn registry(&self) -> &PluginRuntimeRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut PluginRuntimeRegistry {
        &mut self.registry
    }

    pub fn register_static_plugin(
        &mut self,
        plugin: Box<dyn InternalPlugin>,
    ) -> Result<PluginId, PluginRuntimeError> {
        let manifest = plugin.manifest().clone();
        let plugin_id = manifest.plugin_id.clone();
        let descriptor = PluginRuntimeDescriptor::static_internal(
            manifest,
            plugin.capability_manifest().cloned(),
            None,
        );
        self.registry.register_static(descriptor)?;
        self.plugins.insert(plugin_id.clone(), plugin);
        Ok(plugin_id)
    }

    pub fn manifest(&self, plugin_id: &PluginId) -> Option<&PluginManifest> {
        self.registry
            .get(plugin_id)
            .map(|descriptor| &descriptor.manifest)
    }

    pub fn start_plugin(
        &mut self,
        plugin_id: &PluginId,
        validation: &PluginStartupValidation,
        context: &mut PluginContext<'_>,
    ) -> PluginResult<()> {
        if !validation.allowed {
            let reasons = validation.blocker_reasons();
            self.registry
                .transition(plugin_id, PluginLifecycleState::Incompatible)?;
            return Err(PluginRuntimeError::StartupBlocked {
                plugin_id: plugin_id.clone(),
                reasons,
            });
        }

        let Some(plugin) = self.plugins.get_mut(plugin_id) else {
            return Err(PluginRuntimeError::MissingPlugin(plugin_id.clone()));
        };

        self.registry
            .transition(plugin_id, PluginLifecycleState::Initialized)?;
        if let Err(error) = plugin.initialize(context) {
            self.registry.record_failure(plugin_id, error.to_string())?;
            return Err(PluginRuntimeError::LifecycleFailed {
                plugin_id: plugin_id.clone(),
                phase: "initialize",
                error_redacted: error.to_string(),
            });
        }

        self.registry
            .transition(plugin_id, PluginLifecycleState::Starting)?;
        if let Err(error) = plugin.start(context) {
            self.registry.record_failure(plugin_id, error.to_string())?;
            return Err(PluginRuntimeError::LifecycleFailed {
                plugin_id: plugin_id.clone(),
                phase: "start",
                error_redacted: error.to_string(),
            });
        }

        self.registry
            .transition(plugin_id, PluginLifecycleState::Running)?;
        Ok(())
    }

    pub fn stop_plugin(
        &mut self,
        plugin_id: &PluginId,
        context: &mut PluginContext<'_>,
    ) -> PluginResult<()> {
        let Some(plugin) = self.plugins.get_mut(plugin_id) else {
            return Err(PluginRuntimeError::MissingPlugin(plugin_id.clone()));
        };

        self.registry
            .transition(plugin_id, PluginLifecycleState::Stopping)?;
        plugin.stop(context)?;
        self.registry
            .transition(plugin_id, PluginLifecycleState::Stopped)?;
        Ok(())
    }

    pub fn process_batch(
        &mut self,
        plugin_id: &PluginId,
        context: &mut PluginContext<'_>,
        batch: &PluginEventBatch,
    ) -> PluginResult<PluginOutput> {
        if batch.plugin_id != *plugin_id {
            return Err(processing_error(
                plugin_id,
                "event batch was created for a different plugin",
            ));
        }
        if context.runtime.plugin_id != *plugin_id {
            return Err(processing_error(
                plugin_id,
                "runtime context belongs to a different plugin",
            ));
        }
        if !context.privacy.raw_content_persistence_forbidden() {
            return Err(processing_error(
                plugin_id,
                "plugin runtime refuses unsafe persistence context",
            ));
        }

        let descriptor = self
            .registry
            .get(plugin_id)
            .ok_or_else(|| PluginRuntimeError::MissingPlugin(plugin_id.clone()))?;
        if descriptor.runtime_context.lifecycle_state != PluginLifecycleState::Running {
            return Err(processing_error(
                plugin_id,
                "plugin must be running before batch processing",
            ));
        }

        let input_topics = declared_topics(&descriptor.manifest.input_contracts, plugin_id)?;
        let output_topics = declared_topics(&descriptor.manifest.output_contracts, plugin_id)?;
        validate_batch_inputs(plugin_id, context, batch, &input_topics)?;

        let Some(plugin) = self.plugins.get_mut(plugin_id) else {
            return Err(PluginRuntimeError::MissingPlugin(plugin_id.clone()));
        };
        let output = plugin.process_batch(context, batch)?;
        validate_batch_outputs(plugin_id, context, &output, &output_topics)?;
        Ok(output)
    }
}

fn validate_batch_inputs(
    plugin_id: &PluginId,
    context: &PluginContext<'_>,
    batch: &PluginEventBatch,
    declared_topics: &HashSet<TopicName>,
) -> PluginResult<()> {
    for event in &batch.events {
        let topic = event_topic(plugin_id, event.event_type.as_str())?;
        if !declared_topics.contains(&topic) {
            return Err(processing_error(
                plugin_id,
                format!("input topic {topic} is not declared by manifest"),
            ));
        }
        if !context.topic_scope.can_subscribe(&topic) {
            return Err(processing_error(
                plugin_id,
                format!("input topic {topic} is outside the runtime subscribe scope"),
            ));
        }
    }

    Ok(())
}

fn validate_batch_outputs(
    plugin_id: &PluginId,
    context: &PluginContext<'_>,
    output: &PluginOutput,
    declared_topics: &HashSet<TopicName>,
) -> PluginResult<()> {
    for event in &output.events {
        if event.producer_plugin != *plugin_id {
            return Err(processing_error(
                plugin_id,
                "output event producer does not match the runtime plugin",
            ));
        }
        let topic = event_topic(plugin_id, event.event_type.as_str())?;
        if !declared_topics.contains(&topic) {
            return Err(processing_error(
                plugin_id,
                format!("output topic {topic} is not declared by manifest"),
            ));
        }
        if !context.topic_scope.can_publish(&topic) {
            return Err(processing_error(
                plugin_id,
                format!("output topic {topic} is outside the runtime publish scope"),
            ));
        }
    }

    Ok(())
}

fn declared_topics(
    contracts: &[ContractDescriptor],
    plugin_id: &PluginId,
) -> Result<HashSet<TopicName>, PluginRuntimeError> {
    contracts
        .iter()
        .map(|contract| {
            event_topic(
                plugin_id,
                contract
                    .topic
                    .as_deref()
                    .unwrap_or(contract.contract_name.as_str()),
            )
        })
        .collect()
}

fn event_topic(plugin_id: &PluginId, value: &str) -> Result<TopicName, PluginRuntimeError> {
    TopicName::new(value).map_err(|error| processing_error(plugin_id, error.to_string()))
}

fn processing_error(plugin_id: &PluginId, error_redacted: impl Into<String>) -> PluginRuntimeError {
    PluginRuntimeError::LifecycleFailed {
        plugin_id: plugin_id.clone(),
        phase: "process_batch",
        error_redacted: error_redacted.into(),
    }
}
