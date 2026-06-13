use sentinel_contracts::{
    DataSourceId, EvidenceId, FindingId, MetadataParserFamily, MetadataRetentionMode,
    MetadataSamplingBatchId, MetadataSamplingBatchSummary, MetadataSamplingTickResult,
    MetadataSourceHealthState, MetadataWatchCheckpoint, MetadataWatchContractError,
    MetadataWatchControllerStatus, MetadataWatchLifecycleAction, MetadataWatchSourceConfirmation,
    MetadataWatchSourceId, MetadataWatchSourceKind, MetadataWatchSourcePreview,
    MetadataWatchSourcePreviewRequest, MetadataWatchSourceState, MetadataWatchSourceStatus,
    RiskEventId, SecurityFactId, Timestamp, MAX_WATCH_REFS,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContinuousMetadataWatchError {
    Contract(String),
    PreviewNotFound,
    SourceNotFound,
    SourceRevoked,
    NotConfirmed,
}

impl fmt::Display for ContinuousMetadataWatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(reason) => write!(formatter, "watch contract error: {reason}"),
            Self::PreviewNotFound => write!(formatter, "metadata watch preview was not found"),
            Self::SourceNotFound => write!(formatter, "metadata watch source was not found"),
            Self::SourceRevoked => write!(formatter, "metadata watch source is revoked"),
            Self::NotConfirmed => write!(formatter, "metadata watch source was not confirmed"),
        }
    }
}

impl std::error::Error for ContinuousMetadataWatchError {}

impl From<MetadataWatchContractError> for ContinuousMetadataWatchError {
    fn from(value: MetadataWatchContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataSamplingObservation {
    pub source_id: MetadataWatchSourceId,
    pub source_generation_ref: String,
    pub sampled_record_count: u64,
    pub sampled_byte_count: u64,
    pub skipped_record_count: u64,
    pub malformed_record_count: u64,
    pub backpressure_drop_count: u64,
    pub emitted_topics: Vec<String>,
    pub fact_refs: Vec<SecurityFactId>,
    pub evidence_refs: Vec<EvidenceId>,
    pub finding_refs: Vec<FindingId>,
    pub risk_refs: Vec<RiskEventId>,
    pub hypothesis_count: u32,
    pub provenance_id: Option<DataSourceId>,
    pub health_state_override: Option<MetadataSourceHealthState>,
    pub degraded_reason: Option<String>,
    pub error_category: Option<String>,
}

impl MetadataSamplingObservation {
    pub fn safe_generation_hash(&self) -> String {
        safe_generation_hash(&self.source_generation_ref)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContinuousMetadataWatchController {
    previews: HashMap<MetadataWatchSourceId, MetadataWatchSourcePreview>,
    sources: HashMap<MetadataWatchSourceId, MetadataWatchSourceStatus>,
    batches: Vec<MetadataSamplingBatchSummary>,
    dedup_keys: BTreeSet<String>,
    last_tick_at: Option<Timestamp>,
}

impl ContinuousMetadataWatchController {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_read_models(
        sources: Vec<MetadataWatchSourceStatus>,
        batches: Vec<MetadataSamplingBatchSummary>,
    ) -> Result<Self, ContinuousMetadataWatchError> {
        let mut controller = Self::new();
        for source in sources {
            source.validate()?;
            controller.sources.insert(source.source_id.clone(), source);
        }
        for batch in batches {
            batch.validate()?;
            controller.batches.push(batch);
        }
        Ok(controller)
    }

    pub fn preview_source(
        &mut self,
        request: MetadataWatchSourcePreviewRequest,
    ) -> Result<MetadataWatchSourcePreview, ContinuousMetadataWatchError> {
        request.validate()?;
        let preview = MetadataWatchSourcePreview {
            preview_id: MetadataWatchSourceId::new_v4(),
            source_kind: request.source_kind,
            parser_family: request.parser_family,
            display_label_redacted: request.display_label_redacted,
            sampling_mode: request.sampling_mode,
            interval_seconds: request.interval_seconds,
            max_records_per_tick: request.max_records_per_tick,
            max_bytes_per_tick: request.max_bytes_per_tick,
            retention_mode: MetadataRetentionMode::NoRetention,
            redaction_policy: "metadata_redaction_v1".to_string(),
            privacy_boundary: "portable_no_retention_metadata_only".to_string(),
            portable_default_available: true,
            generated_at: Timestamp::now(),
        };
        preview.validate()?;
        self.previews
            .insert(preview.preview_id.clone(), preview.clone());
        Ok(preview)
    }

    pub fn confirm_source(
        &mut self,
        confirmation: MetadataWatchSourceConfirmation,
    ) -> Result<MetadataWatchSourceStatus, ContinuousMetadataWatchError> {
        confirmation.validate()?;
        if !confirmation.user_confirmed {
            return Err(ContinuousMetadataWatchError::NotConfirmed);
        }
        let preview = self
            .previews
            .remove(&confirmation.preview_id)
            .ok_or(ContinuousMetadataWatchError::PreviewNotFound)?;
        let checkpoint = MetadataWatchCheckpoint::new(
            preview.preview_id.clone(),
            preview.source_kind.clone(),
            &preview.parser_family,
        )?;
        let status = MetadataWatchSourceStatus {
            source_id: preview.preview_id.clone(),
            source_kind: preview.source_kind,
            state: MetadataWatchSourceState::Enabled,
            health_state: MetadataSourceHealthState::Enabled,
            sampling_mode: preview.sampling_mode,
            interval_seconds: preview.interval_seconds,
            max_records_per_tick: preview.max_records_per_tick,
            max_bytes_per_tick: preview.max_bytes_per_tick,
            parser_family: preview.parser_family,
            redaction_policy: preview.redaction_policy,
            retention_mode: preview.retention_mode,
            checkpoint,
            counters: sentinel_contracts::MetadataWatchCounters::empty(),
            last_sampled_at: None,
            last_ingested_at: None,
            degraded_reason: None,
            error_category: None,
            provenance_id: None,
            privacy_boundary: preview.privacy_boundary,
            portable_default_available: preview.portable_default_available,
            sampler_ids: sampler_ids_for_source(&preview.preview_id),
            fact_count: 0,
            hypothesis_count: 0,
            finding_count: 0,
            evidence_refs: Vec::new(),
        };
        status.validate()?;
        self.sources
            .insert(status.source_id.clone(), status.clone());
        Ok(status)
    }

    pub fn transition_source(
        &mut self,
        source_id: &MetadataWatchSourceId,
        action: MetadataWatchLifecycleAction,
    ) -> Result<Option<MetadataWatchSourceStatus>, ContinuousMetadataWatchError> {
        if matches!(action, MetadataWatchLifecycleAction::ClearInactive) {
            let removed = self.sources.remove(source_id);
            return Ok(removed);
        }
        let source = self
            .sources
            .get_mut(source_id)
            .ok_or(ContinuousMetadataWatchError::SourceNotFound)?;
        if source.state == MetadataWatchSourceState::Revoked
            && !matches!(action, MetadataWatchLifecycleAction::ClearInactive)
        {
            return Err(ContinuousMetadataWatchError::SourceRevoked);
        }
        match action {
            MetadataWatchLifecycleAction::Enable | MetadataWatchLifecycleAction::Resume => {
                source.state = MetadataWatchSourceState::Enabled;
                source.health_state = MetadataSourceHealthState::Enabled;
                source.degraded_reason = None;
                source.error_category = None;
            }
            MetadataWatchLifecycleAction::Pause => {
                source.state = MetadataWatchSourceState::Paused;
                source.health_state = MetadataSourceHealthState::Paused;
            }
            MetadataWatchLifecycleAction::Disable => {
                source.state = MetadataWatchSourceState::Disabled;
                source.health_state = MetadataSourceHealthState::Disabled;
            }
            MetadataWatchLifecycleAction::Revoke => {
                source.state = MetadataWatchSourceState::Revoked;
                source.health_state = MetadataSourceHealthState::Revoked;
                source.degraded_reason = Some("revoked_by_user".to_string());
            }
            MetadataWatchLifecycleAction::ClearInactive => unreachable!(),
        }
        source.validate()?;
        Ok(Some(source.clone()))
    }

    pub fn record_sampling_observation(
        &mut self,
        observation: MetadataSamplingObservation,
    ) -> Result<MetadataSamplingBatchSummary, ContinuousMetadataWatchError> {
        let source = self
            .sources
            .get_mut(&observation.source_id)
            .ok_or(ContinuousMetadataWatchError::SourceNotFound)?;
        if source.state == MetadataWatchSourceState::Revoked {
            return Err(ContinuousMetadataWatchError::SourceRevoked);
        }
        let started_at = Timestamp::now();
        let generation_hash = observation.safe_generation_hash();
        let dedup_key = dedup_key(source, &generation_hash);
        let duplicate = !self.dedup_keys.insert(dedup_key);
        let completed_at = Timestamp::now();
        let health_state = observation.health_state_override.clone().unwrap_or({
            if observation.backpressure_drop_count > 0 {
                MetadataSourceHealthState::Backpressure
            } else if observation.malformed_record_count > 0 {
                MetadataSourceHealthState::ParserError
            } else {
                MetadataSourceHealthState::Active
            }
        });
        let state_after_sample = if matches!(
            health_state,
            MetadataSourceHealthState::Active
                | MetadataSourceHealthState::RotationDetected
                | MetadataSourceHealthState::CursorResetRequired
        ) {
            MetadataWatchSourceState::Active
        } else {
            MetadataWatchSourceState::Enabled
        };
        let degraded_reason = observation
            .degraded_reason
            .clone()
            .or_else(|| match health_state {
                MetadataSourceHealthState::Backpressure => {
                    Some("bounded_queue_backpressure".to_string())
                }
                MetadataSourceHealthState::ParserError => {
                    Some("parser_error_or_malformed_input".to_string())
                }
                MetadataSourceHealthState::SourceUnavailable => {
                    Some("source_unavailable".to_string())
                }
                MetadataSourceHealthState::OversizedInputSkipped => {
                    Some("oversized_input_skipped".to_string())
                }
                MetadataSourceHealthState::RotationDetected => {
                    Some("rotation_detected".to_string())
                }
                MetadataSourceHealthState::CursorResetRequired => {
                    Some("cursor_reset_required".to_string())
                }
                _ => None,
            });
        let error_category = observation
            .error_category
            .clone()
            .or_else(|| match health_state {
                MetadataSourceHealthState::Backpressure => Some("backpressure".to_string()),
                MetadataSourceHealthState::ParserError => Some("parser_error".to_string()),
                MetadataSourceHealthState::SourceUnavailable => {
                    Some("source_unavailable".to_string())
                }
                MetadataSourceHealthState::OversizedInputSkipped => {
                    Some("oversized_input".to_string())
                }
                MetadataSourceHealthState::RotationDetected => {
                    Some("rotation_detected".to_string())
                }
                MetadataSourceHealthState::CursorResetRequired => {
                    Some("cursor_reset_required".to_string())
                }
                _ => None,
            });
        let duplicate_record_count = if duplicate {
            observation.sampled_record_count.max(1)
        } else {
            0
        };
        let sampled_record_count = if duplicate {
            0
        } else {
            observation.sampled_record_count
        };
        let sampled_byte_count = if duplicate {
            0
        } else {
            observation.sampled_byte_count
        };

        source.state = if duplicate {
            MetadataWatchSourceState::Enabled
        } else {
            state_after_sample
        };
        source.health_state = health_state.clone();
        source.last_sampled_at = Some(started_at.clone());
        source.last_ingested_at = Some(completed_at.clone());
        source.provenance_id = observation.provenance_id.clone();
        source.counters.batch_count = source.counters.batch_count.saturating_add(1);
        source.counters.sampled_record_count = source
            .counters
            .sampled_record_count
            .saturating_add(sampled_record_count);
        source.counters.sampled_byte_count = source
            .counters
            .sampled_byte_count
            .saturating_add(sampled_byte_count);
        source.counters.skipped_record_count = source
            .counters
            .skipped_record_count
            .saturating_add(observation.skipped_record_count);
        source.counters.malformed_record_count = source
            .counters
            .malformed_record_count
            .saturating_add(observation.malformed_record_count);
        source.counters.duplicate_record_count = source
            .counters
            .duplicate_record_count
            .saturating_add(duplicate_record_count);
        source.counters.backpressure_drop_count = source
            .counters
            .backpressure_drop_count
            .saturating_add(observation.backpressure_drop_count);
        source.fact_count = source
            .fact_count
            .saturating_add(bounded_len(observation.fact_refs.len()));
        source.finding_count = source
            .finding_count
            .saturating_add(bounded_len(observation.finding_refs.len()));
        source.hypothesis_count = source
            .hypothesis_count
            .saturating_add(observation.hypothesis_count);
        source.evidence_refs = bounded_refs(
            source
                .evidence_refs
                .iter()
                .cloned()
                .chain(observation.evidence_refs.iter().cloned())
                .collect(),
        );
        source.checkpoint.safe_cursor_bucket = next_cursor_bucket(source.counters.batch_count);
        source.checkpoint.safe_generation_hash = generation_hash;
        source.checkpoint.sampled_time_bucket = Some(started_at.clone());
        source.checkpoint.handoff_time_bucket = Some(completed_at.clone());
        source.checkpoint.health_state = source.health_state.clone();
        source.checkpoint.provenance_id = observation.provenance_id.clone();
        source.degraded_reason = degraded_reason;
        source.error_category = error_category;
        source.validate()?;

        let batch = MetadataSamplingBatchSummary {
            batch_id: MetadataSamplingBatchId::new_v4(),
            source_id: observation.source_id,
            source_kind: source.source_kind.clone(),
            parser_family: source.parser_family.clone(),
            started_at,
            completed_at,
            health_state,
            sampled_record_count,
            sampled_byte_count,
            skipped_record_count: observation.skipped_record_count,
            malformed_record_count: observation.malformed_record_count,
            duplicate_record_count,
            backpressure_drop_count: observation.backpressure_drop_count,
            emitted_topics: observation.emitted_topics,
            fact_refs: if duplicate {
                Vec::new()
            } else {
                bounded_refs(observation.fact_refs)
            },
            evidence_refs: if duplicate {
                Vec::new()
            } else {
                bounded_refs(observation.evidence_refs)
            },
            finding_refs: if duplicate {
                Vec::new()
            } else {
                bounded_refs(observation.finding_refs)
            },
            risk_refs: if duplicate {
                Vec::new()
            } else {
                bounded_refs(observation.risk_refs)
            },
            report_refresh_marker: !duplicate,
            attack_refresh_marker: !duplicate,
            story_available_marker: !duplicate,
            triage_advisory_only: true,
            automatic_llm_calls: false,
            response_execution: false,
        };
        batch.validate()?;
        self.last_tick_at = Some(batch.completed_at.clone());
        self.batches.push(batch.clone());
        Ok(batch)
    }

    pub fn mark_source_health(
        &mut self,
        source_id: &MetadataWatchSourceId,
        health_state: MetadataSourceHealthState,
        degraded_reason: Option<String>,
        error_category: Option<String>,
    ) -> Result<MetadataWatchSourceStatus, ContinuousMetadataWatchError> {
        let source = self
            .sources
            .get_mut(source_id)
            .ok_or(ContinuousMetadataWatchError::SourceNotFound)?;
        if source.state == MetadataWatchSourceState::Revoked {
            return Err(ContinuousMetadataWatchError::SourceRevoked);
        }

        source.state = match health_state {
            MetadataSourceHealthState::Disabled => MetadataWatchSourceState::Disabled,
            MetadataSourceHealthState::Paused => MetadataWatchSourceState::Paused,
            MetadataSourceHealthState::Stopped => MetadataWatchSourceState::Stopped,
            MetadataSourceHealthState::Revoked => MetadataWatchSourceState::Revoked,
            MetadataSourceHealthState::Active => MetadataWatchSourceState::Active,
            MetadataSourceHealthState::RotationDetected => MetadataWatchSourceState::Active,
            MetadataSourceHealthState::CursorResetRequired => MetadataWatchSourceState::Enabled,
            MetadataSourceHealthState::Idle => MetadataWatchSourceState::Enabled,
            MetadataSourceHealthState::OversizedInputSkipped => MetadataWatchSourceState::Enabled,
            _ => MetadataWatchSourceState::Enabled,
        };
        source.health_state = health_state;
        source.degraded_reason = degraded_reason;
        source.error_category = error_category;
        source.checkpoint.health_state = source.health_state.clone();
        source.validate()?;
        Ok(source.clone())
    }

    pub fn tick_result(
        &self,
        batches: Vec<MetadataSamplingBatchSummary>,
    ) -> MetadataSamplingTickResult {
        MetadataSamplingTickResult {
            controller_status: self.status(),
            batches,
            source_statuses: self.sources(),
        }
    }

    pub fn status(&self) -> MetadataWatchControllerStatus {
        let sources = self.sources.values().collect::<Vec<_>>();
        let mut status = MetadataWatchControllerStatus::empty();
        status.running = sources.iter().any(|source| {
            matches!(
                source.state,
                MetadataWatchSourceState::Enabled | MetadataWatchSourceState::Active
            )
        });
        status.enabled_source_count = count_sources(&sources, MetadataWatchSourceState::Enabled);
        status.active_source_count = count_sources(&sources, MetadataWatchSourceState::Active);
        status.paused_source_count = count_sources(&sources, MetadataWatchSourceState::Paused);
        status.revoked_source_count = count_sources(&sources, MetadataWatchSourceState::Revoked);
        status.degraded_source_count = sources
            .iter()
            .filter(|source| {
                matches!(
                    source.health_state,
                    MetadataSourceHealthState::Degraded
                        | MetadataSourceHealthState::ParserError
                        | MetadataSourceHealthState::SourceUnavailable
                        | MetadataSourceHealthState::CursorResetRequired
                        | MetadataSourceHealthState::RotationDetected
                        | MetadataSourceHealthState::OversizedInputSkipped
                )
            })
            .count() as u32;
        status.backpressure_source_count = sources
            .iter()
            .filter(|source| source.health_state == MetadataSourceHealthState::Backpressure)
            .count() as u32;
        status.total_sampled_record_count = sources
            .iter()
            .map(|source| source.counters.sampled_record_count)
            .sum();
        status.total_duplicate_record_count = sources
            .iter()
            .map(|source| source.counters.duplicate_record_count)
            .sum();
        status.total_malformed_record_count = sources
            .iter()
            .map(|source| source.counters.malformed_record_count)
            .sum();
        status.total_backpressure_drop_count = sources
            .iter()
            .map(|source| source.counters.backpressure_drop_count)
            .sum();
        status.last_tick_at = self.last_tick_at.clone();
        status.latest_batch_id = self.batches.last().map(|batch| batch.batch_id.clone());
        status.latest_checkpoint_id = sources
            .iter()
            .filter_map(|source| source.last_ingested_at.as_ref().map(|time| (time, source)))
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(_, source)| source.checkpoint.checkpoint_id.clone());
        status.latest_provenance_id = sources
            .iter()
            .filter_map(|source| {
                source
                    .last_ingested_at
                    .as_ref()
                    .zip(source.provenance_id.clone())
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(_, provenance)| provenance);
        status.fusion_refresh_count = self
            .batches
            .iter()
            .filter(|batch| !batch.fact_refs.is_empty() || !batch.finding_refs.is_empty())
            .count() as u64;
        status.report_refresh_marker_count = self
            .batches
            .iter()
            .filter(|batch| batch.report_refresh_marker)
            .count() as u64;
        status.attack_refresh_marker_count = self
            .batches
            .iter()
            .filter(|batch| batch.attack_refresh_marker)
            .count() as u64;
        status
    }

    pub fn sources(&self) -> Vec<MetadataWatchSourceStatus> {
        self.sources.values().cloned().collect()
    }

    pub fn batches(&self) -> Vec<MetadataSamplingBatchSummary> {
        self.batches.clone()
    }
}

pub fn source_kind_for_parser(parser_family: &MetadataParserFamily) -> MetadataWatchSourceKind {
    match parser_family {
        MetadataParserFamily::Har => MetadataWatchSourceKind::WatchedHarFolder,
        MetadataParserFamily::JsonlNetwork => MetadataWatchSourceKind::WatchedJsonlFolder,
        MetadataParserFamily::WebAccessLog => MetadataWatchSourceKind::TailedWebLog,
        MetadataParserFamily::AuthSecurityLog => MetadataWatchSourceKind::TailedAuthSecurityLog,
        MetadataParserFamily::SaasCloudJsonl => MetadataWatchSourceKind::TailedSaasCloudJsonl,
        MetadataParserFamily::DeceptionJsonl => {
            MetadataWatchSourceKind::TailedDeceptionHoneypotJsonl
        }
        MetadataParserFamily::LocalProxyMetadata => {
            MetadataWatchSourceKind::LocalhostProxyContinuousDrain
        }
    }
}

fn sampler_ids_for_source(source_id: &MetadataWatchSourceId) -> Vec<String> {
    vec![format!(
        "watch_source_{}",
        source_id.to_string().replace('-', "")
    )]
}

fn count_sources(sources: &[&MetadataWatchSourceStatus], state: MetadataWatchSourceState) -> u32 {
    sources
        .iter()
        .filter(|source| source.state == state)
        .count() as u32
}

fn dedup_key(source: &MetadataWatchSourceStatus, generation_hash: &str) -> String {
    format!(
        "{}:{}:{}:{}",
        source.source_id,
        parser_label(&source.parser_family),
        source.checkpoint.parser_schema_version,
        generation_hash
    )
}

fn parser_label(parser_family: &MetadataParserFamily) -> &'static str {
    match parser_family {
        MetadataParserFamily::Har => "har",
        MetadataParserFamily::JsonlNetwork => "jsonl_network",
        MetadataParserFamily::WebAccessLog => "web_access_log",
        MetadataParserFamily::AuthSecurityLog => "auth_security_log",
        MetadataParserFamily::SaasCloudJsonl => "saas_cloud_jsonl",
        MetadataParserFamily::DeceptionJsonl => "deception_jsonl",
        MetadataParserFamily::LocalProxyMetadata => "local_proxy_metadata",
    }
}

fn safe_generation_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn next_cursor_bucket(batch_count: u64) -> String {
    format!("batch_bucket_{batch_count}")
}

fn bounded_len(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn bounded_refs<T>(mut values: Vec<T>) -> Vec<T> {
    values.truncate(MAX_WATCH_REFS);
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::MetadataSamplingMode;

    fn preview_request() -> MetadataWatchSourcePreviewRequest {
        MetadataWatchSourcePreviewRequest {
            source_kind: MetadataWatchSourceKind::TailedWebLog,
            parser_family: MetadataParserFamily::WebAccessLog,
            display_label_redacted: "web_tail_source".to_string(),
            sampling_mode: MetadataSamplingMode::IntervalTick,
            interval_seconds: 5,
            max_records_per_tick: 100,
            max_bytes_per_tick: 64_000,
            reason_redacted: "operator_confirmed".to_string(),
        }
    }

    fn confirmed_controller() -> (ContinuousMetadataWatchController, MetadataWatchSourceId) {
        let mut controller = ContinuousMetadataWatchController::new();
        let preview = controller
            .preview_source(preview_request())
            .expect("preview source");
        let source_id = preview.preview_id.clone();
        controller
            .confirm_source(MetadataWatchSourceConfirmation {
                preview_id: preview.preview_id,
                user_confirmed: true,
                reason_redacted: "operator_confirmed".to_string(),
                requested_by_redacted: Some("local_user".to_string()),
            })
            .expect("confirm source");
        (controller, source_id)
    }

    fn observation(source_id: MetadataWatchSourceId) -> MetadataSamplingObservation {
        MetadataSamplingObservation {
            source_id,
            source_generation_ref: "generation_one".to_string(),
            sampled_record_count: 3,
            sampled_byte_count: 512,
            skipped_record_count: 0,
            malformed_record_count: 0,
            backpressure_drop_count: 0,
            emitted_topics: vec![
                "network.http.metadata".to_string(),
                "security.fact".to_string(),
            ],
            fact_refs: vec![SecurityFactId::new_v4()],
            evidence_refs: vec![EvidenceId::new_v4()],
            finding_refs: vec![FindingId::new_v4()],
            risk_refs: vec![RiskEventId::new_v4()],
            hypothesis_count: 1,
            provenance_id: Some(DataSourceId::new_v4()),
            health_state_override: None,
            degraded_reason: None,
            error_category: None,
        }
    }

    #[test]
    fn preview_creates_no_runtime_source_until_confirmed() {
        let mut controller = ContinuousMetadataWatchController::new();
        let preview = controller
            .preview_source(preview_request())
            .expect("preview");

        assert_eq!(controller.sources().len(), 0);
        assert!(controller
            .confirm_source(MetadataWatchSourceConfirmation {
                preview_id: preview.preview_id,
                user_confirmed: false,
                reason_redacted: "operator_cancelled".to_string(),
                requested_by_redacted: None,
            })
            .is_err());
    }

    #[test]
    fn lifecycle_pause_resume_disable_and_revoke_are_bounded() {
        let (mut controller, source_id) = confirmed_controller();

        controller
            .transition_source(&source_id, MetadataWatchLifecycleAction::Pause)
            .expect("pause");
        assert_eq!(
            controller.sources()[0].state,
            MetadataWatchSourceState::Paused
        );
        controller
            .transition_source(&source_id, MetadataWatchLifecycleAction::Resume)
            .expect("resume");
        assert_eq!(
            controller.sources()[0].state,
            MetadataWatchSourceState::Enabled
        );
        controller
            .transition_source(&source_id, MetadataWatchLifecycleAction::Disable)
            .expect("disable");
        assert_eq!(
            controller.sources()[0].health_state,
            MetadataSourceHealthState::Disabled
        );
        controller
            .transition_source(&source_id, MetadataWatchLifecycleAction::Enable)
            .expect("enable");
        controller
            .transition_source(&source_id, MetadataWatchLifecycleAction::Revoke)
            .expect("revoke");
        assert_eq!(
            controller.sources()[0].state,
            MetadataWatchSourceState::Revoked
        );
        assert!(controller
            .record_sampling_observation(observation(source_id))
            .is_err());
    }

    #[test]
    fn sampling_updates_checkpoint_and_suppresses_duplicate_generation() {
        let (mut controller, source_id) = confirmed_controller();
        let first = controller
            .record_sampling_observation(observation(source_id.clone()))
            .expect("first sample");
        let second = controller
            .record_sampling_observation(observation(source_id))
            .expect("duplicate sample");
        let source = controller.sources()[0].clone();

        assert_eq!(first.sampled_record_count, 3);
        assert_eq!(second.sampled_record_count, 0);
        assert_eq!(second.duplicate_record_count, 3);
        assert_eq!(source.counters.sampled_record_count, 3);
        assert_eq!(source.counters.duplicate_record_count, 3);
        assert!(source
            .checkpoint
            .safe_generation_hash
            .starts_with("sha256:"));
        assert!(!serde_json::to_string(&source)
            .expect("serialize source")
            .contains("generation_one"));
    }

    #[test]
    fn backpressure_and_parser_errors_degrade_without_private_markers() {
        let (mut controller, source_id) = confirmed_controller();
        let mut input = observation(source_id);
        input.malformed_record_count = 2;
        input.backpressure_drop_count = 1;
        let batch = controller
            .record_sampling_observation(input)
            .expect("sample with degradation");
        let serialized =
            serde_json::to_string(&controller.tick_result(vec![batch])).expect("serialize tick");

        assert_eq!(
            controller.sources()[0].health_state,
            MetadataSourceHealthState::Backpressure
        );
        assert!(!serialized.contains("session_token"));
        assert!(!serialized.contains("C:\\Users"));
        assert!(!serialized.contains("http://"));
        assert!(!serialized.contains("alice@example"));
    }
}
