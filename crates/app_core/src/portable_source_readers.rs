use sentinel_contracts::{
    DataSourceId, MetadataParserFamily, MetadataSourceHealthState, MetadataWatchCheckpointId,
    MetadataWatchCounters, MetadataWatchSourceId, MetadataWatchSourceKind,
    MetadataWatchSourcePreview, MetadataWatchSourcePreviewRequest, MetadataWatchSourceState,
    MetadataWatchSourceStatus, PortableCaptureInputSourceType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_DISCOVERY_ENTRIES: usize = 64;
const DEFAULT_MAX_FILES_PER_TICK: usize = 8;
const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableSourceReaderError {
    SourceUnavailable,
    UnauthorizedSourceRef,
    UnsupportedSourceFamily,
    ReaderNotAttached,
    ParserFamilyMismatch,
    Io,
}

impl fmt::Display for PortableSourceReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceUnavailable => write!(formatter, "portable reader source is unavailable"),
            Self::UnauthorizedSourceRef => {
                write!(
                    formatter,
                    "portable reader source reference is not authorized"
                )
            }
            Self::UnsupportedSourceFamily => {
                write!(formatter, "portable reader family is unsupported")
            }
            Self::ReaderNotAttached => write!(formatter, "portable reader is not attached"),
            Self::ParserFamilyMismatch => write!(formatter, "portable reader parser mismatch"),
            Self::Io => write!(formatter, "portable reader input could not be sampled"),
        }
    }
}

impl std::error::Error for PortableSourceReaderError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableReaderSourcePreviewRequest {
    pub watch_request: MetadataWatchSourcePreviewRequest,
    #[serde(skip_serializing)]
    pub source_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableReaderCursorRecord {
    pub source_id: MetadataWatchSourceId,
    pub checkpoint_id: MetadataWatchCheckpointId,
    pub source_kind: MetadataWatchSourceKind,
    pub parser_family: MetadataParserFamily,
    pub parser_schema_version: String,
    pub source_generation_hash: String,
    pub opaque_cursor: String,
    pub sampled_bucket: String,
    pub handoff_bucket: String,
    pub counters: MetadataWatchCounters,
    pub health_state: MetadataSourceHealthState,
    pub degraded_reason: Option<String>,
    pub provenance_id: Option<DataSourceId>,
}

pub struct PortableReaderCandidate {
    pub source_type: PortableCaptureInputSourceType,
    pub content: String,
    pub content_len: usize,
    pub record_count_hint: u64,
    pub generation_ref: String,
}

#[derive(Clone, Debug)]
pub struct PortableReaderCommit {
    source_id: MetadataWatchSourceId,
    byte_offset: Option<u64>,
    completed_generation_hashes: Vec<String>,
    counters: MetadataWatchCounters,
    health_state: MetadataSourceHealthState,
    degraded_reason: Option<String>,
    generation_hash: String,
}

pub struct PortableReaderReadResult {
    pub candidates: Vec<PortableReaderCandidate>,
    pub commit: PortableReaderCommit,
    pub health_state: MetadataSourceHealthState,
    pub degraded_reason: Option<String>,
    pub error_category: Option<String>,
    pub generation_ref: String,
    pub sampled_record_count: u64,
    pub sampled_byte_count: u64,
    pub skipped_record_count: u64,
    pub malformed_record_count: u64,
    pub backpressure_drop_count: u64,
    pub provenance_id_hint: Option<DataSourceId>,
}

#[derive(Clone, Debug)]
struct PortableReaderSourceConfig {
    source_kind: MetadataWatchSourceKind,
    parser_family: MetadataParserFamily,
    reader_kind: PortableReaderKind,
    source_type: PortableCaptureInputSourceType,
    source_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PortableReaderKind {
    WatchFolder,
    TailFile,
    JsonlAppend,
}

#[derive(Clone, Debug)]
struct PrivateReaderCursor {
    byte_offset: u64,
    completed_generation_hashes: BTreeSet<String>,
    counters: MetadataWatchCounters,
    failure_count: u32,
    checkpoint_id: Option<MetadataWatchCheckpointId>,
    cursor_record: Option<PortableReaderCursorRecord>,
}

impl Default for PrivateReaderCursor {
    fn default() -> Self {
        Self {
            byte_offset: 0,
            completed_generation_hashes: BTreeSet::new(),
            counters: MetadataWatchCounters::empty(),
            failure_count: 0,
            checkpoint_id: None,
            cursor_record: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PortableReaderCursorStore {
    cursors: HashMap<MetadataWatchSourceId, PrivateReaderCursor>,
}

impl PortableReaderCursorStore {
    pub fn from_records(records: Vec<PortableReaderCursorRecord>) -> Self {
        let mut store = Self::default();
        for record in records {
            let mut cursor = PrivateReaderCursor {
                byte_offset: decode_opaque_cursor(&record.opaque_cursor).unwrap_or(0),
                completed_generation_hashes: BTreeSet::new(),
                counters: record.counters.clone(),
                failure_count: 0,
                checkpoint_id: Some(record.checkpoint_id.clone()),
                cursor_record: Some(record.clone()),
            };
            cursor
                .completed_generation_hashes
                .insert(record.source_generation_hash.clone());
            store.cursors.insert(record.source_id.clone(), cursor);
        }
        store
    }

    pub fn records(&self) -> Vec<PortableReaderCursorRecord> {
        self.cursors
            .values()
            .filter_map(|cursor| cursor.cursor_record.clone())
            .collect()
    }

    fn cursor_for_source(
        &mut self,
        source: &MetadataWatchSourceStatus,
    ) -> &mut PrivateReaderCursor {
        let cursor = self.cursors.entry(source.source_id.clone()).or_default();
        cursor.checkpoint_id = Some(source.checkpoint.checkpoint_id.clone());
        cursor
    }

    fn record_failure(&mut self, source: &MetadataWatchSourceStatus) -> u32 {
        let cursor = self.cursor_for_source(source);
        cursor.failure_count = cursor.failure_count.saturating_add(1);
        cursor.failure_count
    }

    fn clear_failure(&mut self, source: &MetadataWatchSourceStatus) {
        let cursor = self.cursor_for_source(source);
        cursor.failure_count = 0;
    }

    fn commit(
        &mut self,
        source: &MetadataWatchSourceStatus,
        commit: PortableReaderCommit,
        provenance_id: Option<DataSourceId>,
    ) -> PortableReaderCursorRecord {
        let cursor = self.cursor_for_source(source);
        if let Some(offset) = commit.byte_offset {
            cursor.byte_offset = offset;
        }
        let source_generation_hash = commit
            .completed_generation_hashes
            .last()
            .cloned()
            .unwrap_or_else(|| commit.generation_hash.clone());
        for generation_hash in commit.completed_generation_hashes {
            cursor.completed_generation_hashes.insert(generation_hash);
        }
        cursor.counters.sampled_record_count = cursor
            .counters
            .sampled_record_count
            .saturating_add(commit.counters.sampled_record_count);
        cursor.counters.sampled_byte_count = cursor
            .counters
            .sampled_byte_count
            .saturating_add(commit.counters.sampled_byte_count);
        cursor.counters.skipped_record_count = cursor
            .counters
            .skipped_record_count
            .saturating_add(commit.counters.skipped_record_count);
        cursor.counters.malformed_record_count = cursor
            .counters
            .malformed_record_count
            .saturating_add(commit.counters.malformed_record_count);
        cursor.counters.backpressure_drop_count = cursor
            .counters
            .backpressure_drop_count
            .saturating_add(commit.counters.backpressure_drop_count);
        cursor.counters.batch_count = cursor.counters.batch_count.saturating_add(1);
        cursor.failure_count = 0;

        let record = PortableReaderCursorRecord {
            source_id: commit.source_id,
            checkpoint_id: source.checkpoint.checkpoint_id.clone(),
            source_kind: source.source_kind.clone(),
            parser_family: source.parser_family.clone(),
            parser_schema_version: source.checkpoint.parser_schema_version.clone(),
            source_generation_hash,
            opaque_cursor: encode_opaque_cursor(cursor.byte_offset),
            sampled_bucket: format!("sampled_bucket_{}", cursor.counters.batch_count),
            handoff_bucket: format!("handoff_bucket_{}", cursor.counters.batch_count),
            counters: cursor.counters.clone(),
            health_state: commit.health_state,
            degraded_reason: commit.degraded_reason,
            provenance_id,
        };
        cursor.cursor_record = Some(record.clone());
        record
    }
}

#[derive(Clone, Debug, Default)]
pub struct PortableSourceReaderRuntime {
    pending: HashMap<MetadataWatchSourceId, PortableReaderSourceConfig>,
    sources: HashMap<MetadataWatchSourceId, PortableReaderSourceConfig>,
    cursor_store: PortableReaderCursorStore,
}

impl PortableSourceReaderRuntime {
    pub fn from_cursor_records(records: Vec<PortableReaderCursorRecord>) -> Self {
        Self {
            pending: HashMap::new(),
            sources: HashMap::new(),
            cursor_store: PortableReaderCursorStore::from_records(records),
        }
    }

    pub fn cursor_records(&self) -> Vec<PortableReaderCursorRecord> {
        self.cursor_store.records()
    }

    pub fn preview_source(
        &mut self,
        preview: &MetadataWatchSourcePreview,
        request: &PortableReaderSourcePreviewRequest,
    ) -> Result<(), PortableSourceReaderError> {
        let config = config_from_preview(preview, &request.source_path)?;
        self.pending.insert(preview.preview_id.clone(), config);
        Ok(())
    }

    pub fn confirm_source(&mut self, source: &MetadataWatchSourceStatus) {
        if let Some(config) = self.pending.remove(&source.source_id) {
            self.sources.insert(source.source_id.clone(), config);
            self.cursor_store.cursor_for_source(source);
        }
    }

    pub fn attach_existing_source(
        &mut self,
        source: &MetadataWatchSourceStatus,
        source_path: impl Into<String>,
    ) -> Result<(), PortableSourceReaderError> {
        let config = config_from_source(source, &source_path.into())?;
        self.sources.insert(source.source_id.clone(), config);
        self.cursor_store.cursor_for_source(source);
        Ok(())
    }

    pub fn revoke_source(&mut self, source_id: &MetadataWatchSourceId) {
        self.pending.remove(source_id);
        self.sources.remove(source_id);
        self.cursor_store.cursors.remove(source_id);
    }

    pub fn has_source(&self, source_id: &MetadataWatchSourceId) -> bool {
        self.sources.contains_key(source_id)
    }

    pub fn record_source_failure(&mut self, source: &MetadataWatchSourceStatus) -> u32 {
        self.cursor_store.record_failure(source)
    }

    pub fn read_source(
        &mut self,
        source: &MetadataWatchSourceStatus,
        max_files_per_tick: Option<u32>,
    ) -> Result<PortableReaderReadResult, PortableSourceReaderError> {
        if !matches!(
            source.state,
            MetadataWatchSourceState::Enabled | MetadataWatchSourceState::Active
        ) {
            return Err(PortableSourceReaderError::ReaderNotAttached);
        }
        let config = self
            .sources
            .get(&source.source_id)
            .cloned()
            .ok_or(PortableSourceReaderError::ReaderNotAttached)?;
        if config.parser_family != source.parser_family || config.source_kind != source.source_kind
        {
            return Err(PortableSourceReaderError::ParserFamilyMismatch);
        }
        validate_live_source_ref(&config)?;
        self.cursor_store.clear_failure(source);
        match config.reader_kind {
            PortableReaderKind::WatchFolder => {
                self.read_watch_folder(source, &config, max_files_per_tick)
            }
            PortableReaderKind::TailFile | PortableReaderKind::JsonlAppend => {
                self.read_tail_file(source, &config)
            }
        }
    }

    pub fn commit_source(
        &mut self,
        source: &MetadataWatchSourceStatus,
        commit: PortableReaderCommit,
        provenance_id: Option<DataSourceId>,
    ) -> PortableReaderCursorRecord {
        self.cursor_store.commit(source, commit, provenance_id)
    }

    fn read_watch_folder(
        &mut self,
        source: &MetadataWatchSourceStatus,
        config: &PortableReaderSourceConfig,
        max_files_per_tick: Option<u32>,
    ) -> Result<PortableReaderReadResult, PortableSourceReaderError> {
        let configured_files = max_files_per_tick
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_MAX_FILES_PER_TICK);
        let max_files = configured_files.min(source.max_records_per_tick as usize);
        let mut candidates = Vec::new();
        let mut completed_hashes = Vec::new();
        let mut sampled_bytes = 0u64;
        let mut sampled_records = 0u64;
        let mut skipped = 0u64;
        let mut malformed = 0u64;
        let mut backpressure = 0u64;
        let mut generation_refs = Vec::new();

        let entries = fs::read_dir(&config.source_path)
            .map_err(|_| PortableSourceReaderError::SourceUnavailable)?;
        for (discovery_count, entry) in entries.enumerate() {
            if discovery_count >= MAX_DISCOVERY_ENTRIES || candidates.len() >= max_files {
                backpressure = backpressure.saturating_add(1);
                break;
            }
            let entry = entry.map_err(|_| PortableSourceReaderError::Io)?;
            let entry_path = entry.path();
            let metadata =
                fs::symlink_metadata(&entry_path).map_err(|_| PortableSourceReaderError::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                skipped = skipped.saturating_add(1);
                continue;
            }
            if !extension_matches(&entry_path, &config.source_type) {
                continue;
            }
            if metadata.len() > source.max_bytes_per_tick as u64 {
                skipped = skipped.saturating_add(1);
                continue;
            }
            if sampled_bytes.saturating_add(metadata.len()) > source.max_bytes_per_tick as u64 {
                backpressure = backpressure.saturating_add(1);
                continue;
            }
            let bytes = fs::read(&entry_path).map_err(|_| PortableSourceReaderError::Io)?;
            let content = String::from_utf8(bytes).map_err(|_| PortableSourceReaderError::Io)?;
            let generation_hash = generation_hash_for_content(&source.source_id, &content);
            if self
                .cursor_store
                .cursor_for_source(source)
                .completed_generation_hashes
                .contains(&generation_hash)
            {
                continue;
            }
            let line_validation = validate_jsonl_if_required(
                &config.source_type,
                &content,
                source.max_records_per_tick,
            );
            if let Err(validation_error) = line_validation {
                match validation_error {
                    JsonlValidationError::Malformed => malformed = malformed.saturating_add(1),
                    JsonlValidationError::Oversized => skipped = skipped.saturating_add(1),
                    JsonlValidationError::HighRisk => skipped = skipped.saturating_add(1),
                }
                completed_hashes.push(generation_hash);
                continue;
            }
            sampled_records = sampled_records.saturating_add(record_count_hint(&content));
            sampled_bytes = sampled_bytes.saturating_add(content.len() as u64);
            generation_refs.push(generation_hash.clone());
            completed_hashes.push(generation_hash.clone());
            candidates.push(PortableReaderCandidate {
                source_type: config.source_type.clone(),
                content,
                content_len: metadata.len() as usize,
                record_count_hint: record_count_hint_from_source(
                    &config.source_type,
                    &generation_hash,
                ),
                generation_ref: generation_hash,
            });
        }

        let generation_ref = safe_generation_ref(
            &source.source_id,
            &config.parser_family,
            &generation_refs,
            GenerationStats {
                records: sampled_records,
                bytes: sampled_bytes,
                skipped,
                malformed,
                backpressure,
            },
        );
        let health = reader_health(
            !candidates.is_empty(),
            skipped,
            malformed,
            backpressure,
            MetadataSourceHealthState::Idle,
        );
        let counters = counters(
            sampled_records,
            sampled_bytes,
            skipped,
            malformed,
            backpressure,
        );
        let commit = PortableReaderCommit {
            source_id: source.source_id.clone(),
            byte_offset: None,
            completed_generation_hashes: completed_hashes,
            counters,
            health_state: health.clone(),
            degraded_reason: degraded_reason_for_health(&health),
            generation_hash: hash_text(&generation_ref),
        };
        Ok(PortableReaderReadResult {
            candidates,
            commit,
            health_state: health.clone(),
            degraded_reason: degraded_reason_for_health(&health),
            error_category: error_category_for_health(&health),
            generation_ref,
            sampled_record_count: sampled_records,
            sampled_byte_count: sampled_bytes,
            skipped_record_count: skipped,
            malformed_record_count: malformed,
            backpressure_drop_count: backpressure,
            provenance_id_hint: None,
        })
    }

    fn read_tail_file(
        &mut self,
        source: &MetadataWatchSourceStatus,
        config: &PortableReaderSourceConfig,
    ) -> Result<PortableReaderReadResult, PortableSourceReaderError> {
        let metadata = fs::metadata(&config.source_path)
            .map_err(|_| PortableSourceReaderError::SourceUnavailable)?;
        if !metadata.is_file() {
            return Err(PortableSourceReaderError::SourceUnavailable);
        }
        let cursor = self.cursor_store.cursor_for_source(source);
        let mut offset = cursor.byte_offset;
        let mut base_health = MetadataSourceHealthState::Idle;
        if metadata.len() < offset {
            offset = 0;
            base_health = if metadata.len() == 0 {
                MetadataSourceHealthState::CursorResetRequired
            } else {
                MetadataSourceHealthState::RotationDetected
            };
        }

        let remaining = metadata.len().saturating_sub(offset);
        if remaining == 0 {
            let generation_ref = safe_generation_ref(
                &source.source_id,
                &config.parser_family,
                &[],
                GenerationStats::default(),
            );
            let commit = PortableReaderCommit {
                source_id: source.source_id.clone(),
                byte_offset: Some(offset),
                completed_generation_hashes: Vec::new(),
                counters: counters(0, 0, 0, 0, 0),
                health_state: base_health.clone(),
                degraded_reason: degraded_reason_for_health(&base_health),
                generation_hash: hash_text(&generation_ref),
            };
            return Ok(PortableReaderReadResult {
                candidates: Vec::new(),
                commit,
                health_state: base_health.clone(),
                degraded_reason: degraded_reason_for_health(&base_health),
                error_category: error_category_for_health(&base_health),
                generation_ref,
                sampled_record_count: 0,
                sampled_byte_count: 0,
                skipped_record_count: 0,
                malformed_record_count: 0,
                backpressure_drop_count: 0,
                provenance_id_hint: None,
            });
        }

        let read_len = remaining.min(source.max_bytes_per_tick as u64) as usize;
        let mut file = fs::File::open(&config.source_path)
            .map_err(|_| PortableSourceReaderError::SourceUnavailable)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| PortableSourceReaderError::Io)?;
        let mut buffer = vec![0u8; read_len];
        let actual = file
            .read(&mut buffer)
            .map_err(|_| PortableSourceReaderError::Io)?;
        buffer.truncate(actual);
        let Some(complete_end) = last_complete_line_end(&buffer) else {
            let generation_ref = safe_generation_ref(
                &source.source_id,
                &config.parser_family,
                &[],
                GenerationStats::default(),
            );
            let commit = PortableReaderCommit {
                source_id: source.source_id.clone(),
                byte_offset: Some(offset),
                completed_generation_hashes: Vec::new(),
                counters: counters(0, 0, 0, 0, 0),
                health_state: base_health.clone(),
                degraded_reason: degraded_reason_for_health(&base_health),
                generation_hash: hash_text(&generation_ref),
            };
            return Ok(PortableReaderReadResult {
                candidates: Vec::new(),
                commit,
                health_state: base_health.clone(),
                degraded_reason: degraded_reason_for_health(&base_health),
                error_category: error_category_for_health(&base_health),
                generation_ref,
                sampled_record_count: 0,
                sampled_byte_count: 0,
                skipped_record_count: 0,
                malformed_record_count: 0,
                backpressure_drop_count: 0,
                provenance_id_hint: None,
            });
        };
        let complete = &buffer[..complete_end];
        let (bounded, processed_bytes, backpressure) =
            bounded_complete_lines(complete, source.max_records_per_tick as usize);
        let new_offset = offset.saturating_add(processed_bytes as u64);
        let content = String::from_utf8(bounded).map_err(|_| PortableSourceReaderError::Io)?;
        let (candidate_content, sampled_records, skipped, malformed) =
            if matches!(config.reader_kind, PortableReaderKind::JsonlAppend) {
                let validation =
                    filter_jsonl_append_lines(&content, source.max_records_per_tick as usize)?;
                (
                    validation.content,
                    validation.record_count,
                    validation.skipped_count,
                    validation.malformed_count,
                )
            } else {
                (content.clone(), record_count_hint(&content), 0, 0)
            };

        let sampled_bytes = candidate_content.len() as u64;
        let generation_hash = generation_hash_for_content(&source.source_id, &candidate_content);
        let mut candidates = Vec::new();
        if !candidate_content.trim().is_empty() {
            candidates.push(PortableReaderCandidate {
                source_type: config.source_type.clone(),
                content: candidate_content,
                content_len: sampled_bytes as usize,
                record_count_hint: sampled_records,
                generation_ref: generation_hash.clone(),
            });
        }
        let generation_ref = safe_generation_ref(
            &source.source_id,
            &config.parser_family,
            std::slice::from_ref(&generation_hash),
            GenerationStats {
                records: sampled_records,
                bytes: sampled_bytes,
                skipped,
                malformed,
                backpressure,
            },
        );
        let health = reader_health(
            !candidates.is_empty(),
            skipped,
            malformed,
            backpressure,
            base_health,
        );
        let commit = PortableReaderCommit {
            source_id: source.source_id.clone(),
            byte_offset: Some(new_offset),
            completed_generation_hashes: vec![generation_hash],
            counters: counters(
                sampled_records,
                sampled_bytes,
                skipped,
                malformed,
                backpressure,
            ),
            health_state: health.clone(),
            degraded_reason: degraded_reason_for_health(&health),
            generation_hash: hash_text(&generation_ref),
        };
        Ok(PortableReaderReadResult {
            candidates,
            commit,
            health_state: health.clone(),
            degraded_reason: degraded_reason_for_health(&health),
            error_category: error_category_for_health(&health),
            generation_ref,
            sampled_record_count: sampled_records,
            sampled_byte_count: sampled_bytes,
            skipped_record_count: skipped,
            malformed_record_count: malformed,
            backpressure_drop_count: backpressure,
            provenance_id_hint: None,
        })
    }
}

fn config_from_preview(
    preview: &MetadataWatchSourcePreview,
    source_path: &str,
) -> Result<PortableReaderSourceConfig, PortableSourceReaderError> {
    config_from_parts(
        preview.preview_id.clone(),
        preview.source_kind.clone(),
        preview.parser_family.clone(),
        source_path,
    )
}

fn config_from_source(
    source: &MetadataWatchSourceStatus,
    source_path: &str,
) -> Result<PortableReaderSourceConfig, PortableSourceReaderError> {
    config_from_parts(
        source.source_id.clone(),
        source.source_kind.clone(),
        source.parser_family.clone(),
        source_path,
    )
}

fn config_from_parts(
    _source_id: MetadataWatchSourceId,
    source_kind: MetadataWatchSourceKind,
    parser_family: MetadataParserFamily,
    source_path: &str,
) -> Result<PortableReaderSourceConfig, PortableSourceReaderError> {
    let (reader_kind, expected_parser, source_type) = source_family(source_kind.clone())?;
    if parser_family != expected_parser {
        return Err(PortableSourceReaderError::ParserFamilyMismatch);
    }
    let source_path = PathBuf::from(source_path);
    let config = PortableReaderSourceConfig {
        source_kind,
        parser_family,
        reader_kind,
        source_type,
        source_path,
    };
    validate_live_source_ref(&config)?;
    Ok(config)
}

fn source_family(
    source_kind: MetadataWatchSourceKind,
) -> Result<
    (
        PortableReaderKind,
        MetadataParserFamily,
        PortableCaptureInputSourceType,
    ),
    PortableSourceReaderError,
> {
    match source_kind {
        MetadataWatchSourceKind::WatchedHarFolder => Ok((
            PortableReaderKind::WatchFolder,
            MetadataParserFamily::Har,
            PortableCaptureInputSourceType::ImportedHar,
        )),
        MetadataWatchSourceKind::WatchedJsonlFolder => Ok((
            PortableReaderKind::WatchFolder,
            MetadataParserFamily::JsonlNetwork,
            PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata,
        )),
        MetadataWatchSourceKind::TailedWebLog => Ok((
            PortableReaderKind::TailFile,
            MetadataParserFamily::WebAccessLog,
            PortableCaptureInputSourceType::ImportedWebAccessLog,
        )),
        MetadataWatchSourceKind::TailedAuthSecurityLog => Ok((
            PortableReaderKind::TailFile,
            MetadataParserFamily::AuthSecurityLog,
            PortableCaptureInputSourceType::ImportedAuthSecurityLog,
        )),
        MetadataWatchSourceKind::TailedSaasCloudJsonl => Ok((
            PortableReaderKind::JsonlAppend,
            MetadataParserFamily::SaasCloudJsonl,
            PortableCaptureInputSourceType::ImportedSaasCloudMetadata,
        )),
        MetadataWatchSourceKind::TailedDeceptionHoneypotJsonl => Ok((
            PortableReaderKind::JsonlAppend,
            MetadataParserFamily::DeceptionJsonl,
            PortableCaptureInputSourceType::ImportedDeceptionEventLog,
        )),
        _ => Err(PortableSourceReaderError::UnsupportedSourceFamily),
    }
}

fn validate_live_source_ref(
    config: &PortableReaderSourceConfig,
) -> Result<(), PortableSourceReaderError> {
    if config.source_path.as_os_str().is_empty() {
        return Err(PortableSourceReaderError::SourceUnavailable);
    }
    let metadata = fs::symlink_metadata(&config.source_path)
        .map_err(|_| PortableSourceReaderError::SourceUnavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(PortableSourceReaderError::UnauthorizedSourceRef);
    }
    match config.reader_kind {
        PortableReaderKind::WatchFolder if metadata.is_dir() => Ok(()),
        PortableReaderKind::TailFile | PortableReaderKind::JsonlAppend if metadata.is_file() => {
            Ok(())
        }
        _ => Err(PortableSourceReaderError::SourceUnavailable),
    }
}

fn extension_matches(path: &Path, source_type: &PortableCaptureInputSourceType) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match source_type {
        PortableCaptureInputSourceType::ImportedHar => extension == "har",
        PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata => extension == "jsonl",
        _ => true,
    }
}

fn validate_jsonl_if_required(
    source_type: &PortableCaptureInputSourceType,
    content: &str,
    max_records: u32,
) -> Result<(), JsonlValidationError> {
    if !matches!(
        source_type,
        PortableCaptureInputSourceType::ImportedJsonlNetworkMetadata
            | PortableCaptureInputSourceType::ImportedSaasCloudMetadata
            | PortableCaptureInputSourceType::ImportedDeceptionEventLog
    ) {
        return Ok(());
    }
    let mut count = 0u32;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > MAX_LINE_BYTES {
            return Err(JsonlValidationError::Oversized);
        }
        count = count.saturating_add(1);
        if count > max_records {
            return Err(JsonlValidationError::Oversized);
        }
        let value: Value =
            serde_json::from_str(trimmed).map_err(|_| JsonlValidationError::Malformed)?;
        if !value.is_object() {
            return Err(JsonlValidationError::Malformed);
        }
        if contains_high_risk_json_field(&value) {
            return Err(JsonlValidationError::HighRisk);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum JsonlValidationError {
    Malformed,
    Oversized,
    HighRisk,
}

struct JsonlFilterResult {
    content: String,
    record_count: u64,
    skipped_count: u64,
    malformed_count: u64,
}

fn filter_jsonl_append_lines(
    content: &str,
    max_records: usize,
) -> Result<JsonlFilterResult, PortableSourceReaderError> {
    let mut accepted = Vec::new();
    let mut skipped = 0u64;
    let mut malformed = 0u64;
    for line in content.lines().take(max_records) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > MAX_LINE_BYTES {
            skipped = skipped.saturating_add(1);
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) if value.is_object() && !contains_high_risk_json_field(&value) => {
                accepted.push(trimmed.to_string());
            }
            Ok(value) if value.is_object() => skipped = skipped.saturating_add(1),
            Ok(_) => malformed = malformed.saturating_add(1),
            Err(_) => malformed = malformed.saturating_add(1),
        }
    }
    Ok(JsonlFilterResult {
        content: accepted.join("\n"),
        record_count: accepted.len() as u64,
        skipped_count: skipped,
        malformed_count: malformed,
    })
}

fn contains_high_risk_json_field(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| is_high_risk_json_key(key) || contains_high_risk_json_field(value)),
        Value::Array(values) => values.iter().any(contains_high_risk_json_field),
        _ => false,
    }
}

fn is_high_risk_json_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "cookie"
            | "cookies"
            | "headers"
            | "request_headers"
            | "response_headers"
            | "password"
            | "passwd"
            | "secret"
            | "client_secret"
            | "api_key"
            | "apikey"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "token"
            | "payload"
            | "body"
            | "request_body"
            | "response_body"
            | "command"
            | "command_line"
            | "tenant"
            | "tenant_id"
            | "email"
            | "username"
            | "filename"
            | "filepath"
            | "file_path"
    )
}

fn last_complete_line_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|index| index + 1)
}

fn bounded_complete_lines(buffer: &[u8], max_records: usize) -> (Vec<u8>, usize, u64) {
    let mut processed_bytes = 0usize;
    let mut record_count = 0usize;
    let mut backpressure = 0u64;
    for (index, byte) in buffer.iter().enumerate() {
        if *byte == b'\n' {
            record_count += 1;
            if record_count > max_records {
                backpressure = 1;
                break;
            }
            processed_bytes = index + 1;
        }
    }
    (
        buffer[..processed_bytes].to_vec(),
        processed_bytes,
        backpressure,
    )
}

fn record_count_hint(content: &str) -> u64 {
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u64
}

fn record_count_hint_from_source(
    _source_type: &PortableCaptureInputSourceType,
    _generation_hash: &str,
) -> u64 {
    1
}

fn counters(
    sampled_record_count: u64,
    sampled_byte_count: u64,
    skipped_record_count: u64,
    malformed_record_count: u64,
    backpressure_drop_count: u64,
) -> MetadataWatchCounters {
    MetadataWatchCounters {
        sampled_record_count,
        sampled_byte_count,
        skipped_record_count,
        malformed_record_count,
        duplicate_record_count: 0,
        backpressure_drop_count,
        batch_count: 0,
    }
}

fn reader_health(
    has_candidate: bool,
    skipped: u64,
    malformed: u64,
    backpressure: u64,
    base: MetadataSourceHealthState,
) -> MetadataSourceHealthState {
    if backpressure > 0 {
        MetadataSourceHealthState::Backpressure
    } else if malformed > 0 {
        MetadataSourceHealthState::ParserError
    } else if skipped > 0 && !has_candidate {
        MetadataSourceHealthState::OversizedInputSkipped
    } else if matches!(
        base,
        MetadataSourceHealthState::RotationDetected
            | MetadataSourceHealthState::CursorResetRequired
    ) {
        base
    } else if has_candidate {
        MetadataSourceHealthState::Active
    } else {
        MetadataSourceHealthState::Idle
    }
}

pub fn degraded_reason_for_health(health: &MetadataSourceHealthState) -> Option<String> {
    match health {
        MetadataSourceHealthState::Backpressure => Some("reader_backpressure".to_string()),
        MetadataSourceHealthState::ParserError => Some("parser_error".to_string()),
        MetadataSourceHealthState::SourceUnavailable => Some("source_unavailable".to_string()),
        MetadataSourceHealthState::CursorResetRequired => Some("cursor_reset_required".to_string()),
        MetadataSourceHealthState::RotationDetected => Some("rotation_detected".to_string()),
        MetadataSourceHealthState::OversizedInputSkipped => {
            Some("oversized_input_skipped".to_string())
        }
        _ => None,
    }
}

pub fn error_category_for_health(health: &MetadataSourceHealthState) -> Option<String> {
    match health {
        MetadataSourceHealthState::Backpressure => Some("backpressure".to_string()),
        MetadataSourceHealthState::ParserError => Some("parser_error".to_string()),
        MetadataSourceHealthState::SourceUnavailable => Some("source_unavailable".to_string()),
        MetadataSourceHealthState::CursorResetRequired => Some("cursor_reset_required".to_string()),
        MetadataSourceHealthState::RotationDetected => Some("rotation_detected".to_string()),
        MetadataSourceHealthState::OversizedInputSkipped => Some("oversized_input".to_string()),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct GenerationStats {
    records: u64,
    bytes: u64,
    skipped: u64,
    malformed: u64,
    backpressure: u64,
}

fn safe_generation_ref(
    source_id: &MetadataWatchSourceId,
    parser_family: &MetadataParserFamily,
    generation_hashes: &[String],
    stats: GenerationStats,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_id.to_string().as_bytes());
    hasher.update(format!("{parser_family:?}").as_bytes());
    for generation_hash in generation_hashes {
        hasher.update(generation_hash.as_bytes());
    }
    hasher.update(stats.records.to_le_bytes());
    hasher.update(stats.bytes.to_le_bytes());
    hasher.update(stats.skipped.to_le_bytes());
    hasher.update(stats.malformed.to_le_bytes());
    hasher.update(stats.backpressure.to_le_bytes());
    format!("reader_generation_{:x}", hasher.finalize())
}

fn generation_hash_for_content(source_id: &MetadataWatchSourceId, content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_id.to_string().as_bytes());
    hasher.update(content.as_bytes());
    hash_digest(hasher)
}

fn hash_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hash_digest(hasher)
}

fn hash_digest(hasher: Sha256) -> String {
    format!("sha256:{:x}", hasher.finalize())
}

fn encode_opaque_cursor(offset: u64) -> String {
    format!("cursor_v1_{offset:016x}")
}

fn decode_opaque_cursor(value: &str) -> Option<u64> {
    let raw = value.strip_prefix("cursor_v1_")?;
    u64::from_str_radix(raw, 16).ok()
}
