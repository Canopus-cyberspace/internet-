use sentinel_contracts::{
    AttributionConfidence, AttributionMethod, AttributionStatus, CollectionMode, DnsAnswer,
    DnsFeatures, DnsObservation, FlowAttribution, FlowRecord, HttpMetadata, HttpMethod, IpAddress,
    NetworkContractError, NetworkDirection, PacketRecord, PrivacyClass, ProcessContext,
    ProcessContextId, QualityScore, SchemaVersion, SessionRecord, Timestamp, TlsObservation,
    TransportProtocol, VisibilityLevel,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const NETWORK_OBSERVATION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkObservationError {
    EmptyField(&'static str),
    MissingPort,
    PrivacyMarker { field: &'static str },
    NotVisiblePlaintext,
    Contract(String),
    InvalidQualityScore,
}

impl fmt::Display for NetworkObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::MissingPort => write!(f, "packet record is missing transport ports"),
            Self::PrivacyMarker { field } => {
                write!(f, "{field} contains a forbidden private-content marker")
            }
            Self::NotVisiblePlaintext => write!(f, "HTTP metadata requires visible plaintext"),
            Self::Contract(error) => write!(f, "network observation contract error: {error}"),
            Self::InvalidQualityScore => write!(f, "quality score is outside valid range"),
        }
    }
}

impl std::error::Error for NetworkObservationError {}

impl From<NetworkContractError> for NetworkObservationError {
    fn from(value: NetworkContractError) -> Self {
        Self::Contract(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowSessionizationInput {
    pub packet_records: Vec<PacketRecord>,
    pub process_context: Option<ProcessContext>,
    pub default_attribution_confidence: AttributionConfidence,
}

impl FlowSessionizationInput {
    pub fn new(packet_records: Vec<PacketRecord>) -> Self {
        Self {
            packet_records,
            process_context: None,
            default_attribution_confidence: AttributionConfidence::Unknown,
        }
    }

    pub fn with_process_context(mut self, process_context: ProcessContext) -> Self {
        self.process_context = Some(process_context);
        if self.default_attribution_confidence == AttributionConfidence::Unknown {
            self.default_attribution_confidence = AttributionConfidence::Low;
        }
        self
    }

    pub fn with_default_attribution_confidence(
        mut self,
        confidence: AttributionConfidence,
    ) -> Self {
        self.default_attribution_confidence = confidence;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowSessionizationOutput {
    pub flows: Vec<FlowRecord>,
    pub sessions: Vec<SessionRecord>,
    pub attributions: Vec<FlowAttribution>,
}

#[derive(Clone, Debug, Default)]
pub struct FlowSessionizer;

impl FlowSessionizer {
    pub fn sessionize(
        &self,
        input: FlowSessionizationInput,
    ) -> Result<FlowSessionizationOutput, NetworkObservationError> {
        let mut flows = Vec::<FlowRecord>::new();
        let mut indices = BTreeMap::<FlowKey, usize>::new();

        for packet in &input.packet_records {
            let key = FlowKey::try_from_packet(packet)?;
            if let Some(index) = indices.get(&key).copied() {
                update_flow_from_packet(&mut flows[index], packet);
                continue;
            }

            let mut flow = FlowRecord::new(
                packet.src_ip,
                key.src_port,
                packet.dst_ip,
                key.dst_port,
                packet.protocol.clone(),
                packet.direction.clone(),
            );
            flow.start_time = packet.timestamp.clone();
            flow.trace_id = packet.trace_id.clone();
            flow.process_ref = input
                .process_context
                .as_ref()
                .map(|process| process.process_context_id.clone());
            flow.attribution_confidence = if flow.process_ref.is_some() {
                input.default_attribution_confidence.clone()
            } else {
                AttributionConfidence::Unknown
            };
            flow.quality_score = quality_score(if packet.flags.malformed { 0.45 } else { 0.9 })?;
            update_flow_from_packet(&mut flow, packet);
            let index = flows.len();
            flows.push(flow);
            indices.insert(key, index);
        }

        let mut sessions = Vec::new();
        for flow in &mut flows {
            finalize_flow_timing(flow);
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
            session.bytes_in = flow.bytes_in;
            session.bytes_out = flow.bytes_out;
            session.packets_in = flow.packets_in;
            session.packets_out = flow.packets_out;
            session.process_ref = flow.process_ref.clone();
            session.attribution_confidence = flow.attribution_confidence.clone();
            session.quality_score = flow.quality_score.clone();
            flow.session_ref = Some(session.session_id.clone());
            sessions.push(session);
        }

        let attributions = match &input.process_context {
            Some(process) => flows
                .iter()
                .map(|flow| flow_attribution_for(flow, process))
                .collect(),
            None => Vec::new(),
        };

        Ok(FlowSessionizationOutput {
            flows,
            sessions,
            attributions,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FlowSessionizationPlugin {
    sessionizer: FlowSessionizer,
}

impl FlowSessionizationPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process(
        &self,
        input: FlowSessionizationInput,
    ) -> Result<FlowSessionizationOutput, NetworkObservationError> {
        self.sessionizer.sessionize(input)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DnsMetadataInput {
    pub flow_ref: Option<sentinel_contracts::FlowId>,
    pub query_name_protected: String,
    pub feature_source_name: Option<String>,
    pub query_type: String,
    pub response_code: Option<String>,
    pub resolver_ip: IpAddress,
    pub client_ip: IpAddress,
    pub timestamp: Timestamp,
    pub answers: Vec<DnsAnswer>,
    pub cname_chain_protected: Vec<String>,
    pub process_ref: Option<ProcessContextId>,
}

#[derive(Clone, Debug, Default)]
pub struct DnsFeatureExtractor;

impl DnsFeatureExtractor {
    pub fn extract(
        &self,
        input: &DnsMetadataInput,
    ) -> Result<DnsFeatures, NetworkObservationError> {
        validate_safe_text("query_name_protected", &input.query_name_protected)?;
        validate_safe_text("query_type", &input.query_type)?;
        if let Some(response_code) = &input.response_code {
            validate_safe_text("response_code", response_code)?;
        }
        for cname in &input.cname_chain_protected {
            validate_safe_text("cname_chain_protected", cname)?;
        }
        if let Some(feature_source_name) = &input.feature_source_name {
            validate_safe_text("feature_source_name", feature_source_name)?;
        }

        let feature_source = input
            .feature_source_name
            .as_deref()
            .unwrap_or(&input.query_name_protected);
        let labels = feature_source
            .split('.')
            .filter(|label| !label.is_empty())
            .collect::<Vec<_>>();
        Ok(DnsFeatures {
            query_length: bounded_u16(feature_source.len()),
            label_count: bounded_u16(labels.len()),
            subdomain_depth: bounded_u16(labels.len().saturating_sub(2)),
            character_entropy: entropy(feature_source),
            answer_count: bounded_u16(input.answers.len()),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsSecurityObservationPlugin {
    extractor: DnsFeatureExtractor,
}

impl DnsSecurityObservationPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(
        &self,
        input: DnsMetadataInput,
    ) -> Result<DnsObservation, NetworkObservationError> {
        let features = self.extractor.extract(&input)?;
        let mut observation = DnsObservation::new(
            input.query_name_protected,
            input.query_type,
            input.resolver_ip,
            input.client_ip,
        )?;
        observation.flow_ref = input.flow_ref;
        observation.response_code = input.response_code;
        observation.timestamp = input.timestamp;
        observation.answers = input.answers;
        observation.cname_chain_protected = input.cname_chain_protected;
        observation.features = features;
        observation.process_ref = input.process_ref;
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = quality_score(0.88)?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TlsMetadataInput {
    pub flow_ref: Option<sentinel_contracts::FlowId>,
    pub timestamp: Timestamp,
    pub sni_protected: Option<String>,
    pub alpn: Vec<String>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub extension_summary_protected: Option<String>,
    pub certificate_fingerprint: Option<String>,
    pub issuer_summary_protected: Option<String>,
    pub san_summary_protected: Option<String>,
    pub valid_not_before: Option<Timestamp>,
    pub valid_not_after: Option<Timestamp>,
    pub process_ref: Option<ProcessContextId>,
}

#[derive(Clone, Debug, Default)]
pub struct TlsFingerprintExtractor;

impl TlsFingerprintExtractor {
    pub fn extract(
        &self,
        input: TlsMetadataInput,
    ) -> Result<TlsObservation, NetworkObservationError> {
        if let Some(sni) = &input.sni_protected {
            validate_safe_text("sni_protected", sni)?;
        }
        for alpn in &input.alpn {
            validate_safe_text("alpn", alpn)?;
        }
        for (field, value) in [
            ("tls_version", &input.tls_version),
            ("cipher_suite", &input.cipher_suite),
            (
                "extension_summary_protected",
                &input.extension_summary_protected,
            ),
            ("certificate_fingerprint", &input.certificate_fingerprint),
            ("issuer_summary_protected", &input.issuer_summary_protected),
            ("san_summary_protected", &input.san_summary_protected),
        ] {
            if let Some(value) = value {
                validate_safe_text(field, value)?;
            }
        }

        let ja3 = pseudo_fingerprint(
            "ja3",
            [
                input.tls_version.as_deref(),
                input.cipher_suite.as_deref(),
                Some(&input.alpn.join(",")),
                input.extension_summary_protected.as_deref(),
            ],
        );
        let mut observation = TlsObservation::new();
        observation.flow_ref = input.flow_ref;
        observation.timestamp = input.timestamp;
        observation.sni_protected = input.sni_protected;
        observation.alpn = input.alpn;
        observation.ja3 = Some(ja3);
        // JA4 is intentionally absent until the extractor implements the real algorithm.
        observation.ja4 = None;
        observation.ja4s = None;
        observation.tls_version = input.tls_version;
        observation.cipher_suite = input.cipher_suite;
        observation.extension_summary_protected = input.extension_summary_protected;
        observation.certificate_fingerprint = input.certificate_fingerprint;
        observation.issuer_summary_protected = input.issuer_summary_protected;
        observation.san_summary_protected = input.san_summary_protected;
        observation.valid_not_before = input.valid_not_before;
        observation.valid_not_after = input.valid_not_after;
        observation.process_ref = input.process_ref;
        observation.privacy_class = PrivacyClass::Internal;
        observation.quality_score = quality_score(0.86)?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, Default)]
pub struct TlsFingerprintPlugin {
    extractor: TlsFingerprintExtractor,
}

impl TlsFingerprintPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(
        &self,
        input: TlsMetadataInput,
    ) -> Result<TlsObservation, NetworkObservationError> {
        self.extractor.extract(input)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpMetadataInput {
    pub flow_ref: Option<sentinel_contracts::FlowId>,
    pub timestamp: Timestamp,
    pub method: HttpMethod,
    pub scheme: Option<String>,
    pub host_protected: Option<String>,
    pub path_visible: Option<String>,
    pub status_code: Option<u16>,
    pub result_label: Option<String>,
    pub request_size_bytes: Option<u64>,
    pub response_size_bytes: Option<u64>,
    pub request_content_length_bytes: Option<u64>,
    pub response_content_length_bytes: Option<u64>,
    pub content_type: Option<String>,
    pub user_agent_family: Option<String>,
    pub waf_action: Option<String>,
    pub waf_rule_id: Option<String>,
    pub waf_attack_class: Option<String>,
    pub visible_plaintext: bool,
    pub process_ref: Option<ProcessContextId>,
}

#[derive(Clone, Debug, Default)]
pub struct HttpMetadataExtractor;

impl HttpMetadataExtractor {
    pub fn extract(
        &self,
        input: HttpMetadataInput,
    ) -> Result<Option<HttpMetadata>, NetworkObservationError> {
        if !input.visible_plaintext {
            return Ok(None);
        }

        let scheme = sanitize_optional("scheme", input.scheme)?;
        let host_protected = sanitize_optional("host_protected", input.host_protected)?;
        let (path_template_protected, sensitive_hint) =
            sanitize_http_path(input.path_visible.as_deref())?;
        let result_label = sanitize_optional("result_label", input.result_label)?;
        let content_type = sanitize_optional("content_type", input.content_type)?;
        let user_agent_family = sanitize_optional("user_agent_family", input.user_agent_family)?;
        let waf_action = sanitize_optional("waf_action", input.waf_action)?;
        let waf_rule_id = sanitize_optional("waf_rule_id", input.waf_rule_id)?;
        let waf_attack_class = sanitize_optional("waf_attack_class", input.waf_attack_class)?;

        let mut metadata = HttpMetadata::new(input.method);
        metadata.flow_ref = input.flow_ref;
        metadata.timestamp = input.timestamp;
        metadata.scheme = scheme;
        metadata.host_protected = host_protected;
        metadata.path_template_protected = path_template_protected;
        metadata.endpoint_fingerprint = endpoint_fingerprint(
            metadata.host_protected.as_deref(),
            metadata.path_template_protected.as_deref(),
        );
        metadata.status_code = input.status_code;
        metadata.status_family = status_family(input.status_code);
        metadata.result_label = result_label;
        metadata.request_size_bytes = input.request_size_bytes;
        metadata.response_size_bytes = input.response_size_bytes;
        metadata.request_content_length_bytes = input.request_content_length_bytes;
        metadata.response_content_length_bytes = input.response_content_length_bytes;
        metadata.upload_download_ratio =
            upload_download_ratio(input.request_size_bytes, input.response_size_bytes);
        metadata.content_type = content_type;
        metadata.user_agent_family = user_agent_family;
        metadata.waf_action = waf_action;
        metadata.waf_rule_id = waf_rule_id;
        metadata.waf_attack_class = waf_attack_class;
        metadata.api_hint = metadata
            .path_template_protected
            .as_ref()
            .map(|_| "http_route_template_present".to_string());
        metadata.sensitive_hint = sensitive_hint;
        metadata.visible_plaintext = true;
        metadata.process_ref = input.process_ref;
        metadata.privacy_class = PrivacyClass::Internal;
        metadata.quality_score = quality_score(0.78)?;
        Ok(Some(metadata))
    }
}

#[derive(Clone, Debug, Default)]
pub struct HttpMetadataPlugin {
    extractor: HttpMetadataExtractor,
}

impl HttpMetadataPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(
        &self,
        input: HttpMetadataInput,
    ) -> Result<Option<HttpMetadata>, NetworkObservationError> {
        self.extractor.extract(input)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    protocol: String,
    direction: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

impl FlowKey {
    fn try_from_packet(packet: &PacketRecord) -> Result<Self, NetworkObservationError> {
        Ok(Self {
            protocol: format!("{:?}", packet.protocol),
            direction: format!("{:?}", packet.direction),
            src_ip: packet.src_ip.to_string(),
            src_port: packet
                .src_port
                .ok_or(NetworkObservationError::MissingPort)?,
            dst_ip: packet.dst_ip.to_string(),
            dst_port: packet
                .dst_port
                .ok_or(NetworkObservationError::MissingPort)?,
        })
    }
}

fn update_flow_from_packet(flow: &mut FlowRecord, packet: &PacketRecord) {
    flow.end_time = Some(packet.timestamp.clone());
    match packet.direction {
        NetworkDirection::Inbound => {
            flow.bytes_in = flow.bytes_in.saturating_add(u64::from(packet.length_bytes));
            flow.packets_in = flow.packets_in.saturating_add(1);
        }
        NetworkDirection::Outbound | NetworkDirection::Lateral | NetworkDirection::Loopback => {
            flow.bytes_out = flow
                .bytes_out
                .saturating_add(u64::from(packet.length_bytes));
            flow.packets_out = flow.packets_out.saturating_add(1);
        }
        NetworkDirection::Unknown => {
            flow.bytes_out = flow
                .bytes_out
                .saturating_add(u64::from(packet.length_bytes));
            flow.packets_out = flow.packets_out.saturating_add(1);
        }
    }
}

fn finalize_flow_timing(flow: &mut FlowRecord) {
    if let Some(end_time) = &flow.end_time {
        let duration = end_time
            .as_datetime()
            .signed_duration_since(*flow.start_time.as_datetime());
        flow.duration_millis = duration.num_milliseconds().try_into().ok();
    }
}

fn flow_attribution_for(flow: &FlowRecord, process: &ProcessContext) -> FlowAttribution {
    let method = match flow.protocol {
        TransportProtocol::Tcp => AttributionMethod::TcpEndpointSnapshot,
        TransportProtocol::Udp => AttributionMethod::UdpEndpointSnapshot,
        _ => AttributionMethod::ConnectionTableCorrelation,
    };
    let mut attribution = FlowAttribution::unknown(flow.flow_id.clone()).with_process(
        process.process_context_id.clone(),
        method,
        flow.attribution_confidence.clone(),
    );
    attribution.os_process_id = Some(process.os_process_id);
    attribution.process_start_time = Some(process.process_start_time.clone());
    attribution.process_path_protected = process.process_path_protected.clone();
    attribution.process_hash = process.process_hash.clone();
    attribution.signer_status = process.signer_status.clone();
    attribution.parent_process_ref = process.parent_process_ref.clone();
    attribution.user_session_ref = process.user_session_ref.clone();
    attribution.local_ip = Some(flow.src_ip);
    attribution.local_port = Some(flow.src_port);
    attribution.remote_ip = Some(flow.dst_ip);
    attribution.remote_port = Some(flow.dst_port);
    attribution.visibility_level = VisibilityLevel::MetadataOnly;
    attribution.collection_mode = CollectionMode::Mock;
    attribution.attribution_status = match attribution.attribution_confidence {
        AttributionConfidence::High => AttributionStatus::Confirmed,
        AttributionConfidence::Medium => AttributionStatus::Probable,
        AttributionConfidence::Low => AttributionStatus::Possible,
        AttributionConfidence::Unknown => AttributionStatus::Unknown,
    };
    attribution.known_limitations = vec![
        "Attribution is derived from metadata correlation.".to_string(),
        "Packet metadata alone does not prove packet-to-process truth.".to_string(),
    ];
    attribution.timestamp = Timestamp::now();
    attribution
}

fn entropy(value: &str) -> Option<f32> {
    if value.is_empty() {
        return None;
    }
    let mut counts = BTreeMap::<char, usize>::new();
    for character in value.chars() {
        *counts.entry(character).or_default() += 1;
    }
    let len = value.chars().count() as f32;
    let entropy = counts.values().fold(0.0_f32, |accumulator, count| {
        let p = *count as f32 / len;
        accumulator - (p * p.log2())
    });
    Some(entropy)
}

fn pseudo_fingerprint<'value>(
    prefix: &str,
    values: impl IntoIterator<Item = Option<&'value str>>,
) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for value in values.into_iter().flatten() {
        for byte in value.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{prefix}-{hash:016x}")
}

fn sanitize_optional(
    field: &'static str,
    value: Option<String>,
) -> Result<Option<String>, NetworkObservationError> {
    value
        .map(|value| {
            validate_safe_text(field, &value)?;
            Ok(value)
        })
        .transpose()
}

fn sanitize_http_path(
    path: Option<&str>,
) -> Result<(Option<String>, Option<String>), NetworkObservationError> {
    let Some(path) = path else {
        return Ok((None, None));
    };
    let stripped = path.split('?').next().unwrap_or_default();
    validate_safe_text("path_template_protected", stripped)?;
    let templated = stripped
        .split('/')
        .map(|segment| {
            if segment.parse::<u64>().is_ok() || looks_like_hex_identifier(segment) {
                "{id}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let hint = (path.contains('?')).then(|| "path detail redacted".to_string());
    Ok((Some(templated), hint))
}

fn upload_download_ratio(request_size: Option<u64>, response_size: Option<u64>) -> Option<f32> {
    match (request_size, response_size) {
        (Some(upload), Some(download)) if download > 0 => Some(upload as f32 / download as f32),
        (Some(upload), Some(0)) if upload > 0 => Some(upload as f32),
        _ => None,
    }
}

fn endpoint_fingerprint(host: Option<&str>, path_template: Option<&str>) -> Option<String> {
    let has_host = host.is_some();
    let has_path = path_template.is_some();
    if !has_host && !has_path {
        return None;
    }

    Some(pseudo_fingerprint(
        "endpoint",
        [host, path_template.filter(|path| !path.is_empty())],
    ))
}

fn status_family(status_code: Option<u16>) -> Option<String> {
    status_code.map(|status_code| format!("{}xx", status_code / 100))
}

fn looks_like_hex_identifier(value: &str) -> bool {
    value.len() >= 12 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), NetworkObservationError> {
    if value.trim().is_empty() {
        return Err(NetworkObservationError::EmptyField(field));
    }
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '/', '='], "_");
    for marker in [
        "raw_packet",
        "packet_bytes",
        "raw_payload",
        "payload",
        "http_body",
        "request_body",
        "response_body",
        "authorization",
        "authorization_header",
        "api_key",
        "cookie",
        "credential",
        "password",
        "private_key",
        "session_token",
        "access_token",
        "refresh_token",
        "token",
        "secret",
        "form_content",
    ] {
        if normalized.contains(marker) {
            return Err(NetworkObservationError::PrivacyMarker { field });
        }
    }
    Ok(())
}

fn bounded_u16(value: usize) -> u16 {
    value.min(u16::MAX as usize) as u16
}

fn quality_score(value: f32) -> Result<QualityScore, NetworkObservationError> {
    QualityScore::new(value).map_err(|_| NetworkObservationError::InvalidQualityScore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_contracts::{CaptureSource, PacketFlags, SignerStatus};

    fn ip(value: &str) -> IpAddress {
        IpAddress::parse_str(value).expect("test IP")
    }

    fn process() -> ProcessContext {
        let mut process = ProcessContext::new(4_240, "test_process");
        process.process_path_protected = Some("pathref_test_process".to_string());
        process.process_hash = Some("sha256_test_process".to_string());
        process.signer_status = SignerStatus::Signed;
        process.visibility_level = VisibilityLevel::MetadataOnly;
        process.collection_mode = CollectionMode::Mock;
        process
    }

    fn packet(protocol: TransportProtocol, dst_port: u16, length: u32) -> PacketRecord {
        let mut packet = PacketRecord::new(
            protocol,
            NetworkDirection::Outbound,
            ip("192.0.2.10"),
            ip("198.51.100.24"),
            length,
        );
        packet.src_port = Some(49_152);
        packet.dst_port = Some(dst_port);
        packet.capture_source = CaptureSource::Mock;
        packet.collection_mode = CollectionMode::Mock;
        packet.visibility_level = VisibilityLevel::MetadataOnly;
        packet.flags = PacketFlags::default();
        packet.trace_id = Some(sentinel_contracts::TraceId::new_v4());
        packet
    }

    #[test]
    fn flow_sessionizer_builds_five_tuple_counts_and_attribution() {
        let process = process();
        let input = FlowSessionizationInput::new(vec![
            packet(TransportProtocol::Tcp, 443, 1_200),
            packet(TransportProtocol::Tcp, 443, 800),
        ])
        .with_process_context(process.clone());
        let output = FlowSessionizationPlugin::new()
            .process(input)
            .expect("flow output");

        assert_eq!(output.flows.len(), 1);
        assert_eq!(output.sessions.len(), 1);
        assert_eq!(output.attributions.len(), 1);
        let flow = &output.flows[0];
        assert_eq!(flow.src_ip, ip("192.0.2.10"));
        assert_eq!(flow.src_port, 49_152);
        assert_eq!(flow.dst_ip, ip("198.51.100.24"));
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.bytes_out, 2_000);
        assert_eq!(flow.packets_out, 2);
        assert_eq!(flow.process_ref, Some(process.process_context_id));
        assert!(flow.session_ref.is_some());
        assert!(flow.quality_score.value() > 0.0);
    }

    #[test]
    fn dns_observation_includes_features_answers_ttl_and_process_ref() {
        let process = process();
        let flow = FlowRecord::new(
            ip("192.0.2.10"),
            53_000,
            ip("203.0.113.53"),
            53,
            TransportProtocol::Udp,
            NetworkDirection::Outbound,
        );
        let input = DnsMetadataInput {
            flow_ref: Some(flow.flow_id.clone()),
            query_name_protected: "beacon.example.test".to_string(),
            feature_source_name: Some("beacon.example.test".to_string()),
            query_type: "A".to_string(),
            response_code: Some("NOERROR".to_string()),
            resolver_ip: flow.dst_ip,
            client_ip: flow.src_ip,
            timestamp: Timestamp::now(),
            answers: vec![DnsAnswer::Ip {
                address: ip("198.51.100.24"),
                ttl_seconds: Some(60),
            }],
            cname_chain_protected: Vec::new(),
            process_ref: Some(process.process_context_id.clone()),
        };
        let observation = DnsSecurityObservationPlugin::new()
            .observe(input)
            .expect("dns observation");

        assert_eq!(observation.query_type, "A");
        assert_eq!(observation.response_code.as_deref(), Some("NOERROR"));
        assert_eq!(observation.features.answer_count, 1);
        assert_eq!(observation.features.subdomain_depth, 1);
        assert!(observation.features.character_entropy.is_some());
        assert_eq!(observation.process_ref, Some(process.process_context_id));
        assert!(matches!(
            observation.answers.first(),
            Some(DnsAnswer::Ip {
                ttl_seconds: Some(60),
                ..
            })
        ));
    }

    #[test]
    fn tls_observation_includes_ja3_certificate_optional_ja4_and_process_ref() {
        let process = process();
        let input = TlsMetadataInput {
            flow_ref: Some(sentinel_contracts::FlowId::new_v4()),
            timestamp: Timestamp::now(),
            sni_protected: Some("beacon.example.test".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            tls_version: Some("tls1.3".to_string()),
            cipher_suite: Some("tls_aes_128_gcm_sha256".to_string()),
            extension_summary_protected: Some("sni,alpn,key_share".to_string()),
            certificate_fingerprint: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            issuer_summary_protected: Some("fixture issuer".to_string()),
            san_summary_protected: Some("fixture SAN summary".to_string()),
            valid_not_before: Some(Timestamp::now()),
            valid_not_after: Some(Timestamp::now()),
            process_ref: Some(process.process_context_id.clone()),
        };
        let observation = TlsFingerprintPlugin::new()
            .observe(input)
            .expect("tls observation");

        assert_eq!(
            observation.sni_protected.as_deref(),
            Some("beacon.example.test")
        );
        assert!(!observation.alpn.is_empty());
        assert!(observation.ja3.is_some());
        assert!(observation.ja4.is_none());
        assert!(observation.ja4s.is_none());
        assert!(observation.certificate_fingerprint.is_some());
        assert_eq!(observation.process_ref, Some(process.process_context_id));
    }

    #[test]
    fn http_metadata_is_optional_visible_plaintext_and_redacts_query() {
        let process = process();
        let input = HttpMetadataInput {
            flow_ref: Some(sentinel_contracts::FlowId::new_v4()),
            timestamp: Timestamp::now(),
            method: HttpMethod::Post,
            scheme: Some("https".to_string()),
            host_protected: Some("api.example.test".to_string()),
            path_visible: Some("/v1/upload/12345?case=local".to_string()),
            status_code: Some(200),
            result_label: Some("upstream_response_observed".to_string()),
            request_size_bytes: Some(2_048),
            response_size_bytes: Some(512),
            request_content_length_bytes: Some(2_048),
            response_content_length_bytes: Some(512),
            content_type: Some("application/json".to_string()),
            user_agent_family: Some("fixture-client".to_string()),
            waf_action: None,
            waf_rule_id: None,
            waf_attack_class: None,
            visible_plaintext: true,
            process_ref: Some(process.process_context_id.clone()),
        };
        let metadata = HttpMetadataPlugin::new()
            .observe(input)
            .expect("http metadata")
            .expect("visible plaintext produces metadata");
        let serialized = serde_json::to_string(&metadata).expect("serialize metadata");

        assert_eq!(metadata.scheme.as_deref(), Some("https"));
        assert_eq!(metadata.host_protected.as_deref(), Some("api.example.test"));
        assert_eq!(
            metadata.path_template_protected.as_deref(),
            Some("/v1/upload/{id}")
        );
        assert!(metadata.endpoint_fingerprint.is_some());
        assert_eq!(metadata.status_family.as_deref(), Some("2xx"));
        assert_eq!(
            metadata.result_label.as_deref(),
            Some("upstream_response_observed")
        );
        assert_eq!(
            metadata.sensitive_hint.as_deref(),
            Some("path detail redacted")
        );
        assert!(metadata.upload_download_ratio.is_some());
        assert_eq!(
            metadata.api_hint.as_deref(),
            Some("http_route_template_present")
        );
        assert_eq!(metadata.process_ref, Some(process.process_context_id));
        assert!(!serialized.contains("case=local"));
        assert!(!serialized.contains("authorization"));
        assert!(!serialized.contains("cookie"));
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn http_metadata_is_absent_when_plaintext_not_visible() {
        let input = HttpMetadataInput {
            flow_ref: None,
            timestamp: Timestamp::now(),
            method: HttpMethod::Get,
            scheme: None,
            host_protected: None,
            path_visible: None,
            status_code: None,
            result_label: None,
            request_size_bytes: None,
            response_size_bytes: None,
            request_content_length_bytes: None,
            response_content_length_bytes: None,
            content_type: None,
            user_agent_family: None,
            waf_action: None,
            waf_rule_id: None,
            waf_attack_class: None,
            visible_plaintext: false,
            process_ref: None,
        };

        assert!(HttpMetadataPlugin::new()
            .observe(input)
            .expect("no error")
            .is_none());
    }

    #[test]
    fn sensitive_http_path_marker_is_rejected() {
        let input = HttpMetadataInput {
            flow_ref: None,
            timestamp: Timestamp::now(),
            method: HttpMethod::Get,
            scheme: Some("http".to_string()),
            host_protected: Some("api.example.test".to_string()),
            path_visible: Some("/api_key/private".to_string()),
            status_code: None,
            result_label: None,
            request_size_bytes: None,
            response_size_bytes: None,
            request_content_length_bytes: None,
            response_content_length_bytes: None,
            content_type: None,
            user_agent_family: None,
            waf_action: None,
            waf_rule_id: None,
            waf_attack_class: None,
            visible_plaintext: true,
            process_ref: None,
        };

        assert_eq!(
            HttpMetadataPlugin::new().observe(input),
            Err(NetworkObservationError::PrivacyMarker {
                field: "path_template_protected"
            })
        );
    }

    #[test]
    fn http_metadata_preserves_bounded_waf_fields() {
        let input = HttpMetadataInput {
            flow_ref: Some(sentinel_contracts::FlowId::new_v4()),
            timestamp: Timestamp::now(),
            method: HttpMethod::Get,
            scheme: Some("https".to_string()),
            host_protected: Some("api.example.test".to_string()),
            path_visible: Some("/blocked/123".to_string()),
            status_code: Some(403),
            result_label: Some("blocked".to_string()),
            request_size_bytes: Some(256),
            response_size_bytes: Some(64),
            request_content_length_bytes: Some(0),
            response_content_length_bytes: Some(64),
            content_type: Some("application/json".to_string()),
            user_agent_family: Some("other".to_string()),
            waf_action: Some("blocked".to_string()),
            waf_rule_id: Some("managed_rule_942100".to_string()),
            waf_attack_class: Some("sql_injection".to_string()),
            visible_plaintext: true,
            process_ref: None,
        };
        let metadata = HttpMetadataPlugin::new()
            .observe(input)
            .expect("http metadata")
            .expect("metadata emitted");

        assert_eq!(metadata.waf_action.as_deref(), Some("blocked"));
        assert_eq!(metadata.waf_rule_id.as_deref(), Some("managed_rule_942100"));
        assert_eq!(metadata.waf_attack_class.as_deref(), Some("sql_injection"));
        assert_eq!(metadata.status_family.as_deref(), Some("4xx"));
    }
}
