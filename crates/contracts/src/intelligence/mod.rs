use crate::common::{
    EntityRef, IntelligenceRecordId, PrivacyClass, QualityScore, RiskHintId, SchemaVersion,
    Timestamp,
};
use crate::network::IpAddress;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const INTELLIGENCE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0, 0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntelligenceContractError {
    EmptyField(&'static str),
    EmptyRecords,
    OnlineLookupDisabled,
    SignatureFailure,
    LocalIndexFailure,
    LocalPackReadFailure,
    LocalPackParseFailure,
    UnsupportedSignatureAlgorithm,
    BoundaryViolation(&'static str),
    SensitiveMarker { field: &'static str },
    InvalidConfidence,
}

impl fmt::Display for IntelligenceContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::EmptyRecords => write!(f, "at least one intelligence record is required"),
            Self::OnlineLookupDisabled => {
                write!(f, "online intelligence lookup is disabled by default")
            }
            Self::SignatureFailure => write!(f, "local intelligence pack signature failed"),
            Self::LocalIndexFailure => write!(f, "local intelligence index is unavailable"),
            Self::LocalPackReadFailure => write!(f, "local intelligence pack could not be read"),
            Self::LocalPackParseFailure => write!(f, "local intelligence pack could not be parsed"),
            Self::UnsupportedSignatureAlgorithm => {
                write!(
                    f,
                    "local intelligence pack signature algorithm is unsupported"
                )
            }
            Self::BoundaryViolation(field) => {
                write!(f, "intelligence boundary violation: {field}")
            }
            Self::SensitiveMarker { field } => {
                write!(f, "{field} contains a forbidden sensitive marker")
            }
            Self::InvalidConfidence => write!(f, "intelligence confidence is invalid"),
        }
    }
}

impl std::error::Error for IntelligenceContractError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Domain,
    Ip,
    Asn,
    CertificateFingerprint,
    UrlPatternRedacted,
    CloudRange,
    ProcessHash,
    Ioc,
    AllowlistEntry,
    BlocklistEntry,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceSourceClass {
    BundledLocal,
    SignedLocalUpdate,
    UserImportedIoc,
    UserAllowlist,
    UserBlocklist,
    CommercialFuture,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceLicenseClass {
    RedistributableFixture,
    LocalUserProvided,
    InternalMetadata,
    CommercialRestricted,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceExportPolicy {
    AllowRedactedSummary,
    LocalOnly,
    LicenseRestricted,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceLookupStatus {
    Hit,
    Miss,
    StaleHit,
    OnlineLookupDisabled,
    SignatureRejected,
    LocalIndexUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligencePackStatus {
    Active,
    Stale,
    SignatureFailure,
    LocalIndexFailure,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntelligenceSource {
    pub source_id: String,
    pub source_class: IntelligenceSourceClass,
    pub provenance: String,
    pub version: String,
    pub license_class: IntelligenceLicenseClass,
    pub privacy_class: PrivacyClass,
    pub export_policy: IntelligenceExportPolicy,
}

impl IntelligenceSource {
    pub fn new(
        source_id: impl Into<String>,
        source_class: IntelligenceSourceClass,
        provenance: impl Into<String>,
        version: impl Into<String>,
        license_class: IntelligenceLicenseClass,
        privacy_class: PrivacyClass,
        export_policy: IntelligenceExportPolicy,
    ) -> Result<Self, IntelligenceContractError> {
        let source = Self {
            source_id: require_safe_text("source_id", source_id.into())?,
            source_class,
            provenance: require_safe_text("provenance", provenance.into())?,
            version: require_safe_text("version", version.into())?,
            license_class,
            privacy_class,
            export_policy,
        };
        Ok(source)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntelligenceRecord {
    pub record_id: IntelligenceRecordId,
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub source_id: String,
    pub source_class: IntelligenceSourceClass,
    pub provenance: String,
    pub version: String,
    pub retrieved_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub confidence: QualityScore,
    pub license_class: IntelligenceLicenseClass,
    pub privacy_class: PrivacyClass,
    pub export_policy: IntelligenceExportPolicy,
    pub summary_redacted: String,
    pub labels: Vec<String>,
    pub schema_version: SchemaVersion,
}

impl IntelligenceRecord {
    pub fn new(
        indicator_type: IndicatorType,
        indicator: impl Into<String>,
        source: &IntelligenceSource,
        summary_redacted: impl Into<String>,
    ) -> Result<Self, IntelligenceContractError> {
        Ok(Self {
            record_id: IntelligenceRecordId::new_v4(),
            indicator: require_safe_text("indicator", indicator.into())?,
            indicator_type,
            source_id: source.source_id.clone(),
            source_class: source.source_class.clone(),
            provenance: source.provenance.clone(),
            version: source.version.clone(),
            retrieved_at: Timestamp::now(),
            expires_at: None,
            confidence: QualityScore::default(),
            license_class: source.license_class.clone(),
            privacy_class: source.privacy_class.clone(),
            export_policy: source.export_policy.clone(),
            summary_redacted: require_safe_text("summary_redacted", summary_redacted.into())?,
            labels: Vec::new(),
            schema_version: INTELLIGENCE_SCHEMA_VERSION,
        })
    }

    pub fn with_retrieved_at(mut self, retrieved_at: Timestamp) -> Self {
        self.retrieved_at = retrieved_at;
        self
    }

    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_confidence(mut self, confidence: QualityScore) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    pub fn is_stale_at(&self, now: &Timestamp) -> bool {
        self.expires_at
            .as_ref()
            .is_some_and(|expires_at| expires_at <= now)
    }

    pub fn effective_confidence_at(
        &self,
        now: &Timestamp,
    ) -> Result<QualityScore, IntelligenceContractError> {
        if self.is_stale_at(now) {
            QualityScore::new(self.confidence.value() * 0.5)
                .map_err(|_| IntelligenceContractError::InvalidConfidence)
        } else {
            Ok(self.confidence.clone())
        }
    }

    pub fn validate(&self) -> Result<(), IntelligenceContractError> {
        if self.schema_version != INTELLIGENCE_SCHEMA_VERSION {
            return Err(IntelligenceContractError::BoundaryViolation(
                "unsupported intelligence schema version",
            ));
        }
        validate_safe_text("indicator", &self.indicator)?;
        validate_safe_text("source_id", &self.source_id)?;
        validate_safe_text("provenance", &self.provenance)?;
        validate_safe_text("version", &self.version)?;
        validate_safe_text("summary_redacted", &self.summary_redacted)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskHint {
    pub risk_hint_id: RiskHintId,
    pub hint_type: String,
    pub summary_redacted: String,
    pub risk_delta: f32,
    pub confidence: QualityScore,
    pub entity_ref: Option<EntityRef>,
    pub source_record_refs: Vec<IntelligenceRecordId>,
    pub evidence_input_only: bool,
    pub creates_alert: bool,
    pub creates_incident: bool,
    pub executes_response: bool,
    pub privacy_class: PrivacyClass,
    pub timestamp: Timestamp,
}

impl RiskHint {
    pub fn new(
        hint_type: impl Into<String>,
        summary_redacted: impl Into<String>,
        source_record_refs: Vec<IntelligenceRecordId>,
    ) -> Result<Self, IntelligenceContractError> {
        if source_record_refs.is_empty() {
            return Err(IntelligenceContractError::EmptyRecords);
        }
        Ok(Self {
            risk_hint_id: RiskHintId::new_v4(),
            hint_type: require_safe_text("hint_type", hint_type.into())?,
            summary_redacted: require_safe_text("summary_redacted", summary_redacted.into())?,
            risk_delta: 0.0,
            confidence: QualityScore::default(),
            entity_ref: None,
            source_record_refs,
            evidence_input_only: true,
            creates_alert: false,
            creates_incident: false,
            executes_response: false,
            privacy_class: PrivacyClass::Internal,
            timestamp: Timestamp::now(),
        })
    }

    pub fn with_risk_delta(mut self, risk_delta: f32) -> Self {
        self.risk_delta = risk_delta;
        self
    }

    pub fn with_confidence(mut self, confidence: QualityScore) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn validate_boundary(&self) -> Result<(), IntelligenceContractError> {
        validate_safe_text("hint_type", &self.hint_type)?;
        validate_safe_text("summary_redacted", &self.summary_redacted)?;
        if !self.evidence_input_only {
            return Err(IntelligenceContractError::BoundaryViolation(
                "risk_hint must be evidence input only",
            ));
        }
        if self.creates_alert {
            return Err(IntelligenceContractError::BoundaryViolation(
                "intelligence hit cannot create alert",
            ));
        }
        if self.creates_incident {
            return Err(IntelligenceContractError::BoundaryViolation(
                "intelligence hit cannot create incident",
            ));
        }
        if self.executes_response {
            return Err(IntelligenceContractError::BoundaryViolation(
                "intelligence hit cannot execute response",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalIntelligencePack {
    pub pack_id: String,
    pub display_name: String,
    pub source: IntelligenceSource,
    pub records: Vec<IntelligenceRecord>,
    pub status: IntelligencePackStatus,
    pub signature_verified: bool,
    pub local_index_available: bool,
    pub online_lookup_enabled: bool,
    pub loaded_at: Timestamp,
    pub retrieved_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub privacy_class: PrivacyClass,
    pub labels: Vec<String>,
    pub schema_version: SchemaVersion,
}

impl LocalIntelligencePack {
    pub fn new(
        pack_id: impl Into<String>,
        display_name: impl Into<String>,
        source: IntelligenceSource,
        records: Vec<IntelligenceRecord>,
    ) -> Result<Self, IntelligenceContractError> {
        if records.is_empty() {
            return Err(IntelligenceContractError::EmptyRecords);
        }
        let now = Timestamp::now();
        let pack = Self {
            pack_id: require_safe_text("pack_id", pack_id.into())?,
            display_name: require_safe_text("display_name", display_name.into())?,
            source,
            records,
            status: IntelligencePackStatus::Active,
            signature_verified: true,
            local_index_available: true,
            online_lookup_enabled: false,
            loaded_at: now.clone(),
            retrieved_at: now,
            expires_at: None,
            privacy_class: PrivacyClass::Internal,
            labels: Vec::new(),
            schema_version: INTELLIGENCE_SCHEMA_VERSION,
        };
        pack.validate()?;
        Ok(pack)
    }

    pub fn with_status(mut self, status: IntelligencePackStatus) -> Self {
        match status {
            IntelligencePackStatus::Active => {
                self.signature_verified = true;
                self.local_index_available = true;
            }
            IntelligencePackStatus::Stale => {
                self.signature_verified = true;
                self.local_index_available = true;
            }
            IntelligencePackStatus::SignatureFailure => {
                self.signature_verified = false;
                self.local_index_available = true;
            }
            IntelligencePackStatus::LocalIndexFailure => {
                self.signature_verified = true;
                self.local_index_available = false;
            }
        }
        self.status = status;
        self
    }

    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    pub fn validate(&self) -> Result<(), IntelligenceContractError> {
        if self.schema_version != INTELLIGENCE_SCHEMA_VERSION {
            return Err(IntelligenceContractError::BoundaryViolation(
                "unsupported local intelligence pack schema version",
            ));
        }
        validate_safe_text("pack_id", &self.pack_id)?;
        validate_safe_text("display_name", &self.display_name)?;
        if self.online_lookup_enabled {
            return Err(IntelligenceContractError::OnlineLookupDisabled);
        }
        if self.records.is_empty() {
            return Err(IntelligenceContractError::EmptyRecords);
        }
        for record in &self.records {
            record.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DomainContext {
    pub domain_protected: String,
    pub tld_protected: Option<String>,
    pub suspicious_tld: bool,
    pub allowlisted: bool,
    pub blocklisted: bool,
    pub user_ioc_match: bool,
    pub lexical_score: QualityScore,
    pub lookup_status: IntelligenceLookupStatus,
    pub records: Vec<IntelligenceRecord>,
    pub risk_hints: Vec<RiskHint>,
    pub confidence: QualityScore,
    pub retrieved_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub privacy_class: PrivacyClass,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpContext {
    pub ip: IpAddress,
    pub asn: Option<u32>,
    pub asn_name_protected: Option<String>,
    pub cloud_provider_protected: Option<String>,
    pub risky_asn: bool,
    pub allowlisted: bool,
    pub blocklisted: bool,
    pub user_ioc_match: bool,
    pub lookup_status: IntelligenceLookupStatus,
    pub records: Vec<IntelligenceRecord>,
    pub risk_hints: Vec<RiskHint>,
    pub confidence: QualityScore,
    pub retrieved_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub privacy_class: PrivacyClass,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CloudContext {
    pub range_protected: String,
    pub provider_protected: String,
    pub service_protected: Option<String>,
    pub region_protected: Option<String>,
    pub object_storage_hint: bool,
    pub lookup_status: IntelligenceLookupStatus,
    pub records: Vec<IntelligenceRecord>,
    pub risk_hints: Vec<RiskHint>,
    pub confidence: QualityScore,
    pub retrieved_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub privacy_class: PrivacyClass,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CertificateContext {
    pub fingerprint_protected: String,
    pub issuer_summary_protected: Option<String>,
    pub self_signed_hint: bool,
    pub suspicious_issuer_hint: bool,
    pub lookup_status: IntelligenceLookupStatus,
    pub records: Vec<IntelligenceRecord>,
    pub risk_hints: Vec<RiskHint>,
    pub confidence: QualityScore,
    pub retrieved_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub privacy_class: PrivacyClass,
}

pub trait IntelligenceProvider {
    fn local_pack(&self) -> &LocalIntelligencePack;
    fn online_lookup_enabled(&self) -> bool {
        self.local_pack().online_lookup_enabled
    }
    fn lookup_domain(
        &self,
        domain_protected: &str,
    ) -> Result<DomainContext, IntelligenceContractError>;
    fn lookup_ip(&self, ip: &IpAddress) -> Result<IpContext, IntelligenceContractError>;
    fn lookup_asn(&self, asn: u32) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError>;
    fn lookup_cloud_range(&self, ip: &IpAddress)
        -> Result<CloudContext, IntelligenceContractError>;
    fn lookup_certificate_fingerprint(
        &self,
        fingerprint_protected: &str,
    ) -> Result<CertificateContext, IntelligenceContractError>;
    fn lookup_allowlist(
        &self,
        indicator_type: IndicatorType,
        indicator_protected: &str,
    ) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError>;
    fn lookup_blocklist(
        &self,
        indicator_type: IndicatorType,
        indicator_protected: &str,
    ) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError>;
    fn lookup_user_ioc(
        &self,
        indicator_type: IndicatorType,
        indicator_protected: &str,
    ) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError>;
}

pub fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), IntelligenceContractError> {
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
        "raw_command_line",
    ] {
        if normalized.contains(marker) {
            return Err(IntelligenceContractError::SensitiveMarker { field });
        }
    }
    Ok(())
}

fn require_safe_text(
    field: &'static str,
    value: String,
) -> Result<String, IntelligenceContractError> {
    if value.trim().is_empty() {
        return Err(IntelligenceContractError::EmptyField(field));
    }
    validate_safe_text(field, &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn source() -> IntelligenceSource {
        IntelligenceSource::new(
            "fixture-local-intel",
            IntelligenceSourceClass::BundledLocal,
            "bundled fixture data",
            "2026.06.01",
            IntelligenceLicenseClass::RedistributableFixture,
            PrivacyClass::Internal,
            IntelligenceExportPolicy::AllowRedactedSummary,
        )
        .expect("source")
    }

    #[test]
    fn intelligence_record_carries_required_provenance_and_policy() {
        let source = source();
        let record = IntelligenceRecord::new(
            IndicatorType::Domain,
            "beacon.example.test",
            &source,
            "fixture domain context",
        )
        .expect("record")
        .with_expires_at(Timestamp::from_datetime(Utc::now() + Duration::days(30)))
        .with_confidence(QualityScore::new(0.8).expect("confidence"));

        assert_eq!(record.source_id, "fixture-local-intel");
        assert_eq!(record.source_class, IntelligenceSourceClass::BundledLocal);
        assert_eq!(
            record.license_class,
            IntelligenceLicenseClass::RedistributableFixture
        );
        assert_eq!(
            record.export_policy,
            IntelligenceExportPolicy::AllowRedactedSummary
        );
        assert!(record.expires_at.is_some());
        assert!(record.validate().is_ok());
    }

    #[test]
    fn stale_record_reduces_confidence_without_failing() {
        let source = source();
        let record = IntelligenceRecord::new(
            IndicatorType::Ip,
            "198.51.100.24",
            &source,
            "fixture stale IP context",
        )
        .expect("record")
        .with_expires_at(Timestamp::from_datetime(Utc::now() - Duration::days(1)))
        .with_confidence(QualityScore::new(0.8).expect("confidence"));
        let now = Timestamp::now();

        assert!(record.is_stale_at(&now));
        assert_eq!(
            record.effective_confidence_at(&now).expect("confidence"),
            QualityScore::new(0.4).expect("reduced confidence")
        );
    }

    #[test]
    fn risk_hint_is_context_only_and_cannot_promote_directly() {
        let mut hint = RiskHint::new(
            "domain_reputation_hint",
            "fixture risk context",
            vec![IntelligenceRecordId::new_v4()],
        )
        .expect("hint");

        assert!(hint.validate_boundary().is_ok());
        hint.creates_alert = true;
        assert_eq!(
            hint.validate_boundary(),
            Err(IntelligenceContractError::BoundaryViolation(
                "intelligence hit cannot create alert"
            ))
        );
    }

    #[test]
    fn local_pack_rejects_online_lookup() {
        let source = source();
        let record = IntelligenceRecord::new(
            IndicatorType::Domain,
            "beacon.example.test",
            &source,
            "fixture domain context",
        )
        .expect("record");
        let mut pack =
            LocalIntelligencePack::new("fixture-pack", "Fixture Pack", source, vec![record])
                .expect("pack");

        pack.online_lookup_enabled = true;

        assert_eq!(
            pack.validate(),
            Err(IntelligenceContractError::OnlineLookupDisabled)
        );
    }

    #[test]
    fn sensitive_markers_are_rejected() {
        let source = source();
        let error = IntelligenceRecord::new(
            IndicatorType::Ioc,
            "session_token=abc",
            &source,
            "bad fixture",
        )
        .expect_err("sensitive marker rejected");

        assert_eq!(
            error,
            IntelligenceContractError::SensitiveMarker { field: "indicator" }
        );
    }
}
