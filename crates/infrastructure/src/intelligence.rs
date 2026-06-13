use chrono::{Duration, Utc};
use sentinel_contracts::{
    validate_safe_text, CertificateContext, CloudContext, DomainContext, IndicatorType,
    IntelligenceContractError, IntelligenceExportPolicy, IntelligenceLicenseClass,
    IntelligenceLookupStatus, IntelligencePackStatus, IntelligenceProvider, IntelligenceRecord,
    IntelligenceSource, IntelligenceSourceClass, IpAddress, IpContext, LocalIntelligencePack,
    PrivacyClass, QualityScore, RiskHint, Timestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

pub const DEMO_ONLY_LABEL: &str = "DEMO_ONLY";
pub const LOCAL_FILE_LABEL: &str = "LOCAL_FILE";
pub const CSV_IMPORT_LABEL: &str = "CSV_IMPORT";
pub const SIGNED_LOCAL_UPDATE_LABEL: &str = "SIGNED_LOCAL_UPDATE";
pub const OFFLINE_INTELLIGENCE_SUCCESSOR_TASK: &str =
    "public-key signed offline intelligence update workflow and index refresh";
const SIGNATURE_ALGORITHM_SHA256: &str = "sha256";

#[derive(Clone, Debug)]
pub struct OfflineLocalIntelligenceProvider {
    pack: LocalIntelligencePack,
    index: LocalIntelligenceIndex,
}

impl OfflineLocalIntelligenceProvider {
    pub fn new() -> Result<Self, IntelligenceContractError> {
        Self::demo()
    }

    pub fn demo() -> Result<Self, IntelligenceContractError> {
        Self::demo_with_status(IntelligencePackStatus::Active)
    }

    pub fn stale_demo() -> Result<Self, IntelligenceContractError> {
        Self::demo_with_status(IntelligencePackStatus::Stale)
    }

    pub fn signature_failure_demo() -> Result<Self, IntelligenceContractError> {
        Self::demo_with_status(IntelligencePackStatus::SignatureFailure)
    }

    pub fn local_index_failure_demo() -> Result<Self, IntelligenceContractError> {
        Self::demo_with_status(IntelligencePackStatus::LocalIndexFailure)
    }

    pub fn from_pack(pack: LocalIntelligencePack) -> Result<Self, IntelligenceContractError> {
        pack.validate()?;
        if pack.online_lookup_enabled {
            return Err(IntelligenceContractError::OnlineLookupDisabled);
        }

        let index = LocalIntelligenceIndex::build(&pack)?;
        Ok(Self { pack, index })
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, IntelligenceContractError> {
        let contents = fs::read_to_string(path)
            .map_err(|_| IntelligenceContractError::LocalPackReadFailure)?;
        let file: LocalIntelligencePackFile = serde_json::from_str(&contents)
            .map_err(|_| IntelligenceContractError::LocalPackParseFailure)?;
        Self::from_pack_file(file)
    }

    pub fn from_csv_file(path: impl AsRef<Path>) -> Result<Self, IntelligenceContractError> {
        let contents = fs::read_to_string(path)
            .map_err(|_| IntelligenceContractError::LocalPackReadFailure)?;
        Self::from_csv_text(&contents)
    }

    pub fn successor_task(&self) -> &'static str {
        OFFLINE_INTELLIGENCE_SUCCESSOR_TASK
    }

    fn demo_with_status(status: IntelligencePackStatus) -> Result<Self, IntelligenceContractError> {
        let source = demo_source()?;
        let mut records = demo_records(&source, &status)?;
        let expires_at = match status {
            IntelligencePackStatus::Stale => past_days(1),
            _ => future_days(30),
        };
        for record in &mut records {
            record.expires_at = Some(expires_at.clone());
        }

        let pack = LocalIntelligencePack::new(
            "demo-local-intelligence-pack",
            "Offline Local Intelligence Demo Pack",
            source,
            records,
        )?
        .with_status(status)
        .with_expires_at(expires_at)
        .with_labels(demo_labels());

        Self::from_pack(pack)
    }

    fn from_pack_file(file: LocalIntelligencePackFile) -> Result<Self, IntelligenceContractError> {
        let signature_verified = verify_pack_file_signature(&file)?;
        let source = file.source.to_source()?;
        let expires_at = file.expires_at.clone();
        let retrieved_at = file.retrieved_at.clone().unwrap_or_else(Timestamp::now);
        let mut records = Vec::new();

        for record_file in file.records {
            let record_source = record_file
                .source
                .as_ref()
                .map(LocalIntelligenceSourceFile::to_source)
                .transpose()?
                .unwrap_or_else(|| source.clone());
            records.push(record_from_file(
                record_file,
                &record_source,
                &retrieved_at,
                expires_at.clone(),
                &file.labels,
                signature_verified,
            )?);
        }

        let mut pack =
            LocalIntelligencePack::new(file.pack_id, file.display_name, source, records)?
                .with_status(effective_file_status(file.status, expires_at.as_ref()))
                .with_labels(pack_file_labels(&file.labels, signature_verified));
        pack.retrieved_at = retrieved_at;
        pack.expires_at = expires_at;
        pack.signature_verified = signature_verified;
        Self::from_pack(pack)
    }

    fn from_csv_text(contents: &str) -> Result<Self, IntelligenceContractError> {
        let retrieved_at = Timestamp::now();
        let pack_source = csv_user_ioc_source()?;
        let rows = parse_csv(contents)?;
        let (headers, data_rows) = rows
            .split_first()
            .ok_or(IntelligenceContractError::LocalPackParseFailure)?;
        let header = CsvHeader::parse(headers)?;
        let mut records = Vec::new();
        let pack_labels = vec![CSV_IMPORT_LABEL.to_string()];

        for row in data_rows {
            if row.iter().all(|field| field.trim().is_empty()) {
                continue;
            }

            let record_file = header.record_file(row)?;
            let record_source = csv_source_for_indicator(&record_file.indicator_type)?;
            records.push(record_from_file(
                record_file,
                &record_source,
                &retrieved_at,
                None,
                &pack_labels,
                false,
            )?);
        }

        let mut pack = LocalIntelligencePack::new(
            "user-imported-csv-ioc-pack",
            "User Imported CSV IOC Pack",
            pack_source,
            records,
        )?
        .with_status(IntelligencePackStatus::Active)
        .with_labels(pack_file_labels(&pack_labels, false));
        pack.retrieved_at = retrieved_at;
        pack.signature_verified = false;
        Self::from_pack(pack)
    }

    fn ensure_local_available(&self) -> Result<(), IntelligenceContractError> {
        if self.pack.online_lookup_enabled {
            return Err(IntelligenceContractError::OnlineLookupDisabled);
        }
        match self.pack.status {
            IntelligencePackStatus::SignatureFailure => {
                Err(IntelligenceContractError::SignatureFailure)
            }
            IntelligencePackStatus::LocalIndexFailure => {
                Err(IntelligenceContractError::LocalIndexFailure)
            }
            IntelligencePackStatus::Active | IntelligencePackStatus::Stale => Ok(()),
        }
    }

    fn records_for_indicator(
        &self,
        indicator_type: IndicatorType,
        indicator: &str,
    ) -> Vec<IntelligenceRecord> {
        self.index
            .exact_records(indicator_type, indicator)
            .cloned()
            .collect()
    }

    fn records_for_domain(&self, domain: &str) -> Vec<IntelligenceRecord> {
        let mut records = Vec::new();
        for record in &self.pack.records {
            if matches!(
                record.indicator_type,
                IndicatorType::Domain
                    | IndicatorType::AllowlistEntry
                    | IndicatorType::BlocklistEntry
                    | IndicatorType::Ioc
            ) && domain_matches(&record.indicator, domain)
            {
                records.push(record.clone());
            }
        }
        records
    }

    fn records_for_ip(&self, ip: &IpAddress) -> Vec<IntelligenceRecord> {
        let ip_text = ip.to_string();
        let mut records = self.records_for_indicator(IndicatorType::Ip, &ip_text);
        records.extend(
            self.index
                .exact_records(IndicatorType::AllowlistEntry, &ip_text)
                .cloned(),
        );
        records.extend(
            self.index
                .exact_records(IndicatorType::BlocklistEntry, &ip_text)
                .cloned(),
        );
        records.extend(
            self.index
                .exact_records(IndicatorType::Ioc, &ip_text)
                .cloned(),
        );
        records.extend(
            self.index
                .matching_cloud_ranges(ip)
                .into_iter()
                .map(|entry| entry.record.clone()),
        );
        records
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalIntelligencePackFile {
    pack_id: String,
    display_name: String,
    source: LocalIntelligenceSourceFile,
    records: Vec<LocalIntelligenceRecordFile>,
    #[serde(default)]
    status: Option<IntelligencePackStatus>,
    #[serde(default)]
    retrieved_at: Option<Timestamp>,
    #[serde(default)]
    expires_at: Option<Timestamp>,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    signature: Option<LocalIntelligencePackSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalIntelligenceSourceFile {
    source_id: String,
    source_class: IntelligenceSourceClass,
    provenance: String,
    version: String,
    license_class: IntelligenceLicenseClass,
    privacy_class: PrivacyClass,
    export_policy: IntelligenceExportPolicy,
}

impl LocalIntelligenceSourceFile {
    fn to_source(&self) -> Result<IntelligenceSource, IntelligenceContractError> {
        IntelligenceSource::new(
            &self.source_id,
            self.source_class.clone(),
            &self.provenance,
            &self.version,
            self.license_class.clone(),
            self.privacy_class.clone(),
            self.export_policy.clone(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalIntelligenceRecordFile {
    indicator_type: IndicatorType,
    indicator: String,
    summary_redacted: String,
    #[serde(default)]
    confidence: Option<f32>,
    #[serde(default)]
    retrieved_at: Option<Timestamp>,
    #[serde(default)]
    expires_at: Option<Timestamp>,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    source: Option<LocalIntelligenceSourceFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalIntelligencePackSignature {
    algorithm: String,
    records_sha256: String,
}

struct CsvHeader {
    column_count: usize,
    indicator_type: usize,
    indicator: usize,
    summary_redacted: usize,
    confidence: Option<usize>,
    labels: Option<usize>,
}

impl CsvHeader {
    fn parse(headers: &[String]) -> Result<Self, IntelligenceContractError> {
        let indicator_type = required_csv_column(headers, "indicator_type")?;
        let indicator = required_csv_column(headers, "indicator")?;
        let summary_redacted = required_csv_column(headers, "summary_redacted")?;
        Ok(Self {
            column_count: headers.len(),
            indicator_type,
            indicator,
            summary_redacted,
            confidence: csv_column(headers, "confidence"),
            labels: csv_column(headers, "labels"),
        })
    }

    fn record_file(
        &self,
        row: &[String],
    ) -> Result<LocalIntelligenceRecordFile, IntelligenceContractError> {
        if row.len() > self.column_count {
            return Err(IntelligenceContractError::LocalPackParseFailure);
        }

        let indicator_type = parse_indicator_type(required_csv_field(
            row,
            self.indicator_type,
            "indicator_type",
        )?)?;
        let indicator = required_csv_field(row, self.indicator, "indicator")?.to_string();
        let summary_redacted =
            required_csv_field(row, self.summary_redacted, "summary_redacted")?.to_string();
        let confidence = self
            .confidence
            .and_then(|index| csv_field(row, index))
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .parse::<f32>()
                    .map_err(|_| IntelligenceContractError::InvalidConfidence)
            })
            .transpose()?;
        let labels = self
            .labels
            .and_then(|index| csv_field(row, index))
            .map(parse_csv_labels)
            .transpose()?
            .unwrap_or_default();

        Ok(LocalIntelligenceRecordFile {
            indicator_type,
            indicator,
            summary_redacted,
            confidence,
            retrieved_at: None,
            expires_at: None,
            labels,
            source: None,
        })
    }
}

impl IntelligenceProvider for OfflineLocalIntelligenceProvider {
    fn local_pack(&self) -> &LocalIntelligencePack {
        &self.pack
    }

    fn lookup_domain(
        &self,
        domain_protected: &str,
    ) -> Result<DomainContext, IntelligenceContractError> {
        self.ensure_local_available()?;
        validate_lookup_input("domain_protected", domain_protected)?;

        let normalized_domain = normalize_indicator(domain_protected);
        let records = self.records_for_domain(&normalized_domain);
        let status = lookup_status_for(&self.pack, &records);
        let risk_hints = risk_hints_for_records(&records, &self.pack)?;
        let confidence = confidence_for_records(&records)?;
        let tld = normalized_domain
            .rsplit('.')
            .next()
            .map(|value| value.to_string());
        let suspicious_tld = tld.as_deref().is_some_and(is_high_risk_tld);
        let allowlisted = has_record_type(&records, IndicatorType::AllowlistEntry);
        let blocklisted = has_record_type(&records, IndicatorType::BlocklistEntry);
        let user_ioc_match = has_record_type(&records, IndicatorType::Ioc);

        Ok(DomainContext {
            domain_protected: normalized_domain.clone(),
            tld_protected: tld,
            suspicious_tld: suspicious_tld || blocklisted || user_ioc_match,
            allowlisted,
            blocklisted,
            user_ioc_match,
            lexical_score: lexical_score_for_domain(&normalized_domain, suspicious_tld, &records)?,
            lookup_status: status,
            records,
            risk_hints,
            confidence,
            retrieved_at: self.pack.retrieved_at.clone(),
            expires_at: self.pack.expires_at.clone(),
            privacy_class: PrivacyClass::Internal,
        })
    }

    fn lookup_ip(&self, ip: &IpAddress) -> Result<IpContext, IntelligenceContractError> {
        self.ensure_local_available()?;
        let records = self.records_for_ip(ip);
        let status = lookup_status_for(&self.pack, &records);
        let risk_hints = risk_hints_for_records(&records, &self.pack)?;
        let cloud_provider_protected = self
            .index
            .matching_cloud_ranges(ip)
            .first()
            .map(|entry| cloud_provider_for_record(&entry.record));
        let allowlisted = has_record_type(&records, IndicatorType::AllowlistEntry);
        let blocklisted = has_record_type(&records, IndicatorType::BlocklistEntry);
        let user_ioc_match = has_record_type(&records, IndicatorType::Ioc);

        Ok(IpContext {
            ip: *ip,
            asn: asn_from_records(&records),
            asn_name_protected: asn_from_records(&records).map(|asn| format!("asn:{asn}")),
            cloud_provider_protected,
            risky_asn: has_positive_network_context(&records) && !allowlisted,
            allowlisted,
            blocklisted,
            user_ioc_match,
            lookup_status: status,
            confidence: confidence_for_records(&records)?,
            retrieved_at: self.pack.retrieved_at.clone(),
            expires_at: self.pack.expires_at.clone(),
            privacy_class: PrivacyClass::Internal,
            records,
            risk_hints,
        })
    }

    fn lookup_asn(&self, asn: u32) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError> {
        self.ensure_local_available()?;
        Ok(self.records_for_indicator(IndicatorType::Asn, &asn.to_string()))
    }

    fn lookup_cloud_range(
        &self,
        ip: &IpAddress,
    ) -> Result<CloudContext, IntelligenceContractError> {
        self.ensure_local_available()?;
        let records = self
            .index
            .matching_cloud_ranges(ip)
            .into_iter()
            .map(|entry| entry.record.clone())
            .collect::<Vec<_>>();
        let status = lookup_status_for(&self.pack, &records);
        let risk_hints = risk_hints_for_records(&records, &self.pack)?;
        let first_record = records.first();

        Ok(CloudContext {
            range_protected: first_record
                .map(|record| record.indicator.clone())
                .unwrap_or_else(|| "none".to_string()),
            provider_protected: first_record
                .map(cloud_provider_for_record)
                .unwrap_or_else(|| "unknown".to_string()),
            service_protected: first_record.map(cloud_service_for_record),
            region_protected: first_record.map(cloud_region_for_record),
            object_storage_hint: first_record.is_some_and(cloud_record_has_object_storage_hint),
            lookup_status: status,
            confidence: confidence_for_records(&records)?,
            retrieved_at: self.pack.retrieved_at.clone(),
            expires_at: self.pack.expires_at.clone(),
            privacy_class: PrivacyClass::Internal,
            records,
            risk_hints,
        })
    }

    fn lookup_certificate_fingerprint(
        &self,
        fingerprint_protected: &str,
    ) -> Result<CertificateContext, IntelligenceContractError> {
        self.ensure_local_available()?;
        validate_lookup_input("fingerprint_protected", fingerprint_protected)?;

        let normalized = normalize_indicator(fingerprint_protected);
        let records =
            self.records_for_indicator(IndicatorType::CertificateFingerprint, &normalized);
        let status = lookup_status_for(&self.pack, &records);
        let risk_hints = risk_hints_for_records(&records, &self.pack)?;
        let has_match = !records.is_empty();

        Ok(CertificateContext {
            fingerprint_protected: normalized,
            issuer_summary_protected: has_match
                .then(|| "local certificate intelligence match".to_string()),
            self_signed_hint: has_match,
            suspicious_issuer_hint: has_match,
            lookup_status: status,
            confidence: confidence_for_records(&records)?,
            retrieved_at: self.pack.retrieved_at.clone(),
            expires_at: self.pack.expires_at.clone(),
            privacy_class: PrivacyClass::Internal,
            records,
            risk_hints,
        })
    }

    fn lookup_allowlist(
        &self,
        _indicator_type: IndicatorType,
        indicator_protected: &str,
    ) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError> {
        self.ensure_local_available()?;
        validate_lookup_input("indicator_protected", indicator_protected)?;
        Ok(self.records_for_indicator(IndicatorType::AllowlistEntry, indicator_protected))
    }

    fn lookup_blocklist(
        &self,
        _indicator_type: IndicatorType,
        indicator_protected: &str,
    ) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError> {
        self.ensure_local_available()?;
        validate_lookup_input("indicator_protected", indicator_protected)?;
        Ok(self.records_for_indicator(IndicatorType::BlocklistEntry, indicator_protected))
    }

    fn lookup_user_ioc(
        &self,
        _indicator_type: IndicatorType,
        indicator_protected: &str,
    ) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError> {
        self.ensure_local_available()?;
        validate_lookup_input("indicator_protected", indicator_protected)?;
        Ok(self.records_for_indicator(IndicatorType::Ioc, indicator_protected))
    }
}

#[derive(Clone, Debug)]
struct LocalIntelligenceIndex {
    by_exact: HashMap<(IndicatorType, String), Vec<IntelligenceRecord>>,
    cloud_ranges: Vec<CloudRangeIndexEntry>,
}

impl LocalIntelligenceIndex {
    fn build(pack: &LocalIntelligencePack) -> Result<Self, IntelligenceContractError> {
        let mut by_exact: HashMap<(IndicatorType, String), Vec<IntelligenceRecord>> =
            HashMap::new();
        let mut cloud_ranges = Vec::new();

        for record in &pack.records {
            by_exact
                .entry((
                    record.indicator_type.clone(),
                    normalize_indicator(&record.indicator),
                ))
                .or_default()
                .push(record.clone());

            if record.indicator_type == IndicatorType::CloudRange {
                let range = CidrRange::parse(&record.indicator)
                    .ok_or(IntelligenceContractError::LocalIndexFailure)?;
                cloud_ranges.push(CloudRangeIndexEntry {
                    range,
                    record: record.clone(),
                });
            }
        }

        Ok(Self {
            by_exact,
            cloud_ranges,
        })
    }

    fn exact_records(
        &self,
        indicator_type: IndicatorType,
        indicator: &str,
    ) -> impl Iterator<Item = &IntelligenceRecord> {
        self.by_exact
            .get(&(indicator_type, normalize_indicator(indicator)))
            .into_iter()
            .flatten()
    }

    fn matching_cloud_ranges(&self, ip: &IpAddress) -> Vec<&CloudRangeIndexEntry> {
        self.cloud_ranges
            .iter()
            .filter(|entry| entry.range.contains(ip))
            .collect()
    }
}

#[derive(Clone, Debug)]
struct CloudRangeIndexEntry {
    range: CidrRange,
    record: IntelligenceRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CidrRange {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl CidrRange {
    fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim();
        let (address_text, prefix_text) = normalized
            .split_once('/')
            .map_or((normalized, None), |(address, prefix)| {
                (address, Some(prefix))
            });
        let address = IpAddr::from_str(address_text).ok()?;
        match address {
            IpAddr::V4(address) => {
                let prefix = prefix_text
                    .map(str::parse::<u8>)
                    .transpose()
                    .ok()?
                    .unwrap_or(32);
                if prefix > 32 {
                    return None;
                }
                let address = ipv4_to_u32(address);
                let mask = prefix_mask_v4(prefix);
                Some(Self::V4 {
                    network: address & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) => {
                let prefix = prefix_text
                    .map(str::parse::<u8>)
                    .transpose()
                    .ok()?
                    .unwrap_or(128);
                if prefix > 128 {
                    return None;
                }
                let address = ipv6_to_u128(address);
                let mask = prefix_mask_v6(prefix);
                Some(Self::V6 {
                    network: address & mask,
                    prefix,
                })
            }
        }
    }

    fn contains(&self, ip: &IpAddress) -> bool {
        match (self, ip.as_ip_addr()) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                ipv4_to_u32(address) & prefix_mask_v4(*prefix) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                ipv6_to_u128(address) & prefix_mask_v6(*prefix) == *network
            }
            _ => false,
        }
    }
}

fn csv_user_ioc_source() -> Result<IntelligenceSource, IntelligenceContractError> {
    IntelligenceSource::new(
        "local-csv-user-ioc",
        IntelligenceSourceClass::UserImportedIoc,
        "local CSV user IOC import",
        "csv-import-v1",
        IntelligenceLicenseClass::LocalUserProvided,
        PrivacyClass::Internal,
        IntelligenceExportPolicy::LocalOnly,
    )
}

fn csv_allowlist_source() -> Result<IntelligenceSource, IntelligenceContractError> {
    IntelligenceSource::new(
        "local-csv-allowlist",
        IntelligenceSourceClass::UserAllowlist,
        "local CSV allowlist import",
        "csv-import-v1",
        IntelligenceLicenseClass::LocalUserProvided,
        PrivacyClass::Internal,
        IntelligenceExportPolicy::LocalOnly,
    )
}

fn csv_blocklist_source() -> Result<IntelligenceSource, IntelligenceContractError> {
    IntelligenceSource::new(
        "local-csv-blocklist",
        IntelligenceSourceClass::UserBlocklist,
        "local CSV blocklist import",
        "csv-import-v1",
        IntelligenceLicenseClass::LocalUserProvided,
        PrivacyClass::Internal,
        IntelligenceExportPolicy::LocalOnly,
    )
}

fn csv_source_for_indicator(
    indicator_type: &IndicatorType,
) -> Result<IntelligenceSource, IntelligenceContractError> {
    match indicator_type {
        IndicatorType::AllowlistEntry => csv_allowlist_source(),
        IndicatorType::BlocklistEntry => csv_blocklist_source(),
        _ => csv_user_ioc_source(),
    }
}

fn parse_csv(contents: &str) -> Result<Vec<Vec<String>>, IntelligenceContractError> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut chars = contents.chars().peekable();
    let mut in_quotes = false;
    let mut at_field_start = true;

    while let Some(character) = chars.next() {
        if in_quotes {
            if character == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(character);
            }
            continue;
        }

        match character {
            '"' if at_field_start => {
                in_quotes = true;
                at_field_start = false;
            }
            '"' => return Err(IntelligenceContractError::LocalPackParseFailure),
            ',' => {
                push_csv_field(&mut row, &mut field);
                at_field_start = true;
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                push_csv_field(&mut row, &mut field);
                push_csv_row(&mut rows, &mut row);
                at_field_start = true;
            }
            '\n' => {
                push_csv_field(&mut row, &mut field);
                push_csv_row(&mut rows, &mut row);
                at_field_start = true;
            }
            _ => {
                field.push(character);
                if !character.is_whitespace() {
                    at_field_start = false;
                }
            }
        }
    }

    if in_quotes {
        return Err(IntelligenceContractError::LocalPackParseFailure);
    }
    if !field.is_empty() || !row.is_empty() {
        push_csv_field(&mut row, &mut field);
        push_csv_row(&mut rows, &mut row);
    }

    Ok(rows)
}

fn push_csv_field(row: &mut Vec<String>, field: &mut String) {
    row.push(field.trim().to_string());
    field.clear();
}

fn push_csv_row(rows: &mut Vec<Vec<String>>, row: &mut Vec<String>) {
    if row.iter().any(|field| !field.trim().is_empty()) {
        rows.push(std::mem::take(row));
    } else {
        row.clear();
    }
}

fn csv_column(headers: &[String], name: &str) -> Option<usize> {
    headers
        .iter()
        .position(|header| normalize_csv_name(header) == name)
}

fn required_csv_column(headers: &[String], name: &str) -> Result<usize, IntelligenceContractError> {
    csv_column(headers, name).ok_or(IntelligenceContractError::LocalPackParseFailure)
}

fn csv_field(row: &[String], index: usize) -> Option<&str> {
    row.get(index).map(String::as_str)
}

fn required_csv_field<'row>(
    row: &'row [String],
    index: usize,
    field: &'static str,
) -> Result<&'row str, IntelligenceContractError> {
    let value = csv_field(row, index)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(IntelligenceContractError::EmptyField(field))?;
    validate_safe_text(field, value)?;
    Ok(value)
}

fn parse_csv_labels(value: &str) -> Result<Vec<String>, IntelligenceContractError> {
    let mut labels = Vec::new();
    for label in value.split([';', '|']) {
        let label = label.trim();
        if label.is_empty() {
            continue;
        }
        validate_safe_text("labels", label)?;
        push_unique_label(&mut labels, label);
    }
    Ok(labels)
}

fn parse_indicator_type(value: &str) -> Result<IndicatorType, IntelligenceContractError> {
    match normalize_csv_name(value).as_str() {
        "domain" => Ok(IndicatorType::Domain),
        "ip" => Ok(IndicatorType::Ip),
        "asn" => Ok(IndicatorType::Asn),
        "certificate_fingerprint" | "cert_fingerprint" => Ok(IndicatorType::CertificateFingerprint),
        "url_pattern_redacted" => Ok(IndicatorType::UrlPatternRedacted),
        "cloud_range" => Ok(IndicatorType::CloudRange),
        "process_hash" => Ok(IndicatorType::ProcessHash),
        "ioc" => Ok(IndicatorType::Ioc),
        "allowlist" | "allowlist_entry" => Ok(IndicatorType::AllowlistEntry),
        "blocklist" | "blocklist_entry" => Ok(IndicatorType::BlocklistEntry),
        _ => Err(IntelligenceContractError::LocalPackParseFailure),
    }
}

fn normalize_csv_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn verify_pack_file_signature(
    file: &LocalIntelligencePackFile,
) -> Result<bool, IntelligenceContractError> {
    let signature_required = matches!(
        file.source.source_class,
        IntelligenceSourceClass::SignedLocalUpdate
    );
    let Some(signature) = &file.signature else {
        if signature_required {
            return Err(IntelligenceContractError::SignatureFailure);
        }
        return Ok(false);
    };

    if signature.algorithm.trim().to_ascii_lowercase() != SIGNATURE_ALGORITHM_SHA256 {
        return Err(IntelligenceContractError::UnsupportedSignatureAlgorithm);
    }

    let expected = signature.records_sha256.trim().to_ascii_lowercase();
    if expected.len() != 64
        || !expected
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(IntelligenceContractError::SignatureFailure);
    }

    if expected != pack_records_digest_hex(&file.records)? {
        return Err(IntelligenceContractError::SignatureFailure);
    }

    Ok(true)
}

fn pack_records_digest_hex(
    records: &[LocalIntelligenceRecordFile],
) -> Result<String, IntelligenceContractError> {
    let bytes = serde_json::to_vec(records)
        .map_err(|_| IntelligenceContractError::LocalPackParseFailure)?;
    let digest = Sha256::digest(bytes);
    Ok(hex_lower(&digest))
}

fn record_from_file(
    record_file: LocalIntelligenceRecordFile,
    source: &IntelligenceSource,
    pack_retrieved_at: &Timestamp,
    pack_expires_at: Option<Timestamp>,
    pack_labels: &[String],
    signature_verified: bool,
) -> Result<IntelligenceRecord, IntelligenceContractError> {
    let retrieved_at = record_file
        .retrieved_at
        .clone()
        .unwrap_or_else(|| pack_retrieved_at.clone());
    let expires_at = record_file.expires_at.clone().or(pack_expires_at);
    let confidence = QualityScore::new(record_file.confidence.unwrap_or(0.5))
        .map_err(|_| IntelligenceContractError::InvalidConfidence)?;
    let labels = record_file_labels(pack_labels, &record_file.labels, signature_verified);
    let mut record = IntelligenceRecord::new(
        record_file.indicator_type,
        record_file.indicator,
        source,
        record_file.summary_redacted,
    )?
    .with_retrieved_at(retrieved_at)
    .with_confidence(confidence)
    .with_labels(labels);

    if let Some(expires_at) = expires_at {
        record = record.with_expires_at(expires_at);
    }
    record.validate()?;
    Ok(record)
}

fn effective_file_status(
    declared_status: Option<IntelligencePackStatus>,
    expires_at: Option<&Timestamp>,
) -> IntelligencePackStatus {
    if let Some(status) = declared_status {
        return status;
    }
    if expires_at.is_some_and(|expires_at| expires_at <= &Timestamp::now()) {
        IntelligencePackStatus::Stale
    } else {
        IntelligencePackStatus::Active
    }
}

fn pack_file_labels(pack_labels: &[String], signature_verified: bool) -> Vec<String> {
    let mut labels = Vec::new();
    push_unique_label(&mut labels, LOCAL_FILE_LABEL);
    if signature_verified {
        push_unique_label(&mut labels, SIGNED_LOCAL_UPDATE_LABEL);
    }
    for label in pack_labels {
        push_unique_label(&mut labels, label);
    }
    labels
}

fn record_file_labels(
    pack_labels: &[String],
    record_labels: &[String],
    signature_verified: bool,
) -> Vec<String> {
    let mut labels = pack_file_labels(pack_labels, signature_verified);
    for label in record_labels {
        push_unique_label(&mut labels, label);
    }
    labels
}

fn push_unique_label(labels: &mut Vec<String>, label: &str) {
    if !labels.iter().any(|existing| existing == label) {
        labels.push(label.to_string());
    }
}

fn demo_source() -> Result<IntelligenceSource, IntelligenceContractError> {
    IntelligenceSource::new(
        "demo-local-intel",
        IntelligenceSourceClass::BundledLocal,
        "bundled offline demo intelligence pack",
        "2026.06.01",
        IntelligenceLicenseClass::InternalMetadata,
        PrivacyClass::Internal,
        IntelligenceExportPolicy::AllowRedactedSummary,
    )
}

fn demo_records(
    source: &IntelligenceSource,
    status: &IntelligencePackStatus,
) -> Result<Vec<IntelligenceRecord>, IntelligenceContractError> {
    let retrieved_at = match status {
        IntelligencePackStatus::Stale => past_days(45),
        _ => Timestamp::now(),
    };
    let expires_at = match status {
        IntelligencePackStatus::Stale => past_days(1),
        _ => future_days(30),
    };
    let labels = demo_labels();

    let specs = vec![
        DemoRecordSpec::new(
            IndicatorType::Domain,
            "beacon.example.test",
            "Demo suspicious reserved TEST domain context",
            0.72,
        ),
        DemoRecordSpec::new(
            IndicatorType::Ip,
            "198.51.100.24",
            "Demo TEST-NET destination reputation context",
            0.7,
        ),
        DemoRecordSpec::new(
            IndicatorType::Asn,
            "64512",
            "Demo private ASN risk context",
            0.64,
        ),
        DemoRecordSpec::new(
            IndicatorType::CloudRange,
            "203.0.113.0/24",
            "Demo object storage cloud range context",
            0.66,
        ),
        DemoRecordSpec::new(
            IndicatorType::CertificateFingerprint,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "Demo certificate issuer profile context",
            0.58,
        ),
        DemoRecordSpec::new(
            IndicatorType::AllowlistEntry,
            "trusted.example.test",
            "Demo local allowlist context",
            0.85,
        ),
        DemoRecordSpec::new(
            IndicatorType::BlocklistEntry,
            "blocked.example.test",
            "Demo local blocklist context",
            0.88,
        ),
        DemoRecordSpec::new(
            IndicatorType::Ioc,
            "ioc.example.invalid",
            "Demo user-imported IOC context",
            0.82,
        ),
    ];

    specs
        .into_iter()
        .map(|spec| {
            let record_source = source_for_record(&spec, source)?;
            record(
                spec,
                &record_source,
                &retrieved_at,
                &expires_at,
                labels.clone(),
            )
        })
        .collect()
}

struct DemoRecordSpec<'value> {
    indicator_type: IndicatorType,
    indicator: &'value str,
    summary_redacted: &'value str,
    confidence: f32,
}

impl<'value> DemoRecordSpec<'value> {
    fn new(
        indicator_type: IndicatorType,
        indicator: &'value str,
        summary_redacted: &'value str,
        confidence: f32,
    ) -> Self {
        Self {
            indicator_type,
            indicator,
            summary_redacted,
            confidence,
        }
    }
}

fn source_for_record(
    spec: &DemoRecordSpec<'_>,
    bundled_source: &IntelligenceSource,
) -> Result<IntelligenceSource, IntelligenceContractError> {
    match spec.indicator_type {
        IndicatorType::AllowlistEntry => IntelligenceSource::new(
            "demo-local-allowlist",
            IntelligenceSourceClass::UserAllowlist,
            "local user allowlist demo",
            "user-demo-2026.06.01",
            IntelligenceLicenseClass::LocalUserProvided,
            PrivacyClass::Internal,
            IntelligenceExportPolicy::LocalOnly,
        ),
        IndicatorType::BlocklistEntry => IntelligenceSource::new(
            "demo-local-blocklist",
            IntelligenceSourceClass::UserBlocklist,
            "local user blocklist demo",
            "user-demo-2026.06.01",
            IntelligenceLicenseClass::LocalUserProvided,
            PrivacyClass::Internal,
            IntelligenceExportPolicy::LocalOnly,
        ),
        IndicatorType::Ioc => IntelligenceSource::new(
            "demo-local-user-ioc",
            IntelligenceSourceClass::UserImportedIoc,
            "local user-imported IOC demo",
            "user-demo-2026.06.01",
            IntelligenceLicenseClass::LocalUserProvided,
            PrivacyClass::Internal,
            IntelligenceExportPolicy::LocalOnly,
        ),
        _ => Ok(bundled_source.clone()),
    }
}

fn record(
    spec: DemoRecordSpec<'_>,
    source: &IntelligenceSource,
    retrieved_at: &Timestamp,
    expires_at: &Timestamp,
    labels: Vec<String>,
) -> Result<IntelligenceRecord, IntelligenceContractError> {
    let record = IntelligenceRecord::new(
        spec.indicator_type,
        spec.indicator,
        source,
        spec.summary_redacted,
    )?
    .with_retrieved_at(retrieved_at.clone())
    .with_expires_at(expires_at.clone())
    .with_confidence(
        QualityScore::new(spec.confidence)
            .map_err(|_| IntelligenceContractError::InvalidConfidence)?,
    )
    .with_labels(labels);
    record.validate()?;
    Ok(record)
}

fn lookup_status_for(
    pack: &LocalIntelligencePack,
    records: &[IntelligenceRecord],
) -> IntelligenceLookupStatus {
    if records.is_empty() {
        return IntelligenceLookupStatus::Miss;
    }
    let now = Timestamp::now();
    if pack.status == IntelligencePackStatus::Stale
        || records.iter().any(|record| record.is_stale_at(&now))
    {
        IntelligenceLookupStatus::StaleHit
    } else {
        IntelligenceLookupStatus::Hit
    }
}

fn confidence_for_records(
    records: &[IntelligenceRecord],
) -> Result<QualityScore, IntelligenceContractError> {
    if records.is_empty() {
        return Ok(QualityScore::unknown());
    }
    let now = Timestamp::now();
    let mut best = 0.0_f32;
    for record in records {
        best = best.max(record.effective_confidence_at(&now)?.value());
    }
    QualityScore::new(best).map_err(|_| IntelligenceContractError::InvalidConfidence)
}

fn risk_hints_for_records(
    records: &[IntelligenceRecord],
    pack: &LocalIntelligencePack,
) -> Result<Vec<RiskHint>, IntelligenceContractError> {
    let now = Timestamp::now();
    records
        .iter()
        .map(|record| {
            let (hint_type, delta) = match record.indicator_type {
                IndicatorType::AllowlistEntry => ("local_allowlist_context", -0.35),
                IndicatorType::BlocklistEntry => ("local_blocklist_context", 0.65),
                IndicatorType::Ioc => ("user_ioc_context", 0.75),
                IndicatorType::Asn => ("asn_risk_context", 0.45),
                IndicatorType::CloudRange => ("cloud_range_context", 0.35),
                IndicatorType::CertificateFingerprint => ("certificate_profile_context", 0.4),
                IndicatorType::Domain => ("domain_reputation_context", 0.3),
                IndicatorType::Ip => ("ip_reputation_context", 0.3),
                IndicatorType::UrlPatternRedacted | IndicatorType::ProcessHash => {
                    ("local_intelligence_context", 0.2)
                }
            };
            let confidence = if pack.status == IntelligencePackStatus::Stale {
                QualityScore::new(record.confidence.value() * 0.5)
                    .map_err(|_| IntelligenceContractError::InvalidConfidence)?
            } else {
                record.effective_confidence_at(&now)?
            };
            let hint = RiskHint::new(
                hint_type,
                "Local offline intelligence context; enrichment only",
                vec![record.record_id.clone()],
            )?
            .with_risk_delta(delta)
            .with_confidence(confidence);
            hint.validate_boundary()?;
            Ok(hint)
        })
        .collect()
}

fn validate_lookup_input(
    field: &'static str,
    value: &str,
) -> Result<(), IntelligenceContractError> {
    if value.trim().is_empty() {
        return Err(IntelligenceContractError::EmptyField(field));
    }
    validate_safe_text(field, value)
}

fn domain_matches(indicator: &str, domain: &str) -> bool {
    let indicator = normalize_indicator(indicator)
        .trim_start_matches('.')
        .to_string();
    let domain = normalize_indicator(domain);
    domain == indicator || domain.ends_with(&format!(".{indicator}"))
}

fn has_record_type(records: &[IntelligenceRecord], indicator_type: IndicatorType) -> bool {
    records
        .iter()
        .any(|record| record.indicator_type == indicator_type)
}

fn has_positive_network_context(records: &[IntelligenceRecord]) -> bool {
    records.iter().any(|record| {
        matches!(
            record.indicator_type,
            IndicatorType::Ip
                | IndicatorType::Asn
                | IndicatorType::CloudRange
                | IndicatorType::BlocklistEntry
                | IndicatorType::Ioc
        )
    })
}

fn asn_from_records(records: &[IntelligenceRecord]) -> Option<u32> {
    records
        .iter()
        .find(|record| record.indicator_type == IndicatorType::Asn)
        .and_then(|record| record.indicator.parse().ok())
}

fn lexical_score_for_domain(
    domain: &str,
    suspicious_tld: bool,
    records: &[IntelligenceRecord],
) -> Result<QualityScore, IntelligenceContractError> {
    let max_label_len = domain.split('.').map(str::len).max().unwrap_or_default();
    let digit_or_dash_count = domain
        .chars()
        .filter(|character| character.is_ascii_digit() || *character == '-')
        .count();
    let mut score: f32 = if records.is_empty() { 0.05 } else { 0.35 };
    if suspicious_tld {
        score += 0.25;
    }
    if max_label_len >= 18 {
        score += 0.2;
    }
    if digit_or_dash_count >= 4 {
        score += 0.15;
    }
    QualityScore::new(score.min(0.95)).map_err(|_| IntelligenceContractError::InvalidConfidence)
}

fn is_high_risk_tld(tld: &str) -> bool {
    matches!(
        tld,
        "click"
            | "country"
            | "download"
            | "gq"
            | "invalid"
            | "mov"
            | "stream"
            | "tk"
            | "top"
            | "work"
            | "xyz"
            | "zip"
    )
}

fn cloud_provider_for_record(record: &IntelligenceRecord) -> String {
    let summary = normalize_indicator(&record.summary_redacted);
    if summary.contains("object_storage") || summary.contains("object storage") {
        "demo-object-storage".to_string()
    } else {
        "local-cloud-range".to_string()
    }
}

fn cloud_service_for_record(record: &IntelligenceRecord) -> String {
    let summary = normalize_indicator(&record.summary_redacted);
    if summary.contains("object_storage") || summary.contains("object storage") {
        "object-storage".to_string()
    } else {
        "cloud-range".to_string()
    }
}

fn cloud_region_for_record(_record: &IntelligenceRecord) -> String {
    "local-region".to_string()
}

fn cloud_record_has_object_storage_hint(record: &IntelligenceRecord) -> bool {
    let summary = normalize_indicator(&record.summary_redacted);
    summary.contains("object_storage") || summary.contains("object storage")
}

fn normalize_indicator(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn demo_labels() -> Vec<String> {
    vec![DEMO_ONLY_LABEL.to_string()]
}

fn future_days(days: i64) -> Timestamp {
    Timestamp::from_datetime(Utc::now() + Duration::days(days))
}

fn past_days(days: i64) -> Timestamp {
    Timestamp::from_datetime(Utc::now() - Duration::days(days))
}

fn ipv4_to_u32(value: Ipv4Addr) -> u32 {
    u32::from_be_bytes(value.octets())
}

fn ipv6_to_u128(value: Ipv6Addr) -> u128 {
    u128::from_be_bytes(value.octets())
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn provider_is_offline_demo_labeled_and_has_required_records() {
        let provider = OfflineLocalIntelligenceProvider::demo().expect("provider");
        let pack = provider.local_pack();

        assert!(!provider.online_lookup_enabled());
        assert!(pack.labels.contains(&DEMO_ONLY_LABEL.to_string()));
        assert!(pack.records.iter().all(|record| {
            record.labels.contains(&DEMO_ONLY_LABEL.to_string())
                && record.privacy_class == PrivacyClass::Internal
                && record.export_policy != IntelligenceExportPolicy::Blocked
                && record.expires_at.is_some()
        }));
    }

    #[test]
    fn domain_lookup_returns_context_and_risk_hints_only() {
        let provider = OfflineLocalIntelligenceProvider::demo().expect("provider");
        let context = provider
            .lookup_domain("beacon.example.test")
            .expect("domain context");

        assert_eq!(context.lookup_status, IntelligenceLookupStatus::Hit);
        assert!(!context.records.is_empty());
        assert!(!context.risk_hints.is_empty());
        assert!(context.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
                && hint.validate_boundary().is_ok()
        }));
    }

    #[test]
    fn domain_lookup_supports_parent_domain_matches() {
        let source = demo_source().expect("source");
        let record = record(
            DemoRecordSpec::new(
                IndicatorType::Domain,
                "example.test",
                "Demo parent domain context",
                0.6,
            ),
            &source,
            &Timestamp::now(),
            &future_days(30),
            demo_labels(),
        )
        .expect("record");
        let pack = LocalIntelligencePack::new(
            "demo-parent-domain",
            "Demo Parent Domain",
            source,
            vec![record],
        )
        .expect("pack");
        let provider = OfflineLocalIntelligenceProvider::from_pack(pack).expect("provider");

        let context = provider
            .lookup_domain("beacon.example.test")
            .expect("context");

        assert_eq!(context.lookup_status, IntelligenceLookupStatus::Hit);
    }

    #[test]
    fn stale_pack_lowers_confidence_without_failing_lookup() {
        let active = OfflineLocalIntelligenceProvider::demo().expect("provider");
        let stale = OfflineLocalIntelligenceProvider::stale_demo().expect("stale provider");

        let active_context = active
            .lookup_domain("beacon.example.test")
            .expect("active context");
        let stale_context = stale
            .lookup_domain("beacon.example.test")
            .expect("stale context");

        assert_eq!(
            stale_context.lookup_status,
            IntelligenceLookupStatus::StaleHit
        );
        assert!(stale_context.confidence.value() < active_context.confidence.value());
    }

    #[test]
    fn signature_and_local_index_failures_are_explicit() {
        let signature_failed =
            OfflineLocalIntelligenceProvider::signature_failure_demo().expect("provider");
        let index_failed =
            OfflineLocalIntelligenceProvider::local_index_failure_demo().expect("provider");

        assert_eq!(
            signature_failed.lookup_domain("beacon.example.test"),
            Err(IntelligenceContractError::SignatureFailure)
        );
        assert_eq!(
            index_failed.lookup_domain("beacon.example.test"),
            Err(IntelligenceContractError::LocalIndexFailure)
        );
    }

    #[test]
    fn covers_ip_asn_cloud_certificate_allowlist_blocklist_and_ioc() {
        let provider = OfflineLocalIntelligenceProvider::demo().expect("provider");
        let ip = IpAddress::parse_str("198.51.100.24").expect("ip");
        let cloud_ip = IpAddress::parse_str("203.0.113.10").expect("cloud ip");

        assert_eq!(
            provider.lookup_ip(&ip).expect("ip").lookup_status,
            IntelligenceLookupStatus::Hit
        );
        assert!(!provider.lookup_asn(64_512).expect("asn").is_empty());
        assert_eq!(
            provider
                .lookup_cloud_range(&cloud_ip)
                .expect("cloud")
                .lookup_status,
            IntelligenceLookupStatus::Hit
        );
        assert_eq!(
            provider
                .lookup_certificate_fingerprint(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                )
                .expect("certificate")
                .lookup_status,
            IntelligenceLookupStatus::Hit
        );
        assert!(!provider
            .lookup_allowlist(IndicatorType::Domain, "trusted.example.test")
            .expect("allowlist")
            .is_empty());
        assert!(!provider
            .lookup_blocklist(IndicatorType::Domain, "blocked.example.test")
            .expect("blocklist")
            .is_empty());
        assert!(!provider
            .lookup_user_ioc(IndicatorType::Domain, "ioc.example.invalid")
            .expect("ioc")
            .is_empty());
    }

    #[test]
    fn cloud_range_lookup_uses_cidr_matching() {
        let provider = OfflineLocalIntelligenceProvider::demo().expect("provider");
        let in_range = IpAddress::parse_str("203.0.113.42").expect("ip");
        let out_of_range = IpAddress::parse_str("203.0.114.42").expect("ip");

        assert_eq!(
            provider
                .lookup_cloud_range(&in_range)
                .expect("context")
                .lookup_status,
            IntelligenceLookupStatus::Hit
        );
        assert_eq!(
            provider
                .lookup_cloud_range(&out_of_range)
                .expect("context")
                .lookup_status,
            IntelligenceLookupStatus::Miss
        );
    }

    #[test]
    fn user_allowlist_blocklist_and_ioc_records_keep_local_user_provenance() {
        let provider = OfflineLocalIntelligenceProvider::demo().expect("provider");

        let allowlist = provider
            .lookup_allowlist(IndicatorType::Domain, "trusted.example.test")
            .expect("allowlist");
        let blocklist = provider
            .lookup_blocklist(IndicatorType::Domain, "blocked.example.test")
            .expect("blocklist");
        let user_ioc = provider
            .lookup_user_ioc(IndicatorType::Domain, "ioc.example.invalid")
            .expect("ioc");

        assert!(allowlist.iter().all(|record| {
            record.source_class == IntelligenceSourceClass::UserAllowlist
                && record.license_class == IntelligenceLicenseClass::LocalUserProvided
                && record.export_policy == IntelligenceExportPolicy::LocalOnly
                && record.provenance == "local user allowlist demo"
        }));
        assert!(blocklist.iter().all(|record| {
            record.source_class == IntelligenceSourceClass::UserBlocklist
                && record.license_class == IntelligenceLicenseClass::LocalUserProvided
                && record.export_policy == IntelligenceExportPolicy::LocalOnly
                && record.provenance == "local user blocklist demo"
        }));
        assert!(user_ioc.iter().all(|record| {
            record.source_class == IntelligenceSourceClass::UserImportedIoc
                && record.license_class == IntelligenceLicenseClass::LocalUserProvided
                && record.export_policy == IntelligenceExportPolicy::LocalOnly
                && record.provenance == "local user-imported IOC demo"
        }));
    }

    #[test]
    fn sensitive_lookup_markers_are_rejected() {
        let provider = OfflineLocalIntelligenceProvider::demo().expect("provider");

        assert_eq!(
            provider.lookup_domain("api_key.example.test"),
            Err(IntelligenceContractError::SensitiveMarker {
                field: "domain_protected"
            })
        );
    }

    #[test]
    fn invalid_cloud_range_marks_local_index_failure() {
        let source = demo_source().expect("source");
        let record = record(
            DemoRecordSpec::new(
                IndicatorType::CloudRange,
                "203.0.113.0/99",
                "Demo invalid cloud range",
                0.5,
            ),
            &source,
            &Timestamp::now(),
            &future_days(30),
            demo_labels(),
        )
        .expect("record");
        let pack = LocalIntelligencePack::new(
            "demo-invalid-range",
            "Demo Invalid Range",
            source,
            vec![record],
        )
        .expect("pack");

        assert_eq!(
            OfflineLocalIntelligenceProvider::from_pack(pack).expect_err("index failure"),
            IntelligenceContractError::LocalIndexFailure
        );
    }

    #[test]
    fn signed_json_pack_loads_real_local_records_without_demo_labels() {
        let mut file = local_pack_file(
            "task590-local-pack",
            IntelligenceSourceClass::SignedLocalUpdate,
            vec![
                local_record(
                    IndicatorType::Domain,
                    "suspicious.example.test",
                    "Local signed domain reputation context",
                    0.81,
                ),
                local_record(
                    IndicatorType::Ip,
                    "198.51.100.200",
                    "Local signed IP reputation context",
                    0.73,
                ),
            ],
        );
        sign_pack_file(&mut file);
        let path = write_pack_file("signed-json-pack", &file);

        let provider = OfflineLocalIntelligenceProvider::from_json_file(&path).expect("provider");
        let pack = provider.local_pack();
        let context = provider
            .lookup_domain("api.suspicious.example.test")
            .expect("domain context");
        let ip = IpAddress::parse_str("198.51.100.200").expect("ip");

        assert!(!provider.online_lookup_enabled());
        assert!(pack.signature_verified);
        assert!(pack.labels.contains(&LOCAL_FILE_LABEL.to_string()));
        assert!(pack.labels.contains(&SIGNED_LOCAL_UPDATE_LABEL.to_string()));
        assert!(!pack.labels.contains(&DEMO_ONLY_LABEL.to_string()));
        assert_eq!(
            pack.source.source_class,
            IntelligenceSourceClass::SignedLocalUpdate
        );
        assert_eq!(context.lookup_status, IntelligenceLookupStatus::Hit);
        assert!(context.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
        }));
        assert_eq!(
            provider.lookup_ip(&ip).expect("ip").lookup_status,
            IntelligenceLookupStatus::Hit
        );
        assert!(pack.records.iter().all(|record| {
            record.labels.contains(&LOCAL_FILE_LABEL.to_string())
                && record
                    .labels
                    .contains(&SIGNED_LOCAL_UPDATE_LABEL.to_string())
                && !record.labels.contains(&DEMO_ONLY_LABEL.to_string())
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn signed_json_pack_requires_matching_signature() {
        let mut unsigned = local_pack_file(
            "task590-signature-required",
            IntelligenceSourceClass::SignedLocalUpdate,
            vec![local_record(
                IndicatorType::Domain,
                "blocked.example.test",
                "Local signed blocklist context",
                0.88,
            )],
        );
        let unsigned_path = write_pack_file("unsigned-json-pack", &unsigned);

        assert!(matches!(
            OfflineLocalIntelligenceProvider::from_json_file(&unsigned_path),
            Err(IntelligenceContractError::SignatureFailure)
        ));

        unsigned.signature = Some(LocalIntelligencePackSignature {
            algorithm: SIGNATURE_ALGORITHM_SHA256.to_string(),
            records_sha256: "0".repeat(64),
        });
        let mismatched_path = write_pack_file("mismatched-json-pack", &unsigned);

        assert!(matches!(
            OfflineLocalIntelligenceProvider::from_json_file(&mismatched_path),
            Err(IntelligenceContractError::SignatureFailure)
        ));

        let _ = std::fs::remove_file(unsigned_path);
        let _ = std::fs::remove_file(mismatched_path);
    }

    #[test]
    fn unsigned_user_ioc_json_pack_is_allowed_but_not_claimed_signed() {
        let file = local_pack_file(
            "task590-user-ioc-pack",
            IntelligenceSourceClass::UserImportedIoc,
            vec![local_record(
                IndicatorType::Ioc,
                "user-ioc.example.invalid",
                "Local user imported IOC context",
                0.77,
            )],
        );
        let path = write_pack_file("unsigned-user-ioc-json-pack", &file);

        let provider = OfflineLocalIntelligenceProvider::from_json_file(&path).expect("provider");
        let pack = provider.local_pack();

        assert!(!pack.signature_verified);
        assert!(pack.labels.contains(&LOCAL_FILE_LABEL.to_string()));
        assert!(!pack.labels.contains(&SIGNED_LOCAL_UPDATE_LABEL.to_string()));
        assert!(!provider
            .lookup_user_ioc(IndicatorType::Domain, "user-ioc.example.invalid")
            .expect("ioc")
            .is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn csv_pack_loads_local_iocs_without_demo_or_signature_labels() {
        let csv = "\
indicator_type,indicator,summary_redacted,confidence,labels
Domain,malicious.example.test,Local CSV domain reputation context,0.79,task590;operator
Ip,198.51.100.201,Local CSV IP reputation context,0.71,task590
Cloud Range,203.0.113.0/25,Local CSV object storage context,0.67,task590
";
        let path = write_text_file("user-ioc-csv-pack", "csv", csv);

        let provider = OfflineLocalIntelligenceProvider::from_csv_file(&path).expect("provider");
        let pack = provider.local_pack();
        let domain = provider
            .lookup_domain("api.malicious.example.test")
            .expect("domain");
        let ip = IpAddress::parse_str("198.51.100.201").expect("ip");
        let cloud_ip = IpAddress::parse_str("203.0.113.25").expect("cloud ip");

        assert!(!provider.online_lookup_enabled());
        assert!(!pack.signature_verified);
        assert!(pack.labels.contains(&LOCAL_FILE_LABEL.to_string()));
        assert!(pack.labels.contains(&CSV_IMPORT_LABEL.to_string()));
        assert!(!pack.labels.contains(&SIGNED_LOCAL_UPDATE_LABEL.to_string()));
        assert!(!pack.labels.contains(&DEMO_ONLY_LABEL.to_string()));
        assert_eq!(domain.lookup_status, IntelligenceLookupStatus::Hit);
        assert!(domain.risk_hints.iter().all(|hint| {
            hint.evidence_input_only
                && !hint.creates_alert
                && !hint.creates_incident
                && !hint.executes_response
        }));
        assert_eq!(
            provider.lookup_ip(&ip).expect("ip").lookup_status,
            IntelligenceLookupStatus::Hit
        );
        assert_eq!(
            provider
                .lookup_cloud_range(&cloud_ip)
                .expect("cloud")
                .lookup_status,
            IntelligenceLookupStatus::Hit
        );
        assert!(pack.records.iter().all(|record| {
            record.labels.contains(&LOCAL_FILE_LABEL.to_string())
                && record.labels.contains(&CSV_IMPORT_LABEL.to_string())
                && !record.labels.contains(&DEMO_ONLY_LABEL.to_string())
                && !record
                    .labels
                    .contains(&SIGNED_LOCAL_UPDATE_LABEL.to_string())
                && record.export_policy == IntelligenceExportPolicy::LocalOnly
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn csv_allowlist_and_blocklist_keep_user_provenance() {
        let csv = "\
indicator_type,indicator,summary_redacted,confidence
allowlist,trusted-csv.example.test,Local CSV allowlist context,0.9
blocklist,blocked-csv.example.test,Local CSV blocklist context,0.9
";
        let path = write_text_file("allow-block-csv-pack", "csv", csv);

        let provider = OfflineLocalIntelligenceProvider::from_csv_file(&path).expect("provider");
        let allowlist = provider
            .lookup_allowlist(IndicatorType::Domain, "trusted-csv.example.test")
            .expect("allowlist");
        let blocklist = provider
            .lookup_blocklist(IndicatorType::Domain, "blocked-csv.example.test")
            .expect("blocklist");

        assert!(allowlist.iter().all(|record| {
            record.source_class == IntelligenceSourceClass::UserAllowlist
                && record.license_class == IntelligenceLicenseClass::LocalUserProvided
                && record.export_policy == IntelligenceExportPolicy::LocalOnly
                && record.provenance == "local CSV allowlist import"
        }));
        assert!(blocklist.iter().all(|record| {
            record.source_class == IntelligenceSourceClass::UserBlocklist
                && record.license_class == IntelligenceLicenseClass::LocalUserProvided
                && record.export_policy == IntelligenceExportPolicy::LocalOnly
                && record.provenance == "local CSV blocklist import"
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn csv_pack_rejects_sensitive_markers_and_malformed_rows() {
        let sensitive = "\
indicator_type,indicator,summary_redacted
domain,api_key.example.test,Local CSV sensitive marker context
";
        let sensitive_path = write_text_file("sensitive-csv-pack", "csv", sensitive);

        assert!(matches!(
            OfflineLocalIntelligenceProvider::from_csv_file(&sensitive_path),
            Err(IntelligenceContractError::SensitiveMarker { field: "indicator" })
        ));

        let malformed = "\
indicator_type,indicator,summary_redacted
domain,\"unterminated.example.test,Local CSV malformed context
";
        let malformed_path = write_text_file("malformed-csv-pack", "csv", malformed);

        assert!(matches!(
            OfflineLocalIntelligenceProvider::from_csv_file(&malformed_path),
            Err(IntelligenceContractError::LocalPackParseFailure)
        ));

        let _ = std::fs::remove_file(sensitive_path);
        let _ = std::fs::remove_file(malformed_path);
    }

    fn local_pack_file(
        pack_id: &str,
        source_class: IntelligenceSourceClass,
        records: Vec<LocalIntelligenceRecordFile>,
    ) -> LocalIntelligencePackFile {
        LocalIntelligencePackFile {
            pack_id: pack_id.to_string(),
            display_name: "Task 590 Local Pack".to_string(),
            source: LocalIntelligenceSourceFile {
                source_id: "task590-local-source".to_string(),
                source_class,
                provenance: "local operator supplied offline pack".to_string(),
                version: "2026.06.05".to_string(),
                license_class: IntelligenceLicenseClass::LocalUserProvided,
                privacy_class: PrivacyClass::Internal,
                export_policy: IntelligenceExportPolicy::LocalOnly,
            },
            records,
            status: None,
            retrieved_at: Some(Timestamp::now()),
            expires_at: Some(future_days(30)),
            labels: vec!["task590".to_string()],
            signature: None,
        }
    }

    fn local_record(
        indicator_type: IndicatorType,
        indicator: &str,
        summary_redacted: &str,
        confidence: f32,
    ) -> LocalIntelligenceRecordFile {
        LocalIntelligenceRecordFile {
            indicator_type,
            indicator: indicator.to_string(),
            summary_redacted: summary_redacted.to_string(),
            confidence: Some(confidence),
            retrieved_at: None,
            expires_at: None,
            labels: Vec::new(),
            source: None,
        }
    }

    fn sign_pack_file(file: &mut LocalIntelligencePackFile) {
        file.signature = Some(LocalIntelligencePackSignature {
            algorithm: SIGNATURE_ALGORITHM_SHA256.to_string(),
            records_sha256: pack_records_digest_hex(&file.records).expect("digest"),
        });
    }

    fn write_pack_file(label: &str, file: &LocalIntelligencePackFile) -> PathBuf {
        let json = serde_json::to_string_pretty(file).expect("json");
        write_text_file(label, "json", &json)
    }

    fn write_text_file(label: &str, extension: &str, contents: &str) -> PathBuf {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target")
            .join("intelligence-tests");
        std::fs::create_dir_all(&root).expect("test root");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = root.join(format!("{label}-{unique}.{extension}"));
        std::fs::write(&path, contents).expect("write pack");
        path
    }
}
