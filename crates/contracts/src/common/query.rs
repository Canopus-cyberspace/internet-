use crate::common::{
    AlertId, CapabilityId, CorrelationId, EntityId, FindingId, IncidentId, PageRequest,
    PageResponse, PluginId, ReportId, Timestamp, TraceId,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: Option<Timestamp>,
    pub end: Option<Timestamp>,
}

impl TimeRange {
    pub fn all() -> Self {
        Self {
            start: None,
            end: None,
        }
    }

    pub fn new(start: Option<Timestamp>, end: Option<Timestamp>) -> Result<Self, TimeRangeError> {
        let range = Self { start, end };
        range.validate()?;
        Ok(range)
    }

    pub fn validate(&self) -> Result<(), TimeRangeError> {
        if let (Some(start), Some(end)) = (&self.start, &self.end) {
            if start > end {
                return Err(TimeRangeError::StartAfterEnd);
            }
        }

        Ok(())
    }

    pub fn is_bounded(&self) -> bool {
        self.start.is_some() || self.end.is_some()
    }
}

impl Default for TimeRange {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeRangeError {
    StartAfterEnd,
}

impl fmt::Display for TimeRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartAfterEnd => write!(f, "time range start must not be after end"),
        }
    }
}

impl std::error::Error for TimeRangeError {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    #[default]
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortSpec {
    pub field: String,
    pub direction: SortDirection,
}

impl SortSpec {
    pub fn new(
        field: impl Into<String>,
        direction: SortDirection,
    ) -> Result<Self, QueryFieldError> {
        let field = validate_query_field(field.into())?;
        Ok(Self { field, direction })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOperator {
    Eq,
    NotEq,
    Contains,
    StartsWith,
    EndsWith,
    In,
    NotIn,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Exists,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FilterValue {
    String(String),
    Number(f64),
    Bool(bool),
    Strings(Vec<String>),
    Null,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FilterSpec {
    pub field: String,
    pub operator: FilterOperator,
    pub value: Option<FilterValue>,
}

impl FilterSpec {
    pub fn new(
        field: impl Into<String>,
        operator: FilterOperator,
        value: Option<FilterValue>,
    ) -> Result<Self, QueryFieldError> {
        let field = validate_query_field(field.into())?;
        Ok(Self {
            field,
            operator,
            value,
        })
    }

    pub fn exists(field: impl Into<String>) -> Result<Self, QueryFieldError> {
        Self::new(field, FilterOperator::Exists, None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum QueryScope {
    Global,
    LocalHost,
    Plugin(PluginId),
    Capability(CapabilityId),
    Entity(EntityId),
    Trace(TraceId),
    Correlation(CorrelationId),
    Finding(FindingId),
    Alert(AlertId),
    Incident(IncidentId),
    Report(ReportId),
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryRequest {
    pub page: PageRequest,
    pub time_range: Option<TimeRange>,
    pub filters: Vec<FilterSpec>,
    pub sort: Vec<SortSpec>,
    pub scope: QueryScope,
}

impl QueryRequest {
    pub fn new(scope: QueryScope) -> Self {
        Self {
            page: PageRequest::default(),
            time_range: None,
            filters: Vec::new(),
            sort: Vec::new(),
            scope,
        }
    }

    pub fn with_page(mut self, page: PageRequest) -> Self {
        self.page = page;
        self
    }

    pub fn with_time_range(mut self, time_range: TimeRange) -> Self {
        self.time_range = Some(time_range);
        self
    }

    pub fn with_filters(mut self, filters: Vec<FilterSpec>) -> Self {
        self.filters = filters;
        self
    }

    pub fn with_sort(mut self, sort: Vec<SortSpec>) -> Self {
        self.sort = sort;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryResponse<T> {
    pub page: PageResponse<T>,
}

impl<T> QueryResponse<T> {
    pub fn new(page: PageResponse<T>) -> Self {
        Self { page }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryFieldError {
    Empty,
}

impl fmt::Display for QueryFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "query field must not be empty"),
        }
    }
}

impl std::error::Error for QueryFieldError {}

fn validate_query_field(field: String) -> Result<String, QueryFieldError> {
    if field.trim().is_empty() {
        return Err(QueryFieldError::Empty);
    }

    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_rejects_empty_field() {
        let result = FilterSpec::new(
            " ",
            FilterOperator::Eq,
            Some(FilterValue::String("blocked".to_string())),
        );

        assert_eq!(result, Err(QueryFieldError::Empty));
    }

    #[test]
    fn query_request_defaults_to_cursor_page() {
        let request = QueryRequest::new(QueryScope::Global);

        assert_eq!(request.page.limit, crate::common::DEFAULT_PAGE_LIMIT);
        assert!(request.page.cursor.is_none());
    }
}
