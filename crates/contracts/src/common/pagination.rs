use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;

pub const DEFAULT_PAGE_LIMIT: u32 = 100;
pub const MAX_PAGE_LIMIT: u32 = 1_000;
pub const MAX_CURSOR_LENGTH: usize = 2_048;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Cursor(String);

impl Cursor {
    pub fn new(value: impl Into<String>) -> Result<Self, CursorError> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(CursorError::Empty);
        }

        if value.len() > MAX_CURSOR_LENGTH {
            return Err(CursorError::TooLong {
                max: MAX_CURSOR_LENGTH,
                actual: value.len(),
            });
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for Cursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Cursor {
    type Err = CursorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorError {
    Empty,
    TooLong { max: usize, actual: usize },
}

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "cursor must not be empty"),
            Self::TooLong { max, actual } => {
                write!(f, "cursor length {actual} exceeds maximum length {max}")
            }
        }
    }
}

impl std::error::Error for CursorError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PageRequest {
    pub limit: u32,
    pub cursor: Option<Cursor>,
}

impl PageRequest {
    pub fn new(limit: u32, cursor: Option<Cursor>) -> Result<Self, PageRequestError> {
        validate_limit(limit)?;

        Ok(Self { limit, cursor })
    }

    pub fn first(limit: u32) -> Result<Self, PageRequestError> {
        Self::new(limit, None)
    }

    pub fn validate(&self) -> Result<(), PageRequestError> {
        validate_limit(self.limit)
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            cursor: None,
        }
    }
}

impl<'de> Deserialize<'de> for PageRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PageRequestWire {
            limit: u32,
            cursor: Option<Cursor>,
        }

        let wire = PageRequestWire::deserialize(deserializer)?;
        Self::new(wire.limit, wire.cursor).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageRequestError {
    LimitTooSmall,
    LimitTooLarge { max: u32, actual: u32 },
}

impl fmt::Display for PageRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitTooSmall => write!(f, "page limit must be greater than zero"),
            Self::LimitTooLarge { max, actual } => {
                write!(f, "page limit {actual} exceeds maximum page limit {max}")
            }
        }
    }
}

impl std::error::Error for PageRequestError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub limit: u32,
    pub cursor: Option<Cursor>,
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

impl<T> PageResponse<T> {
    pub fn new(
        items: Vec<T>,
        limit: u32,
        cursor: Option<Cursor>,
        next_cursor: Option<Cursor>,
        has_more: bool,
    ) -> Result<Self, PageRequestError> {
        validate_limit(limit)?;

        Ok(Self {
            items,
            limit,
            cursor,
            next_cursor,
            has_more,
        })
    }

    pub fn from_request(
        items: Vec<T>,
        request: &PageRequest,
        next_cursor: Option<Cursor>,
        has_more: bool,
    ) -> Self {
        Self {
            items,
            limit: request.limit,
            cursor: request.cursor.clone(),
            next_cursor,
            has_more,
        }
    }

    pub fn empty(request: &PageRequest) -> Self {
        Self::from_request(Vec::new(), request, None, false)
    }
}

fn validate_limit(limit: u32) -> Result<(), PageRequestError> {
    if limit == 0 {
        return Err(PageRequestError::LimitTooSmall);
    }

    if limit > MAX_PAGE_LIMIT {
        return Err(PageRequestError::LimitTooLarge {
            max: MAX_PAGE_LIMIT,
            actual: limit,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cursor_rejects_empty_values() {
        assert_eq!(Cursor::new("   "), Err(CursorError::Empty));
    }

    #[test]
    fn page_request_uses_cursor_contract() {
        let cursor = Cursor::new("opaque-position").expect("valid cursor");
        let request = PageRequest::new(50, Some(cursor)).expect("valid page request");
        let value = serde_json::to_value(request).expect("serialize request");

        assert_eq!(value["limit"], json!(50));
        assert_eq!(value["cursor"], json!("opaque-position"));
        assert!(value.get("offset").is_none());
    }
}
