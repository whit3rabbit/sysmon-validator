use quick_xml::Error as XmlError;
use quick_xml::events::attributes::AttrError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("XML Parsing Error: {0}")]
    XmlError(#[from] XmlError),

    #[error("Attribute Error: {0}")]
    AttrError(#[from] AttrError),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid schema version: {0}")]
    InvalidSchemaVersion(String),
    #[error("Unsupported operator: {0}")]
    UnsupportedOperator(String),
    #[error("Event type '{0}' has multiple include/exclude filters")]
    MultipleFilters(String),
    #[error("RuleGroup '{0}' contains multiple EventTypes")]
    MultipleEventTypesInRuleGroup(String),
    #[error("Invalid event type: {0}")]
    InvalidEventType(String),
    #[error("Event type '{0}' is not filterable")]
    NonFilterableEventType(String),
    #[error("Invalid groupRelation value: {0}")]
    InvalidGroupRelation(String),
}
