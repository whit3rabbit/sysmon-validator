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
    
    #[error("Schema Parsing Error: {0}")]
    SchemaError(String),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid schema version: {0}")]
    InvalidSchemaVersion(String),
    
    #[error("Schema validation failed: {0}")]
    SchemaValidationError(String),

    #[error("Failed to read schema file: {0}")]
    SchemaFileError(String),

    #[error("Failed to parse schema: {0}")]
    SchemaParseError(String),

    #[error("Schema validation failed: {0}")]
    SchemaValidationFailed(String),

    #[error("No matching schema found for version {0}")]
    NoMatchingSchema(String),

    #[error("Invalid schema file: {0}")]
    InvalidSchemaFile(String),

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

    #[error("Invalid field name '{1}' for event type '{0}'")]
    InvalidFieldName(String, String),

    #[error("Invalid format for field '{0}': {1}")]
    InvalidFieldFormat(String, String),

    #[error("Missing required field '{1}' for event type '{0}'")]
    MissingRequiredField(String, String),

    #[error("Value too long for field '{0}' (max: {1})")]
    FieldValueTooLong(String, usize),

    // New version-specific error variants
    #[error("Empty version string")]
    EmptyVersion,

    #[error("Invalid version format: {0}")]
    InvalidVersionFormat(String),

    #[error("Invalid major version number: {0}")]
    InvalidMajorVersion(String),

    #[error("Invalid minor version number: {0}")]
    InvalidMinorVersion(String),
}

// Helper functions for common validation error patterns
impl ValidationError {
    pub fn schema_not_found(version: &str) -> Self {
        ValidationError::NoMatchingSchema(version.to_string())
    }
    
    pub fn invalid_schema(details: &str) -> Self {
        ValidationError::InvalidSchemaFile(details.to_string())
    }
    
    pub fn validation_failed(details: &str) -> Self {
        ValidationError::SchemaValidationFailed(details.to_string())
    }

    // New helper functions for version validation
    pub fn invalid_version_format(details: &str) -> Self {
        ValidationError::InvalidVersionFormat(details.to_string())
    }

    pub fn invalid_major_version(version: &str) -> Self {
        ValidationError::InvalidMajorVersion(version.to_string())
    }

    pub fn invalid_minor_version(version: &str) -> Self {
        ValidationError::InvalidMinorVersion(version.to_string())
    }

    /// Validates a version string format and returns a Result
    pub fn validate_version(version: &str) -> Result<f32, Self> {
        if version.is_empty() {
            return Err(ValidationError::EmptyVersion);
        }

        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 2 {
            return Err(ValidationError::invalid_version_format(
                "Version must have major and minor numbers separated by dot"
            ));
        }

        let major = parts[0].parse::<u32>()
            .map_err(|_| ValidationError::invalid_major_version(parts[0]))?;

        let minor = parts[1].parse::<u32>()
            .map_err(|_| ValidationError::invalid_minor_version(parts[1]))?;

        Ok(major as f32 + (minor as f32 / 100.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_messages() {
        let error = ValidationError::schema_not_found("4.22");
        assert_eq!(
            error.to_string(),
            "No matching schema found for version 4.22"
        );

        let error = ValidationError::invalid_schema("Invalid structure");
        assert_eq!(
            error.to_string(),
            "Invalid schema file: Invalid structure"
        );

        let error = ValidationError::validation_failed("Missing required element");
        assert_eq!(
            error.to_string(),
            "Schema validation failed: Missing required element"
        );
    }

    #[test]
    fn test_parser_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let parser_error = ParserError::IoError(io_error);
        assert!(parser_error.to_string().contains("File not found"));
    }

    #[test]
    fn test_version_validation() {
        // Test valid versions
        assert!(ValidationError::validate_version("4.22").is_ok());
        assert!(ValidationError::validate_version("10.0").is_ok());

        // Test empty version
        match ValidationError::validate_version("") {
            Err(ValidationError::EmptyVersion) => {},
            _ => panic!("Expected EmptyVersion error"),
        }

        // Test invalid format
        match ValidationError::validate_version("4") {
            Err(ValidationError::InvalidVersionFormat(_)) => {},
            _ => panic!("Expected InvalidVersionFormat error"),
        }

        // Test invalid major version
        match ValidationError::validate_version("invalid.22") {
            Err(ValidationError::InvalidMajorVersion(_)) => {},
            _ => panic!("Expected InvalidMajorVersion error"),
        }

        // Test invalid minor version
        match ValidationError::validate_version("4.invalid") {
            Err(ValidationError::InvalidMinorVersion(_)) => {},
            _ => panic!("Expected InvalidMinorVersion error"),
        }
    }

    #[test]
    fn test_version_error_messages() {
        assert_eq!(
            ValidationError::EmptyVersion.to_string(),
            "Empty version string"
        );

        assert_eq!(
            ValidationError::invalid_version_format("bad format").to_string(),
            "Invalid version format: bad format"
        );

        assert_eq!(
            ValidationError::invalid_major_version("abc").to_string(),
            "Invalid major version number: abc"
        );

        assert_eq!(
            ValidationError::invalid_minor_version("xyz").to_string(),
            "Invalid minor version number: xyz"
        );
    }
}