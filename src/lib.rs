pub mod errors;
pub mod models;
pub mod parser;
pub mod validator;
pub mod xsd;

use std::path::Path;
pub use errors::ValidationError;
pub use models::SysmonConfig;
pub use parser::{parse_sysmon_config, parse_sysmon_config_from_str};
pub use validator::validate_sysmon_config;
pub use xsd::XsdValidator;

// Global XSD validator instance
use lazy_static::lazy_static;
use std::sync::Arc;

lazy_static! {
    static ref XSD_VALIDATOR: Arc<XsdValidator> = {
        let validator = XsdValidator::new();
        
        // Log available schema versions
        let versions = validator.available_versions();
        log::info!("Loaded embedded schema versions: {:?}", versions);
        
        Arc::new(validator)
    };
}

/// Validates a Sysmon configuration from a string containing XML data.
///
/// This function performs both structural validation and XSD schema validation:
/// 1. Parses and validates the basic XML structure
/// 2. Validates the configuration against Sysmon rules
/// 3. Validates against the appropriate XSD schema for the specified version
///
/// # Arguments
/// * `xml_content` - A string containing the Sysmon configuration XML
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) if validation passes
pub fn validate_config_from_str(xml_content: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the configuration
    let config = parse_sysmon_config_from_str(xml_content)?;
    
    // Get schema version
    let version = config.schema_version.as_ref().ok_or_else(|| {
        ValidationError::InvalidSchemaVersion("Missing schema version".to_string())
    })?;
    
    // Perform structural and rule validation
    validate_sysmon_config(&config)?;
    
    // Perform XSD validation
    XSD_VALIDATOR.validate_xml(xml_content, version)?;
    
    Ok(())
}

/// Validates a Sysmon configuration file at the given path.
///
/// This function reads the file and performs both structural and XSD schema validation.
///
/// # Arguments
/// * `config_path` - Path to the Sysmon configuration XML file
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) if validation passes
pub fn validate_config<P: AsRef<Path>>(config_path: P) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(&config_path)?;
    validate_config_from_str(&config_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_config_from_str() {
        // Valid configuration
        let valid_xml = r#"
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="TestGroup">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>
        "#;
        assert!(validate_config_from_str(valid_xml).is_ok());

        // Invalid configuration - wrong schema version
        let invalid_xml = r#"
            <Sysmon schemaversion="3.50">
                <EventFiltering>
                    <RuleGroup name="TestGroup">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>
        "#;
        assert!(validate_config_from_str(invalid_xml).is_err());

        // Invalid configuration - missing schema version
        let invalid_xml = r#"
            <Sysmon>
                <EventFiltering>
                    <RuleGroup name="TestGroup">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>
        "#;
        assert!(validate_config_from_str(invalid_xml).is_err());
    }

    #[test]
    fn test_validate_config_file() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test_config.xml");

        // Write a valid configuration
        let valid_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="TestGroup">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
        fs::write(&config_path, valid_xml)?;

        // Test validation
        assert!(validate_config(&config_path).is_ok());

        Ok(())
    }

    #[test]
    fn test_schema_version_validation() {
        // Test missing schema version
        let no_version_xml = r#"
            <Sysmon>
                <EventFiltering>
                    <RuleGroup name="TestGroup">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>
        "#;
        
        let result = validate_config_from_str(no_version_xml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing schema version"));
    }
}