pub mod errors;
pub mod models;
pub mod parser;
pub mod validator;

pub use errors::{ParserError, ValidationError};
pub use models::SysmonConfig;
pub use parser::{parse_sysmon_config, parse_sysmon_config_from_str};
pub use validator::validate_sysmon_config;

/// Validates a Sysmon configuration from a string containing XML data.
///
/// # Arguments
/// * `xml_content` - A string containing the Sysmon configuration XML
///
/// # Returns
/// * `Result<(), Error>` - Ok(()) if validation passes, Error otherwise
///
/// # Example
/// ```no_run
/// use sysmon_validator::validate_config_from_str;
///
/// let xml_content = r#"
///     <Sysmon schemaversion="4.30">
///         <EventFiltering>
///             <!-- config content -->
///         </EventFiltering>
///     </Sysmon>
/// "#;
///
/// match validate_config_from_str(xml_content) {
///     Ok(()) => println!("Configuration is valid"),
///     Err(e) => eprintln!("Configuration error: {}", e),
/// }
/// ```
pub fn validate_config_from_str(xml_content: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_sysmon_config_from_str(xml_content)?;
    validate_sysmon_config(&config)?;
    Ok(())
}

/// Validates a Sysmon configuration file at the given path.
///
/// This is a convenience function that combines parsing and validation into a single call.
///
/// # Arguments
/// * `config_path` - Path to the Sysmon configuration XML file
///
/// # Returns
/// * `Result<(), Error>` - Ok(()) if validation passes, Error otherwise
///
/// # Example
/// ```rust
/// use sysmon_validator::validate_config;
///
/// match validate_config("path/to/config.xml") {
///     Ok(()) => println!("Configuration is valid"),
///     Err(e) => eprintln!("Configuration is invalid: {}", e),
/// }
/// ```
pub fn validate_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_sysmon_config(config_path)?;
    validate_sysmon_config(&config)?;
    Ok(())
}