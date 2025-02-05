use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use roxmltree;
use log::{debug, error, info, warn};
use include_dir::{include_dir, Dir};
use crate::errors::ValidationError;

// Include the schemas directory in the binary
static SCHEMAS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/schemas");

/// Handles loading and validation of schema files
pub struct XsdValidator {
    schema_paths: HashMap<String, String>, // Changed to String to store filenames
    schema_contents: HashMap<String, String>,
}

impl XsdValidator {

    /// Creates a new XsdValidator instance without loading embedded schemas (for testing)
    #[cfg(test)]
    pub fn new_for_testing() -> Self {
        XsdValidator {
            schema_paths: HashMap::new(),
            schema_contents: HashMap::new(),
        }
    }

    /// Creates a new XsdValidator instance and loads embedded schemas
    pub fn new() -> Self {
        let mut validator = XsdValidator {
            schema_paths: HashMap::new(),
            schema_contents: HashMap::new(),
        };
        
        // Load embedded schemas
        for file in SCHEMAS_DIR.files() {
            if let Some(filename) = file.path().file_name().and_then(|n| n.to_str()) {
                if filename.ends_with(".xsd") {
                    if let Some(version) = validator.extract_version_from_filename(filename) {
                        if let Ok(content) = std::str::from_utf8(file.contents()) {
                            info!("Loaded embedded schema version {}", version);
                            validator.schema_contents.insert(version.clone(), content.to_string());
                            validator.schema_paths.insert(version, filename.to_string());
                        }
                    }
                }
            }
        }

        validator
    }
   
    /// Loads additional schema files from the specified directory
    pub fn load_schemas<P: AsRef<Path>>(&mut self, schema_dir: P) -> std::io::Result<()> {
        let schema_dir = schema_dir.as_ref();
        if !schema_dir.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Schema directory not found: {}", schema_dir.display())
            ));
        }

        let mut found_any = false;
        for entry in fs::read_dir(schema_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("xsd") {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(version) = self.extract_version_from_filename(filename) {
                        match fs::read_to_string(&path) {
                            Ok(schema_content) => {
                                info!("Loading schema version: {}", version);
                                self.schema_contents.insert(version.clone(), schema_content);
                                self.schema_paths.insert(version, path.to_string_lossy().into_owned());
                                found_any = true;
                            }
                            Err(e) => {
                                error!("Failed to read schema file {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        // Debug print the loaded versions
        info!("Loaded schema versions: {:?}", self.schema_paths.keys().collect::<Vec<_>>());

        if !found_any {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No valid schema files found"
            ));
        }

        Ok(())
    }

    /// Gets the path for a specific schema version
    pub fn get_schema_path(&self, version: &str) -> Option<PathBuf> {
        self.schema_paths.get(version).map(|p| PathBuf::from(p))
    }

    /// Extracts version from schema filename (e.g., "v4_22_schema.xsd" -> "4.22")
    fn extract_version_from_filename<P: AsRef<str>>(&self, filename: P) -> Option<String> {
        let filename = filename.as_ref();
        
        // Try v-format first (v4_22_schema.xsd)
        let v_format = regex::Regex::new(r"^v(\d+)_(\d+)_schema\.xsd$").unwrap();
        if let Some(caps) = v_format.captures(filename) {
            return Some(format!("{}.{}", &caps[1], &caps[2]));
        }
        
        // Try sysmon format (sysmonconfig-schema-4.22.xsd)
        let sysmon_format = regex::Regex::new(r"^sysmonconfig-schema-(\d+\.\d+)\.xsd$").unwrap();
        if let Some(caps) = sysmon_format.captures(filename) {
            return Some(caps[1].to_string());
        }
        
        None
    }

    /// Validates XML content against the schema
    pub fn validate_xml(&self, xml_content: &str, version: &str) -> Result<(), ValidationError> {
        debug!("Starting XML validation for version {}", version);
        
        // Parse the XML document
        let doc = roxmltree::Document::parse(xml_content)
            .map_err(|e| ValidationError::SchemaValidationError(e.to_string()))?;

        // Basic structure validation
        let root = doc.root_element();
        
        // Verify root element is Sysmon
        if root.tag_name().name() != "Sysmon" {
            return Err(ValidationError::SchemaValidationError(
                "Root element must be 'Sysmon'".to_string()
            ));
        }

        // Verify schema version attribute
        let schema_version = root.attribute("schemaversion")
            .ok_or_else(|| ValidationError::SchemaValidationError(
                "Missing 'schemaversion' attribute".to_string()
            ))?;

        // Verify the schema version matches what was requested
        if schema_version != version {
            return Err(ValidationError::SchemaValidationError(
                format!("Schema version mismatch: XML specifies '{}' but '{}' was requested", 
                       schema_version, version)
            ));
        }

        // Find compatible schema version
        self.find_compatible_schema_version(version)?;

        // Verify EventFiltering element exists and validate its structure
        self.validate_event_filtering(&root)?;

        Ok(())
    }

    /// Validates the EventFiltering section of the XML
    fn validate_event_filtering(&self, root: &roxmltree::Node) -> Result<(), ValidationError> {
        let event_filtering = root.children()
            .find(|n| n.is_element() && n.tag_name().name() == "EventFiltering")
            .ok_or_else(|| ValidationError::SchemaValidationError(
                "Missing 'EventFiltering' element".to_string()
            ))?;

        // Verify at least one RuleGroup exists
        let rule_groups: Vec<_> = event_filtering.children()
            .filter(|n| n.is_element() && n.tag_name().name() == "RuleGroup")
            .collect();

        if rule_groups.is_empty() {
            return Err(ValidationError::SchemaValidationError(
                "At least one 'RuleGroup' element is required".to_string()
            ));
        }

        // Validate each RuleGroup
        for rule_group in rule_groups {
            self.validate_rule_group(&rule_group)?;
        }

        Ok(())
    }

    /// Validates a RuleGroup element
    fn validate_rule_group(&self, rule_group: &roxmltree::Node) -> Result<(), ValidationError> {
        // Check for required name attribute
        if rule_group.attribute("name").is_none() {
            warn!("RuleGroup missing 'name' attribute");
        }

        // Validate groupRelation if present
        if let Some(relation) = rule_group.attribute("groupRelation") {
            let relation_lower = relation.to_lowercase();
            if relation_lower != "or" && relation_lower != "and" {
                return Err(ValidationError::SchemaValidationError(
                    format!("Invalid groupRelation value: {}", relation)
                ));
            }
        }

        // Must contain at least one event type
        let has_events = rule_group.children().any(|n| 
            n.is_element() && !matches!(n.tag_name().name(), "RuleGroup")
        );

        if !has_events {
            return Err(ValidationError::SchemaValidationError(
                "RuleGroup must contain at least one event type".to_string()
            ));
        }

        Ok(())
    }

    /// Helper method to validate version format
    pub fn validate_version_format(version: &str) -> Result<f32, ValidationError> {
        if version.is_empty() {
            return Err(ValidationError::EmptyVersion);
        }

        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 2 {
            return Err(ValidationError::invalid_version_format(
                &format!("Version must have major and minor numbers separated by dot: {}", version)
            ));
        }

        let major = parts[0].parse::<u32>()
            .map_err(|_| ValidationError::invalid_major_version(parts[0]))?;

        let minor = parts[1].parse::<u32>()
            .map_err(|_| ValidationError::invalid_minor_version(parts[1]))?;

        Ok(major as f32 + (minor as f32 / 100.0))
    }

    /// Checks if a specific schema version is available
    pub fn has_schema_version(&self, version: &str) -> bool {
        debug!("Checking version availability: {}", version);
        debug!("Available versions: {:?}", self.schema_paths.keys().collect::<Vec<_>>());
        
        // First validate the version format
        match Self::validate_version_format(version) {
            Ok(version_num) => {
                // Only return true if we have an exact match
                let has_version = self.schema_paths.contains_key(version);
                debug!("Version {} (number: {}) availability: {}", version, version_num, has_version);
                has_version
            },
            Err(e) => {
                warn!("Invalid version format: {}", e);
                false
            }
        }
    }

    /// Gets a compatible version string if one exists
    pub fn get_compatible_version(&self, version: &str) -> Option<String> {
        debug!("Finding compatible version for: {}", version);
        
        match Self::validate_version_format(version) {
            Ok(target_version) => {
                let mut compatible_versions: Vec<(f32, &String)> = self.schema_paths.keys()
                    .filter_map(|ver| {
                        Self::validate_version_format(ver)
                            .ok()
                            .filter(|&v| v <= target_version)
                            .map(|v| (v, ver))
                    })
                    .collect();

                compatible_versions.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
                
                debug!("Found compatible versions: {:?}", compatible_versions);
                
                compatible_versions.first().map(|(_, ver)| (*ver).clone())
            },
            Err(e) => {
                warn!("Invalid version format while finding compatible version: {}", e);
                None
            }
        }
    }

    /// Internal method to find compatible schema content for validation
    fn find_compatible_schema_version(&self, target_version: &str) -> Result<&String, ValidationError> {
        let target_num = Self::version_to_float(target_version)
            .map_err(|_| ValidationError::InvalidSchemaVersion(target_version.to_string()))?;

        let mut compatible_versions: Vec<(f32, &String)> = self.schema_contents
            .keys()
            .filter_map(|ver| {
                Self::version_to_float(ver)
                    .ok()
                    .filter(|&v| v <= target_num)
                    .map(|v| (v, ver))
            })
            .collect();

        compatible_versions.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        compatible_versions
            .first()
            .map(|(_, ver)| self.schema_contents.get(*ver).unwrap())
            .ok_or_else(|| ValidationError::NoMatchingSchema(target_version.to_string()))
    }

    /// Parse version string into float for comparison
    fn version_to_float(version: &str) -> Result<f32, ValidationError> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 2 {
            return Err(ValidationError::InvalidSchemaVersion(
                format!("Invalid version format: {}", version)
            ));
        }

        let major = parts[0].parse::<u32>()
            .map_err(|_| ValidationError::InvalidSchemaVersion(version.to_string()))?;
        let minor = parts[1].parse::<u32>()
            .map_err(|_| ValidationError::InvalidSchemaVersion(version.to_string()))?;

        Ok(major as f32 + (minor as f32 / 100.0))
    }

    /// Returns list of available schema versions
    pub fn available_versions(&self) -> Vec<String> {
        let mut versions: Vec<String> = self.schema_paths.keys().cloned().collect();
        versions.sort_by(|a, b| {
            let a_num = Self::version_to_float(a).unwrap_or(0.0);
            let b_num = Self::version_to_float(b).unwrap_or(0.0);
            a_num.partial_cmp(&b_num).unwrap_or(std::cmp::Ordering::Equal)
        });
        versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;

    // Helper function to create a test XML content
    fn create_test_xml(version: &str, valid: bool) -> String {
        if valid {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
                <Sysmon schemaversion="{}">
                    <EventFiltering>
                        <RuleGroup name="Test Group" groupRelation="or">
                            <ProcessCreate onmatch="include"/>
                        </RuleGroup>
                    </EventFiltering>
                </Sysmon>"#,
                version
            )
        } else {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
                <Sysmon schemaversion="{}">
                    <EventFiltering>
                        <InvalidElement/>
                    </EventFiltering>
                </Sysmon>"#,
                version
            )
        }
    }

    fn create_test_schema(dir: &Path, version: &str) -> std::io::Result<PathBuf> {
        let schema_content = r#"<?xml version="1.0" encoding="UTF-8"?>
            <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
                <!-- Test schema content -->
            </xs:schema>"#;
        
        let schema_path = dir.join(format!("v{}_schema.xsd", version.replace(".", "_")));
        let mut file = File::create(&schema_path)?;
        write!(file, "{}", schema_content)?;
        Ok(schema_path)
    }

    #[test]
    fn test_schema_loading() -> std::io::Result<()> {
        let temp_dir = TempDir::new()?;
        
        // Create test schemas
        create_test_schema(&temp_dir.path(), "4.22")?;
        create_test_schema(&temp_dir.path(), "4.30")?;

        let mut validator = XsdValidator::new_for_testing();
        validator.load_schemas(temp_dir.path())?;

        // Debug print loaded schemas
        println!("Loaded schemas: {:?}", validator.schema_paths.keys().collect::<Vec<_>>());
        
        assert!(validator.has_schema_version("4.22"), "4.22 should be available");
        assert!(validator.has_schema_version("4.30"), "4.30 should be available");
        assert!(!validator.has_schema_version("4.50"), "4.50 should not be available");

        Ok(())
    }

    #[test]
    fn test_version_compatibility() {
        let mut validator = XsdValidator::new_for_testing();
        let temp_dir = TempDir::new().unwrap();
        
        create_test_schema(&temp_dir.path(), "4.22").unwrap();
        create_test_schema(&temp_dir.path(), "4.30").unwrap();
        
        validator.load_schemas(temp_dir.path()).unwrap();

        assert!(!validator.has_schema_version("4.50"));
        
        // Test compatible version finding
        assert_eq!(validator.get_compatible_version("4.22"), Some("4.22".to_string()));
        assert_eq!(validator.get_compatible_version("4.25"), Some("4.22".to_string()));
        assert_eq!(validator.get_compatible_version("4.30"), Some("4.30".to_string()));
        assert_eq!(validator.get_compatible_version("4.50"), Some("4.30".to_string()));
        assert_eq!(validator.get_compatible_version("3.00"), None);
    }

    #[test]
    fn test_version_availability() {
        let mut validator = XsdValidator::new_for_testing();
        let temp_dir = TempDir::new().unwrap();
        
        create_test_schema(&temp_dir.path(), "4.22").unwrap();
        create_test_schema(&temp_dir.path(), "4.30").unwrap();
        
        validator.load_schemas(temp_dir.path()).unwrap();

        // Debug print loaded schemas
        println!("Loaded schemas: {:?}", validator.schema_paths.keys().collect::<Vec<_>>());
        
        assert!(validator.has_schema_version("4.22"));
        assert!(validator.has_schema_version("4.30"));
        assert!(!validator.has_schema_version("4.50"), "4.50 should not be available");
        assert!(!validator.has_schema_version("3.00"));
        assert!(!validator.has_schema_version("4.25"));
    }

    #[test]
    fn test_empty_schema_directory() {
        let temp_dir = TempDir::new().unwrap();
        let mut validator = XsdValidator::new_for_testing();
        
        assert!(validator.load_schemas(temp_dir.path()).is_err());
    }

    #[test]
    fn test_invalid_schema_directory() {
        let mut validator = XsdValidator::new_for_testing();
        assert!(validator.load_schemas("/nonexistent/path").is_err());
    }

    #[test]
    fn test_validate_xml_structure() {
        let mut validator = XsdValidator::new_for_testing();
        let temp_dir = TempDir::new().unwrap();
        
        create_test_schema(&temp_dir.path(), "4.30").unwrap();
        validator.load_schemas(temp_dir.path()).unwrap();
    
        // Test with valid XML
        let valid_xml = create_test_xml("4.30", true);
        assert!(validator.validate_xml(&valid_xml, "4.30").is_ok());
    
        // Test with missing Sysmon root element
        let invalid_xml = r#"<?xml version="1.0"?><NotSysmon></NotSysmon>"#;
        assert!(validator.validate_xml(invalid_xml, "4.30").is_err());
    
        // Test with missing schemaversion attribute
        let invalid_xml = r#"<?xml version="1.0"?><Sysmon></Sysmon>"#;
        assert!(validator.validate_xml(invalid_xml, "4.30").is_err());
    
        // Test with missing EventFiltering element
        let invalid_xml = r#"<?xml version="1.0"?><Sysmon schemaversion="4.30"></Sysmon>"#;
        assert!(validator.validate_xml(invalid_xml, "4.30").is_err());
    }
    
    #[test]
    fn test_validate_rule_groups() {
        let mut validator = XsdValidator::new_for_testing();
        let temp_dir = TempDir::new().unwrap();
        
        create_test_schema(&temp_dir.path(), "4.30").unwrap();
        validator.load_schemas(temp_dir.path()).unwrap();
    
        // Test with empty RuleGroup
        let invalid_xml = r#"<?xml version="1.0"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="Empty Group" groupRelation="or">
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
        assert!(validator.validate_xml(invalid_xml, "4.30").is_err());
    
        // Test with invalid groupRelation
        let invalid_xml = r#"<?xml version="1.0"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="Test Group" groupRelation="invalid">
                        <ProcessCreate onmatch="include"/>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
        assert!(validator.validate_xml(invalid_xml, "4.30").is_err());
    }
    
    #[test]
    fn test_version_format_validation() {
        // Test valid version formats
        assert!(XsdValidator::validate_version_format("4.30").is_ok());
        assert!(XsdValidator::validate_version_format("10.05").is_ok());
        
        // Test invalid version formats
        assert!(XsdValidator::validate_version_format("").is_err());
        assert!(XsdValidator::validate_version_format("4").is_err());
        assert!(XsdValidator::validate_version_format("4.30.1").is_err());
        assert!(XsdValidator::validate_version_format("a.30").is_err());
        assert!(XsdValidator::validate_version_format("4.b").is_err());
    }
    
    #[test]
    fn test_schema_version_extraction() {
        let validator = XsdValidator::new_for_testing();
        
        // Test v-format filenames
        assert_eq!(validator.extract_version_from_filename("v4_22_schema.xsd"), 
                  Some("4.22".to_string()));
        assert_eq!(validator.extract_version_from_filename("v10_05_schema.xsd"), 
                  Some("10.05".to_string()));
    
        // Test sysmon format filenames
        assert_eq!(validator.extract_version_from_filename("sysmonconfig-schema-4.22.xsd"), 
                  Some("4.22".to_string()));
        assert_eq!(validator.extract_version_from_filename("sysmonconfig-schema-10.05.xsd"), 
                  Some("10.05".to_string()));
    
        // Test invalid filenames
        assert_eq!(validator.extract_version_from_filename("invalid.xsd"), None);
        assert_eq!(validator.extract_version_from_filename("v4_22.xsd"), None);
        assert_eq!(validator.extract_version_from_filename("schema-4.22.xsd"), None);
    }
    
    #[test]
    fn test_available_versions_sorting() {
        let mut validator = XsdValidator::new_for_testing();
        let temp_dir = TempDir::new().unwrap();
        
        // Create schemas in non-sorted order
        create_test_schema(&temp_dir.path(), "4.30").unwrap();
        create_test_schema(&temp_dir.path(), "4.22").unwrap();
        create_test_schema(&temp_dir.path(), "10.05").unwrap();
        
        validator.load_schemas(temp_dir.path()).unwrap();
        
        let versions = validator.available_versions();
        assert_eq!(versions, vec!["4.22", "4.30", "10.05"]);
    }
    
    #[test]
    fn test_concurrent_schema_loading() {
        use std::sync::Arc;
        use std::thread;
    
        let temp_dir = TempDir::new().unwrap();
        create_test_schema(&temp_dir.path(), "4.30").unwrap();
        
        let temp_dir_path = Arc::new(temp_dir.path().to_path_buf());
        
        let mut handles = vec![];
        
        for _ in 0..3 {
            let temp_dir = Arc::clone(&temp_dir_path);
            let handle = thread::spawn(move || {
                let mut validator = XsdValidator::new_for_testing();
                validator.load_schemas(&*temp_dir).unwrap();
                assert!(validator.has_schema_version("4.30"));
            });
            handles.push(handle);
        }
    
        for handle in handles {
            handle.join().unwrap();
        }
    }
}