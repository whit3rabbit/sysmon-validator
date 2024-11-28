use crate::errors::ValidationError;
use crate::models::*;
use log::info;

use std::collections::HashMap;

const VALID_EVENT_TYPES: &[&str] = &[
    "ProcessCreate",          // Event ID 1
    "FileCreateTime",         // Event ID 2
    "NetworkConnect",         // Event ID 3
    "ProcessTerminate",       // Event ID 5
    "DriverLoad",             // Event ID 6
    "ImageLoad",              // Event ID 7
    "CreateRemoteThread",     // Event ID 8
    "RawAccessRead",          // Event ID 9
    "ProcessAccess",          // Event ID 10
    "FileCreate",             // Event ID 11
    "RegistryEvent",          // Event IDs 12,13,14
    "FileCreateStreamHash",   // Event ID 15
    "PipeEvent",              // Event IDs 17,18
    "WmiEvent",               // Event IDs 19,20,21
    "DnsQuery",               // Event ID 22
    "FileDelete",             // Event ID 23
    "ClipboardChange",        // Event ID 24
    "ProcessTampering",       // Event ID 25
    "FileDeleteDetected",     // Event ID 26
    "FileBlockExecutable",    // Event ID 27
    "FileBlockShredding",     // Event ID 28
    "FileExecutableDetected", // Event ID 29
];

const NON_FILTERABLE_EVENT_TYPES: &[&str] = &[
    "ServiceConfigurationChange", // Event ID 16
    "Error",                      // Event ID 255
];

pub fn validate_sysmon_config(config: &SysmonConfig) -> Result<(), ValidationError> {
    // Validate schema version
    if let Some(version) = &config.schema_version {
        info!("Validating schema version: {}", version);
        if version.parse::<f32>().unwrap_or(0.0) < 4.22 {
            return Err(ValidationError::InvalidSchemaVersion(version.clone()));
        }
    }

    // Validate EventFiltering
    if let Some(ref event_filtering) = config.event_filtering {
        let mut event_type_filters: HashMap<String, (usize, usize)> = HashMap::new();

        for rule_group in &event_filtering.rule_groups {
            info!("Validating RuleGroup: {:?}", rule_group.name);

            let group_relation = rule_group.group_relation.as_deref().unwrap_or("or");
            
            // Check for invalid characters in groupRelation
            if group_relation.contains('|') {
                return Err(ValidationError::InvalidGroupRelation(
                    format!("'{}' contains invalid character '|'", group_relation)
                ));
            }
            
            // Check if it's a valid value
            if !["and", "or"].contains(&group_relation.to_lowercase().as_str()) {
                return Err(ValidationError::InvalidGroupRelation(
                    format!("'{}' must be either 'and' or 'or'", group_relation)
                ));
            }

            // Ensure only one EventType per RuleGroup
            let mut event_types_in_group = HashMap::new();

            for event in &rule_group.events {
                let event_type = &event.event_type;
                
                // First check if it's a non-filterable event type
                let event_type_lower = event_type.trim().to_lowercase();
                if NON_FILTERABLE_EVENT_TYPES
                    .iter()
                    .any(|&et| et.eq_ignore_ascii_case(&event_type_lower))
                {
                    return Err(ValidationError::NonFilterableEventType(event_type.clone()));
                }

                // Then check if it's a valid event type
                if !VALID_EVENT_TYPES
                    .iter()
                    .any(|&et| et.eq_ignore_ascii_case(&event_type_lower))
                {
                    return Err(ValidationError::InvalidEventType(event_type.clone()));
                }

                *event_types_in_group.entry(event_type.clone()).or_insert(0) += 1;

                let onmatch = event.onmatch.as_deref().unwrap_or("exclude");
                if !["include", "exclude"].contains(&onmatch) {
                    return Err(ValidationError::UnsupportedOperator(onmatch.to_string()));
                }

                if let Some(counts) = event_type_filters.get_mut(event_type) {
                    if onmatch.eq_ignore_ascii_case("include") {
                        counts.0 += 1;
                    } else {
                        counts.1 += 1;
                    }
                } else {
                    if onmatch.eq_ignore_ascii_case("include") {
                        event_type_filters.insert(event_type.clone(), (1, 0));
                    } else {
                        event_type_filters.insert(event_type.clone(), (0, 1));
                    }
                }

                // Check if multiple include/exclude filters exist for the same EventType
                let counts = event_type_filters.get(event_type).unwrap();
                if counts.0 > 1 || counts.1 > 1 {
                    return Err(ValidationError::MultipleFilters(event_type.clone()));
                }

                // Validate conditions within the event
                for field in &event.fields {
                    validate_condition(&field)?;
                }
            }

            // Ensure only one EventType per RuleGroup
            if event_types_in_group.len() > 1 {
                return Err(ValidationError::MultipleEventTypesInRuleGroup(
                    rule_group.name.clone().unwrap_or_default(),
                ));
            }
        }
    }

    Ok(())
}

fn validate_condition(field: &Field) -> Result<(), ValidationError> {
    let valid_operators = vec![
        "is",
        "is any",
        "is not",
        "contains",
        "contains any",
        "contains all",
        "excludes",
        "excludes any",
        "excludes all",
        "begin with",
        "not begin with",
        "end with",
        "not end with",
        "less than",
        "more than",
        "image",
        ];

    // Convert operator to lowercase for comparison
    if let Some(ref operator) = field.condition {
        let operator_lower = operator.trim().to_lowercase();

        if !valid_operators
            .iter()
            .any(|op| op.eq_ignore_ascii_case(&operator_lower))
        {
            return Err(ValidationError::UnsupportedOperator(operator.clone()));
        }
    } else {
        // Handle the case where condition is None
        return Err(ValidationError::UnsupportedOperator(
            "Condition operator is missing".to_string(),
        ));
    }

    if field.value.trim().is_empty() {
        return Err(ValidationError::UnsupportedOperator(
            "Condition value cannot be empty".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_sysmon_config, parse_sysmon_config_from_str};
    use std::path::PathBuf;

    #[test]
    fn test_validate_valid_config() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/tests/test_configs/valid_config.xml");
        let config = parse_sysmon_config(path.to_str().unwrap()).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_schema_version() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/tests/test_configs/invalid_schema_version.xml");
        let config = parse_sysmon_config(path.to_str().unwrap()).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidSchemaVersion(_))
        ));
    }

    #[test]
    fn test_invalid_operator() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/tests/test_configs/invalid_operator.xml");
        let config = parse_sysmon_config(path.to_str().unwrap()).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(matches!(
            result,
            Err(ValidationError::UnsupportedOperator(_))
        ));
    }

    #[test]
    fn test_multiple_filters() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/tests/test_configs/multiple_filters.xml");
        let config = parse_sysmon_config(path.to_str().unwrap()).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(matches!(
            result,
            Err(ValidationError::MultipleFilters(_))
        ));
    }

    #[test]
    fn test_invalid_event_type() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/tests/test_configs/invalid_event_types.xml");
        let config = parse_sysmon_config(path.to_str().unwrap()).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidEventType(_))
        ));
    }

    #[test]
    fn test_non_filterable_event_type() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/tests/test_configs/non_filterable_event_type.xml");
        let config = parse_sysmon_config(path.to_str().unwrap()).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(
            matches!(result, Err(ValidationError::NonFilterableEventType(_))),
            "Expected NonFilterableEventType error, got {:?}",
            result
        );
    }

    #[test]
    fn test_operator_case_insensitivity() {
        let field = Field {
            name: "Image".to_string(),
            condition: Some("Is".to_string()), // Note the uppercase 'I'
            value: "C:\\Windows\\System32\\cmd.exe".to_string(),
        };
    
        let result = validate_condition(&field);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_group_relation() {
        let xml_content = r#"
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="InvalidGroupRelation" groupRelation="and|or">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>
        "#;
        
        let config = parse_sysmon_config_from_str(xml_content).unwrap();
        let result = validate_sysmon_config(&config);
        
        assert!(matches!(
            result,
            Err(ValidationError::InvalidGroupRelation(_))
        ));
        
        if let Err(ValidationError::InvalidGroupRelation(msg)) = result {
            assert!(msg.contains("'|'"), "Error message should mention the invalid '|' character");
        }
    }

    #[test]
    fn test_valid_group_relations() {
        let valid_relations = ["and", "or", "AND", "OR", "And", "Or"];
        
        for relation in valid_relations.iter() {
            let xml_content = format!(
                r#"
                <Sysmon schemaversion="4.30">
                    <EventFiltering>
                        <RuleGroup name="ValidGroupRelation" groupRelation="{}">
                            <ProcessCreate onmatch="include">
                                <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                            </ProcessCreate>
                        </RuleGroup>
                    </EventFiltering>
                </Sysmon>
                "#,
                relation
            );
            
            let config = parse_sysmon_config_from_str(&xml_content).unwrap();
            let result = validate_sysmon_config(&config);
            assert!(result.is_ok(), "Failed to validate groupRelation '{}'", relation);
        }
    }

    #[test]
    fn test_invalid_group_relation_value() {
        let xml_content = r#"
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="InvalidGroupRelation" groupRelation="invalid">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>
        "#;
        
        let config = parse_sysmon_config_from_str(xml_content).unwrap();
        let result = validate_sysmon_config(&config);
        
        assert!(matches!(
            result,
            Err(ValidationError::InvalidGroupRelation(_))
        ));
        
        if let Err(ValidationError::InvalidGroupRelation(msg)) = result {
            assert!(msg.contains("must be either 'and' or 'or'"), 
                "Error message should mention valid values");
        }
    }

}
