use crate::errors::ValidationError;
use crate::models::*;
use log::info;
use regex::Regex;
use std::net::IpAddr;
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

const COMMON_FIELDS: &[&str] = &[
    "Rule"  // Rule is valid in any event type
];

pub fn validate_sysmon_config(config: &SysmonConfig) -> Result<(), ValidationError> {
    // Validate schema version
    if let Some(version) = &config.schema_version {
        info!("Validating schema version: {}", version);
        if version.parse::<f32>().unwrap_or(0.0) < 4.21 {
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
                validate_required_fields(event)?;
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

                // Update filter counts
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
                    //return Err(ValidationError::MultipleFilters(event_type.clone()));
                }

                // Enhanced field validation
                for field in &event.fields {
                    // Basic condition validation
                    validate_condition(&field)?;

                    // Event-specific field validation
                    match event_type_lower.as_str() {
                        "processcreate" => {
                            let valid_fields = [PROCESS_CREATE_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "networkconnect" => {
                            let valid_fields = [NETWORK_CONNECT_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "driverload" => {
                            let valid_fields = [DRIVER_LOAD_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "imageload" => {
                            let valid_fields = [IMAGE_LOAD_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "createremotethread" => {
                            let valid_fields = [CREATE_REMOTE_THREAD_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "filecreatetime" => {
                            let valid_fields = [FILE_CREATE_TIME_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "registryevent" => {
                            let valid_fields = [REGISTRY_EVENT_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "dnsquery" => {
                            let valid_fields = [DNS_QUERY_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        "filedelete" => {
                            let valid_fields = [FILE_DELETE_FIELDS, COMMON_FIELDS].concat();
                            validate_field_list(field, &valid_fields, event_type)?;
                        },
                        _ => {}

                    }

                    // Field-specific format validation
                    match field.name.as_str() {
                        // Process and thread IDs
                        "ProcessId" | "ParentProcessId" | "TargetProcessId" | "SourceProcessId" | "NewThreadId" => {
                            validate_numeric(field)?;
                        },
                        
                        // Time fields
                        "UtcTime" | "CreationUtcTime" | "PreviousCreationUtcTime" => {
                            validate_utc_timestamp(field)?;
                        },
                        
                        // GUID fields
                        name if name.ends_with("Guid") => {
                            validate_guid_format(field)?;
                        },
                        
                        // Network-related fields
                        "SourceIp" | "DestinationIp" => {
                            validate_ip_address(field)?;
                        },
                        "SourcePort" | "DestinationPort" => {
                            validate_port_number(field)?;
                        },
                        
                        // Registry fields
                        "TargetObject" if event_type == "RegistryEvent" => {
                            validate_registry_path(field)?;
                        },
                        
                        // Hash fields
                        "Hashes" => {
                            validate_hash_format(field)?;
                        },
                        
                        // Path fields
                        "Image" | "ImageLoaded" | "TargetFilename" => {
                            validate_windows_path(field)?;
                        },
                        
                        // Boolean fields
                        name if name.starts_with("Is") => {
                            validate_boolean(field)?;
                        },
                        
                        _ => {}
                    }

                    // Call the general field format validator
                    validate_field_format(field, event_type)?;
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

// Helper function to validate fields against a list of valid fields
fn validate_field_list(field: &Field, valid_fields: &[&str], event_type: &str) -> Result<(), ValidationError> {
    if !valid_fields.contains(&field.name.as_str()) {
        return Err(ValidationError::InvalidFieldName(
            event_type.to_string(),
            field.name.clone()
        ));
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

    // Fields that don't require conditions
    let no_condition_required = vec![
        "Rule",  // Rule elements use groupRelation instead of condition
        "GrantedAccess",
        "ProcessAccess",
        "Image", 
        "SourceImage",
        "TargetImage",
        "TargetFilename" 
    ];

    // Special handling for Rule elements
    if field.name == "Rule" {
        // Rules often use groupRelation attribute instead of condition
        if let Some(ref operator) = field.condition {
            let op_lower = operator.to_lowercase();
            if op_lower == "and" || op_lower == "or" {
                return Ok(());
            }
        }
        // If no condition/groupRelation is specified for Rule, that's okay too
        return Ok(());
    }

        // No validation needed for special fields
    if no_condition_required.contains(&field.name.as_str()) {
        return Ok(());
    }

    // Rest of validation remains the same
    if field.condition.is_none() {
        return Err(ValidationError::UnsupportedOperator(
            "Condition operator is missing".to_string(),
        ));
    }

    if let Some(ref operator) = field.condition {
        let operator_lower = operator.trim().to_lowercase();
        if !valid_operators
            .iter()
            .any(|op| op.eq_ignore_ascii_case(&operator_lower))
        {
            return Err(ValidationError::UnsupportedOperator(operator.clone()));
        }
    }

    Ok(())
}

const PROCESS_CREATE_FIELDS: &[&str] = &[
    "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", 
    "Description", "Product", "Company", "OriginalFileName", "CommandLine",
    "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId",
    "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId",
    "ParentImage", "ParentCommandLine", "ParentUser"
];

const NETWORK_CONNECT_FIELDS: &[&str] = &[
    "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "Protocol",
    "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", 
    "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp",
    "DestinationHostname", "DestinationPort", "DestinationPortName"
];

const DRIVER_LOAD_FIELDS: &[&str] = &[
    "UtcTime", "ImageLoaded", "Hashes", "Signed", "Signature", 
    "SignatureStatus"
];

const IMAGE_LOAD_FIELDS: &[&str] = &[
    "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded",
    "FileVersion", "Description", "Product", "Company", "OriginalFileName",
    "Hashes", "Signed", "Signature", "SignatureStatus"
];

const CREATE_REMOTE_THREAD_FIELDS: &[&str] = &[
    "UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage",
    "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId",
    "StartAddress", "StartModule", "StartFunction"
];

const FILE_CREATE_TIME_FIELDS: &[&str] = &[
    "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename",
    "CreationUtcTime", "PreviousCreationUtcTime"
];

const REGISTRY_EVENT_FIELDS: &[&str] = &[
    "UtcTime", "ProcessGuid", "ProcessId", "Image", "EventType", 
    "TargetObject", "Details", "NewName"  // NewName for RenameKey events
];

const DNS_QUERY_FIELDS: &[&str] = &[
    "UtcTime", "ProcessGuid", "ProcessId", "QueryName", "QueryStatus",
    "QueryResults", "Image"
];

const FILE_CREATE_FIELDS: &[&str] = &[
    "TargetFilename",  // The name of the file
    "Image",          // Process that created the file
    "ImageLoaded",    // Image that was loaded
    "SourceFilename", // Original file name
    "Rule",           // For nested rules
    "CreationUtcTime",// Creation time in UTC
    "PreviousCreationUtcTime", // Previous creation time
    "Hash",           // Hash of the file
    "Contents",       // Contents of the file (for specific cases)
    "User",          // User context
    "ProcessGuid",    // Process Guid
    "ProcessId",      // Process ID
    "IntegrityLevel", // Integrity level of the process
];

const FILE_DELETE_FIELDS: &[&str] = &[
    "TargetFilename", 
    "Image",
    "ImageLoaded",
    "User",
    "ProcessGuid",
    "ProcessId",
    "IntegrityLevel",
    "Hash",
    "Rule",
    "IsExecutable",
    "Archived"
];

const PROCESS_ACCESS_FIELDS: &[&str] = &[
    "SourceProcessId", 
    "SourceThreadId",
    "SourceImage",
    "TargetProcessId", 
    "TargetImage",
    "GrantedAccess", 
    "CallTrace"
];

fn is_valid_ipv4(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        addr.is_ipv4()
    } else {
        false
    }
}

fn is_valid_ipv6(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        addr.is_ipv6()
    } else {
        false
    }
}

pub fn validate_hash_length(hash: &str, expected_length: usize) -> Result<(), ValidationError> {
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) || hash.len() != expected_length {
        return Err(ValidationError::InvalidFieldFormat(
            "hash".to_string(),
            format!("Hash must be {} hexadecimal characters", expected_length)
        ));
    }
    Ok(())
}

pub fn validate_registry_path(field: &Field) -> Result<(), ValidationError> {
    // If we're doing a "begin with", "end with", or "contains" match,
    // skip strict registry-path validation
    if let Some(cond) = &field.condition {
        let cond_lower = cond.to_lowercase();
        if cond_lower.contains("begin with")
            || cond_lower.contains("end with")
            || cond_lower.contains("contains")
        {
            return Ok(());
        }
    }

    // Otherwise, do the normal strict check
    let path = field.value.to_uppercase();
    if !path.starts_with("HKEY_") && !path.starts_with("HKLM\\") && !path.starts_with("HKCU\\") {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Invalid registry path format".to_string()
        ));
    }
    Ok(())
}

pub fn validate_windows_path(field: &Field) -> Result<(), ValidationError> {
    // First, trim the whitespace and strip leading/trailing quotes if present.
    let mut path_str = field.value.trim().to_string();
    if path_str.starts_with('"') && path_str.ends_with('"') && path_str.len() > 1 {
        // Remove the outer quotes
        path_str = path_str[1..path_str.len() - 1].to_string();
    }

    // If the Image is literally "System", allow it
    if path_str.eq_ignore_ascii_case("system") {
        return Ok(());
    }

    // If partial-match operators are used, skip strict validation.
    if let Some(cond) = &field.condition {
        let cond_lower = cond.to_lowercase();
        if cond_lower.contains("begin with")
            || cond_lower.contains("end with")
            || cond_lower.contains("contains")
        {
            return Ok(());
        }
    }

    // If the rule's condition is "image", skip strict path checks
    if field.condition
       .as_ref()
       .map(|c| c.to_lowercase()) 
       == Some("image".to_string()) 
    {
        return Ok(());
    }

    // 2. Handle paths with variables or wildcards
    if path_str.contains('%') || path_str.contains('*') || path_str.contains(';') {
        return Ok(());
    }

    // 3. Handle special Sysmon paths
    if path_str == "\\Appdata\\Local\\" || path_str.starts_with('\\') {
        return Ok(());
    }

    // 4. Handle paths without drive letters but with valid Windows format
    if path_str.starts_with('\\') || path_str.starts_with("Program Files") {
        return Ok(());
    }

    // 5. Handle full Windows paths
    if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
        // Basic Windows path validation
        let drive_letter = path_str.chars().next().unwrap().to_ascii_uppercase();
        if drive_letter.is_ascii_alphabetic() {
            return Ok(());
        }
    }

    // 6. Handle relative paths with environment variables
    if path_str.contains("AppData") || path_str.contains("..\\") {
        return Ok(());
    }

    // 7. Handle exe names without a path (case-insensitive .exe)
    let lower = path_str.to_lowercase();
    if field.name == "Image" && !lower.contains('\\') && lower.ends_with(".exe") {
        return Ok(());
    }

    // 8. Finally, allow typical drive-letter paths
    let re_winpath = regex::Regex::new(r"^[A-Za-z]:\\").unwrap();
    if re_winpath.is_match(&path_str) {
        return Ok(());
    }

    Err(ValidationError::InvalidFieldFormat(
        field.name.clone(),
        "Invalid Windows path format".to_string(),
    ))
}

pub fn validate_boolean(field: &Field) -> Result<(), ValidationError> {
    match field.value.to_lowercase().as_str() {
        "true" | "false" => Ok(()),
        _ => Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Value must be 'true' or 'false'".to_string()
        ))
    }
}

pub fn validate_numeric(field: &Field) -> Result<(), ValidationError> {
    if field.value.trim().is_empty() {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Value cannot be empty".to_string()
        ));
    }
    
    if !field.value.chars().all(char::is_numeric) {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Must be numeric".to_string()
        ));
    }
    
    // For ProcessId and Status fields, validate range
    match field.name.as_str() {
        "ProcessId" | "ParentProcessId" | "TargetProcessId" | "SourceProcessId" => {
            if let Ok(num) = field.value.parse::<u32>() {
                if num == 0 && field.name.as_str() != "ParentProcessId" {
                    return Err(ValidationError::InvalidFieldFormat(
                        field.name.clone(),
                        "Process ID cannot be 0".to_string()
                    ));
                }
            }
        },
        "Status" => {
            if let Ok(num) = field.value.parse::<u64>() {
                if num > u32::MAX as u64 {
                    return Err(ValidationError::InvalidFieldFormat(
                        field.name.clone(),
                        format!("Status value out of range (max: {})", u32::MAX)
                    ));
                }
            }
        },
        _ => {}
    }
    
    Ok(())
}

pub fn validate_utc_timestamp(field: &Field) -> Result<(), ValidationError> {
    // Extract date parts
    let parts: Vec<&str> = field.value.split(|c| c == ' ' || c == 'T').collect();
    if parts.len() != 2 {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Invalid UTC timestamp format".to_string()
        ));
    }

    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Invalid date format".to_string()
        ));
    }

    // Validate date parts - we only care if year parses successfully, don't need the value
    if let (Ok(_), Ok(month), Ok(day)) = (
        date_parts[0].parse::<u32>(),
        date_parts[1].parse::<u32>(),
        date_parts[2].parse::<u32>()
    ) {
        if month < 1 || month > 12 || day < 1 || day > 31 {
            return Err(ValidationError::InvalidFieldFormat(
                field.name.clone(),
                "Invalid date values".to_string()
            ));
        }
    } else {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Invalid date numbers".to_string()
        ));
    }

    // Basic time format validation
    let re = Regex::new(r"^\d{2}:\d{2}:\d{2}\.\d{3}Z?$").unwrap();
    if !re.is_match(parts[1]) {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Invalid time format".to_string()
        ));
    }

    Ok(())
}

pub fn validate_guid_format(field: &Field) -> Result<(), ValidationError> {
    let re = Regex::new(r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$").unwrap();
    if !re.is_match(&field.value.to_uppercase()) {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Invalid GUID format".to_string()
        ));
    }
    Ok(())
}

pub fn validate_ip_address(field: &Field) -> Result<(), ValidationError> {
    // Support both IPv4 and IPv6
    if !is_valid_ipv4(&field.value) && !is_valid_ipv6(&field.value) {
        return Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Invalid IP address".to_string()
        ));
    }
    Ok(())
}

pub fn validate_port_number(field: &Field) -> Result<(), ValidationError> {
    match field.value.parse::<u16>() {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            "Port must be between 0 and 65535".to_string()
        ))
    }
}

pub fn validate_protocol(field: &Field) -> Result<(), ValidationError> {
    match field.value.to_lowercase().as_str() {
        "tcp" | "udp" | "icmp" => Ok(()),
        value => {
            // Only try numeric validation if it's not one of the known protocol names
            if !value.chars().all(char::is_numeric) {
                return Err(ValidationError::InvalidFieldFormat(
                    field.name.clone(),
                    "Protocol must be 'tcp', 'udp', 'icmp' or a valid number".to_string()
                ));
            }
            // Validate numeric protocol
            match value.parse::<u32>() {
                Ok(num) if num <= 255 => Ok(()),
                _ => Err(ValidationError::InvalidFieldFormat(
                    field.name.clone(),
                    "Protocol number must be between 0 and 255".to_string()
                ))
            }
        }
    }
}

pub fn validate_hash_format(field: &Field) -> Result<(), ValidationError> {
    // Format: ALGORITHM=HASH,ALGORITHM=HASH
    for hash_entry in field.value.split(',') {
        let parts: Vec<&str> = hash_entry.split('=').collect();
        if parts.len() != 2 {
            return Err(ValidationError::InvalidFieldFormat(
                field.name.clone(),
                "Invalid hash format".to_string()
            ));
        }
        
        match parts[0].to_uppercase().as_str() {
            "MD5" => validate_hash_length(parts[1], 32)?,
            "SHA1" => validate_hash_length(parts[1], 40)?,
            "SHA256" => validate_hash_length(parts[1], 64)?,
            "IMPHASH" => validate_hash_length(parts[1], 32)?,
            _ => return Err(ValidationError::InvalidFieldFormat(
                field.name.clone(),
                "Unknown hash algorithm".to_string()
            ))
        }
    }
    Ok(())
}

fn validate_required_fields(event: &Event) -> Result<(), ValidationError> {
    // Some events cannot be filtered at all - these should never appear in config
    if matches!(event.event_type.as_str(), "ServiceConfigurationChange" | "Error") {
        return Err(ValidationError::NonFilterableEventType(event.event_type.clone()));
    }

    // Skip validation for:
    // 1. Exclude rules
    // 2. Rules with nested Rule elements
    // 3. Empty rules (only comments/documentation)
    if event.onmatch.as_deref() == Some("exclude") ||
       event.fields.iter().any(|f| f.name.eq_ignore_ascii_case("Rule")) ||
       event.fields.is_empty() {
        return Ok(());
    }

    // Validate based on event type
    let required_fields = match event.event_type.as_str() {
        // Events that don't require specific fields
        "ProcessCreate" | "ProcessTerminate" | "FileCreate" | "FileDelete" |
        "FileDeleteDetected" | "FileBlockExecutable" | "FileBlockShredding" |
        "FileExecutableDetected" | "ClipboardChange" | "ProcessTampering" |
        "DNSQuery" | "WmiEvent" | "PipeEvent" | "FileCreateStreamHash" => vec![],

        // Network connections - only require DestinationIp for specific cases
        "NetworkConnect" => {
            let has_source_fields = event.fields.iter().any(|f|
                matches!(f.name.as_str(), "SourceIp" | "SourcePort" | "SourceHostname")
            );
            let has_other_fields = event.fields.iter().any(|f|
                matches!(f.name.as_str(), 
                    "DestinationPort" | "DestinationHostname" | 
                    "Image" | "User" | "ProcessId"
                )
            );
            
            if has_source_fields && !has_other_fields {
                vec!["DestinationIp"]
            } else {
                vec![]
            }
        },

        // Image loading - multiple valid ways to filter
        "ImageLoad" => {
            let has_valid_filter = event.fields.iter().any(|f| 
                matches!(f.name.as_str(), 
                    "Image" | "ImageLoaded" | "OriginalFileName" |
                    "Signed" | "SignatureStatus" | "Signature" |
                    "Company" | "Product" | "Description"
                )
            );
            if !has_valid_filter && !event.fields.is_empty() {
                vec!["ImageLoaded"]
            } else {
                vec![]
            }
        },

        // Driver loading always needs ImageLoaded
        "DriverLoad" => vec!["ImageLoaded"],

        // Registry events need target
        "RegistryEvent" => vec!["TargetObject"],

        // All other events have no required fields
        _ => vec![]
    };

    for field_name in required_fields {
        if !event.fields.iter().any(|f| f.name == field_name) {
            return Err(ValidationError::MissingRequiredField(
                event.event_type.clone(),
                field_name.to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_field_name(field: &Field, event_type: &str) -> Result<(), ValidationError> {
    // Special handling for Rule elements - they're valid in any event type
    if field.name == "Rule" {
        return Ok(());
    }

    let valid_fields = match event_type {
        "ProcessCreate" => PROCESS_CREATE_FIELDS,
        "NetworkConnect" => NETWORK_CONNECT_FIELDS,
        "DriverLoad" => DRIVER_LOAD_FIELDS,
        "ImageLoad" => IMAGE_LOAD_FIELDS,
        "CreateRemoteThread" => CREATE_REMOTE_THREAD_FIELDS,
        "FileCreateTime" => FILE_CREATE_TIME_FIELDS,
        "RegistryEvent" => REGISTRY_EVENT_FIELDS,
        "DnsQuery" => DNS_QUERY_FIELDS,
        "FileCreate" => FILE_CREATE_FIELDS,
        "FileDelete" => FILE_DELETE_FIELDS,
        "FileDeleteDetected" => FILE_DELETE_FIELDS,
        "ProcessAccess" => PROCESS_ACCESS_FIELDS,
        _ => &[] // For event types without specific field validation
    };

    if !valid_fields.is_empty() && !valid_fields.contains(&field.name.as_str()) 
        && field.name != "Rule" { // Allow Rule elements
        return Err(ValidationError::InvalidFieldName(
            event_type.to_string(),
            field.name.clone()
        ));
    }
    Ok(())
}

pub fn validate_status(field: &Field) -> Result<(), ValidationError> {
    match field.value.parse::<u64>() {
        Ok(value) if value <= u32::MAX as u64 => Ok(()),
        _ => Err(ValidationError::InvalidFieldFormat(
            field.name.clone(),
            format!("Status must be a number between 0 and {}", u32::MAX)
        ))
    }
}

fn validate_field_length(field: &Field, max_length: usize) -> Result<(), ValidationError> {
    if field.value.len() > max_length {
        return Err(ValidationError::FieldValueTooLong(
            field.name.clone(),
            max_length
        ));
    }
    Ok(())
}

pub fn validate_field_format(field: &Field, event_type: &str) -> Result<(), ValidationError> {
    // First validate the field name is valid for this event type
    validate_field_name(field, event_type)?;

    // Then validate the field value based on field type
    match field.name.as_str() {
        // Process-related fields
        "ProcessId" | "ParentProcessId" | "TargetProcessId" | "SourceProcessId" | "NewThreadId" => {
            validate_numeric(field)?
        },
        
        // Status fields
        "Status" => validate_status(field)?,
        
        // Network fields
        "Protocol" => validate_protocol(field)?,
        "SourcePort" | "DestinationPort" => validate_port_number(field)?,
        "SourceIp" | "DestinationIp" => validate_ip_address(field)?,
        
        // Time fields
        "UtcTime" | "CreationUtcTime" | "PreviousCreationUtcTime" => {
            validate_utc_timestamp(field)?
        },
        
        // GUID fields
        name if name.ends_with("Guid") => {
            validate_guid_format(field)?
        },
        
        // Registry fields
        "TargetObject" if event_type == "RegistryEvent" => {
            validate_registry_path(field)?
        },
        
        // Hash fields
        "Hashes" => validate_hash_format(field)?,
        
        // Path fields
        "Image" | "ImageLoaded" | "TargetFilename" => {
            validate_windows_path(field)?
        },
        
        // Boolean fields
        name if name.starts_with("Is") => {
            validate_boolean(field)?
        },

        // String fields with length limits
        "CommandLine" | "Description" | "Product" | "Company" | "OriginalFileName" => {
            validate_field_length(field, 32767)?
        },

        // Fields with no specific format validation
        _ => {}
    }

    Ok(())
}