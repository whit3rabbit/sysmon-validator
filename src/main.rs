use std::env;
use std::fs;
use colored::Colorize;
use env_logger;
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;

use sysmon_validator::{
    parse_sysmon_config,
    validate_sysmon_config,
    errors::ValidationError,
};

fn main() {
    // Initialize the logger
    env_logger::init();

    // Get the configuration file path from command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", "Usage: sysmon_validator <path_to_sysmon_config.xml>".red());
        std::process::exit(1);
    }
    let config_path = &args[1];

    // Parse the Sysmon configuration
    match parse_sysmon_config(config_path) {
        Ok(config) => {
            // Validate the configuration
            if let Err(e) = validate_sysmon_config(&config) {
                print_validation_error(e, config_path);
                std::process::exit(1);
            } else {
                println!("{}", "✓ Sysmon configuration is valid.".green());
            }
        }
        Err(e) => {
            eprintln!("{}: {}", "Failed to parse Sysmon configuration".red(), e);
            std::process::exit(1);
        }
    }
}

fn find_xml_line_context(content: &str, search_term: &str) -> Option<usize> {
    let mut reader = Reader::from_str(content);
    reader.trim_text(true);
    reader.check_comments(true);
    
    let mut buf = Vec::new();

    // Track actual XML elements containing our search term
    let mut found_in_actual_xml = false;
    let mut found_line = None;
    
    // Split content into lines and handle empty lines
    let lines: Vec<&str> = content.lines()
        .map(|line| line.trim())
        .collect();
    
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Comment(_)) => {
                // Skip comments
                continue;
            },
            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => {
                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                    let value = String::from_utf8_lossy(&attr.value).into_owned();
                    
                    if key == "condition" && value == search_term {
                        // Found a match in actual XML content
                        found_in_actual_xml = true;
                        
                        // Find the line containing this attribute
                        for (idx, line) in lines.iter().enumerate() {
                            if !line.trim_start().starts_with("<!--") && 
                               line.contains(&format!("condition=\"{}\"", value)) {
                                found_line = Some(idx + 1);
                                break;
                            }
                        }
                    }
                }
            },
            Ok(XmlEvent::Eof) => break,
            Err(e) => {
                eprintln!("Error while parsing XML for error context: {}", e);
                break;
            },
            _ => {}
        }
        
        buf.clear();
    }

    // Only return a line number if we found the term in actual XML content
    if found_in_actual_xml {
        found_line
    } else {
        None
    }
}

fn print_validation_error(error: ValidationError, config_path: &str) {
    // Read the configuration file content
    let content = fs::read_to_string(config_path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();

    match error {
        ValidationError::InvalidSchemaVersion(version) => {
            eprintln!("{}: Schema version {} is not supported (minimum required: 4.22)", 
                "Invalid Configuration".red(),
                version);
            
            // Find and print the line containing schemaversion
            if let Some((line_num, _line)) = lines.iter().enumerate()
                .find(|(_, &line)| line.contains(&version) && line.contains("schemaversion")) {
                print_error_context(lines.as_slice(), line_num);
            }
        }
        ValidationError::UnsupportedOperator(operator) => {
            eprintln!("{}: Unsupported operator '{}'", 
                "Invalid Configuration".red(),
                operator);
            
            // Find and print the line containing the invalid operator using XML-aware search
            if let Some(line_num) = find_xml_line_context(&content, &operator) {
                print_error_context(lines.as_slice(), line_num - 1);  // -1 because line numbers are 0-based in the array
            }
        }
        ValidationError::MultipleFilters(event_type) => {
            eprintln!("{}: Multiple include/exclude filters found for event type '{}'",
                "Invalid Configuration".red(),
                event_type);
            
            // Find and print lines containing the event type
            let matching_lines: Vec<(usize, &&str)> = lines.iter().enumerate()
                .filter(|(_, &line)| line.contains(&event_type))
                .collect();
            
            for (line_num, _) in matching_lines {
                print_error_context(lines.as_slice(), line_num);
                println!();  // Add separator between multiple instances
            }
        }
        ValidationError::MultipleEventTypesInRuleGroup(group_name) => {
            eprintln!("{}: Multiple event types found in rule group '{}'",
                "Invalid Configuration".red(),
                group_name);
            
            // Find the RuleGroup and print its contents
            if let Some(start_line) = lines.iter().enumerate()
                .find(|(_, &line)| line.contains(&group_name)) {
                print_rule_group_context(lines.as_slice(), start_line.0);
            }
        }
        ValidationError::InvalidEventType(event_type) => {
            eprintln!("{}: Invalid event type '{}'",
                "Invalid Configuration".red(),
                event_type);
            
            // Find and print the line containing the invalid event type
            if let Some((line_num, _line)) = lines.iter().enumerate()
                .find(|(_, &line)| line.contains(&event_type)) {
                print_error_context(lines.as_slice(), line_num);
            }
        }
        ValidationError::NonFilterableEventType(event_type) => {
            eprintln!("{}: Event type '{}' cannot be filtered",
                "Invalid Configuration".red(),
                event_type);
            
            // Find and print the line containing the non-filterable event type
            if let Some((line_num, _line)) = lines.iter().enumerate()
                .find(|(_, &line)| line.contains(&event_type)) {
                print_error_context(lines.as_slice(), line_num);
            }
        }
        ValidationError::InvalidGroupRelation(value) => {
            eprintln!("{}: Invalid groupRelation value '{}'",
                "Invalid Configuration".red(),
                value);
            
            // Find and print the line containing the invalid groupRelation
            if let Some((line_num, _line)) = lines.iter().enumerate()
                .find(|(_, &line)| line.contains("groupRelation") && line.contains(&value)) {
                print_error_context(lines.as_slice(), line_num);
            }
        }
    }
}

fn print_error_context(lines: &[&str], error_line: usize) {
    // Print line numbers and content for context
    let start_line = error_line.saturating_sub(2);
    let end_line = (error_line + 3).min(lines.len());

    println!("\n{}:", "Context".yellow());
    for i in start_line..end_line {
        let line_marker = if i == error_line { ">" } else { " " };
        let line_display = if i == error_line {
            lines[i].red().to_string()
        } else {
            lines[i].to_string()
        };
        println!("{} {:4} | {}", line_marker, i + 1, line_display);
    }
}

fn print_rule_group_context(lines: &[&str], start_line: usize) {
    let mut depth = 0;
    let mut in_rule_group = false;
    let mut rule_group_lines = Vec::new();

    for (i, &line) in lines.iter().enumerate().skip(start_line) {
        if line.contains("<RuleGroup") {
            in_rule_group = true;
            depth += 1;
        }
        
        if in_rule_group {
            rule_group_lines.push((i, line));
        }
        
        if line.contains("</RuleGroup>") {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
    }

    println!("\n{}:", "Rule Group Context".yellow());
    for (i, line) in rule_group_lines {
        println!("  {:4} | {}", i + 1, line.red());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_validator::parser::parse_sysmon_config_from_str;
    use sysmon_validator::validate_sysmon_config;

    #[test]
    fn test_xml_comment_handling() {
        let xml_content = r#"<!-- Line 1: Comment with begin with -->
<!-- Line 2: Another comment -->
<Sysmon schemaversion="4.30">
    <EventFiltering>
        <RuleGroup name="TestGroup">
            <ProcessCreate onmatch="include">
                <Image condition="begin with">C:\Windows</Image>
            </ProcessCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>"#;
        
        // Test that the find_xml_line_context function ignores comments
        let line_num = find_xml_line_context(xml_content, "begin with");
        assert!(line_num.is_some(), "Should find 'begin with' in actual XML content");
        assert_eq!(line_num.unwrap(), 7, "Operator should be found on line 7");
        
        // Test that validation succeeds since the actual XML uses valid 'begin with'
        let config = parse_sysmon_config_from_str(xml_content).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(result.is_ok(), "Should validate successfully with correct operator");
    }

    #[test]
    fn test_find_xml_line_context_with_actual_content() {
        let xml_content = r#"<!-- Line 1: Comment with operators -->
<!-- Line 2: Another comment -->
<Sysmon>
    <EventFiltering>
        <!-- Comment -->
        <RuleGroup>
            <ProcessCreate>
                <Image condition="begin with">test</Image>
            </ProcessCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>"#;

        // Test finding the operator
        let line_num = find_xml_line_context(xml_content, "begin with");
        assert!(line_num.is_some(), "Should find 'begin with' in actual XML content");
        assert_eq!(line_num.unwrap(), 8, "Operator should be found on line 8");
    }
}