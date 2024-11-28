use std::env;
use std::fs;
use colored::Colorize;
use env_logger;

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
            
            // Find and print the line containing the invalid operator
            if let Some((line_num, _line)) = lines.iter().enumerate()
                .find(|(_, &line)| line.contains(&operator)) {
                print_error_context(lines.as_slice(), line_num);
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