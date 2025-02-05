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
    // Initialize the logger with a custom format
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            let level_color = match record.level() {
                log::Level::Error => "red",
                log::Level::Warn => "yellow",
                log::Level::Info => "green",
                _ => "white",
            };
            writeln!(
                buf,
                "{} {}",
                record.level().to_string().color(level_color),
                record.args()
            )
        })
        .init();

    // Get the configuration file path from command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", "Usage: sysmon_validator <path_to_sysmon_config.xml>".red());
        eprintln!("Optional flags:");
        eprintln!("  --verbose    Show detailed validation information");
        eprintln!("  --debug      Show debug information including schema validation details");
        std::process::exit(1);
    }

    let config_path = &args[1];
    let verbose = args.iter().any(|arg| arg == "--verbose");
    let debug = args.iter().any(|arg| arg == "--debug");

    // Parse and validate the Sysmon configuration
    match parse_sysmon_config(config_path) {
        Ok(config) => {
            if debug {
                println!("{}", "Parsed configuration successfully.".green());
                if let Some(version) = &config.schema_version {
                    println!("Schema version: {}", version);
                }
            }

            // Validate the configuration
            if let Err(e) = validate_sysmon_config(&config) {
                print_validation_error(&e, config_path, verbose);
                std::process::exit(1);
            } else {
                if verbose {
                    println!("\n{}", "Configuration structure validation passed.".green());
                }

                // Print overall success message
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
    reader.config_mut().trim_text(true);
    reader.config_mut().check_comments = true; 
    
    let mut buf = Vec::new();
    let mut found_in_actual_xml = false;
    let mut found_line = None;
    
    let lines: Vec<&str> = content.lines()
        .map(|line| line.trim())
        .collect();
    
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Comment(_)) => continue,
            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => {
                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                    let value = String::from_utf8_lossy(&attr.value).into_owned();
                    
                    if key == "condition" && value == search_term {
                        found_in_actual_xml = true;
                        
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

    if found_in_actual_xml {
        found_line
    } else {
        None
    }
}

fn print_validation_error(error: &ValidationError, config_path: &str, verbose: bool) {
    // Read the configuration file content
    let content = fs::read_to_string(config_path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();

    match error {
        ValidationError::InvalidSchemaVersion(version) => {
            eprintln!("{}: Schema version {} is not supported", 
                "Invalid Configuration".red(),
                version);
            
            if verbose {
                println!("Supported schema versions: 4.22 and above");
                if let Some((line_num, _line)) = lines.iter().enumerate()
                    .find(|(_, &line)| line.contains(version) && line.contains("schemaversion")) {
                    print_error_context(lines.as_slice(), line_num);
                }
            }
        },
        ValidationError::SchemaValidationError(msg) => {
            eprintln!("{}: {}", 
                "Schema Validation Error".red(),
                msg);
            
            if verbose {
                println!("The configuration does not match the schema requirements.");
            }
        },
        ValidationError::SchemaValidationFailed(msg) => {
            eprintln!("{}: {}", 
                "Schema Validation Failed".red(),
                msg);
            
            if verbose {
                println!("Failed to validate against schema requirements.");
            }
        },
        ValidationError::NoMatchingSchema(version) => {
            eprintln!("{}: No compatible schema found for version {}", 
                "Schema Error".red(),
                version);
            
            if verbose {
                println!("Please use a supported Sysmon schema version.");
            }
        },
        ValidationError::UnsupportedOperator(op) => {
            eprintln!("{}: Unsupported operator '{}'", 
                "Invalid Configuration".red(),
                op);
            
            if let Some(line_num) = find_xml_line_context(&content, op) {
                print_error_context(lines.as_slice(), line_num - 1);
            }
        },
        ValidationError::MultipleFilters(event_type) => {
            eprintln!("{}: Multiple include/exclude filters for event type '{}'",
                "Invalid Configuration".red(),
                event_type);
            
            let matching_lines: Vec<(usize, &&str)> = lines.iter().enumerate()
                .filter(|(_, &line)| line.contains(event_type))
                .collect();
            
            for (line_num, _) in matching_lines {
                print_error_context(lines.as_slice(), line_num);
                println!();
            }
        },
        _ => {
            eprintln!("{}: {}", "Validation Error".red(), error);
        }
    }
}

fn print_error_context(lines: &[&str], error_line: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_validator::parser::parse_sysmon_config_from_str;
    use sysmon_validator::validate_sysmon_config;

    #[test]
    fn test_error_context_finding() {
        let xml = r#"
                <!-- Comment with is -->
                <ProcessCreate>
                    <Image condition="is">test.exe</Image>
                </ProcessCreate>"#;
        
        let line = find_xml_line_context(xml, "is");
        assert!(line.is_some());
        assert_eq!(line.unwrap(), 4);
    }

    #[test]
    fn test_validation_error_display() {
        let xml = r#"
            <Sysmon schemaversion="3.0">
                <EventFiltering>
                    <RuleGroup name="Test">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">test.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;

        let config = parse_sysmon_config_from_str(xml).unwrap();
        let result = validate_sysmon_config(&config);
        assert!(result.is_err());
    }
}