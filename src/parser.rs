use crate::models::*;
use crate::errors::ParserError;
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::fs::File;
use std::io::BufReader;
use log::{debug, error, info, warn};

// Constants for commonly used strings
const SCHEMA_VERSION: &[u8] = b"schemaversion";
const ONMATCH: &[u8] = b"onmatch";
const CONDITION: &[u8] = b"condition";
const NAME: &[u8] = b"name";
const GROUP_RELATION: &[u8] = b"groupRelation";

/// Parses a Sysmon configuration file and returns a SysmonConfig struct.
///
/// This function reads an XML file containing Sysmon configuration and parses it into
/// a structured format. It handles nested elements including RuleGroups, Events, and Fields,
/// while properly handling XML comments and maintaining error context.
///
/// # Arguments
/// * `file_path` - A string slice containing the path to the Sysmon configuration XML file
///
/// # Returns
/// * `Result<SysmonConfig, ParserError>` - The parsed configuration or an error
///
/// # Example
/// ```no_run
/// use sysmon_validator::parse_sysmon_config;
/// 
/// let config = parse_sysmon_config("path/to/sysmonconfig.xml").unwrap();
/// println!("Schema version: {:?}", config.schema_version);
/// ```
pub fn parse_sysmon_config(file_path: &str) -> Result<SysmonConfig, ParserError> {
    info!("Starting to parse Sysmon config from: {}", file_path);
    
    let file = File::open(file_path).map_err(|e| {
        error!("Failed to open config file: {}", e);
        ParserError::IoError(e)
    })?;
    
    let reader = BufReader::new(file);
    parse_sysmon_config_from_reader(reader)
}

/// Parses a Sysmon configuration from a string containing XML data.
///
/// This function takes XML content as a string and parses it into a structured format.
/// It handles nested elements including RuleGroups, Events, and Fields, while properly
/// handling XML comments.
///
/// # Arguments
/// * `xml_content` - A string slice containing the Sysmon configuration XML
///
/// # Returns
/// * `Result<SysmonConfig, ParserError>` - The parsed configuration or an error
pub fn parse_sysmon_config_from_str(xml_content: &str) -> Result<SysmonConfig, ParserError> {
    info!("Starting to parse Sysmon config from string input");
    parse_sysmon_config_from_reader(std::io::Cursor::new(xml_content))
}

// Internal function to handle the actual parsing logic
fn parse_sysmon_config_from_reader<R: std::io::BufRead>(reader: R) -> Result<SysmonConfig, ParserError> {
    let mut reader = Reader::from_reader(reader);
    // Configure the reader settings separately since they modify in place
    reader.config_mut().trim_text(true);
    reader.config_mut().check_comments = true; 

    let mut buf = Vec::new();
    let mut sysmon_config = SysmonConfig {
        schema_version: None,
        event_filtering: None,
    };

    let mut current_element = Vec::new();
    let mut event_filtering = None;
    let mut current_rule_group = None;
    let mut current_event = None;
    let mut current_field = None;
    let mut depth = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) => {
                depth += 1;
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                current_element.push(tag_name.clone());
                debug!("Processing start element: {} at depth {}", tag_name, depth);

                match current_element.join("/").as_str() {
                    "Sysmon" => {
                        handle_sysmon_element(e, &mut sysmon_config)?;
                    }
                    "Sysmon/EventFiltering" => {
                        debug!("Initializing EventFiltering");
                        event_filtering = Some(EventFiltering {
                            rule_groups: Vec::new(),
                        });
                    }
                    "Sysmon/EventFiltering/RuleGroup" => {
                        current_rule_group = Some(parse_rule_group(e)?);
                    }
                    path if path.starts_with("Sysmon/EventFiltering/RuleGroup/") => {
                        if current_element.len() == 4 {
                            current_event = Some(parse_event(e, &tag_name)?);
                        } else if current_element.len() == 5 {
                            current_field = Some(parse_field(e, &tag_name)?);
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::Comment(e)) => {
                debug!("Skipping comment block: {}", String::from_utf8_lossy(&e));
                continue;
            }
            Ok(XmlEvent::Text(e)) => {
                if let Some(ref mut field) = current_field {
                    field.value = e.unescape()?.into_owned();
                    debug!("Set field value: {}", field.value);
                }
            }
            Ok(XmlEvent::End(_)) => {
                depth -= 1;
                match current_element.join("/").as_str() {
                    "Sysmon/EventFiltering/RuleGroup" => {
                        if let Some(rule_group) = current_rule_group.take() {
                            if let Some(ref mut ef) = event_filtering {
                                debug!("Adding RuleGroup to EventFiltering");
                                ef.rule_groups.push(rule_group);
                            }
                        }
                    }
                    path if path.starts_with("Sysmon/EventFiltering/RuleGroup/") => {
                        handle_end_element(
                            &mut current_event,
                            &mut current_field,
                            &mut current_rule_group,
                            current_element.len(),
                        );
                    }
                    _ => {}
                }
                current_element.pop();
            }
            Ok(XmlEvent::Eof) => {
                info!("Finished parsing Sysmon config at depth {}", depth);
                if depth != 0 {
                    warn!("XML parsing ended with unmatched elements");
                }
                break;
            }
            Err(e) => {
                error!("Error parsing XML: {}", e);
                return Err(ParserError::XmlError(e));
            }
            _ => {}
        }
        buf.clear();
    }

    sysmon_config.event_filtering = event_filtering;
    Ok(sysmon_config)
}

// Helper function to handle Sysmon element attributes
fn handle_sysmon_element(
    e: &quick_xml::events::BytesStart,
    config: &mut SysmonConfig,
) -> Result<(), ParserError> {
    for attr in e.attributes() {
        match attr {
            Ok(attr) if attr.key.as_ref() == SCHEMA_VERSION => {
                let version = attr.unescape_value()?;
                config.schema_version = Some(version.into_owned());
                debug!("Found schema version: {:?}", config.schema_version);
            }
            Ok(_) => {}
            Err(e) => {
                error!("Failed to parse Sysmon attribute: {}", e);
                return Err(ParserError::AttrError(e));
            }
        }
    }
    Ok(())
}

// Helper function to parse RuleGroup attributes
fn parse_rule_group(e: &quick_xml::events::BytesStart) -> Result<RuleGroup, ParserError> {
    let mut name = None;
    let mut group_relation = None;

    for attr in e.attributes() {
        match attr {
            Ok(attr) => match attr.key.as_ref() {
                key if key == NAME => {
                    name = Some(attr.unescape_value()?.into_owned());
                }
                key if key == GROUP_RELATION => {
                    group_relation = Some(attr.unescape_value()?.into_owned());
                }
                _ => {}
            },
            Err(e) => {
                error!("Failed to parse RuleGroup attribute: {}", e);
                return Err(ParserError::AttrError(e));
            }
        }
    }

    debug!("Creating new RuleGroup: {:?}", name);
    Ok(RuleGroup {
        name,
        group_relation,
        events: Vec::new(),
    })
}

// Helper function to parse Event attributes
fn parse_event(
    e: &quick_xml::events::BytesStart,
    event_type: &str,
) -> Result<Event, ParserError> {
    let mut onmatch = None;

    for attr in e.attributes() {
        match attr {
            Ok(attr) if attr.key.as_ref() == ONMATCH => {
                onmatch = Some(attr.unescape_value()?.into_owned());
            }
            Ok(_) => {}
            Err(e) => {
                error!("Failed to parse Event attribute: {}", e);
                return Err(ParserError::AttrError(e));
            }
        }
    }

    debug!("Creating new Event: {} with onmatch: {:?}", event_type, onmatch);
    Ok(Event {
        event_type: event_type.to_string(),
        onmatch,
        fields: Vec::new(),
    })
}

// Helper function to parse Field attributes
fn parse_field(
    e: &quick_xml::events::BytesStart,
    field_name: &str,
) -> Result<Field, ParserError> {
    let mut condition = None;

    for attr in e.attributes() {
        match attr {
            Ok(attr) if attr.key.as_ref() == CONDITION => {
                condition = Some(attr.unescape_value()?.into_owned());
            }
            Ok(_) => {}
            Err(e) => {
                error!("Failed to parse Field attribute: {}", e);
                return Err(ParserError::AttrError(e));
            }
        }
    }

    debug!("Creating new Field: {} with condition: {:?}", field_name, condition);
    Ok(Field {
        name: field_name.to_string(),
        condition,
        value: String::new(),
    })
}

// Helper function to handle end elements
fn handle_end_element(
    current_event: &mut Option<Event>,
    current_field: &mut Option<Field>,
    current_rule_group: &mut Option<RuleGroup>,
    element_len: usize,
) {
    if element_len == 4 {
        if let Some(event) = current_event.take() {
            if let Some(ref mut rg) = current_rule_group {
                debug!("Adding Event to RuleGroup: {}", event.event_type);
                rg.events.push(event);
            }
        }
    } else if element_len == 5 {
        if let Some(field) = current_field.take() {
            if let Some(ref mut event) = current_event {
                debug!("Adding Field to Event: {}", field.name);
                event.fields.push(field);
            }
        }
    }
}