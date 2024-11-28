use crate::models::*;
use crate::errors::ParserError;
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::fs::File;
use std::io::BufReader;
use log::{debug, error, info};

/// Parses a Sysmon configuration file and returns a SysmonConfig struct.
///
/// This function reads an XML file containing Sysmon configuration and parses it into
/// a structured format. It handles nested elements including RuleGroups, Events, and Fields.
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
    
    let mut reader = Reader::from_reader(BufReader::new(file));
    reader.trim_text(true);

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

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                current_element.push(tag_name.clone());
                debug!("Processing start element: {}", tag_name);

                match current_element.join("/").as_str() {
                    "Sysmon" => {
                        for attr in e.attributes() {
                            match attr {
                                Ok(attr) => {
                                    if attr.key.as_ref() == b"schemaversion" {
                                        let version = attr.unescape_value()?;
                                        sysmon_config.schema_version = Some(version.into_owned());
                                        debug!("Found schema version: {:?}", sysmon_config.schema_version);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse attribute: {}", e);
                                    return Err(ParserError::AttrError(e));
                                }
                            }
                        }
                    }
                    "Sysmon/EventFiltering" => {
                        debug!("Initializing EventFiltering");
                        event_filtering = Some(EventFiltering {
                            rule_groups: Vec::new(),
                        });
                    }
                    "Sysmon/EventFiltering/RuleGroup" => {
                        let mut name = None;
                        let mut group_relation = None;

                        for attr in e.attributes() {
                            match attr {
                                Ok(attr) => {
                                    match attr.key.as_ref() {
                                        b"name" => {
                                            name = Some(attr.unescape_value()?.into_owned());
                                        }
                                        b"groupRelation" => {
                                            group_relation = Some(attr.unescape_value()?.into_owned());
                                        }
                                        _ => {}
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse RuleGroup attribute: {}", e);
                                    return Err(ParserError::AttrError(e));
                                }
                            }
                        }

                        debug!("Creating new RuleGroup: {:?}", name);
                        current_rule_group = Some(RuleGroup {
                            name,
                            group_relation,
                            events: Vec::new(),
                        });
                    }
                    path if path.starts_with("Sysmon/EventFiltering/RuleGroup/") => {
                        if current_element.len() == 4 {
                            let event_type = tag_name;
                            let mut onmatch = None;

                            for attr in e.attributes() {
                                match attr {
                                    Ok(attr) => {
                                        if attr.key.as_ref() == b"onmatch" {
                                            onmatch = Some(attr.unescape_value()?.into_owned());
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse Event attribute: {}", e);
                                        return Err(ParserError::AttrError(e));
                                    }
                                }
                            }

                            debug!("Creating new Event: {} with onmatch: {:?}", event_type, onmatch);
                            current_event = Some(Event {
                                event_type,
                                onmatch,
                                fields: Vec::new(),
                            });
                        } else if current_element.len() == 5 {
                            let field_name = tag_name;
                            let mut condition = None;

                            for attr in e.attributes() {
                                match attr {
                                    Ok(attr) => {
                                        if attr.key.as_ref() == b"condition" {
                                            condition = Some(attr.unescape_value()?.into_owned());
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse Field attribute: {}", e);
                                        return Err(ParserError::AttrError(e));
                                    }
                                }
                            }

                            debug!("Creating new Field: {} with condition: {:?}", field_name, condition);
                            current_field = Some(Field {
                                name: field_name,
                                condition,
                                value: String::new(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::Text(e)) => {
                if let Some(ref mut field) = current_field {
                    field.value = e.unescape()?.into_owned();
                    debug!("Set field value: {}", field.value);
                }
            }
            Ok(XmlEvent::End(_)) => {
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
                        if current_element.len() == 4 {
                            if let Some(event) = current_event.take() {
                                if let Some(ref mut rg) = current_rule_group {
                                    debug!("Adding Event to RuleGroup: {}", event.event_type);
                                    rg.events.push(event);
                                }
                            }
                        } else if current_element.len() == 5 {
                            if let Some(field) = current_field.take() {
                                if let Some(ref mut event) = current_event {
                                    debug!("Adding Field to Event: {}", field.name);
                                    event.fields.push(field);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                current_element.pop();
            }
            Ok(XmlEvent::Eof) => {
                info!("Finished parsing Sysmon config");
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


/// Parses a Sysmon configuration from a string containing XML data.
///
/// This function takes XML content as a string and parses it into a structured format.
/// It handles nested elements including RuleGroups, Events, and Fields.
///
/// # Arguments
/// * `xml_content` - A string slice containing the Sysmon configuration XML
///
/// # Returns
/// * `Result<SysmonConfig, ParserError>` - The parsed configuration or an error
///
/// # Example
/// ```no_run
/// use sysmon_validator::parse_sysmon_config_from_str;
///
/// let xml_content = r#"
///     <Sysmon schemaversion="4.30">
///         <EventFiltering>
///             <RuleGroup name="Example">
///                 <ProcessCreate onmatch="include">
///                     <Image condition="is">C:\Windows\System32\cmd.exe</Image>
///                 </ProcessCreate>
///             </RuleGroup>
///         </EventFiltering>
///     </Sysmon>
/// "#;
///
/// let config = parse_sysmon_config_from_str(xml_content)?;
/// println!("Schema version: {:?}", config.schema_version);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_sysmon_config_from_str(xml_content: &str) -> Result<SysmonConfig, ParserError> {
    info!("Starting to parse Sysmon config from string input");
    
    let mut reader = Reader::from_str(xml_content);
    reader.trim_text(true);

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


    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                current_element.push(tag_name.clone());
                debug!("Processing start element: {}", tag_name);

                match current_element.join("/").as_str() {
                    "Sysmon" => {
                        for attr in e.attributes() {
                            match attr {
                                Ok(attr) => {
                                    if attr.key.as_ref() == b"schemaversion" {
                                        let version = attr.unescape_value()?;
                                        sysmon_config.schema_version = Some(version.into_owned());
                                        debug!("Found schema version: {:?}", sysmon_config.schema_version);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse attribute: {}", e);
                                    return Err(ParserError::AttrError(e));
                                }
                            }
                        }
                    }
                    "Sysmon/EventFiltering" => {
                        debug!("Initializing EventFiltering");
                        event_filtering = Some(EventFiltering {
                            rule_groups: Vec::new(),
                        });
                    }
                    "Sysmon/EventFiltering/RuleGroup" => {
                        let mut name = None;
                        let mut group_relation = None;

                        for attr in e.attributes() {
                            match attr {
                                Ok(attr) => {
                                    match attr.key.as_ref() {
                                        b"name" => {
                                            name = Some(attr.unescape_value()?.into_owned());
                                        }
                                        b"groupRelation" => {
                                            group_relation = Some(attr.unescape_value()?.into_owned());
                                        }
                                        _ => {}
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse RuleGroup attribute: {}", e);
                                    return Err(ParserError::AttrError(e));
                                }
                            }
                        }

                        debug!("Creating new RuleGroup: {:?}", name);
                        current_rule_group = Some(RuleGroup {
                            name,
                            group_relation,
                            events: Vec::new(),
                        });
                    }
                    path if path.starts_with("Sysmon/EventFiltering/RuleGroup/") => {
                        if current_element.len() == 4 {
                            let event_type = tag_name;
                            let mut onmatch = None;

                            for attr in e.attributes() {
                                match attr {
                                    Ok(attr) => {
                                        if attr.key.as_ref() == b"onmatch" {
                                            onmatch = Some(attr.unescape_value()?.into_owned());
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse Event attribute: {}", e);
                                        return Err(ParserError::AttrError(e));
                                    }
                                }
                            }

                            debug!("Creating new Event: {} with onmatch: {:?}", event_type, onmatch);
                            current_event = Some(Event {
                                event_type,
                                onmatch,
                                fields: Vec::new(),
                            });
                        } else if current_element.len() == 5 {
                            let field_name = tag_name;
                            let mut condition = None;

                            for attr in e.attributes() {
                                match attr {
                                    Ok(attr) => {
                                        if attr.key.as_ref() == b"condition" {
                                            condition = Some(attr.unescape_value()?.into_owned());
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse Field attribute: {}", e);
                                        return Err(ParserError::AttrError(e));
                                    }
                                }
                            }

                            debug!("Creating new Field: {} with condition: {:?}", field_name, condition);
                            current_field = Some(Field {
                                name: field_name,
                                condition,
                                value: String::new(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::Text(e)) => {
                if let Some(ref mut field) = current_field {
                    field.value = e.unescape()?.into_owned();
                    debug!("Set field value: {}", field.value);
                }
            }
            Ok(XmlEvent::End(_)) => {
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
                        if current_element.len() == 4 {
                            if let Some(event) = current_event.take() {
                                if let Some(ref mut rg) = current_rule_group {
                                    debug!("Adding Event to RuleGroup: {}", event.event_type);
                                    rg.events.push(event);
                                }
                            }
                        } else if current_element.len() == 5 {
                            if let Some(field) = current_field.take() {
                                if let Some(ref mut event) = current_event {
                                    debug!("Adding Field to Event: {}", field.name);
                                    event.fields.push(field);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                current_element.pop();
            }
            Ok(XmlEvent::Eof) => {
                info!("Finished parsing Sysmon config");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_valid_config() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/tests/test_configs/valid_config.xml");
        let result = parse_sysmon_config(path.to_str().unwrap());
        assert!(result.is_ok(), "Parsing failed: {:?}", result.unwrap_err());

        let config = result.unwrap();
        assert!(config.schema_version.is_some());
        assert!(config.event_filtering.is_some());

        let event_filtering = config.event_filtering.unwrap();
        assert_eq!(event_filtering.rule_groups.len(), 1);

        let rule_group = &event_filtering.rule_groups[0];
        assert_eq!(rule_group.name.as_deref(), Some("ValidRuleGroup"));
        assert_eq!(rule_group.events.len(), 1);

        let event = &rule_group.events[0];
        assert_eq!(event.event_type, "ProcessCreate");
        assert_eq!(event.onmatch.as_deref(), Some("include"));
        assert_eq!(event.fields.len(), 1);

        let field = &event.fields[0];
        assert_eq!(field.name, "Image");
        assert_eq!(field.condition.as_deref(), Some("is"));
        assert_eq!(field.value, r#"C:\Windows\System32\cmd.exe"#);
    }
}