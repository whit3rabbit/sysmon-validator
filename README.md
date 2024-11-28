# Sysmon Config Validator

A robust validation tool for Sysmon configuration files, available both as a command-line utility and a Rust library.

## Features

- Validates Sysmon configuration XML files
- Checks for schema version compatibility (minimum 4.22)
- Validates event types and operators
- Ensures proper rule group structure
- Provides detailed error messages with context
- Can be used as both a CLI tool and a library

## Command-Line Usage

### Installation

```bash
# Clone the repository
git clone https://github.com/whit3rabbit/sysmon-validator.git
cd sysmon-validator

# Build the project
cargo build --release

# The binary will be available in target/release/sysmon_validator
```

### Using the CLI

```bash
sysmon_validator path/to/your/sysmonconfig.xml
```

If the configuration is valid, you'll see:

```bash
✓ Sysmon configuration is valid.
```

If there are issues, you'll get detailed error messages with context, for example:

```bash
Invalid Configuration: Schema version 3.50 is not supported (minimum required: 4.22)

Context:
    1 | <?xml version="1.0" encoding="UTF-8"?>
  > 2 | <Sysmon schemaversion="3.50">
    3 |   <EventFiltering>
```

## Library Usage

### Add as a Dependency

Add this to your `Cargo.toml`:

```toml
[dependencies]
sysmon_validator = { git = "https://github.com/whit3rabbit/sysmon-validator.git" }
```

### Basic Validation

#### From File

```rust
use sysmon_validator::validate_config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match validate_config("path/to/config.xml") {
        Ok(()) => println!("Configuration is valid!"),
        Err(e) => eprintln!("Configuration error: {}", e),
    }
    Ok(())
}
```

#### From String

```rust
use std::fs;
use sysmon_validator::validate_config_from_str;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get XML content (e.g., from a file, but could be from any source)
    let xml_content = fs::read_to_string("path/to/config.xml")?;
    
    match validate_config_from_str(&xml_content) {
        Ok(()) => println!("Configuration is valid!"),
        Err(e) => eprintln!("Configuration error: {}", e),
    }
    Ok(())
}
```

### Advanced Usage

For more control over the validation process, you can use the parser and validator separately:

#### Working with Files

```rust
use sysmon_validator::{parse_sysmon_config, validate_sysmon_config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse the configuration from file
    let config = parse_sysmon_config("path/to/config.xml")?;
    
    // Do something with the parsed config if needed
    println!("Schema version: {:?}", config.schema_version);
    
    // Validate the configuration
    validate_sysmon_config(&config)?;
    
    Ok(())
}
```

#### Working with Strings

```rust
use sysmon_validator::{parse_sysmon_config_from_str, validate_sysmon_config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xml_content = r#"
        <Sysmon schemaversion="4.30">
            <EventFiltering>
                <RuleGroup name="Example">
                    <ProcessCreate onmatch="include">
                        <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                    </ProcessCreate>
                </RuleGroup>
            </EventFiltering>
        </Sysmon>
    "#;

    // Parse the configuration from string
    let config = parse_sysmon_config_from_str(xml_content)?;
    
    // Access parsed configuration
    if let Some(ef) = &config.event_filtering {
        for rule_group in &ef.rule_groups {
            println!("Rule group: {:?}", rule_group.name);
            for event in &rule_group.events {
                println!("Event type: {}", event.event_type);
            }
        }
    }
    
    // Validate the configuration
    validate_sysmon_config(&config)?;
    
    Ok(())
}
```

### Error Handling

Both file and string-based methods provide the same error types:

```rust
use sysmon_validator::{
    parse_sysmon_config_from_str,
    validate_sysmon_config,
    errors::ValidationError
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xml_content = fs::read_to_string("config.xml")?;
    let config = match parse_sysmon_config_from_str(&xml_content) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to parse configuration: {}", e);
            return Ok(());
        }
    };

    match validate_sysmon_config(&config) {
        Ok(()) => println!("Configuration is valid!"),
        Err(e) => match e {
            ValidationError::InvalidSchemaVersion(version) => {
                eprintln!("Invalid schema version {}, minimum required is 4.22", version);
            }
            ValidationError::UnsupportedOperator(op) => {
                eprintln!("Unsupported operator: {}", op);
            }
            ValidationError::MultipleFilters(event_type) => {
                eprintln!("Multiple filters found for event type: {}", event_type);
            }
            ValidationError::InvalidEventType(event_type) => {
                eprintln!("Invalid event type: {}", event_type);
            }
            ValidationError::NonFilterableEventType(event_type) => {
                eprintln!("Event type cannot be filtered: {}", event_type);
            }
            ValidationError::MultipleEventTypesInRuleGroup(group) => {
                eprintln!("Multiple event types in rule group: {}", group);
            }
        }
    }
    Ok(())
}
```

## Running Tests

```bash
cargo test
```