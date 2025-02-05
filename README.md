# Sysmon Configuration Validator

A comprehensive Rust library and command-line tool for validating Sysmon configuration files. Performs both structural validation and XSD schema validation to ensure your Sysmon configurations are correct and compatible.

## Features

- Full XSD schema validation against official Sysmon schemas
- Support for multiple schema versions (4.22 and above)
- Intelligent schema version selection and compatibility
- Comprehensive validation including:
  - XML structure and syntax
  - Rule group relationships and structure
  - Event field formats and requirements
  - Event type compatibility
  - Field value formats (GUIDs, timestamps, paths, etc.)
  - Include/exclude filter logic
- Detailed error reporting with context
- Both command-line and library interfaces

## Installation

### From Source

```bash
git clone https://github.com/whit3rabbit/sysmon_validator
cd sysmon_validator
cargo build --release
```

The compiled binary will be available at `target/release/sysmon_validator`

### Schema Files

Place your XSD schema files in one of these locations:

- `./schemas/`
- `./src/schemas/`
- Same directory as the executable

Schema files should follow one of these naming patterns:

- `v4_22_schema.xsd`
- `sysmonconfig-schema-4.22.xsd`

## Command Line Usage

Basic validation:

```bash
sysmon_validator path/to/sysmonconfig.xml
```

With additional options:

```bash
sysmon_validator path/to/sysmonconfig.xml --verbose
sysmon_validator path/to/sysmonconfig.xml --debug
```

### Command Line Options

- `--verbose`: Show detailed validation information and error context
- `--debug`: Show debug information including schema validation details

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
sysmon_validator = { git = "https://github.com/whit3rabbit/sysmon_validator" }
```

### Basic Validation

```rust
use sysmon_validator::validate_config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match validate_config("path/to/config.xml") {
        Ok(()) => println!("Configuration is valid"),
        Err(e) => eprintln!("Validation error: {}", e),
    }
    Ok(())
}
```

### String Validation

```rust
use sysmon_validator::validate_config_from_str;

fn validate_my_config(xml_content: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_config_from_str(xml_content)?;
    Ok(())
}
```

### Custom Validation Pipeline

```rust
use sysmon_validator::{parse_sysmon_config_from_str, validate_sysmon_config};

fn custom_validation(xml_content: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the configuration
    let config = parse_sysmon_config_from_str(xml_content)?;
    
    // Perform custom pre-validation checks
    // ...
    
    // Perform standard validation
    validate_sysmon_config(&config)?;
    
    // Perform custom post-validation checks
    // ...
    
    Ok(())
}
```

## Schema Versioning

The validator supports Sysmon configuration schema versions 4.22 and above. It automatically selects the most appropriate schema version for validation based on the `schemaversion` attribute in your configuration file.

### Version Compatibility

When validating a configuration file with version X.YY:

1. The validator looks for an exact matching schema version
2. If not found, it uses the highest available schema version that's lower than X.YY
3. Returns an error if no compatible schema version is found

## Validation Coverage

### Event Types

Supports all standard Sysmon event types including:

- ProcessCreate (Event ID 1)
- FileCreateTime (Event ID 2)
- NetworkConnect (Event ID 3)
- ProcessTerminate (Event ID 5)
- DriverLoad (Event ID 6)
- ImageLoad (Event ID 7)
- CreateRemoteThread (Event ID 8)
- RawAccessRead (Event ID 9)
- ProcessAccess (Event ID 10)
- FileCreate (Event ID 11)
- RegistryEvent (Event IDs 12,13,14)
- FileCreateStreamHash (Event ID 15)
- PipeEvent (Event IDs 17,18)
- WmiEvent (Event IDs 19,20,21)
- DnsQuery (Event ID 22)
- FileDelete (Event ID 23)
- ClipboardChange (Event ID 24)
- ProcessTampering (Event ID 25)
- FileDeleteDetected (Event ID 26)
- FileBlockExecutable (Event ID 27)
- FileBlockShredding (Event ID 28)
- FileExecutableDetected (Event ID 29)

### Field Validation

Validates various field formats including:

- Windows paths and file names
- IPv4 and IPv6 addresses
- Port numbers
- Registry paths
- UTC timestamps
- GUIDs
- Hash values (MD5, SHA1, SHA256, IMPHASH)
- Process IDs
- Boolean values

## Error Messages

The validator provides detailed error messages with context for:

- Schema version mismatches
- XML syntax errors
- Invalid event types
- Invalid field names or formats
- Missing required fields
- Invalid operators or conditions
- Multiple filter conflicts
- Rule group validation errors

## Development

### Running Tests

```bash
cargo test
```

### Debug Logging

```bash
RUST_LOG=debug cargo run -- path/to/config.xml
```

### Contributing

1. Ensure all tests pass
2. Add tests for new features
3. Update documentation for changes
4. Follow Rust formatting guidelines
