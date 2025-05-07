# Checkpoint to ASA NAT Rule Converter

This tool converts NAT rules from Checkpoint R81.x format to Cisco ASA format. It handles the conversion of static NAT rules, no-NAT rules, and pool NAT rules.

## Features

- Converts Checkpoint R81.x NAT rules to Cisco ASA format
- Handles different types of NAT rules:
  - Static NAT (85% of rules)
  - No-NAT rules (10% of rules)
  - Pool NAT rules
- Resolves object UUIDs to actual values (IPs, networks, services)
- Supports different object types:
  - Host objects (single IP)
  - Network objects (subnets)
  - Group objects (with nested members)
  - Unknown types (uses name field as fallback)
- Skips automatic generated rules
- Generates proper ASA configurations including access lists
- Supports both source and destination NAT
- Preserves rule comments and section organization
- Includes rule UUIDs for traceability
- Comprehensive logging and error handling
- Detailed translation statistics

## Requirements

- Python 3.7+
- Required packages:
  - pydantic
  - typing
  - logging
  - json

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Method 1: Command Line Interface (Recommended for Simple Usage)

Use `convertor.py` for simple command-line conversion:

```bash
python convertor.py nat_rules.json objects.json asa_nat_rules.txt
```

This will:
1. Load the Checkpoint NAT rules and objects from their respective JSON files
2. Resolve all object UUIDs to their actual values
3. Convert the rules to ASA format
4. Save the converted rules to the output file
5. Provide progress feedback during the conversion
6. Generate detailed logs and statistics

### Method 2: Programmatic Usage (For Integration)

Use `programmatic_usage.py` when you need to:
- Integrate the converter into another Python program
- Process multiple files
- Add custom processing logic

Basic usage:
```python
from nat_translator import NATTranslator

# Initialize the translator with objects file
translator = NATTranslator(objects_file='objects.json')

# Load and convert rules
checkpoint_rules = translator.load_checkpoint_rules('nat_rules.json')
asa_rules = translator.translate_rules(checkpoint_rules)

# Save the converted rules
translator.save_asa_rules(asa_rules, 'asa_nat_rules.txt')
```

## Input Format

### NAT Rules JSON Format
```json
[
    {
        "uid": "string",
        "name": "string",
        "type": "nat-section" | "nat-rule",
        "method": "hide" | "static" | "no-nat",
        "auto-generated": boolean,
        "translated-destination": "uuid",
        "original-service": "uuid",
        "translated-source": "uuid",
        "translated-service": "uuid",
        "enabled": boolean,
        "rule-number": number,
        "original-destination": "uuid",
        "original-source": "uuid",
        "Comments": "string",
        "section-uid": "string"
    }
]
```

### Objects JSON Format
```json
[
    {
        "uid": "string",
        "type": "host" | "network" | "group" | "global" | "cpmi",
        "name": "string",
        "ipv4-address": "x.x.x.x",  // for host type
        "subnet4": "x.x.x.x/y",     // for network type
        "members": ["uuid1", "uuid2"] // for group type
    }
]
```

## Output Format

The output will be a text file containing ASA-compatible NAT rules, including:
- Section headers preserving Checkpoint organization
- Rule comments with both original comments and UUIDs
- Static NAT rules
- No-NAT rules with corresponding access lists
- Pool NAT rules with global pools and access lists

Example output:
```
! Generated ASA NAT Rules from Checkpoint R81.x
! ============================================

! Checkpoint NAT Section: Internet Access
! Rule: Allow web access | UUID: abc123
static (inside,outside) 10.0.0.1 192.168.1.1 netmask 255.255.255.255

! Checkpoint NAT Section: Internal Services
! Rule: NA | UUID: def456
access-list NO_NAT_Rule1 extended permit ip 192.168.1.0 255.255.255.0 any
nat (inside,outside) 0 access-list NO_NAT_Rule1
```

## Project Structure

- `convertor.py`: Command-line interface for simple file conversion
- `programmatic_usage.py`: Programmatic interface for integration and batch processing
- `nat_translator.py`: Main translator class and NAT rule model
- `nat_handlers.py`: Handlers for different types of NAT rules
- `object_resolver.py`: Resolves object UUIDs to actual values
- `utils.py`: Utility functions for validation and formatting
- `requirements.txt`: Project dependencies
- `README.md`: Project documentation

## Error Handling

The converter includes comprehensive error handling:
- Validates input JSON structure
- Handles file not found errors
- Logs unhandled rules and conversion issues
- Provides detailed error messages for troubleshooting
- Handles missing or invalid object references
- Tracks and reports translation statistics

## Logging

The converter generates detailed logs in a file named `nat_translation_YYYYMMDD_HHMMSS.log` containing:
- Conversion progress
- Rule processing status
- Unhandled rules
- Validation errors
- Object resolution issues
- Translation errors
- General conversion statistics

### Log Format Examples

```
Rule 1 loaded successfully
Rule 2 skipped - Rule is disabled
Rule 3 skipped - Auto-generated rule
Rule 4 failed - Object resolution error: Invalid object type
Rule 5 translated successfully to static NAT
Rule 6 translation failed - Handler returned no rule
Rule 7 translation failed - Error: Invalid IP address

Translation Statistics:
Total rules processed: 100
Successfully translated: 85
Failed translations: 10
Skipped rules: 5
Object resolution errors: 3
Translation errors: 7
``` 