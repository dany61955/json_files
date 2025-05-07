# Checkpoint to ASA NAT Rule Converter

This tool converts NAT rules from Checkpoint R81.x format to Cisco ASA format. It handles the conversion of static NAT rules, no-NAT rules, and pool NAT rules.

## Features

- Converts Checkpoint R81.x NAT rules to Cisco ASA format
- Handles different types of NAT rules:
  - Static NAT (85% of rules)
  - No-NAT rules (10% of rules)
  - Pool NAT rules
- Skips automatic generated rules
- Generates proper ASA configurations including access lists
- Supports both source and destination NAT

## Requirements

- Python 3.7+
- Required packages (see requirements.txt)

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
python convertor.py checkpoint_nat_policy.json asa_nat_rules.txt
```

This will:
1. Load the Checkpoint NAT rules from the input JSON file
2. Convert them to ASA format
3. Save the converted rules to the output file
4. Provide progress feedback during the conversion

### Method 2: Programmatic Usage (For Integration)

Use `programmatic_usage.py` when you need to:
- Integrate the converter into another Python program
- Process multiple files
- Add custom processing logic

Basic usage:
```python
from programmatic_usage import convert_nat_rules

# Convert a single file
rules = convert_nat_rules('checkpoint_nat_policy.json', 'asa_nat_rules.txt')
```

Process multiple files:
```python
from programmatic_usage import process_multiple_files

# Convert multiple files
input_files = ['policy1.json', 'policy2.json']
results = process_multiple_files(input_files, 'output_directory')
```

## Input Format

The input should be a JSON file containing Checkpoint NAT rules with the following structure:
```json
{
    "nat-policy": [
        {
            "type": "user-defined",
            "rules": [
                {
                    "name": "rule_name",
                    "source": {
                        "ip": "192.168.1.1"
                    },
                    "destination": {
                        "ip": "10.0.0.1"
                    },
                    "service": "any",
                    "action": "static"
                }
            ]
        }
    ]
}
```

## Output Format

The output will be a text file containing ASA-compatible NAT rules, including:
- Static NAT rules
- No-NAT rules with corresponding access lists
- Pool NAT rules with global pools and access lists

Example output:
```
! Generated ASA NAT Rules from Checkpoint R81.x
! ============================================

static (inside,outside) 10.0.0.1 192.168.1.1 netmask 255.255.255.255
access-list NO_NAT_Rule1 extended permit ip 192.168.1.0 255.255.255.0 any
nat (inside,outside) 0 access-list NO_NAT_Rule1
```

## Project Structure

- `convertor.py`: Command-line interface for simple file conversion
- `programmatic_usage.py`: Programmatic interface for integration and batch processing
- `nat_translator.py`: Main translator class and NAT rule model
- `nat_handlers.py`: Handlers for different types of NAT rules
- `utils.py`: Utility functions for validation and formatting
- `requirements.txt`: Project dependencies
- `README.md`: Project documentation

## Error Handling

The converter includes comprehensive error handling:
- Validates input JSON structure
- Handles file not found errors
- Logs unhandled rules and conversion issues
- Provides detailed error messages for troubleshooting

## Logging

The converter generates detailed logs in a file named `nat_translation_YYYYMMDD_HHMMSS.log` containing:
- Conversion progress
- Unhandled rules
- Validation errors
- General conversion statistics 