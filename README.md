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

1. Export your Checkpoint NAT policy as JSON
2. Run the converter:
```python
from nat_translator import NATTranslator

# Initialize the translator
translator = NATTranslator()

# Load and convert rules
checkpoint_rules = translator.load_checkpoint_rules('checkpoint_nat_policy.json')
asa_rules = translator.translate_rules(checkpoint_rules)

# Save the converted rules
translator.save_asa_rules(asa_rules, 'asa_nat_rules.txt')
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

- `nat_translator.py`: Main translator class and NAT rule model
- `nat_handlers.py`: Handlers for different types of NAT rules
- `requirements.txt`: Project dependencies
- `README.md`: Project documentation 