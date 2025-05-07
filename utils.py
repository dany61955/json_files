import json
from typing import Dict, Any, List
import logging

def validate_checkpoint_json(json_data: Dict[str, Any]) -> bool:
    """Validate the structure of Checkpoint NAT rules JSON"""
    if not isinstance(json_data, dict):
        return False
        
    if 'nat-policy' not in json_data:
        return False
        
    for section in json_data['nat-policy']:
        if not isinstance(section, dict):
            return False
        if 'type' not in section or 'rules' not in section:
            return False
        for rule in section['rules']:
            if not isinstance(rule, dict):
                return False
            if not all(field in rule for field in ['name', 'source', 'destination']):
                return False
    
    return True

def create_asa_acl(rule: Dict[str, Any]) -> str:
    """Create ASA access-list for NAT rules"""
    acl_name = f"NAT_ACL_{rule.get('name', '')}"
    source = rule.get('source', 'any')
    destination = rule.get('destination', 'any')
    service = rule.get('service', 'any')
    
    return f"access-list {acl_name} extended permit {service} {source} {destination}"

def format_asa_rule(rule: str, comment: str = None) -> str:
    """Format ASA rule with proper indentation and comments"""
    if comment:
        return f"! {comment}\n{rule}\n"
    return f"{rule}\n"

def log_unhandled_rule(logger: logging.Logger, rule: Dict[str, Any], reason: str):
    """Log unhandled NAT rule with details"""
    rule_details = {
        'name': rule.get('name', 'unnamed'),
        'type': rule.get('type', 'unknown'),
        'action': rule.get('action', 'unknown'),
        'source': rule.get('source', {}),
        'destination': rule.get('destination', {})
    }
    logger.warning(f"Unhandled rule: {reason}\nRule details: {json.dumps(rule_details, indent=2)}") 