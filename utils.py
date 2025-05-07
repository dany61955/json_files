import json
from typing import Dict, Any, List
import logging

def validate_checkpoint_json(json_data: List[Dict[str, Any]]) -> bool:
    """
    Validate the structure of Checkpoint NAT rules JSON
    
    Expected format:
    [
        {
            "uid": "string",
            "name": "string",
            "type": "nat-section" | "nat-rule",
            "method": "hide" | "static",
            "auto-generated": boolean,
            "translated-destination": "string",
            "original-service": "string",
            "translated-source": "string",
            "translated-service": "string",
            "enabled": boolean,
            "rule-number": number,
            "original-destination": "string",
            "original-source": "string"
        }
    ]
    """
    if not isinstance(json_data, list):
        return False
        
    for rule in json_data:
        if not isinstance(rule, dict):
            return False
            
        # Check required fields for nat-rule type
        if rule.get('type') == 'nat-rule':
            required_fields = [
                'method',
                'auto-generated',
                'translated-destination',
                'original-service',
                'translated-source',
                'translated-service',
                'enabled',
                'uid',
                'rule-number',
                'original-destination',
                'original-source'
            ]
            if not all(field in rule for field in required_fields):
                return False
                
        # Check required fields for nat-section type
        elif rule.get('type') == 'nat-section':
            required_fields = ['uid', 'name', 'type']
            if not all(field in rule for field in required_fields):
                return False
    
    return True

def create_asa_acl(rule: Dict[str, Any]) -> str:
    """Create ASA access-list for NAT rules"""
    acl_name = f"NAT_ACL_{rule.get('name', '')}"
    source = rule.get('original-source', 'any')
    destination = rule.get('original-destination', 'any')
    service = rule.get('original-service', 'any')
    
    return f"access-list {acl_name} extended permit {service} {source} {destination}"

def format_asa_rule(rule: str, comment: str = None) -> str:
    """Format ASA rule with proper indentation and comments"""
    if comment:
        return f"! {comment}\n{rule}\n"
    return f"{rule}\n"

def log_unhandled_rule(logger: logging.Logger, rule: Dict[str, Any], reason: str):
    """Log unhandled NAT rule with details"""
    rule_details = {
        'uid': rule.get('uid', 'unknown'),
        'type': rule.get('type', 'unknown'),
        'method': rule.get('method', 'unknown'),
        'auto-generated': rule.get('auto-generated', False),
        'original-source': rule.get('original-source', 'unknown'),
        'original-destination': rule.get('original-destination', 'unknown')
    }
    logger.warning(f"Unhandled rule: {reason}\nRule details: {json.dumps(rule_details, indent=2)}") 