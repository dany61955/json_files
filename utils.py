import json
from typing import Dict, Any, List
import logging
import re

def validate_checkpoint_json(data: List[Dict[str, Any]]) -> bool:
    """
    Validate the structure of Checkpoint NAT rules JSON
    
    Args:
        data (List[Dict[str, Any]]): The JSON data to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(data, list):
        return False
        
    required_fields = {
        'nat-rule': ['uid', 'type', 'method'],
        'nat-section': ['uid', 'type', 'name']
    }
    
    for item in data:
        item_type = item.get('type')
        if item_type not in required_fields:
            continue
            
        for field in required_fields[item_type]:
            if field not in item:
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
    """
    Format an ASA rule with optional comment
    
    Args:
        rule (str): The ASA rule to format
        comment (str, optional): Comment to add before the rule
        
    Returns:
        str: Formatted rule with comment
    """
    if not rule:
        return ""
        
    formatted = []
    if comment:
        formatted.append(f"! {comment}")
    formatted.append(rule)
    formatted.append("")  # Add blank line after rule
    
    return "\n".join(formatted)

def log_unhandled_rule(logger: logging.Logger, rule: Dict[str, Any], reason: str):
    """
    Log an unhandled rule with details
    
    Args:
        logger (logging.Logger): Logger instance
        rule (Dict[str, Any]): The unhandled rule
        reason (str): Reason why the rule was unhandled
    """
    rule_number = rule.get('rule-number', 'unknown')
    rule_uid = rule.get('uid', 'unknown')
    rule_method = rule.get('method', 'unknown')
    
    logger.warning(
        f"Unhandled rule {rule_number} (UID: {rule_uid}, Method: {rule_method}) - {reason}"
    )

def validate_ip_address(ip: str) -> bool:
    """
    Validate an IP address format
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not ip or ip == 'any':
        return True
        
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
        
    # Check each octet
    try:
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False

def validate_subnet(subnet: str) -> bool:
    """
    Validate a subnet format (CIDR notation)
    
    Args:
        subnet (str): Subnet to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not subnet or subnet == 'any':
        return True
        
    try:
        ip, mask = subnet.split('/')
        if not validate_ip_address(ip):
            return False
        mask = int(mask)
        return 0 <= mask <= 32
    except ValueError:
        return False 