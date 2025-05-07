from base_handler import NATHandler
from typing import Dict, Any, Optional
import logging
from utils import create_asa_acl

class StaticNATHandler(NATHandler):
    """Handler for static NAT rules"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def translate(self, rule: Dict[str, Any]) -> Optional[str]:
        """Translate static NAT rule to ASA format"""
        try:
            # Get original and translated IPs
            original_source = rule.get('original-source', '')
            translated_source = rule.get('translated-source', '')
            original_destination = rule.get('original-destination', '')
            translated_destination = rule.get('translated-destination', '')
            
            # Get service information
            original_service = rule.get('original-service', 'any')
            translated_service = rule.get('translated-service', 'any')
            
            # Handle both source and destination NAT
            if original_source and translated_source:
                # Create ACL for source NAT
                acl = create_asa_acl(rule, use_translated=False)
                # Create static NAT rule
                nat_rule = f"static (inside,outside) {translated_source} {original_source} netmask 255.255.255.255"
                return f"{acl}\n{nat_rule}"
            elif original_destination and translated_destination:
                # Create ACL for destination NAT
                acl = create_asa_acl(rule, use_translated=True)
                # Create static NAT rule
                nat_rule = f"static (inside,outside) {original_destination} {translated_destination} netmask 255.255.255.255"
                return f"{acl}\n{nat_rule}"
            
            self.logger.warning(f"Static NAT rule missing required fields - Source: {original_source}/{translated_source}, Destination: {original_destination}/{translated_destination}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error translating static NAT rule: {str(e)}")
            return None

class NoNATHandler(NATHandler):
    """Handler for no-NAT rules"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def translate(self, rule: Dict[str, Any]) -> Optional[str]:
        """Translate no-NAT rule to ASA format"""
        try:
            # Create ACL using original fields
            acl = create_asa_acl(rule, use_translated=False)
            
            # Create NAT rule using the ACL name from the ACL line
            acl_name = acl.split()[1]  # Get the ACL name from the ACL line
            nat_config = f"nat (inside,outside) 0 access-list {acl_name}"
            
            return f"{acl}\n{nat_config}"
            
        except Exception as e:
            self.logger.error(f"Error translating no-NAT rule: {str(e)}")
            return None

class PoolNATHandler(NATHandler):
    """Handler for pool NAT rules"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def translate(self, rule: Dict[str, Any]) -> Optional[str]:
        """Translate pool NAT rule to ASA format"""
        try:
            # Extract pool information
            rule_number = rule.get('rule-number', 0)
            pool_name = f"NAT_POOL_{rule_number:04d}"
            
            # Get IP range from translated source
            translated_source = rule.get('translated-source', '')
            if not translated_source:
                self.logger.warning(f"Pool NAT rule missing translated source")
                return None
                
            # Create pool configuration
            pool_config = f"global (outside) {pool_name} {translated_source} netmask 255.255.255.0"
            
            # Create ACL using original fields
            acl = create_asa_acl(rule, use_translated=False)
            
            # Create NAT rule using the ACL name from the ACL line
            acl_name = acl.split()[1]  # Get the ACL name from the ACL line
            nat_config = f"nat (inside) 1 access-list {acl_name}"
            
            return f"{acl}\n{pool_config}\n{nat_config}"
            
        except Exception as e:
            self.logger.error(f"Error translating pool NAT rule: {str(e)}")
            return None 