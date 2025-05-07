from base_handler import NATHandler
from typing import Dict, Any, Optional
import logging

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
                return f"static (inside,outside) {translated_source} {original_source} netmask 255.255.255.255"
            elif original_destination and translated_destination:
                return f"static (inside,outside) {original_destination} {translated_destination} netmask 255.255.255.255"
            
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
            # Extract network objects
            source_network = rule.get('original-source', 'any')
            dest_network = rule.get('original-destination', 'any')
            
            # Create access list name based on rule UID
            acl_name = f"NO_NAT_{rule.get('uid', '').replace('-', '_')}"
            
            # Create access list and NAT rule
            acl_config = f"access-list {acl_name} extended permit ip {source_network} {dest_network}"
            nat_config = f"nat (inside,outside) 0 access-list {acl_name}"
            
            return f"{acl_config}\n{nat_config}"
            
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
            pool_name = f"NAT_POOL_{rule.get('uid', '').replace('-', '_')}"
            
            # Get IP range from translated source
            translated_source = rule.get('translated-source', '')
            if not translated_source:
                self.logger.warning(f"Pool NAT rule missing translated source")
                return None
                
            # Create pool configuration
            pool_config = f"global (outside) {pool_name} {translated_source} netmask 255.255.255.0"
            
            # Create access list for the pool
            source_network = rule.get('original-source', 'any')
            acl_name = f"{pool_name}_ACL"
            acl_config = f"access-list {acl_name} extended permit ip {source_network} any"
            
            # Create NAT rule
            nat_config = f"nat (inside) 1 access-list {acl_name}"
            
            return f"{acl_config}\n{pool_config}\n{nat_config}"
            
        except Exception as e:
            self.logger.error(f"Error translating pool NAT rule: {str(e)}")
            return None 