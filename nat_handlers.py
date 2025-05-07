from base_handler import NATHandler
from typing import Dict, Any

class StaticNATHandler(NATHandler):
    """Handler for static NAT rules"""
    
    def translate(self, rule: Dict[str, Any]) -> str:
        """Translate static NAT rule to ASA format"""
        # Extract source and destination information
        source = rule.get('source', {})
        destination = rule.get('destination', {})
        
        # Get original and translated IPs
        original_ip = source.get('ip', '')
        translated_ip = destination.get('ip', '')
        
        # Get service information
        service = rule.get('service', 'any')
        
        # Handle both source and destination NAT
        if original_ip and translated_ip:
            return f"static (inside,outside) {translated_ip} {original_ip} netmask 255.255.255.255"
        elif original_ip:
            return f"static (inside,outside) {original_ip} {original_ip} netmask 255.255.255.255"
        elif translated_ip:
            return f"static (inside,outside) {translated_ip} {translated_ip} netmask 255.255.255.255"
        
        return None

class NoNATHandler(NATHandler):
    """Handler for no-NAT rules"""
    
    def translate(self, rule: Dict[str, Any]) -> str:
        """Translate no-NAT rule to ASA format"""
        source = rule.get('source', {})
        destination = rule.get('destination', {})
        
        # Extract network objects
        source_network = source.get('ip', 'any')
        dest_network = destination.get('ip', 'any')
        
        # Create access list name based on rule name
        acl_name = f"NO_NAT_{rule.get('name', '').replace(' ', '_')}"
        
        # Create access list and NAT rule
        acl_config = f"access-list {acl_name} extended permit ip {source_network} {dest_network}"
        nat_config = f"nat (inside,outside) 0 access-list {acl_name}"
        
        return f"{acl_config}\n{nat_config}"

class PoolNATHandler(NATHandler):
    """Handler for pool NAT rules"""
    
    def translate(self, rule: Dict[str, Any]) -> str:
        """Translate pool NAT rule to ASA format"""
        # Extract pool information
        pool = rule.get('pool', {})
        pool_name = pool.get('name', 'NAT_POOL')
        
        # Get IP range
        start_ip = pool.get('start_ip', '')
        end_ip = pool.get('end_ip', '')
        netmask = pool.get('netmask', '255.255.255.0')
        
        if not (start_ip and end_ip):
            return None
            
        # Create pool configuration
        pool_config = f"global (outside) {pool_name} {start_ip}-{end_ip} netmask {netmask}"
        
        # Create access list for the pool
        source = rule.get('source', {})
        source_network = source.get('ip', 'any')
        acl_name = f"{pool_name}_ACL"
        acl_config = f"access-list {acl_name} extended permit ip {source_network} any"
        
        # Create NAT rule
        nat_config = f"nat (inside) 1 access-list {acl_name}"
        
        return f"{acl_config}\n{pool_config}\n{nat_config}" 