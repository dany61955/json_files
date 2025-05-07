from abc import ABC, abstractmethod
from typing import Dict, Any, List
import json
import logging
from datetime import datetime
from pydantic import BaseModel
from nat_handlers import StaticNATHandler, NoNATHandler, PoolNATHandler
from utils import validate_checkpoint_json, format_asa_rule, log_unhandled_rule
from object_resolver import ObjectResolver

class NATRule(BaseModel):
    """Base model for NAT rules"""
    uid: str
    type: str
    method: str
    auto_generated: bool
    translated_destination: str
    original_service: str
    translated_source: str
    translated_service: str
    enabled: bool
    rule_number: int
    original_destination: str
    original_source: str

class NATTranslator:
    """Main class for translating NAT rules from Checkpoint to ASA"""
    
    def __init__(self, objects_file: str = None, log_file: str = None):
        self.handlers = {
            'static': StaticNATHandler(),
            'no_nat': NoNATHandler(),
            'pool': PoolNATHandler()
        }
        
        # Setup logging
        if log_file is None:
            log_file = f"nat_translation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize object resolver if objects file is provided
        self.object_resolver = ObjectResolver(objects_file) if objects_file else None
    
    def load_checkpoint_rules(self, file_path: str) -> List[Dict[str, Any]]:
        """Load NAT rules from Checkpoint JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        # Validate JSON structure
        if not validate_checkpoint_json(data):
            error_msg = "Invalid Checkpoint NAT rules JSON structure"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Extract NAT rules from the policy
        nat_rules = []
        
        # Process only nat-rule type entries
        for rule in data:
            if rule.get('type') == 'nat-rule':
                # Skip disabled rules and auto-generated rules
                if not rule.get('enabled', True) or rule.get('auto-generated', False):
                    continue
                    
                # Resolve object UUIDs if resolver is available
                if self.object_resolver:
                    rule = self.object_resolver.resolve_rule_objects(rule)
                    
                nat_rules.append(rule)
        
        return nat_rules
    
    def translate_rules(self, checkpoint_rules: List[Dict[str, Any]]) -> List[str]:
        """Translate Checkpoint NAT rules to ASA format"""
        asa_rules = []
        
        for rule in checkpoint_rules:
            # Determine NAT type based on rule properties
            nat_type = self._determine_nat_type(rule)
            handler = self.handlers.get(nat_type)
            
            if handler:
                asa_rule = handler.translate(rule)
                if asa_rule:
                    asa_rules.append(format_asa_rule(asa_rule, f"Rule: {rule.get('uid')}"))
            else:
                log_unhandled_rule(self.logger, rule, f"No handler found for NAT type: {nat_type}")
        
        return asa_rules
    
    def _determine_nat_type(self, rule: Dict[str, Any]) -> str:
        """Determine the NAT type based on rule properties"""
        method = rule.get('method', '').lower()
        
        # Check for no-NAT rules
        if method == 'no-nat':
            return 'no_nat'
            
        # Check for pool NAT rules
        if method == 'hide':
            return 'pool'
            
        # Check for static NAT rules
        if method == 'static':
            return 'static'
            
        # Log unhandled NAT type
        log_unhandled_rule(self.logger, rule, f"Could not determine NAT type for method: {method}, defaulting to static")
        return 'static'
    
    def save_asa_rules(self, asa_rules: List[str], output_file: str):
        """Save translated ASA rules to a file"""
        with open(output_file, 'w') as f:
            # Write header comments
            f.write("! Generated ASA NAT Rules from Checkpoint R81.x\n")
            f.write("! ============================================\n\n")
            
            # Write rules
            for rule in asa_rules:
                f.write(rule)
                
        self.logger.info(f"Successfully saved {len(asa_rules)} ASA rules to {output_file}") 