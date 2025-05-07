from abc import ABC, abstractmethod
from typing import Dict, Any, List
import json
import logging
from datetime import datetime
from pydantic import BaseModel
from nat_handlers import StaticNATHandler, NoNATHandler, PoolNATHandler
from utils import validate_checkpoint_json, format_asa_rule, log_unhandled_rule

class NATRule(BaseModel):
    """Base model for NAT rules"""
    name: str
    source: str
    destination: str
    service: str
    action: str
    type: str
    auto_generated: bool = False

class NATTranslator:
    """Main class for translating NAT rules from Checkpoint to ASA"""
    
    def __init__(self, log_file: str = None):
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
        
        # Process user-defined rules first
        if 'nat-policy' in data:
            for section in data['nat-policy']:
                if section.get('type') == 'user-defined':
                    for rule in section.get('rules', []):
                        rule['auto_generated'] = False
                        nat_rules.append(rule)
        
        return nat_rules
    
    def translate_rules(self, checkpoint_rules: List[Dict[str, Any]]) -> List[str]:
        """Translate Checkpoint NAT rules to ASA format"""
        asa_rules = []
        
        for rule in checkpoint_rules:
            # Skip automatic rules
            if rule.get('auto_generated', False):
                continue
                
            # Determine NAT type based on rule properties
            nat_type = self._determine_nat_type(rule)
            handler = self.handlers.get(nat_type)
            
            if handler:
                asa_rule = handler.translate(rule)
                if asa_rule:
                    asa_rules.append(format_asa_rule(asa_rule, f"Rule: {rule.get('name')}"))
            else:
                log_unhandled_rule(self.logger, rule, f"No handler found for NAT type: {nat_type}")
        
        return asa_rules
    
    def _determine_nat_type(self, rule: Dict[str, Any]) -> str:
        """Determine the NAT type based on rule properties"""
        # Check for no-NAT rules first
        if rule.get('action') == 'no-nat' or rule.get('type') == 'no-nat':
            return 'no_nat'
            
        # Check for pool NAT rules
        if (rule.get('action') == 'hide' or 
            rule.get('type') == 'hide' or 
            'pool' in rule.get('translation', {})):
            return 'pool'
            
        # Check for static NAT rules
        if (rule.get('action') == 'static' or 
            rule.get('type') == 'static' or 
            (rule.get('translation', {}).get('method') == 'static')):
            return 'static'
            
        # Additional checks for static NAT based on rule structure
        translation = rule.get('translation', {})
        if (translation.get('original') and translation.get('translated') and
            not isinstance(translation.get('translated'), list)):
            return 'static'
            
        # Log unhandled NAT type
        log_unhandled_rule(self.logger, rule, "Could not determine NAT type, defaulting to static")
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