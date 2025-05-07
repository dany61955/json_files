from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple, Optional
import json
import logging
from datetime import datetime
from pydantic import BaseModel, Field
from nat_handlers import StaticNATHandler, NoNATHandler, PoolNATHandler
from utils import validate_checkpoint_json, format_asa_rule, log_unhandled_rule
from object_resolver import ObjectResolver

class NATRule(BaseModel):
    """Base model for NAT rules"""
    uid: str
    type: str
    method: str
    auto_generated: bool = Field(alias='auto-generated')
    translated_destination: str = Field(alias='translated-destination')
    original_service: str = Field(alias='original-service')
    translated_source: str = Field(alias='translated-source')
    translated_service: str = Field(alias='translated-service')
    enabled: bool = True
    rule_number: int = Field(alias='rule-number')
    original_destination: str = Field(alias='original-destination')
    original_source: str = Field(alias='original-source')
    Comments: Optional[str] = None
    section_uid: Optional[str] = Field(None, alias='section-uid')

    class Config:
        allow_population_by_field_name = True

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
        
        # Track section names
        self.section_names = {}
        
        # Statistics for rule processing
        self.stats = {
            'total_rules': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'object_errors': 0,
            'translation_errors': 0
        }
        
    def load_checkpoint_rules(self, file_path: str) -> List[Tuple[Dict[str, Any], str]]:
        """Load NAT rules from Checkpoint JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Validate JSON structure
            if not validate_checkpoint_json(data):
                error_msg = "Invalid Checkpoint NAT rules JSON structure"
                self.logger.error(error_msg)
                raise ValueError(error_msg)
                
            # Extract NAT rules from the policy
            nat_rules = []
            current_section = "Default Section"
            
            # First pass: collect section names
            for item in data:
                if item.get('type') == 'nat-section':
                    self.section_names[item.get('uid', '')] = item.get('name', 'Unnamed Section')
            
            # Second pass: process rules
            for rule in data:
                if rule.get('type') == 'nat-rule':
                    self.stats['total_rules'] += 1
                    rule_number = rule.get('rule-number', 0)
                    
                    # Skip disabled rules and auto-generated rules
                    if not rule.get('enabled', True):
                        self.logger.info(f"Rule {rule_number} skipped - Rule is disabled")
                        self.stats['skipped'] += 1
                        continue
                        
                    if rule.get('auto-generated', False):
                        self.logger.info(f"Rule {rule_number} skipped - Auto-generated rule")
                        self.stats['skipped'] += 1
                        continue
                        
                    # Resolve object UUIDs if resolver is available
                    if self.object_resolver:
                        try:
                            rule = self.object_resolver.resolve_rule_objects(rule)
                        except Exception as e:
                            self.logger.error(f"Rule {rule_number} failed - Object resolution error: {str(e)}")
                            self.stats['object_errors'] += 1
                            self.stats['failed'] += 1
                            continue
                    
                    # Get section name if available
                    section_name = self.section_names.get(rule.get('section-uid', ''), "Default Section")
                    nat_rules.append((rule, section_name))
                    self.logger.info(f"Rule {rule_number} loaded successfully")
            
            return nat_rules
            
        except FileNotFoundError:
            error_msg = f"Checkpoint rules file not found: {file_path}"
            self.logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        except json.JSONDecodeError:
            error_msg = f"Invalid JSON format in file: {file_path}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Error loading Checkpoint rules: {str(e)}"
            self.logger.error(error_msg)
            raise
    
    def translate_rules(self, checkpoint_rules: List[Tuple[Dict[str, Any], str]]) -> List[str]:
        """Translate Checkpoint NAT rules to ASA format"""
        asa_rules = []
        current_section = None
        
        for rule, section_name in checkpoint_rules:
            rule_number = rule.get('rule-number', 0)
            
            # Add section header if section changes
            if section_name != current_section:
                asa_rules.append(f"! Checkpoint NAT Section: {section_name}\n")
                current_section = section_name
            
            # Determine NAT type based on rule properties
            nat_type = self._determine_nat_type(rule)
            handler = self.handlers.get(nat_type)
            
            if handler:
                try:
                    asa_rule = handler.translate(rule)
                    if asa_rule:
                        # Create rule comment with both comment and UUID
                        comment = rule.get('Comments', 'NA')
                        rule_comment = f"Rule: {comment} | UUID: {rule.get('uid')}"
                        asa_rules.append(format_asa_rule(asa_rule, rule_comment))
                        self.logger.info(f"Rule {rule_number} translated successfully to {nat_type} NAT")
                        self.stats['successful'] += 1
                    else:
                        self.logger.warning(f"Rule {rule_number} translation failed - Handler returned no rule")
                        self.stats['translation_errors'] += 1
                        self.stats['failed'] += 1
                except Exception as e:
                    self.logger.error(f"Rule {rule_number} translation failed - Error: {str(e)}")
                    self.stats['translation_errors'] += 1
                    self.stats['failed'] += 1
            else:
                log_unhandled_rule(self.logger, rule, f"No handler found for NAT type: {nat_type}")
                self.stats['translation_errors'] += 1
                self.stats['failed'] += 1
        
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
        try:
            with open(output_file, 'w') as f:
                # Write header comments
                f.write("! Generated ASA NAT Rules from Checkpoint R81.x\n")
                f.write("! ============================================\n\n")
                
                # Write rules
                for rule in asa_rules:
                    f.write(rule)
                    
            # Log final statistics
            self.logger.info("\nTranslation Statistics:")
            self.logger.info(f"Total rules processed: {self.stats['total_rules']}")
            self.logger.info(f"Successfully translated: {self.stats['successful']}")
            self.logger.info(f"Failed translations: {self.stats['failed']}")
            self.logger.info(f"Skipped rules: {self.stats['skipped']}")
            self.logger.info(f"Object resolution errors: {self.stats['object_errors']}")
            self.logger.info(f"Translation errors: {self.stats['translation_errors']}")
            
            self.logger.info(f"Successfully saved {len(asa_rules)} ASA rules to {output_file}")
            
        except Exception as e:
            error_msg = f"Error saving ASA rules: {str(e)}"
            self.logger.error(error_msg)
            raise 