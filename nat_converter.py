#!/usr/bin/env python3

import json
import logging
import sys
import re
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from abc import ABC, abstractmethod
from pydantic import BaseModel, Field

# Base NAT Handler Class
class NATHandler(ABC):
    """Base class for NAT rule handlers"""
    
    @abstractmethod
    def translate(self, rule: Dict[str, Any]) -> Optional[str]:
        """Translate a NAT rule to ASA format"""
        pass

# NAT Handlers
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

# Object Resolver
class ObjectResolver:
    """Resolves object UUIDs to their actual values"""
    
    def __init__(self, objects_file: str):
        self.objects = {}
        self.logger = logging.getLogger(__name__)
        self._load_objects(objects_file)
        
    def _load_objects(self, file_path: str):
        """Load objects from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Create lookup dictionary
            for obj in data:
                uid = obj.get('uid')
                if uid:
                    self.objects[uid] = obj
                    
        except Exception as e:
            self.logger.error(f"Error loading objects file: {str(e)}")
            raise
            
    def _resolve_host(self, obj: Dict[str, Any]) -> str:
        """Resolve host object to IP address"""
        return obj.get('ipv4-address', '')
        
    def _resolve_network(self, obj: Dict[str, Any]) -> str:
        """Resolve network object to subnet"""
        return obj.get('subnet4', '')
        
    def _resolve_group(self, obj: Dict[str, Any]) -> List[str]:
        """Resolve group object to list of members"""
        members = []
        for member_uid in obj.get('members', []):
            member = self.objects.get(member_uid)
            if member:
                resolved = self.resolve_object(member_uid)
                if resolved:
                    members.append(resolved)
        return members
        
    def resolve_object(self, uid: str) -> Optional[str]:
        """Resolve object UUID to its value"""
        obj = self.objects.get(uid)
        if not obj:
            self.logger.warning(f"Object not found for UUID: {uid}")
            return None
            
        obj_type = obj.get('type', '').lower()
        
        # Try to resolve based on type
        if obj_type == 'host':
            return self._resolve_host(obj)
        elif obj_type == 'network':
            return self._resolve_network(obj)
        elif obj_type == 'group':
            members = self._resolve_group(obj)
            return ' '.join(members) if members else None
        else:
            # For unknown types (global, cpmi, etc.), use the name field as fallback
            name = obj.get('name')
            if name:
                self.logger.warning(f"Using name field for unknown object type '{obj_type}' with UUID: {uid}")
                return name
            else:
                self.logger.warning(f"Unknown object type '{obj_type}' and no name field for UUID: {uid}")
                return None

    def resolve_rule_objects(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve all object UUIDs in a rule"""
        fields_to_resolve = [
            'original-source', 'original-destination', 'original-service',
            'translated-source', 'translated-destination', 'translated-service'
        ]
        
        resolved_rule = rule.copy()
        for field in fields_to_resolve:
            if field in rule:
                resolved = self.resolve_object(rule[field])
                if resolved:
                    resolved_rule[field] = resolved
                    
        return resolved_rule

# Utility Functions
def validate_checkpoint_json(data: List[Dict[str, Any]]) -> bool:
    """Validate the structure of Checkpoint NAT rules JSON"""
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

def create_asa_acl(rule: Dict[str, Any], use_translated: bool = False) -> str:
    """Create ASA access-list for NAT rules"""
    # Use rule number for ACL name, with leading zeros for consistent formatting
    rule_number = rule.get('rule-number', 0)
    acl_name = f"NAT_ACL_{rule_number:04d}"
    
    # Choose between original and translated fields
    if use_translated:
        source = rule.get('translated-source', 'any')
        destination = rule.get('translated-destination', 'any')
        service = rule.get('translated-service', 'any')
    else:
        source = rule.get('original-source', 'any')
        destination = rule.get('original-destination', 'any')
        service = rule.get('original-service', 'any')
    
    return f"access-list {acl_name} extended permit {service} {source} {destination}"

def format_asa_rule(rule: str, comment: str = None) -> str:
    """Format an ASA rule with optional comment"""
    if not rule:
        return ""
        
    formatted = []
    if comment:
        formatted.append(f"! {comment}")
    formatted.append(rule)
    formatted.append("")  # Add blank line after rule
    
    return "\n".join(formatted)

def log_unhandled_rule(logger: logging.Logger, rule: Dict[str, Any], reason: str):
    """Log an unhandled rule with details"""
    rule_number = rule.get('rule-number', 0)
    rule_uid = rule.get('uid', 'unknown')
    rule_method = rule.get('method', 'unknown')
    
    logger.warning(
        f"Unhandled rule {rule_number:04d} (UID: {rule_uid}, Method: {rule_method}) - {reason}"
    )

def validate_ip_address(ip: str) -> bool:
    """Validate an IP address format"""
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
    """Validate a subnet format (CIDR notation)"""
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

# Main NAT Translator Class
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
        
        # Create file handler for detailed logging
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        # Create console handler for statistics only
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.addFilter(lambda record: 'Translation Statistics:' in record.getMessage())
        
        # Setup root logger
        logging.basicConfig(
            level=logging.INFO,
            handlers=[file_handler, console_handler]
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
            
            # First pass: collect section names
            for item in data:
                if item.get('type') == 'nat-section':
                    section_uid = item.get('uid', '')
                    section_name = item.get('name', 'Unnamed Section')
                    # Skip auto-generated section names
                    if not section_name.startswith('Automatic Generated rules:'):
                        self.section_names[section_uid] = section_name
                    else:
                        self.logger.info(f"Skipping auto-generated section: {section_name}")
            
            # Second pass: process rules
            for rule in data:
                if rule.get('type') == 'nat-rule':
                    self.stats['total_rules'] += 1
                    rule_number = rule.get('rule-number', 0)
                    
                    # Skip disabled rules and auto-generated rules
                    if not rule.get('enabled', True):
                        self.logger.info(f"Rule {rule_number:04d} skipped - Rule is disabled")
                        self.stats['skipped'] += 1
                        continue
                        
                    if rule.get('auto-generated', False):
                        self.logger.info(f"Rule {rule_number:04d} skipped - Auto-generated rule")
                        self.stats['skipped'] += 1
                        continue
                        
                    # Resolve object UUIDs if resolver is available
                    if self.object_resolver:
                        try:
                            rule = self.object_resolver.resolve_rule_objects(rule)
                        except Exception as e:
                            self.logger.error(f"Rule {rule_number:04d} failed - Object resolution error: {str(e)}")
                            self.stats['object_errors'] += 1
                            self.stats['failed'] += 1
                            continue
                    
                    # Get section name if available
                    section_uid = rule.get('section-uid', '')
                    section_name = self.section_names.get(section_uid, "Default Section")
                    nat_rules.append((rule, section_name))
                    self.logger.info(f"Rule {rule_number:04d} loaded successfully")
            
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
                        rule_comment = f"Rule {rule_number:04d}: {comment} | UUID: {rule.get('uid')}"
                        asa_rules.append(format_asa_rule(asa_rule, rule_comment))
                        self.logger.info(f"Rule {rule_number:04d} translated successfully to {nat_type} NAT")
                        self.stats['successful'] += 1
                    else:
                        self.logger.warning(f"Rule {rule_number:04d} translation failed - Handler returned no rule")
                        self.stats['translation_errors'] += 1
                        self.stats['failed'] += 1
                except Exception as e:
                    self.logger.error(f"Rule {rule_number:04d} translation failed - Error: {str(e)}")
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

def main():
    """Main function to handle the conversion process"""
    import argparse
    
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description='Convert Checkpoint NAT rules to Cisco ASA format'
    )
    parser.add_argument(
        'nat_rules_file',
        help='Path to the Checkpoint NAT rules JSON file'
    )
    parser.add_argument(
        'objects_file',
        help='Path to the Checkpoint objects JSON file'
    )
    parser.add_argument(
        'output_file',
        help='Path to save the converted ASA rules'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_file = f"nat_translation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    # Create file handler for detailed logging
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # Create console handler for statistics only
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.addFilter(lambda record: 'Translation Statistics:' in record.getMessage())
    
    # Setup root logger
    logging.basicConfig(
        level=logging.INFO,
        handlers=[file_handler, console_handler]
    )
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting NAT rule conversion process")
        logger.info(f"Input files: NAT rules={args.nat_rules_file}, Objects={args.objects_file}")
        logger.info(f"Output file: {args.output_file}")
        
        # Initialize translator
        translator = NATTranslator(
            objects_file=args.objects_file,
            log_file=None  # We're handling logging in this script
        )
        
        # Load and process rules
        logger.info("Loading Checkpoint NAT rules...")
        checkpoint_rules = translator.load_checkpoint_rules(args.nat_rules_file)
        
        logger.info("Translating rules to ASA format...")
        asa_rules = translator.translate_rules(checkpoint_rules)
        
        logger.info("Saving ASA rules...")
        translator.save_asa_rules(asa_rules, args.output_file)
        
        # Print final statistics
        logger.info("\nTranslation Statistics:")
        logger.info(f"Total rules processed: {translator.stats['total_rules']}")
        logger.info(f"Successfully translated: {translator.stats['successful']}")
        logger.info(f"Failed translations: {translator.stats['failed']}")
        logger.info(f"Skipped rules: {translator.stats['skipped']}")
        logger.info(f"Object resolution errors: {translator.stats['object_errors']}")
        logger.info(f"Translation errors: {translator.stats['translation_errors']}")
        
        logger.info("Conversion completed successfully")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {str(e)}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Invalid input: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 