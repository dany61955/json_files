from typing import Dict, Any, List, Set
import json
import logging

class ObjectResolver:
    """Resolves object UUIDs to their actual values"""
    
    def __init__(self, objects_file: str):
        self.objects = {}
        self.logger = logging.getLogger(__name__)
        self._load_objects(objects_file)
        
    def _load_objects(self, objects_file: str):
        """Load objects from JSON file"""
        try:
            with open(objects_file, 'r') as f:
                objects_data = json.load(f)
                
            # Create a mapping of UUID to object
            for obj in objects_data:
                if 'uid' in obj:
                    self.objects[obj['uid']] = obj
                    
        except Exception as e:
            self.logger.error(f"Error loading objects file: {e}")
            raise
            
    def resolve_object(self, uuid: str) -> List[str]:
        """
        Resolve an object UUID to its actual value(s)
        Returns a list of values because groups can have multiple members
        """
        if not uuid:
            return ['any']
            
        obj = self.objects.get(uuid)
        if not obj:
            self.logger.warning(f"Object not found for UUID: {uuid}")
            return ['any']
            
        obj_type = obj.get('type', '').lower()
        
        # Handle different object types
        if obj_type == 'host':
            return [obj.get('ipv4-address', 'any')]
            
        elif obj_type == 'network':
            return [obj.get('subnet4', 'any')]
            
        elif obj_type == 'group':
            # Recursively resolve group members
            resolved_members = set()
            for member_uuid in obj.get('members', []):
                member_values = self.resolve_object(member_uuid)
                resolved_members.update(member_values)
            return list(resolved_members)
            
        else:
            self.logger.warning(f"Unknown object type: {obj_type} for UUID: {uuid}")
            return ['any']
            
    def resolve_rule_objects(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve all object UUIDs in a rule to their actual values"""
        resolved_rule = rule.copy()
        
        # Fields that need resolution
        fields_to_resolve = [
            'original-source',
            'original-destination',
            'original-service',
            'translated-source',
            'translated-destination',
            'translated-service'
        ]
        
        for field in fields_to_resolve:
            if field in rule:
                values = self.resolve_object(rule[field])
                # For now, just take the first value
                # TODO: Handle multiple values properly
                resolved_rule[field] = values[0] if values else 'any'
                
        return resolved_rule 