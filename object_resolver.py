from typing import Dict, Any, List, Set, Optional
import json
import logging

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
        resolved_rule = rule.copy()
        
        # List of fields that might contain object UUIDs
        object_fields = [
            'original-source',
            'original-destination',
            'translated-source',
            'translated-destination',
            'original-service',
            'translated-service'
        ]
        
        for field in object_fields:
            if field in resolved_rule:
                uid = resolved_rule[field]
                if uid:
                    resolved_value = self.resolve_object(uid)
                    if resolved_value:
                        resolved_rule[field] = resolved_value
                    else:
                        # If resolution fails, keep the original UUID
                        self.logger.warning(f"Could not resolve {field} with UUID: {uid}")
                        
        return resolved_rule 