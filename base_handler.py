from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class NATHandler(ABC):
    """Base class for NAT rule handlers"""
    
    @abstractmethod
    def translate(self, rule: Dict[str, Any]) -> Optional[str]:
        """
        Translate a NAT rule to ASA format
        
        Args:
            rule (Dict[str, Any]): The NAT rule to translate
            
        Returns:
            Optional[str]: The translated ASA rule, or None if translation fails
        """
        pass 