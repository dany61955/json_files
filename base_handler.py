from abc import ABC, abstractmethod
from typing import Dict, Any

class NATHandler(ABC):
    """Abstract base class for NAT handlers"""
    
    @abstractmethod
    def translate(self, rule: Dict[str, Any]) -> str:
        """Translate a NAT rule to ASA format"""
        pass 