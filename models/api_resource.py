from enum import Enum
from typing import List, Optional


class ResourceType(Enum):
    USER_OWNED = "user_owned"
    GLOBAL = "global"
    ADMIN = "admin"
    AUTH = "auth"


class ApiResource:
    def __init__(
        self,
        name: str,
        path: str,
        methods: List[str],
        resource_type: ResourceType,
        owner_identifier: Optional[str] = None,
        sensitive_fields: Optional[List[str]] = None,
        writable_fields: Optional[List[str]] = None,
        discovered_by: str = "unknown",
    ):
        self.name = name
        self.path = path
        self.methods = methods
        self.resource_type = resource_type
        self.owner_identifier = owner_identifier
        self.sensitive_fields = sensitive_fields or []
        self.writable_fields = writable_fields or []
        self.discovered_by = discovered_by
        self.risk_flags: List[str] = []

    def __repr__(self):
        return f"<ApiResource {self.name} {self.path}>"
