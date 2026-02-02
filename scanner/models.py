from enum import Enum
from typing import List, Optional


class ResourceType(Enum):
    """
    Defines the type of API resource.
    Used to decide which security checks apply.
    """
    USER_OWNED = "user_owned"   # Resource belongs to a specific user (BOLA risk)
    PUBLIC = "public"           # Public resource, no ownership
    ADMIN = "admin"             # Admin-only resource (BFLA risk)
    AUTH = "auth"               # Authentication / token endpoints


class ApiResource:
    """
    Represents a single API resource (endpoint) and its security-relevant properties.
    """

    def __init__(
        self,
        name: str,
        endpoint: str,
        methods: List[str],
        resource_type: ResourceType,
        owner_field: Optional[str] = None,
        sensitive_fields: Optional[List[str]] = None,
        writable_fields: Optional[List[str]] = None,
    ):
        self.name = name
        self.endpoint = endpoint
        self.methods = methods
        self.resource_type = resource_type
        self.owner_field = owner_field
        self.sensitive_fields = sensitive_fields or []
        self.writable_fields = writable_fields or []

    def __repr__(self) -> str:
        return f"<ApiResource name={self.name} endpoint={self.endpoint} type={self.resource_type.value}>"



# =========================
# Example usage (for understanding)
# =========================
#
# user_profile = ApiResource(
#     name="User Profile",
#     endpoint="/api/user/{id}",
#     methods=["GET", "PUT"],
#     resource_type=ResourceType.USER_OWNED,
#     owner_field="id",
#     sensitive_fields=["role", "balance", "is_admin"],
#     writable_fields=["name", "email"]
# )
#
# admin_panel = ApiResource(
#     name="Admin Panel",
#     endpoint="/api/admin/stats",
#     methods=["GET"],
#     resource_type=ResourceType.ADMIN
# )
#
# products = ApiResource(
#     name="Products",
#     endpoint="/api/products",
#     methods=["GET"],
#     resource_type=ResourceType.PUBLIC
# )
