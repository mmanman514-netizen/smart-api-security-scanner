# models.py

from typing import List, Optional


class ApiResource:
    def __init__(
        self,
        name: str,
        endpoint: str,
        methods: List[str],
        owner_field: Optional[str] = None,
        sensitive_fields: Optional[List[str]] = None,
        writable_fields: Optional[List[str]] = None,
    ):
        self.name = name
        self.endpoint = endpoint
        self.methods = methods
        self.owner_field = owner_field
        self.sensitive_fields = sensitive_fields or []
        self.writable_fields = writable_fields or []

    def __repr__(self):
        return f"<ApiResource {self.name} {self.endpoint}>"
        # Example usage:
#
# user_resource = ApiResource(
#     name="User",
#     endpoint="/api/user/{id}",
#     methods=["GET", "PUT", "DELETE"],
#     owner_field="id",
#     sensitive_fields=["role", "balance"],
#     writable_fields=["name", "email"]
# )
