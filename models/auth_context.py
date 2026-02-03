# models/auth_context.py

from typing import Optional, Dict


class AuthContext:
    """
    Represents authentication context for a user
    Supports header-based and cookie-based authentication
    """

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        label: str = "unknown",
    ):
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.label = label  # user_a / user_b

    def __repr__(self):
        return f"<AuthContext {self.label}>"
