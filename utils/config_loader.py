# utils/config_loader.py

import json
from models.api_resource import ApiResource
from models.auth_context import AuthContext


def load_config(path: str):
    with open(path, "r") as f:
        data = json.load(f)

    # Auth contexts
    user_a = AuthContext(
        headers=data["auth"]["user_a"].get("headers"),
        cookies=data["auth"]["user_a"].get("cookies"),
        label="user_a",
    )

    user_b = AuthContext(
        headers=data["auth"]["user_b"].get("headers"),
        cookies=data["auth"]["user_b"].get("cookies"),
        label="user_b",
    )

    # Resources
    resources = []
    for r in data["resources"]:
        resources.append(
            ApiResource(
                name=r["name"],
                endpoint=r["endpoint"],
                methods=r["methods"],
                owner_field=r.get("owner_field"),
            )
        )

    return {
        "target": data["target"],
        "user_a": user_a,
        "user_b": user_b,
        "resources": resources,
        "scan": data["scan"],
    }
