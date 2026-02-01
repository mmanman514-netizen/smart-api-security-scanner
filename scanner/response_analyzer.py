def analyze_json_response(response):
    result = {
        "is_json": False,
        "keys": set(),
        "sensitive_fields": set()
    }

    try:
        data = response.json()
    except ValueError:
        return result

    if isinstance(data, dict):
        result["is_json"] = True
        result["keys"] = set(data.keys())

        sensitive_keywords = {
            "email", "password", "token", "role",
            "balance", "credit", "ssn", "phone"
        }

        for key in data.keys():
            if key.lower() in sensitive_keywords:
                result["sensitive_fields"].add(key)

    return result
