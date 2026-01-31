def analyze_json_response(response):
    try:
        data = response.json()
    except ValueError:
        return {
            "is_json": False,
            "keys": set(),
            "sensitive_fields": set()
        }

    def extract_keys(obj, prefix=""):
        keys = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                keys |= extract_keys(v, full_key)
        elif isinstance(obj, list):
            for item in obj:
                keys |= extract_keys(item, prefix)
        return keys

    keys = extract_keys(data)

    sensitive_markers = {"email", "password", "token", "balance", "role", "phone"}
    sensitive_found = {k for k in keys if any(s in k.lower() for s in sensitive_markers)}

    return {
        "is_json": True,
        "keys": keys,
        "sensitive_fields": sensitive_found
    }
