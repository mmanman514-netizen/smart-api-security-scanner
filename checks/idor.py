import requests


def check_idor(
    endpoint: str,
    method: str = "GET",
    token: str | None = None,
    object_id: int | str = None,
    timeout: int = 10
):
    """
    Perform a non-destructive IDOR check on a REST API endpoint.
    """

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def send_request(test_id):
        url = endpoint.replace("{id}", str(test_id))
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=timeout
        )
        return response

    # 1️⃣ Baseline request
    try:
        base_response = send_request(object_id)
    except Exception as e:
        return {
            "vulnerability": "IDOR",
            "status": "error",
            "error": str(e)
        }

    if base_response.status_code != 200:
        return {
            "vulnerability": "IDOR",
            "status": "skipped",
            "reason": "Baseline request failed"
        }

    base_length = len(base_response.text)

    # 2️⃣ Generate test IDs
    test_ids = [
        int(object_id) - 1,
        int(object_id) + 1
    ]

    # 3️⃣ Compare responses
    from scanner.response_analyzer import analyze_json_response

base_meta = analyze_json_response(base_response)

for test_id in test_ids:
    test_response = send_request(test_id)
    if test_response.status_code != 200:
        continue

    test_meta = analyze_json_response(test_response)

    if test_meta["is_json"] and base_meta["is_json"]:
        keys_diff = test_meta["keys"] - base_meta["keys"]
        sensitive_diff = test_meta["sensitive_fields"]

        if keys_diff or sensitive_diff:
            return {
                "vulnerability": "IDOR",
                "endpoint": endpoint,
                "risk_level": "HIGH",
                "description": "Object-level authorization may be missing (IDOR).",
                "impact": "Possible access to other users' sensitive data.",
                "evidence": {
                    "new_keys": list(keys_diff),
                    "sensitive_fields": list(sensitive_diff)
                },
                "recommendation": (
                    "Enforce object ownership checks and validate authorization "
                    "for every object access."
                )
            }
