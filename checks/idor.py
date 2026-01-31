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
    for test_id in test_ids:
        try:
            test_response = send_request(test_id)
        except Exception:
            continue

        if test_response.status_code == 200:
            test_length = len(test_response.text)

            if test_length != base_length:
                return {
                    "vulnerability": "IDOR",
                    "endpoint": endpoint,
                    "risk_level": "HIGH",
                    "description": "Possible Insecure Direct Object Reference detected.",
                    "impact": "Unauthorized access to other users' resources.",
                    "recommendation": (
                        "Implement object-level authorization checks "
                        "and validate ownership on every request."
                    )
                }

    return {
        "vulnerability": "IDOR",
        "status": "safe",
        "message": "No IDOR behavior detected."
  }
