from scanner.response_analyzer import analyze_json_response


def check_idor(engine, endpoint, method, object_id):
    base_response = engine.send(
        method=method,
        url=endpoint.replace("{id}", str(object_id))
    )

    if base_response.status_code != 200:
        return None

    base_meta = analyze_json_response(base_response)

    test_ids = [object_id - 1, object_id + 1]

    for test_id in test_ids:
        test_response = engine.send(
            method=method,
            url=endpoint.replace("{id}", str(test_id))
        )

        if test_response.status_code != 200:
            continue

        test_meta = analyze_json_response(test_response)

        if test_meta["sensitive_fields"] - base_meta["sensitive_fields"]:
            return {
                "type": "IDOR",
                "risk": "HIGH",
                "endpoint": endpoint
            }

    return None
