from scanner.request_engine import RequestEngine
from scanner.checks.idor import check_idor


class CoreScanner:
    def __init__(self, token=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self.engine = RequestEngine(base_headers=headers)

    def scan(self, endpoint, method="GET", object_id=None):
        findings = []

        idor_result = check_idor(
            engine=self.engine,
            endpoint=endpoint,
            method=method,
            object_id=object_id
        )

        if idor_result:
            findings.append(idor_result)

        return findings
