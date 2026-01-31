import requests


class RequestEngine:
    def __init__(
        self,
        base_headers: dict | None = None,
        timeout: int = 10,
        verify_ssl: bool = True
    ):
        self.base_headers = base_headers or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def send(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        json: dict | None = None
    ):
        final_headers = self.base_headers.copy()
        if headers:
            final_headers.update(headers)

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=final_headers,
                params=params,
                json=json,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            return response

        except requests.exceptions.Timeout:
            return self._error("timeout", url)

        except requests.exceptions.ConnectionError:
            return self._error("connection_error", url)

        except Exception as e:
            return self._error(str(e), url)

    def _error(self, reason: str, url: str):
        return {
            "error": True,
            "reason": reason,
            "url": url
        }
