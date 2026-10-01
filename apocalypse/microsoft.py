import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any


class MicrosoftApiError(RuntimeError):
    pass


class MicrosoftClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._tokens: dict[str, str] = {}

    def token(self, scope: str) -> str:
        if scope in self._tokens:
            return self._tokens[scope]
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        body = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": scope,
        }).encode()
        request = urllib.request.Request(url, data=body, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise MicrosoftApiError(f"Token request failed ({error.code}): {detail}") from error
        self._tokens[scope] = payload["access_token"]
        return self._tokens[scope]

    def get_json(self, url: str, scope: str) -> dict[str, Any]:
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self.token(scope)}")
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", "ApocalypseSecurityAgent/1.0 (Enterprise Risk Intelligence)")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise MicrosoftApiError(f"GET {url} failed ({error.code}): {detail}") from error
        except TimeoutError as error:
            raise MicrosoftApiError(f"GET {url} timed out after 60s") from error
        except Exception as error:
            raise MicrosoftApiError(f"GET {url} network error: {error}") from error


def since_iso(hours: int) -> str:
    value = datetime.now(timezone.utc) - timedelta(hours=hours)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")