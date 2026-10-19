"""HTTP client helpers for the Task 3 training application.

Used by ``demo_attacks.py`` and by ``task-3/tests/test_web_demo.py`` so the
same interaction code drives both the demo and the assertions.

All payloads sent by callers are harmlessly scoped to the local app: fake
credentials, fake email addresses and fixture paths inside ``task-3/``.
"""

from __future__ import annotations

import re
from typing import Any

import requests

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class DemoClient:
    """A thin wrapper around requests.Session for the local training routes."""

    def __init__(self, base_url: str = "http://127.0.0.1:8091", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ApexPlanet-Task3-Demo/1.0"})

    # -- low level ---------------------------------------------------------
    def get(self, path: str, **params: Any) -> requests.Response:
        return self.session.get(self.base_url + path, params=params, timeout=self.timeout)

    def post(self, path: str, data: dict[str, Any]) -> requests.Response:
        return self.session.post(self.base_url + path, data=data, timeout=self.timeout)

    # -- demos -------------------------------------------------------------
    def login(self, mode: str, username: str, password: str) -> requests.Response:
        return self.post(f"/{mode}/sqli", {
            "action": "login",
            "username": username,
            "password": password,
        })

    def search(self, mode: str, query: str) -> requests.Response:
        return self.get(f"/{mode}/sqli", q=query)

    def greet(self, mode: str, name: str) -> requests.Response:
        return self.get(f"/{mode}/xss", name=name)

    def guestbook(self, mode: str, author: str, message: str) -> requests.Response:
        return self.post(f"/{mode}/xss", {
            "action": "guestbook",
            "author": author,
            "message": message,
        })

    def account_page(self, mode: str) -> requests.Response:
        return self.get(f"/{mode}/csrf")

    def csrf_token(self, mode: str = "secure") -> str:
        response = self.account_page(mode)
        match = CSRF_RE.search(response.text)
        return match.group(1) if match else ""

    def change_email(self, mode: str, email: str, token: str | None = None) -> requests.Response:
        data: dict[str, Any] = {"action": "update_email", "email": email}
        if token is not None:
            data["csrf_token"] = token
        return self.post(f"/{mode}/csrf", data)

    def lfi(self, mode: str, file: str) -> requests.Response:
        return self.get(f"/{mode}/lfi", file=file)


def payloads() -> dict[str, str]:
    """The harmless proof-of-concept inputs used throughout the demo."""
    return {
        "sqli_login": "admin' -- ",
        "sqli_union": "' UNION SELECT 999, username, password_hash, 'leaked' FROM users -- ",
        "xss_reflected": "<script>window.__xss=1</script>",
        "xss_stored": "<svg onload=alert('stored-xss')>",
        "lfi_traversal": "../private/flag.txt",
        "lfi_escape": "../../../README.md",
    }
