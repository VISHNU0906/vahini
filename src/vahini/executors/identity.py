"""Account response through the identity provider."""

from __future__ import annotations

from .base import HttpExecutor, HttpRequest


class EntraExecutor(HttpExecutor):
    """Microsoft Entra ID via Graph: disable the account and revoke its sessions."""

    tools = ("disable_user",)

    def __init__(self, base_url: str = "https://graph.microsoft.com/v1.0", **kw) -> None:
        super().__init__(base_url, **kw)

    def build(self, tool: str, args: dict[str, str]) -> HttpRequest:
        return HttpRequest("PATCH", f"{self.base_url}/users/{args['user']}", self.headers(), {"accountEnabled": False})

    def revoke_sessions(self, user: str) -> HttpRequest:
        return HttpRequest("POST", f"{self.base_url}/users/{user}/revokeSignInSessions", self.headers())


class OktaExecutor(HttpExecutor):
    """Okta: suspend the user."""

    tools = ("disable_user",)

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"SSWS {self.token}", "Content-Type": "application/json"}

    def build(self, tool: str, args: dict[str, str]) -> HttpRequest:
        return HttpRequest("POST", f"{self.base_url}/api/v1/users/{args['user']}/lifecycle/suspend", self.headers())
