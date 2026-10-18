"""Case notes into the ticketing system."""

from __future__ import annotations

import base64

from .base import HttpExecutor, HttpRequest


class JiraExecutor(HttpExecutor):
    """Jira Cloud: add the triage note as a new issue in the SOC project."""

    tools = ("comment",)

    def __init__(self, base_url: str, email: str = "", project: str = "SOC", **kw) -> None:
        super().__init__(base_url, **kw)
        self.email, self.project = email, project

    def headers(self) -> dict[str, str]:
        basic = base64.b64encode(f"{self.email}:{self.token}".encode()).decode()
        return {"Authorization": f"Basic {basic}", "Content-Type": "application/json"}

    def build(self, tool: str, args: dict[str, str]) -> HttpRequest:
        return HttpRequest("POST", f"{self.base_url}/rest/api/3/issue", self.headers(), {"fields": {
            "project": {"key": self.project},
            "issuetype": {"name": "Task"},
            "summary": args.get("text", "Vahini triage note")[:250],
        }})


class ServiceNowExecutor(HttpExecutor):
    """ServiceNow: open a security incident record."""

    tools = ("comment",)

    def build(self, tool: str, args: dict[str, str]) -> HttpRequest:
        return HttpRequest("POST", f"{self.base_url}/api/now/table/incident", self.headers(),
                           {"short_description": args.get("text", "Vahini triage note")[:160],
                            "category": "security"})
