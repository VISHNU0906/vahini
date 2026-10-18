"""Host containment through the EDR."""

from __future__ import annotations

from .base import HttpExecutor, HttpRequest


class CrowdStrikeExecutor(HttpExecutor):
    """CrowdStrike Falcon: network-contain a host by device id (``host`` arg)."""

    tools = ("isolate_host",)

    def __init__(self, base_url: str = "https://api.crowdstrike.com", **kw) -> None:
        super().__init__(base_url, **kw)

    def build(self, tool: str, args: dict[str, str]) -> HttpRequest:
        return HttpRequest("POST", f"{self.base_url}/devices/entities/devices-actions/v2?action_name=contain",
                           self.headers(), {"ids": [args["host"]]})


class DefenderExecutor(HttpExecutor):
    """Microsoft Defender for Endpoint: isolate a machine by machine id (``host`` arg)."""

    tools = ("isolate_host",)

    def __init__(self, base_url: str = "https://api.security.microsoft.com", **kw) -> None:
        super().__init__(base_url, **kw)

    def build(self, tool: str, args: dict[str, str]) -> HttpRequest:
        return HttpRequest("POST", f"{self.base_url}/api/machines/{args['host']}/isolate", self.headers(),
                           {"Comment": "Isolated by Vahini after analyst approval", "IsolationType": "Full"})
