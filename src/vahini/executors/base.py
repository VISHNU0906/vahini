from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from ..privacy import Vault


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | list[Any] | None = None


@dataclass
class ActionResult:
    tool: str
    ok: bool
    dry_run: bool
    detail: str
    request: HttpRequest | None = None


class HttpExecutor:
    """Base for executors that talk to a vendor API."""

    tools: tuple[str, ...] = ()

    def __init__(self, base_url: str, token: str = "", dry_run: bool = True, timeout: float = 15) -> None:
        self.base_url, self.token, self.dry_run, self.timeout = base_url.rstrip("/"), token, dry_run, timeout

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def build(self, tool: str, args: dict[str, str]) -> HttpRequest:  # pragma: no cover - abstract
        raise NotImplementedError

    def execute(self, tool: str, args: dict[str, str]) -> ActionResult:
        req = self.build(tool, args)
        if self.dry_run:
            return ActionResult(tool, True, True, f"{req.method} {req.url}", req)
        data = json.dumps(req.body).encode() if req.body is not None else None
        http = urllib.request.Request(req.url, data=data, headers=req.headers, method=req.method)
        try:
            with urllib.request.urlopen(http, timeout=self.timeout) as resp:  # noqa: S310 - configured vendor URL
                return ActionResult(tool, 200 <= resp.status < 300, False, f"HTTP {resp.status}", req)
        except OSError as exc:
            return ActionResult(tool, False, False, f"failed: {exc}", req)


class Router:
    """Maps Vahini tool names to executors and reveals tokens inside the customer boundary."""

    def __init__(self, vault: Vault | None = None) -> None:
        self.vault = vault
        self.routes: dict[str, Callable[[str, dict[str, str]], ActionResult]] = {}
        self.history: list[ActionResult] = []

    def register(self, executor: HttpExecutor) -> "Router":
        for tool in executor.tools:
            self.routes[tool] = executor.execute
        return self

    def run(self, tool: str, args: dict[str, str]) -> str:
        real = {k: (self.vault.reveal(v) or v) if self.vault else v for k, v in args.items()}
        handler = self.routes.get(tool)
        result = handler(tool, real) if handler else ActionResult(tool, True, True, "no executor; recorded only")
        self.history.append(result)
        return f"{'dry-run' if result.dry_run else 'live'}: {tool} -> {result.detail}"
