"""IP blocking through an External Dynamic List (EDL).

Palo Alto, Fortinet and Check Point firewalls can all poll a plain-text list of
IPs over HTTPS. Vahini appends approved blocks to that file; the firewall picks
them up on its next refresh. No firewall credentials ever live in Vahini.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from .base import ActionResult

# Never block our own address space at the perimeter; contain internal hosts through the EDR instead.
INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                              "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7",
                                              "fe80::/10")]


class EdlFirewallExecutor:
    tools = ("block_ip",)

    def __init__(self, path: str | Path, dry_run: bool = True) -> None:
        self.path, self.dry_run = Path(path), dry_run

    def execute(self, tool: str, args: dict[str, str]) -> ActionResult:
        try:
            ip = ipaddress.ip_address(args["ip"])
        except ValueError:
            return ActionResult(tool, False, self.dry_run, f"refused: {args['ip']!r} is not an IP address")
        if any(ip in net for net in INTERNAL if net.version == ip.version):
            return ActionResult(tool, False, self.dry_run, f"refused: {ip} is internal; block at the host instead")
        if self.dry_run:
            return ActionResult(tool, True, True, f"would add {ip} to {self.path}")
        existing = set(self.path.read_text().split()) if self.path.exists() else set()
        if str(ip) not in existing:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(f"{ip}\n")
        return ActionResult(tool, True, False, f"added {ip} to {self.path}")
