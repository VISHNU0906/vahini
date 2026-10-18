"""Customer-side executors: the only place tokens become real names and actions become real.

Every executor builds a concrete ``HttpRequest`` first and only sends it when
``dry_run`` is off, so each action can be reviewed, logged and signed before it
touches production.
"""

from .base import ActionResult, HttpRequest, Router
from .edr import CrowdStrikeExecutor, DefenderExecutor
from .firewall import EdlFirewallExecutor
from .identity import EntraExecutor, OktaExecutor
from .ticketing import JiraExecutor, ServiceNowExecutor

__all__ = [
    "ActionResult", "HttpRequest", "Router",
    "CrowdStrikeExecutor", "DefenderExecutor", "EdlFirewallExecutor",
    "EntraExecutor", "OktaExecutor", "JiraExecutor", "ServiceNowExecutor",
]
