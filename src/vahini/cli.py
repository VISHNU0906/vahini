"""Command line: ``vahini demo | replay | serve``."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys

from .agents import AgentMesh, DryRunExecutor
from .conformal import ConformalGate
from .connectors.wazuh import iter_alerts
from .policy import Policy, Risk
from .privacy import Vault
from .triage import Vahini


def build_mesh() -> AgentMesh:
    """A mesh with a demo calibration. Replace the calibration with labelled history in production."""
    rng = random.Random(42)
    gate = ConformalGate.calibrate([rng.betavariate(6, 2) for _ in range(500)],
                                   [rng.betavariate(2, 6) for _ in range(2000)])
    key = os.environ.get("VAHINI_TENANT_KEY", "change-me").encode()
    vault = Vault(os.environ.get("VAHINI_TENANT", "default"), key)
    crown = frozenset(filter(None, os.environ.get("VAHINI_CROWN_JEWELS", "").split(",")))
    vahini = Vahini(gate=gate, policy=Policy(auto_max_risk=Risk.LOW, crown_jewels=crown), vault=vault)
    return AgentMesh(vahini, DryRunExecutor(vault))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vahini", description="AI-powered SOC that cannot be manipulated.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="run the offline end-to-end demo")
    rp = sub.add_parser("replay", help="triage a Wazuh alerts.json file")
    rp.add_argument("path")
    sv = sub.add_parser("serve", help="start the HTTP API")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)

    if args.cmd == "demo":
        from .demo import main as demo
        demo()
    elif args.cmd == "replay":
        mesh = build_mesh()
        for alert in iter_alerts(args.path):
            rep = mesh.handle_alert(alert)
            print(json.dumps({"case": rep.alert_id, "route": rep.route.value, "score": rep.score}))
        print(json.dumps({"pending_approvals": [p.summary() for p in mesh.approvals.values()]}, indent=2))
    elif args.cmd == "serve":
        import uvicorn

        from .service import create_app
        uvicorn.run(create_app(build_mesh()), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
