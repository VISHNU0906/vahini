"""HTTP API around the agent mesh (``pip install vahini[service]``).

    POST /v1/alerts              a Vahini alert, or a raw Wazuh alert (?source=wazuh)
    POST /v1/traces              an OTLP/JSON trace export
    GET  /v1/cases/{id}          verdict, route, actions and the verified ledger
    GET  /v1/incidents           correlated incidents, most advanced first
    GET  /v1/approvals           actions waiting for an analyst
    POST /v1/approvals/{id}      {"decision": "approve" | "deny", "analyst": "...", "note": "..."}
    GET  /v1/keys                public keys, so auditors can verify every signed ledger entry
    GET  /                       the analyst console
    GET  /healthz
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .agents import AgentMesh
from .connectors.otel import flatten, group_by_trace
from .connectors.wazuh import from_wazuh


def create_app(mesh: AgentMesh):
    from fastapi import Body, FastAPI, HTTPException
    from fastapi.responses import HTMLResponse

    app = FastAPI(title="Vahini", version="0.2.0")

    @app.get("/", response_class=HTMLResponse)
    def console() -> str:
        return (Path(__file__).parent / "console" / "index.html").read_text(encoding="utf-8")

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/alerts")
    def ingest_alert(alert: dict[str, Any] = Body(...), source: str = "vahini") -> dict[str, Any]:
        native = from_wazuh(alert) if source == "wazuh" else alert
        rep = mesh.handle_alert(native)
        return {"case": rep.alert_id, "route": rep.route.value, "score": rep.score,
                "pending_approvals": [p.id for p in mesh.approvals.values() if p.case_id == rep.alert_id]}

    @app.post("/v1/traces")
    def ingest_trace(otlp: dict[str, Any] = Body(...)) -> dict[str, Any]:
        found = []
        for spans in group_by_trace(flatten(otlp)).values():
            found += [a.rule for a in mesh.handle_trace(spans)]
        return {"agent_alerts": found}

    @app.get("/v1/cases/{case_id}")
    def case(case_id: str) -> dict[str, Any]:
        rep = mesh.cases.get(case_id)
        if rep is None:
            raise HTTPException(404, "unknown case")
        ok, bad = rep.ledger.verify()
        return {
            "case": case_id, "category": rep.category, "score": rep.score, "route": rep.route.value,
            "notes": rep.notes,
            "actions": [{"tool": a.tool.name, "decision": d.value, "reasons": r} for a, d, r in rep.actions],
            "ledger": {"intact": ok, "first_bad": bad,
                       "entries": [{"seq": e.seq, "actor": e.actor, "kind": e.kind, "body": e.body,
                                    "hash": e.digest, "signer": e.signer, "signature": e.signature}
                                   for e in rep.ledger.entries]},
        }

    @app.get("/v1/keys")
    def keys() -> dict[str, str]:
        kr = mesh.vahini.keyring
        return kr.export_public() if kr is not None else {}

    @app.get("/v1/incidents")
    def incidents() -> list[dict[str, Any]]:
        return [{"alerts": i.alert_ids, "tactics": i.tactics, "stages": i.progression,
                 "entities": sorted(i.entities)} for i in mesh.incidents()]

    @app.get("/v1/approvals")
    def approvals() -> list[dict[str, Any]]:
        return [p.summary() for p in mesh.approvals.values()]

    @app.post("/v1/approvals/{approval_id}")
    def decide(approval_id: str, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        if approval_id not in mesh.approvals:
            raise HTTPException(404, "unknown approval")
        analyst = str(body.get("analyst") or "unknown")
        if body.get("decision") == "approve":
            return {"result": mesh.approve(approval_id, analyst)}
        mesh.deny(approval_id, analyst, str(body.get("note", "")))
        return {"result": "denied"}

    return app
