"""Tests for the LLM layer, connectors, agent mesh and HTTP API."""

import asyncio
import json
import re
from pathlib import Path

import pytest

from vahini.agents import AgentMesh, DryRunExecutor
from vahini.capability import Source, label
from vahini.conformal import ConformalGate
from vahini.connectors.otel import flatten, group_by_trace
from vahini.connectors.wazuh import from_wazuh, iter_alerts
from vahini.agentwatch import analyse_trace
from vahini.llm import FakeModel, LLMPlanner, QuarantinedExtractor
from vahini.privacy import Vault
from vahini.triage import Vahini

EX = Path(__file__).resolve().parent.parent / "examples"
CANARY = re.compile(r"VHN-[0-9a-f]{12}")


def _fields(**kw):
    return {k: label(v, Source.TELEMETRY) for k, v in kw.items()}


# --- quarantined reader -------------------------------------------------------------

def _echo_canary(extra):
    def reply(system, user):
        return json.dumps({"canary": CANARY.search(user).group(0), **extra})
    return reply


def test_reader_returns_tainted_typed_facts():
    model = FakeModel(_echo_canary({"ips": ["ip-c287-0e39"], "users": ["user-c82dc726"], "hosts": []}))
    ex = QuarantinedExtractor(model).extract(_fields(src_ip="ip-c287-0e39", user="user-c82dc726", message="x"))
    assert ex.canary_ok
    assert [v.value for v in ex.facts["ips"]] == ["ip-c287-0e39"]
    assert all(not v.trusted for v in ex.facts["ips"] + ex.facts["users"])
    assert DATA_MARKER_IN(model)


def DATA_MARKER_IN(model):
    return "DATA" in model.calls[0][1]


def test_reader_rejects_values_not_in_data_or_wrong_shape():
    model = FakeModel(_echo_canary({"ips": ["ip-dead-beef", "10.0.0.1"], "hosts": ["host-e189d37a"]}))
    ex = QuarantinedExtractor(model).extract(_fields(host="host-e189d37a"))
    assert ex.facts["ips"] == [] and [v.value for v in ex.facts["hosts"]] == ["host-e189d37a"]
    assert len(ex.rejected) == 2


def test_reader_discards_output_when_canary_breaks():
    model = FakeModel(json.dumps({"canary": "something-else", "ips": ["ip-c287-0e39"]}))
    ex = QuarantinedExtractor(model).extract(_fields(src_ip="ip-c287-0e39"))
    assert not ex.canary_ok and ex.facts["ips"] == []


def test_reader_survives_non_json():
    ex = QuarantinedExtractor(FakeModel("sure! here you go")).extract(_fields(message="x"))
    assert not ex.canary_ok and "discarded" in ex.note


# --- planner --------------------------------------------------------------------------

def test_planner_keeps_only_menu_items():
    reply = json.dumps({"steps": [
        {"tool": "block_ip", "refs": {"ip": "$ip0"}, "why": "stop the source"},
        {"tool": "allowlist_ip", "refs": {"ip": "$ip0"}},           # not on the menu
        {"tool": "comment", "refs": {"text": "$nope"}},             # unknown reference
        {"tool": "lookup_user", "refs": {"host": "$user0"}},        # wrong argument name
    ]})
    steps = LLMPlanner(FakeModel(reply)).plan(
        "auth.bruteforce",
        {"block_ip": ["ip"], "comment": ["text"], "lookup_user": ["user"]},
        {"$ip0": "ip", "$user0": "user"},
    )
    assert [s.tool for s in steps] == ["block_ip"]


def test_planner_never_sees_raw_text():
    model = FakeModel('{"steps": []}')
    LLMPlanner(model).plan("auth.bruteforce", {"comment": ["text"]}, {"$ip0": "ip"})
    assert "198.51.100.7" not in model.calls[0][1] and "ravi" not in model.calls[0][1]


# --- connectors -----------------------------------------------------------------------

def test_wazuh_mapping():
    alerts = list(iter_alerts(EX / "wazuh_alerts.json"))
    assert len(alerts) == 3                                   # the non-JSON line is skipped
    brute, login, ps = alerts
    assert brute["category"] == "auth.bruteforce" and brute["severity"] == "high"
    assert brute["tactic"] == "credential-access" and brute["src_ip"] == "198.51.100.7"
    assert login["tactic"] == "initial-access" and login["user"] == "ravi.k"
    assert ps["category"] == "endpoint.malware" and ps["severity"] == "critical"
    assert ps["user"] == "ravi.k" and ps["command_line"].startswith("powershell.exe")


def _to_otlp(spans):
    def attr(k, v):
        return {"key": k, "value": {"stringValue": v}}
    return {"resourceSpans": [{
        "resource": {"attributes": [attr("service.name", "helpdesk-bot")]},
        "scopeSpans": [{"spans": [{
            "traceId": s["trace_id"], "spanId": s["span_id"], "name": s["name"],
            "startTimeUnixNano": str(s["start_time"]),
            "attributes": [attr(k, v) for k, v in s["attributes"].items()],
        } for s in spans]}],
    }]}


def test_otlp_flatten_feeds_agentwatch():
    spans = json.loads((EX / "agent_trace.json").read_text())
    traces = group_by_trace(flatten(_to_otlp(spans)))
    (only,) = traces.values()
    assert only[0]["service"] == "helpdesk-bot"
    assert {a.rule.split()[0] for a in analyse_trace(only)} == {"AGENT-001", "AGENT-002"}


# --- agent mesh ------------------------------------------------------------------------

def _mesh():
    vault = Vault("vishnu-org", b"k")
    return AgentMesh(Vahini(gate=ConformalGate(0.3, 0.6), vault=vault), DryRunExecutor(vault))


def test_mesh_acts_on_trusted_and_parks_the_rest():
    mesh = _mesh()
    for a in json.loads((EX / "alerts.json").read_text()):
        mesh.handle_alert(a)
    ran = {tool for tool, _ in mesh.executor.log}
    parked = {p.action.tool.name for p in mesh.approvals.values()}
    assert {"comment", "enrich_ip", "lookup_user"} <= ran
    assert {"block_ip", "isolate_host", "disable_user"} <= parked
    assert not ran & {"block_ip", "isolate_host", "disable_user", "allowlist_ip"}


def test_executor_sees_real_names_only_inside_the_boundary():
    mesh = _mesh()
    mesh.handle_alert(json.loads((EX / "alerts.json").read_text())[0])
    args = [a for t, a in mesh.executor.log if t == "enrich_ip"][0]
    assert args["ip"] == "198.51.100.7"                        # revealed by the customer-side vault
    assert mesh.cases["A-101"].model_view["src_ip"].startswith("ip-")


def test_approval_runs_action_and_is_recorded():
    mesh = _mesh()
    rep = mesh.handle_alert(json.loads((EX / "alerts.json").read_text())[0])
    pid = next(p.id for p in mesh.approvals.values() if p.action.tool.name == "block_ip")
    assert "dry-run: block_ip" in mesh.approve(pid, "analyst@vishnu.corp")
    assert rep.ledger.by_kind("approved") and rep.ledger.verify() == (True, None)


def test_mesh_correlates_wazuh_stream_into_one_incident():
    mesh = _mesh()
    for a in iter_alerts(EX / "wazuh_alerts.json"):
        mesh.handle_alert(a)
    top = mesh.incidents()[0]
    assert len(top.alert_ids) == 3 and top.progression == 3


def test_always_on_loop_processes_queue():
    async def scenario():
        mesh = _mesh()
        stop = asyncio.Event()
        task = asyncio.create_task(mesh.run(stop))
        for a in json.loads((EX / "alerts.json").read_text()):
            await mesh.submit("alert", a)
        await mesh.submit("trace", json.loads((EX / "agent_trace.json").read_text()))
        await mesh.queue.join()
        stop.set()
        await task
        return mesh
    mesh = asyncio.run(scenario())
    assert len(mesh.cases) >= 6 and len(mesh.agent_alerts) == 2


# --- HTTP API ------------------------------------------------------------------------------

def test_http_api_end_to_end():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from vahini.service import create_app

    mesh = _mesh()
    client = TestClient(create_app(mesh))
    assert client.get("/healthz").json() == {"status": "ok"}
    raw = json.loads((EX / "wazuh_alerts.json").read_text().splitlines()[0])
    r = client.post("/v1/alerts?source=wazuh", json=raw).json()
    case = client.get(f"/v1/cases/{r['case']}").json()
    assert case["ledger"]["intact"] and case["category"] == "auth.bruteforce"
    pending = client.get("/v1/approvals").json()
    assert pending and pending[0]["provenance"]["ip"] == ["q_llm", "telemetry"]
    done = client.post(f"/v1/approvals/{pending[0]['id']}", json={"decision": "deny", "analyst": "a"}).json()
    assert done == {"result": "denied"}
