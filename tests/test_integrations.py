"""Connectors, executors, playbooks, storage, evaluation and console."""

import json
from pathlib import Path

import pytest

from vahini.conformal import ConformalGate, Route
from vahini.connectors.cef import from_cef
from vahini.connectors.common import severity, tactic
from vahini.connectors.elastic import from_elastic
from vahini.connectors.sentinel import from_graph_alert
from vahini.connectors.splunk import from_notable
from vahini.executors import (CrowdStrikeExecutor, DefenderExecutor, EdlFirewallExecutor, EntraExecutor,
                              JiraExecutor, OktaExecutor, Router)
from vahini.ledger import Ledger
from vahini.playbooks import load_all
from vahini.privacy import Vault
from vahini.storage import LedgerStore
from vahini.triage import PLAYBOOKS, Vahini
from vahini.eval.metrics import score
from vahini.eval.guide import calibrate, load_incidents

EX = Path(__file__).resolve().parent.parent / "examples"


# --- normalisation ---------------------------------------------------------------------

@pytest.mark.parametrize("raw,want", [("Credential Access", "credential-access"), ("CredentialAccess", "credential-access"),
                                      ("lateral_movement", "lateral-movement"), ("InitialAccess", "initial-access")])
def test_tactic(raw, want):
    assert tactic(raw) == want


def test_severity_words_and_numbers():
    assert severity("Informational") == "low" and severity("High") == "high"
    assert severity(9, 10) == "critical" and severity(73, 100) == "high" and severity(10, 100) == "low"


# --- connectors --------------------------------------------------------------------------

def test_elastic_flat_ecs():
    doc = json.loads((EX / "elastic_alert.json").read_text())
    a = from_elastic(doc)
    assert a["source"] == "elastic" and a["tactic"] == "credential-access"
    assert a["host"] == "BLR-VPN-01" and a["src_ip"] == "198.51.100.7" and a["user"] == "ravi.k"
    assert a["category"] == "auth.bruteforce" and a["severity"] == "high"


def test_defender_graph_alert():
    a = from_graph_alert(json.loads((EX / "defender_alert.json").read_text()))
    assert a["host"] == "FIN-LT-044" and a["user"] == "ravi.k" and a["tactic"] == "execution"
    assert a["category"] == "endpoint.malware" and a["command_line"].startswith("powershell")


def test_splunk_notable_webhook():
    a = from_notable(json.loads((EX / "splunk_notable.json").read_text()))
    assert a["src_ip"] == "198.51.100.7" and a["host"] == "BLR-VPN-01" and a["severity"] == "high"
    assert a["tactic"] == "credential-access"


def test_cef_line():
    line = (EX / "firewall.cef").read_text().strip()
    a = from_cef(line)
    assert a["source"] == "cef:Palo Alto Networks/PAN-OS" and a["src_ip"] == "203.0.113.50"
    assert a["severity"] == "high" and a["message"] == "outbound connection to known C2 = blocked"
    assert from_cef("not a cef line") is None


def test_connectors_feed_triage():
    v = Vahini(gate=ConformalGate(0.3, 0.6), vault=Vault("vishnu-org", b"k"))
    for alert in (from_elastic(json.loads((EX / "elastic_alert.json").read_text())),
                  from_graph_alert(json.loads((EX / "defender_alert.json").read_text()))):
        assert v.triage(alert).ledger.verify()[0]


# --- executors -----------------------------------------------------------------------------

def test_executors_build_vendor_requests():
    assert CrowdStrikeExecutor(token="t").build("isolate_host", {"host": "abc"}).url.endswith("action_name=contain")
    assert DefenderExecutor(token="t").build("isolate_host", {"host": "m1"}).url.endswith("/api/machines/m1/isolate")
    assert EntraExecutor(token="t").build("disable_user", {"user": "u"}).body == {"accountEnabled": False}
    assert OktaExecutor("https://acme.okta.com", token="t").headers()["Authorization"].startswith("SSWS ")
    assert JiraExecutor("https://x.atlassian.net", email="a@b", token="t").build(
        "comment", {"text": "hi"}).body["fields"]["project"]["key"] == "SOC"


def test_router_reveals_tokens_and_stays_dry(tmp_path):
    vault = Vault("vishnu-org", b"k")
    token = vault.token("ip", "203.0.113.50")
    router = Router(vault).register(EdlFirewallExecutor(tmp_path / "edl.txt"))
    out = router.run("block_ip", {"ip": token})
    assert "203.0.113.50" in out and out.startswith("dry-run")
    assert not (tmp_path / "edl.txt").exists()


def test_edl_refuses_internal_and_writes_once(tmp_path):
    fw = EdlFirewallExecutor(tmp_path / "edl.txt", dry_run=False)
    assert not fw.execute("block_ip", {"ip": "10.0.0.5"}).ok
    fw.execute("block_ip", {"ip": "203.0.113.50"})
    fw.execute("block_ip", {"ip": "203.0.113.50"})
    assert (tmp_path / "edl.txt").read_text().split() == ["203.0.113.50"]


# --- playbooks, storage, eval ---------------------------------------------------------------

def test_playbooks_match_engine():
    books = load_all()
    assert set(books) == set(PLAYBOOKS)
    for cat, book in books.items():
        assert list(book.tools) == PLAYBOOKS[cat] and book.hypotheses


def test_ledger_store_is_append_only(tmp_path):
    store = LedgerStore(tmp_path / "l.db")
    lg = Ledger("case-1")
    lg.append("scanner", "finding", {"x": 1}, ts=1)
    lg.append("judge", "verdict", {"route": "analyst"}, ts=2)
    assert store.save(lg) == 2 and store.save(lg) == 0
    assert store.load("case-1").verify() == (True, None)
    with pytest.raises(Exception):
        store.db.execute("UPDATE ledger_entries SET kind = 'x'")
    with pytest.raises(Exception):
        store.db.execute("DELETE FROM ledger_entries")


def test_scorecard_counts_misses_and_unsafe_actions():
    v = Vahini(gate=ConformalGate(0.99, 1.0), vault=Vault("t", b"k"))   # auto-closes nearly everything
    alerts = json.loads((EX / "alerts.json").read_text())
    reports = [v.triage(a) for a in alerts]
    card = score(reports, {"A-103": True, "A-104": True},
                 {r.alert_id: [a.get("user", ""), a.get("src_ip", "")] for r, a in zip(reports, alerts)})
    assert card.unsafe_actions == 0 and card.raw_leaks == 0
    assert card.attacks == 2 and card.miss_rate == sum(r.route == Route.AUTO_CLOSE for r in reports
                                                        if r.alert_id in {"A-103", "A-104"}) / 2


def test_guide_loader_and_calibration():
    incidents = load_incidents(EX / "guide_sample.csv")
    assert {i.grade for i in incidents} == {"TruePositive", "BenignPositive", "FalsePositive"}
    gate = calibrate(incidents, lambda i: 0.9 if i.is_attack else 0.1, alpha=0.2, beta=0.2)
    assert gate.close_below <= gate.escalate_above


# --- console --------------------------------------------------------------------------------

def test_console_is_served():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from vahini.agents import AgentMesh, DryRunExecutor
    from vahini.service import create_app
    mesh = AgentMesh(Vahini(gate=ConformalGate(0.3, 0.6)), DryRunExecutor())
    html = TestClient(create_app(mesh)).get("/").text
    assert "Analyst console" in html and "/v1/approvals" in html
