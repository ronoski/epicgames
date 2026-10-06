from datetime import datetime, timezone

from recon.store import Graph, GraphStore
from recon.events import EventLog
from recon.factory import make_node
from recon.models import ScopeBinding, Verdict


def binding(verdict=Verdict.IN_SCOPE):
    return ScopeBinding(verdict=verdict, snapshot_id="snap1",
                        observed_at="2026-01-01T00:00:00+00:00")


def node(id_, source, attrs=None, now=None):
    return make_node("DNSName", id_, binding=binding(), source=source,
                     attrs=attrs or {}, now=now or datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_create_then_dedupe_merge_raises_confidence():
    g = Graph()
    r1 = g.upsert_node(node("dns:api.epicgames.com", "crtsh"))
    assert r1.outcome == "created"
    before = g.store.get("dns:api.epicgames.com").confidence.log_odds
    r2 = g.upsert_node(node("dns:api.epicgames.com", "passivedns"))
    assert r2.outcome == "merged"
    after = g.store.get("dns:api.epicgames.com").confidence.log_odds
    assert after > before  # independent corroboration raised confidence
    assert g.store.get("dns:api.epicgames.com").confidence.independent_sources == 2


def test_contradiction_forks_not_overwrites():
    g = Graph()
    g.upsert_node(node("dns:x.epicgames.com", "a", attrs={"ip": "1.1.1.1"}))
    r = g.upsert_node(node("dns:x.epicgames.com", "b", attrs={"ip": "2.2.2.2"}))
    assert r.outcome == "forked"
    assert r.id == "dns:x.epicgames.com#fork1"
    # original preserved
    assert g.store.get("dns:x.epicgames.com").attrs["ip"] == "1.1.1.1"
    fork = g.store.get("dns:x.epicgames.com#fork1")
    assert fork.attrs["ip"] == "2.2.2.2"
    assert fork.confidence.forked_from == "dns:x.epicgames.com"


def test_events_emitted_and_idempotent():
    log = EventLog()
    g = Graph(log=log)
    g.upsert_node(node("dns:a.epicgames.com", "crtsh"))
    g.upsert_node(node("dns:a.epicgames.com", "crtsh"))  # same last_seen -> idempotent event
    kinds = [e.kind for e in log.all()]
    assert "node_upserted" in kinds


def test_event_log_persist_and_replay(tmp_path):
    p = tmp_path / "events.jsonl"
    log = EventLog(path=p)
    log.append("scope_snapshot_taken", {"snapshot_id": "snap1"})
    log.append("node_upserted", {"id": "dns:a"})
    replayed = EventLog.replay(p)
    assert [e.kind for e in replayed] == ["scope_snapshot_taken", "node_upserted"]
    assert replayed[0].seq == 0 and replayed[1].seq == 1
