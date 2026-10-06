import json

import pytest

from recon.cli import main


CONFIG = """
scope:
  include:
    - "*.example.com"
  exclude:
    - "secret.example.com"
  prefilter:
    - "*.owned-but-unlisted.com"
targets:
  - "*.example.com"
policy_text: "example program policy v1"
allow_active: false
rate:
  global_qps_ceiling: 1.0
"""


@pytest.fixture()
def cfg(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text(CONFIG, encoding="utf-8")
    return str(p)


def run(argv, capsys):
    code = main(argv)
    return code, capsys.readouterr().out


def test_scope_check_verdicts(cfg, capsys):
    code, out = run(["scope-check", "-c", cfg, "--json",
                     "api.example.com", "secret.example.com", "other.org",
                     "x.owned-but-unlisted.com"], capsys)
    rows = {r["value"]: r for r in json.loads(out)}
    assert rows["api.example.com"]["verdict"] == "in_scope"
    assert rows["secret.example.com"]["verdict"] == "out_of_scope"
    assert rows["other.org"]["verdict"] == "out_of_scope"
    assert rows["x.owned-but-unlisted.com"]["verdict"] == "prefilter_only"
    assert rows["x.owned-but-unlisted.com"]["actionable"] is False
    assert code == 0


def test_modules_lists_registry(capsys):
    code, out = run(["modules", "--json"], capsys)
    data = json.loads(out)
    assert isinstance(data, list)
    assert code == 0


def test_plan_is_readonly_and_ranks_gaps(cfg, tmp_path, capsys):
    code, out = run(["plan", "-c", cfg, "--workdir", str(tmp_path / "wd"), "--json"], capsys)
    data = json.loads(out)
    assert code == 0
    assert "gaps" in data and "coverage" in data and "nodes" in data
    # plan must never emit an active gap while allow_active is false
    assert all(g["passive"] for g in data["gaps"])


def test_run_defaults_to_dry_run(cfg, tmp_path, capsys):
    code, out = run(["run", "-c", cfg, "--workdir", str(tmp_path / "wd"),
                     "--max-cycles", "3", "--json"], capsys)
    data = json.loads(out)
    assert data["dry_run"] is True
    assert data["ran"] == 0  # dry run dispatches nothing
    assert code == 0


def test_run_execute_without_allow_active_stays_passive(cfg, tmp_path, capsys):
    code, out = run(["run", "-c", cfg, "--workdir", str(tmp_path / "wd"),
                     "--execute", "--max-cycles", "2", "--json"], capsys)
    data = json.loads(out)
    # allow_active=false in config: no active module may have run
    assert all(c["passive"] or c["outcome"] in ("skipped", "refused")
               for c in data["cycles_detail"])
    assert code == 0


def test_invariants_clean(cfg, tmp_path, capsys):
    code, out = run(["invariants", "-c", cfg, "--workdir", str(tmp_path / "wd"), "--json"], capsys)
    data = json.loads(out)
    assert data["ok"] is True
    assert code == 0


# --- P2: diff / replay / drift ------------------------------------------------

DRIFTED = CONFIG.replace('    - "*.example.com"\n',
                         '    - "*.example.com"\n    - "*.example.net"\n')


@pytest.fixture()
def drifted_cfg(tmp_path):
    p = tmp_path / "drifted.yaml"
    p.write_text(DRIFTED, encoding="utf-8")
    return str(p)


def test_diff_without_a_log_explains_itself(tmp_path, capsys):
    code, out = run(["diff", "--workdir", str(tmp_path / "empty"), "--json"], capsys)
    assert code == 2 and "no event log" in json.loads(out)["error"]


def test_run_then_diff_reports_the_new_nodes(cfg, tmp_path, capsys):
    wd = str(tmp_path / "wd")
    run(["run", "-c", cfg, "--workdir", wd, "--max-cycles", "2", "--json"], capsys)
    code, out = run(["diff", "--workdir", wd, "--json"], capsys)
    data = json.loads(out)
    assert code == 0
    assert data["new"], "the first run planted seeds, so the delta must not be empty"
    assert data["quiet"] is False
    assert "headline" in data


def test_replay_rebuilds_the_graph_from_the_log(cfg, tmp_path, capsys):
    wd = str(tmp_path / "wd")
    run(["run", "-c", cfg, "--workdir", wd, "--max-cycles", "2", "--json"], capsys)
    code, out = run(["replay", "--workdir", wd, "--json"], capsys)
    data = json.loads(out)
    assert code == 0
    assert data["events_replayed"] > 0
    assert data["nodes"], "replay must reconstruct the nodes the run created"
    assert data["skipped_without_payload"] == 0
    assert data["violations"] == []


def test_drift_with_no_previous_snapshot_is_not_drift(cfg, tmp_path, capsys):
    code, out = run(["drift", "-c", cfg, "--workdir", str(tmp_path / "wd"), "--json"], capsys)
    data = json.loads(out)
    assert code == 0 and data["drifted"] is False
    assert data["previous_snapshot_known"] is False


def test_drift_detects_an_added_asset_and_exits_3(cfg, drifted_cfg, tmp_path, capsys):
    wd = str(tmp_path / "wd")
    # pin the original policy
    run(["drift", "-c", cfg, "--workdir", wd, "--accept", "--json"], capsys)
    code, out = run(["drift", "-c", drifted_cfg, "--workdir", wd, "--json"], capsys)
    data = json.loads(out)
    assert code == 3, "a drifted scope is a call to action, signalled by exit 3"
    assert data["added"] == ["*.example.net"]
    assert "1 added" in data["summary"]


def test_drift_rebind_reevaluates_retained_data(cfg, tmp_path, capsys):
    wd = str(tmp_path / "wd")
    run(["run", "-c", cfg, "--workdir", wd, "--max-cycles", "2", "--json"], capsys)
    run(["drift", "-c", cfg, "--workdir", wd, "--accept", "--json"], capsys)

    # the apex we already collected now leaves scope
    lost = tmp_path / "lost.yaml"
    lost.write_text(CONFIG.replace('    - "secret.example.com"\n',
                                   '    - "secret.example.com"\n    - "example.com"\n'),
                    encoding="utf-8")
    code, out = run(["drift", "-c", str(lost), "--workdir", wd, "--rebind", "--json"], capsys)
    data = json.loads(out)
    assert code == 3
    rebind = data["rebind"]
    assert rebind["rebound"] > 0
    assert rebind["lost_scope"], "a retained node that left scope must be reported"


def test_unreviewed_drift_refuses_to_execute(cfg, drifted_cfg, tmp_path, capsys):
    """Acting on a scope that moved underneath us would use a stale authorization."""

    wd = str(tmp_path / "wd")
    run(["drift", "-c", cfg, "--workdir", wd, "--accept", "--json"], capsys)

    code, out = run(["run", "-c", drifted_cfg, "--workdir", wd, "--execute",
                     "--max-cycles", "2", "--json"], capsys)
    data = json.loads(out)
    assert code == 3
    assert data["scope_drift"], "the drift must be reported"
    assert data["dry_run"] is True, "--execute must be downgraded to dry-run"
    assert data["ran"] == 0


def test_run_emits_its_own_delta(cfg, tmp_path, capsys):
    code, out = run(["run", "-c", cfg, "--workdir", str(tmp_path / "wd"),
                     "--max-cycles", "2", "--json"], capsys)
    data = json.loads(out)
    assert "delta" in data and "headline" in data["delta"]


def test_a_second_run_with_the_same_scope_is_quiet(cfg, tmp_path, capsys):
    """The knowledge base must be durable: run 2 must not re-discover run 1's findings.

    Each run previously started from a blank store, so every delta reported the whole
    graph as new, which defeats the point of tracking change over time.
    """

    wd = str(tmp_path / "wd")
    run(["run", "-c", cfg, "--workdir", wd, "--run-id", "r1", "--max-cycles", "3",
         "--json"], capsys)
    _, out = run(["run", "-c", cfg, "--workdir", wd, "--run-id", "r2", "--max-cycles", "3",
                  "--json"], capsys)
    data = json.loads(out)
    assert data["delta"]["quiet"] is True
    assert data["delta"]["headline"] == "no change since the previous run"


def test_a_run_does_not_silently_accept_drift(cfg, drifted_cfg, tmp_path, capsys):
    """Saving the new snapshot during a run would dissolve the gate it just raised."""

    wd = str(tmp_path / "wd")
    run(["run", "-c", cfg, "--workdir", wd, "--max-cycles", "2", "--json"], capsys)
    run(["run", "-c", drifted_cfg, "--workdir", wd, "--max-cycles", "2", "--json"], capsys)
    # the drift must STILL be pending after that run
    code, out = run(["drift", "-c", drifted_cfg, "--workdir", wd, "--json"], capsys)
    assert code == 3, "the drift must still require explicit review"
    assert json.loads(out)["added"] == ["*.example.net"]
