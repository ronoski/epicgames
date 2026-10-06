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
