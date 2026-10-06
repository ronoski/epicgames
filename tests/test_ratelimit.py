import pytest

from recon.ratelimit import RateLedger, RateBudgetExceeded


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_unified_key_shares_budget_across_subdomains():
    clk = FakeClock()
    led = RateLedger(global_qps=1.0, capacity=2.0, clock=clk)
    # two different subdomains map to the same registrable-domain target
    led.debit("api.epicgames.com", "http-GET")
    led.debit("cdn.epicgames.com", "http-GET")
    # budget for the shared target is now exhausted
    with pytest.raises(RateBudgetExceeded):
        led.debit("www.epicgames.com", "http-GET")


def test_fail_closed_when_insufficient():
    clk = FakeClock()
    led = RateLedger(global_qps=1.0, capacity=1.0, clock=clk)
    led.debit("epicgames.com", "resolve")
    with pytest.raises(RateBudgetExceeded):
        led.debit("epicgames.com", "resolve")


def test_refill_over_time():
    clk = FakeClock()
    led = RateLedger(global_qps=1.0, capacity=1.0, clock=clk)
    led.debit("epicgames.com", "resolve")
    clk.advance(1.0)  # one token refills
    led.debit("epicgames.com", "resolve")  # should not raise


def test_balance_never_negative_and_logged():
    clk = FakeClock()
    led = RateLedger(global_qps=1.0, capacity=3.0, clock=clk)
    led.debit("epicgames.com", "port-scan")
    led.debit("epicgames.com", "port-scan")
    assert led.balance("epicgames.com") >= 0
    assert len(led.log) == 2
    assert all(e.balance_after >= 0 for e in led.log)


def test_separate_targets_have_separate_budgets():
    clk = FakeClock()
    led = RateLedger(global_qps=1.0, capacity=1.0, clock=clk)
    led.debit("epicgames.com", "resolve")
    # different registrable domain -> separate bucket, not exhausted
    led.debit("fortnite.com", "resolve")
