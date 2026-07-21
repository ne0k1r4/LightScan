# tests for the adaptive-timing dead-stats bug found testing against a
# real target (scanme.nmap.org).
#
# engine.run(tasks) is called from cli.py with no target= argument, so
# self._target defaulted to "" - falsy - which meant record_sent/
# record_response/record_timeout never fired regardless of whether
# adaptive mode was on. every single scan printed a static
# "sent=0 recv=0 loss=100.0%" no matter what actually happened, and
# because _maybe_adjust() only runs off those same recordings,
# current_concurrency never moved off the raw timing template default
# either - meaning the ulimit-tuned concurrency value silently got
# ignored the moment adaptive mode was on (which is the default).
import pytest

from lightscan.core.engine import PhantomEngine


def test_host_from_label_plain_host_port():
    assert PhantomEngine._host_from_label("10.0.0.5:80", "fallback") == "10.0.0.5"


def test_host_from_label_hostname_port():
    assert PhantomEngine._host_from_label("scanme.nmap.org:22", "fallback") == "scanme.nmap.org"


def test_host_from_label_udp_prefixed():
    assert PhantomEngine._host_from_label("udp:10.0.0.5:53", "fallback") == "10.0.0.5"


def test_host_from_label_empty_uses_fallback():
    assert PhantomEngine._host_from_label("", "fallback") == "fallback"


def test_host_from_label_no_port_shape_uses_fallback():
    assert PhantomEngine._host_from_label("not-a-host-port-label", "fallback") == "fallback"


def test_adaptive_starting_concurrency_respects_lower_ceiling():
    # this is the actual bug: template default (512 for timing=4) used to
    # win outright, ignoring the ulimit-tuned ceiling passed in as
    # max_concurrency/concurrency
    e = PhantomEngine(concurrency=256, adaptive=True, timing=4)
    assert e._adaptive.current_concurrency == 256


def test_adaptive_starting_concurrency_capped_by_template_when_ceiling_higher():
    # ceiling above the template's own default shouldn't inflate beyond
    # what the timing template calls for
    e = PhantomEngine(concurrency=1000, adaptive=True, timing=4)
    assert e._adaptive.current_concurrency == 512


@pytest.mark.asyncio
async def test_adaptive_stats_actually_record_during_a_real_scan():
    # the actual regression: run a real scan through the engine and
    # confirm sent/recv are non-zero afterward, not stuck at the
    # 0/0/100%-loss the real-world run always showed
    import asyncio
    from lightscan.scan.portscan import build_scan_tasks

    engine = PhantomEngine(concurrency=32, timeout=1.0, adaptive=True, timing=3)
    tasks = build_scan_tasks(["127.0.0.1"], [1, 2, 3, 4, 5], timeout=0.3)
    await engine.run(tasks)

    stats = engine._adaptive.get_stats("127.0.0.1")
    assert stats.sent == 5
    # every one of these either connects or gets refused fast on
    # localhost, so recv should track right along with sent - it
    # shouldn't be stuck at 0 the way it was before the fix
    assert stats.responded + stats.timeouts == 5


@pytest.mark.asyncio
async def test_multi_host_batch_attributes_stats_to_the_right_host():
    # this is the part a naive "just pass target= once" fix would still
    # get wrong - a single run() call scanning multiple hosts needs each
    # task's stats going to the host that task actually touched, not all
    # lumped under one label
    from lightscan.scan.portscan import build_scan_tasks

    engine = PhantomEngine(concurrency=32, timeout=1.0, adaptive=True, timing=3)
    tasks = build_scan_tasks(["127.0.0.1", "127.0.0.2"], [1, 2], timeout=0.3)
    await engine.run(tasks)

    s1 = engine._adaptive.get_stats("127.0.0.1")
    s2 = engine._adaptive.get_stats("127.0.0.2")
    assert s1.sent == 2
    assert s2.sent == 2
