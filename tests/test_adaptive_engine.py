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
    e = PhantomEngine(concurrency=256, adaptive=True, timing=4)
    assert e._adaptive.current_concurrency == 256

def test_adaptive_starting_concurrency_capped_by_template_when_ceiling_higher():
    e = PhantomEngine(concurrency=1000, adaptive=True, timing=4)
    assert e._adaptive.current_concurrency == 512

@pytest.mark.asyncio
async def test_adaptive_stats_actually_record_during_a_real_scan():
    import asyncio
    from lightscan.scan.portscan import build_scan_tasks

    engine = PhantomEngine(concurrency=32, timeout=1.0, adaptive=True, timing=3)
    tasks = build_scan_tasks(["127.0.0.1"], [1, 2, 3, 4, 5], timeout=0.3)
    await engine.run(tasks)

    stats = engine._adaptive.get_stats("127.0.0.1")
    assert stats.sent == 5
    assert stats.responded + stats.timeouts == 5

@pytest.mark.asyncio
async def test_multi_host_batch_attributes_stats_to_the_right_host():
    from lightscan.scan.portscan import build_scan_tasks

    engine = PhantomEngine(concurrency=32, timeout=1.0, adaptive=True, timing=3)
    tasks = build_scan_tasks(["127.0.0.1", "127.0.0.2"], [1, 2], timeout=0.3)
    await engine.run(tasks)

    s1 = engine._adaptive.get_stats("127.0.0.1")
    s2 = engine._adaptive.get_stats("127.0.0.2")
    assert s1.sent == 2
    assert s2.sent == 2
