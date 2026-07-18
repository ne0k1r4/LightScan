# tests for _tune_concurrency() - rustscan-style ulimit-aware batch sizing.
#
# before this, --concurrency defaulted to a flat 256 no matter what the
# process could actually open. cli.py already tried to raise the ulimit to
# the hard limit on startup, but that was wrapped in a bare except: pass -
# if it failed (common in containers/restricted environments), the scan
# would still run at concurrency=256 regardless of whether the real ceiling
# was 64 or 1000000, with zero feedback either way.
import sys
from unittest.mock import patch

from lightscan.cli import _tune_concurrency, _DEFAULT_CONCURRENCY, _FD_SAFETY_MARGIN


def test_no_request_ulimit_comfortably_above_default():
    with patch("resource.getrlimit", return_value=(1024, 1024)):
        assert _tune_concurrency(None) == _DEFAULT_CONCURRENCY


def test_no_request_ulimit_very_low_gets_halved():
    with patch("resource.getrlimit", return_value=(64, 1024)):
        assert _tune_concurrency(None) == 32


def test_no_request_ulimit_just_below_default_uses_margin():
    with patch("resource.getrlimit", return_value=(300, 1024)):
        assert _tune_concurrency(None) == 200  # 300 - margin(100)


def test_no_request_never_goes_below_floor():
    with patch("resource.getrlimit", return_value=(10, 1024)):
        assert _tune_concurrency(None) >= 8


def test_no_request_huge_ulimit_still_uses_safe_default():
    # never auto-increase past the default even with massive headroom -
    # that's a user opt-in via --concurrency, not something to guess at
    with patch("resource.getrlimit", return_value=(1_000_000, 1_000_000)):
        assert _tune_concurrency(None) == _DEFAULT_CONCURRENCY


def test_explicit_request_always_respected():
    with patch("resource.getrlimit", return_value=(300, 1024)):
        assert _tune_concurrency(280) == 280  # even though it's unsafe, it's what they asked for


def test_explicit_request_safe_no_warning(capsys):
    with patch("resource.getrlimit", return_value=(10_000, 10_000)):
        _tune_concurrency(500)
    assert capsys.readouterr().err == ""


def test_explicit_request_unsafe_warns_on_stderr(capsys):
    with patch("resource.getrlimit", return_value=(300, 1024)):
        _tune_concurrency(280)
    err = capsys.readouterr().err
    assert "280" in err and "300" in err


def test_windows_skips_resource_entirely():
    with patch("sys.platform", "win32"):
        assert _tune_concurrency(None) == _DEFAULT_CONCURRENCY
        assert _tune_concurrency(99) == 99


def test_getrlimit_failure_falls_back_safely():
    # restricted environments where resource.getrlimit itself isn't usable -
    # shouldn't crash the whole cli over it
    with patch("resource.getrlimit", side_effect=Exception("no permission")):
        assert _tune_concurrency(None) == _DEFAULT_CONCURRENCY
        assert _tune_concurrency(123) == 123
