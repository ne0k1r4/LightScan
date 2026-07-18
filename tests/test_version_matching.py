# tests for version_ok() - the version: constraint comparator used to gate
# cve templates. these are plain dotted-number comparisons, not real semver.
import pytest
from lightscan.cve.template_engine import version_ok, _ver_tuple


def test_below_cutoff_is_vulnerable():
    assert version_ok("6.2.6", "<6.2.7") is True


def test_at_cutoff_is_patched():
    assert version_ok("6.2.7", "<6.2.7") is False


def test_above_cutoff_is_patched():
    assert version_ok("7.0.0", "<6.2.7") is False


def test_no_detected_version_never_excludes():
    # missing a real vuln because we don't know the version is worse than
    # running one extra check, so no version -> template still runs
    assert version_ok("", "<6.2.7") is True


def test_no_constraint_always_passes():
    assert version_ok("6.2.7", "") is True


def test_garbage_version_string_never_excludes():
    assert version_ok("not-a-version", "<6.2.7") is True


def test_garbage_constraint_never_excludes():
    assert version_ok("6.2.7", "not-a-constraint-either") is True


def test_rc_and_build_suffixes_get_stripped():
    assert version_ok("7.2.4-rc1", "<7.0.0") is False
    assert version_ok("7.2.4+build99", "<7.0.0") is False


def test_and_range_lower_bound():
    assert version_ok("1.9", ">=2.0,<3.5") is False


def test_and_range_inside():
    assert version_ok("3.4.9", ">=2.0,<3.5") is True


def test_and_range_upper_bound_excluded():
    assert version_ok("3.5", ">=2.0,<3.5") is False


def test_exact_match_no_operator():
    assert version_ok("2.6.32", "==2.6.32") is True
    assert version_ok("2.6.33", "==2.6.32") is False


def test_not_equal():
    assert version_ok("2.6.32", "!=2.6.32") is False
    assert version_ok("2.6.33", "!=2.6.32") is True


def test_short_version_pads_correctly():
    # 2.0 vs 2.0.0 should compare equal, not "less than" from tuple length
    assert version_ok("2.0", "==2.0.0") is True
    assert version_ok("2.0.0", "==2.0") is True


def test_ver_tuple_basic():
    assert _ver_tuple("6.2.7") == (6, 2, 7)
    assert _ver_tuple("7.2.4-rc1") == (7, 2, 4)
    assert _ver_tuple("garbage") == ()
