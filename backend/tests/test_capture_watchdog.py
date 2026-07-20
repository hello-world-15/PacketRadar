"""
Unit tests for app.capture.watchdog.needs_restart — the pure decision
function behind the capture watchdog. Deliberately doesn't touch
capture_watchdog_loop itself (that's an infinite asyncio loop driving
real threads; needs_restart is what it decides with, factored out
specifically so it can be tested without either).
"""

from app.capture.watchdog import STALE_HEARTBEAT_SECONDS, needs_restart

NOW = 1_000_000.0


def test_never_started_does_not_need_restart():
    # e.g. missing root — a startup problem the person needs to fix,
    # not something the watchdog restarting will resolve.
    assert needs_restart(is_running=False, ever_started=False, last_packet_at=None, now=NOW) is False


def test_dead_thread_after_successful_start_needs_restart():
    assert needs_restart(is_running=False, ever_started=True, last_packet_at=NOW - 50, now=NOW) is True


def test_running_with_no_packet_yet_does_not_need_restart():
    # Just (re)started — hasn't seen a packet yet, not the same as stale.
    assert needs_restart(is_running=True, ever_started=True, last_packet_at=None, now=NOW) is False


def test_running_with_recent_packet_does_not_need_restart():
    assert needs_restart(is_running=True, ever_started=True, last_packet_at=NOW - 2, now=NOW) is False


def test_running_but_stale_heartbeat_needs_restart():
    stale_at = NOW - (STALE_HEARTBEAT_SECONDS + 1)
    assert needs_restart(is_running=True, ever_started=True, last_packet_at=stale_at, now=NOW) is True


def test_running_at_exactly_the_threshold_does_not_need_restart():
    # Boundary: strictly greater-than, not greater-or-equal.
    at_threshold = NOW - STALE_HEARTBEAT_SECONDS
    assert needs_restart(is_running=True, ever_started=True, last_packet_at=at_threshold, now=NOW) is False


def test_custom_threshold_is_respected():
    assert (
        needs_restart(
            is_running=True,
            ever_started=True,
            last_packet_at=NOW - 10,
            now=NOW,
            stale_after_seconds=5.0,
        )
        is True
    )
