"""
Pause and stop, for everything that runs long enough to need them.

A pentest tool that cannot be stopped is a liability. The person running it
is on someone else's network, on a clock, under a scope agreement, and when
they press Pause they mean *stop touching the target* — not "stop the
progress bar". When they close the window they mean it even more firmly.

This is the one object both engines use to mean that. It has no Qt and no
network, so it works the same on the interface thread, on a worker thread,
and inside the scanner's thread pool.

Two states, deliberately separate:

  * **paused** is reversible. Work blocks where it is and resumes from the
    same place. A forty-minute nmap is not thrown away.
  * **stopped** is not. Anything blocked wakes up immediately and unwinds.

Stopping always wins: a stopped gate never blocks, so a paused scan can
still be shut down without being resumed first. That matters on close, and
it is the bug that would otherwise hang the window for anyone who pressed
Pause and then quit.
"""

from __future__ import annotations

import threading


class Stopped(Exception):
    """Raised inside worker code when the run has been told to stop."""


class RunGate:
    """One run's pause/stop state, shared across its threads.

    Cheap to consult — the common case is one ``Event.is_set()`` — so it can
    sit in front of every single request without being felt.
    """

    def __init__(self):
        # Set means "go". Clearing it is what blocks the waiters.
        self._resume = threading.Event()
        self._resume.set()
        self._stop = threading.Event()

    # ── state ────────────────────────────────────────────────────────────
    @property
    def paused(self):
        return not self._resume.is_set() and not self._stop.is_set()

    @property
    def stopped(self):
        return self._stop.is_set()

    @property
    def running(self):
        return not self._stop.is_set() and self._resume.is_set()

    # ── control ──────────────────────────────────────────────────────────
    def pause(self):
        """Hold every waiter at its next checkpoint."""
        if not self._stop.is_set():
            self._resume.clear()
        return self.paused

    def resume(self):
        self._resume.set()
        return self.running

    def toggle(self):
        """Pause if running, resume if paused. Returns True when paused."""
        if self.paused:
            self.resume()
        else:
            self.pause()
        return self.paused

    def stop(self):
        """End the run. Wakes anything blocked so it can unwind."""
        self._stop.set()
        # Release the waiters — a gate that is stopped must never block, or
        # closing the window while paused would hang waiting for a resume
        # that is never coming.
        self._resume.set()

    def reset(self):
        """Back to a clean running state, for the next run."""
        self._stop.clear()
        self._resume.set()

    # ── checkpoints ──────────────────────────────────────────────────────
    def wait(self, timeout=None):
        """Block while paused. Returns True only when it is safe to proceed.

        Call this immediately before doing anything that touches the target.

        Without a ``timeout`` it blocks until the run is resumed or stopped,
        which is what every caller in the application wants. With one, it
        gives up and returns **False** if the run is still paused when the
        time is up — false rather than true, because the question this
        answers is "may I send?", and the answer while paused is no however
        long the caller is willing to wait.
        """
        if self._stop.is_set():
            return False
        if not self._resume.is_set():
            # Wake periodically rather than sleeping on the event alone, so a
            # stop that arrives while paused is noticed straight away.
            waited = 0.0
            while not self._resume.wait(0.05):
                if self._stop.is_set():
                    return False
                waited += 0.05
                if timeout is not None and waited >= timeout:
                    return False
        return not self._stop.is_set()

    def check(self):
        """:meth:`wait`, but raises :class:`Stopped` instead of returning."""
        if not self.wait():
            raise Stopped("the run was stopped")

    def __call__(self):
        """So a gate can be dropped in wherever a pace function is wanted."""
        return self.wait()


def gate_session(session, gate):
    """Make every request through ``session`` obey ``gate``.

    One chokepoint covers a whole family of probes without any of them having
    to know the gate exists — which is the point, because the probe that
    forgets to check is the one that keeps hammering a client's server after
    the operator has pressed Pause.

    A stopped run raises :class:`Stopped` out of the request call, which the
    worker turns into an ordinary early finish.
    """
    if session is None or gate is None:
        return session
    original = session.request

    def guarded(method, url, *args, **kwargs):
        if not gate.wait():
            raise Stopped("the run was stopped")
        return original(method, url, *args, **kwargs)

    session.request = guarded
    session.cb_gate = gate
    return session
