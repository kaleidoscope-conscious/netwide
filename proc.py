"""Subprocess timeout + logging policy (P0 hardening).

Central wrapper so every check_output/run call is bounded. Decision-
critical loops should use this instead of bare subprocess.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Any, Sequence

logger = logging.getLogger(__name__)

def run_with_timeout(
    cmd: Sequence[str],
    timeout: float = 5.0,
    capture: bool = True,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Run cmd with hard timeout. Raises TimeoutExpired on breach."""
    return subprocess.run(
        list(cmd),
        capture_output=capture,
        text=text,
        timeout=timeout,
        check=check,
    )

def check_output_with_timeout(
    cmd: Sequence[str],
    timeout: float = 5.0,
    stderr: Any = subprocess.DEVNULL,
) -> bytes:
    return subprocess.check_output(
        list(cmd), stderr=stderr, timeout=timeout,
    )

def stop_process_gracefully(proc: subprocess.Popen, grace: float = 2.0) -> None:
    """terminate -> wait(grace) -> kill -> reap. No orphans."""
    try:
        if proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            pass
        proc.kill()
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
    except Exception:
        pass
