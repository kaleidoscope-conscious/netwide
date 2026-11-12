"""
NetPulse Test Configuration & Session Fixtures.
Ensures pytest runs in a fully isolated sandbox without mutating the production SQLite database.
"""

import os
import tempfile
import pytest

# Allocate temporary database file path before any module imports net_db or subscription_engine
_temp_db_fd, _temp_db_path = tempfile.mkstemp(prefix="netpulse_test_", suffix=".db")
os.close(_temp_db_fd)
os.environ["NETPULSE_DB_PATH"] = _temp_db_path

# The sandbox node acts like the operator's node: privileged licensing actions are
# allowed from loopback. Tests that assert the gate is closed remove this opt-in.
os.environ["NETPULSE_ALLOW_LOOPBACK_ADMIN"] = "1"


@pytest.fixture(scope="session", autouse=True)
def isolate_test_database():
    """Ensure test suite runs strictly on a temporary SQLite database, cleaned up after completion."""
    yield
    for suffix in ("", "-wal", "-shm"):
        p = _temp_db_path + suffix
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
