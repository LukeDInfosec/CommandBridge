"""
The active scanner.

Command Bridge's Coffee Break chain runs other people's tools and reads their
output. This is different: it is a scanner of its own — it logs in, walks the
application, finds every place data can be put, attacks each of them, and
reports only what it could prove.

    from command_bridge.modules.scanner import ScanEngine, Profile, AuthConfig

    auth = AuthConfig("form", login_url="https://app/login",
                      username="alice", password="…",
                      check_url="https://app/account",
                      logged_in_signature="Sign out")
    engine = ScanEngine("https://app", auth=auth, profile=Profile.standard())
    result = engine.run()

Everything it reports carries the request and response pair that proved it.
"""

from command_bridge.modules.scanner.engine import (      # noqa: F401
    PROFILES, Profile, ScanEngine, ScanResult, build_scope)
from command_bridge.modules.scanner.model import (       # noqa: F401
    Evidence, InsertionPoint, Request, ScanFinding, insertion_points)
from command_bridge.modules.scanner.session import (     # noqa: F401
    AuthConfig, Authenticator)

__all__ = ["ScanEngine", "ScanResult", "Profile", "PROFILES", "AuthConfig",
           "Authenticator", "Request", "InsertionPoint", "ScanFinding",
           "Evidence", "insertion_points", "build_scope"]
