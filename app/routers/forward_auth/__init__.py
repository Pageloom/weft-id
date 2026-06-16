"""Forward-auth runtime router package.

Implements the multi-domain forward-auth handshake endpoints:

  * ``GET /forward-auth/check``     -- proxy subrequest gate (portal host)
  * ``GET /forward-auth/start``     -- begin the handshake (portal host)
  * ``GET /forward-auth/authorize`` -- mint token (canonical tenant host)
  * ``GET /forward-auth/callback``  -- set per-domain cookie (portal host)

See app/services/forward_auth.py for the decision + audit logic and
app/utils/forward_auth.py for the crypto core.
"""

from routers.forward_auth.runtime import router

__all__ = ["router"]
