"""/api/v1 alias middleware — rewrite /api/v1/* → /api/* without breaking existing clients."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class ApiV1AliasMiddleware(BaseHTTPMiddleware):
    """Cheap API versioning: /api/v1/foo maps to the same handlers as /api/foo.

    Existing /api routes stay canonical for the current static UI. External
    consumers can target /api/v1 now; a later hard cutover can deprecate bare /api.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.scope.get("path") or ""
        if path == "/api/v1" or path.startswith("/api/v1/"):
            rest = path[len("/api/v1") :].lstrip("/")
            new_path = "/api" if not rest else f"/api/{rest}"
            request.scope["path"] = new_path
            # raw_path is bytes in ASGI
            try:
                request.scope["raw_path"] = new_path.encode("utf-8")
            except Exception:
                pass
        return await call_next(request)
