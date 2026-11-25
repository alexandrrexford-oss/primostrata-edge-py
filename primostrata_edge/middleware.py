from __future__ import annotations

from typing import Awaitable, Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .sdk import PrimostrataEdge


class PrimostrataEdgeMiddleware(BaseHTTPMiddleware):
    """Drop-in FastAPI/Starlette middleware backed by Primostrata Edge binary SDK."""

    def __init__(self, app, edge: PrimostrataEdge | None = None, strip_html_scripts: bool = True):
        super().__init__(app)
        self.edge = edge or PrimostrataEdge()
        self.strip_html_scripts = strip_html_scripts

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        url = str(request.url)
        headers = list(request.headers.items())
        if not self.edge.inspect(url, headers):
            return JSONResponse({"detail": "Blocked by Primostrata SHIELD"}, status_code=403)
        resp = await call_next(request)
        if (
            self.strip_html_scripts
            and resp.headers.get("content-type", "").startswith("text/html")
        ):
            if hasattr(resp, "body"):
                raw_body = resp.body
            else:
                chunks = [chunk async for chunk in resp.body_iterator]
                raw_body = b"".join(chunks)
            clean = self.edge.strip_scripts(raw_body)
            hdrs = dict(resp.headers)
            hdrs.pop("content-length", None)
            return Response(content=clean, status_code=resp.status_code, headers=hdrs)
        return resp
