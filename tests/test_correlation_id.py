"""Regression tests for CorrelationIdMiddleware + intent_response envelope.

Verifies four contracts that together let operators trace a single tool call
through both the response returned to the agent and the structured log lines
emitted by service clients on the server side.
"""

from __future__ import annotations

import asyncio
import re

import structlog

from mcp_intent import CorrelationIdMiddleware, _request_id_var, intent_response

# ── intent_response envelope ────────────────────────────────────────────


def test_envelope_has_no_request_id_when_unset():
    """No middleware ran → no request_id key. Keeps direct-call shape stable."""
    r = intent_response("success", "hi")
    assert "request_id" not in r


def test_envelope_includes_request_id_when_set():
    token = _request_id_var.set("abc123def456")
    try:
        r = intent_response("success", "hi")
        assert r["request_id"] == "abc123def456"
    finally:
        _request_id_var.reset(token)


# ── middleware behaviour ────────────────────────────────────────────────


class _FakeContext:
    """Minimal stand-in for fastmcp's MiddlewareContext.

    The middleware never actually reads this — it passes it straight to
    call_next — so we don't need real CallToolRequestParams here.
    """


async def _call_middleware_and_return_rid(mw: CorrelationIdMiddleware) -> str:
    """Invoke the middleware once and return whatever request_id it bound.

    The captured value is read inside call_next (while the contextvar is
    still set); afterwards the middleware resets it, which is exactly the
    lifecycle we want to verify.
    """
    captured: dict[str, str | None] = {}

    async def call_next(_ctx):
        captured["rid"] = _request_id_var.get()
        captured["log_rid"] = structlog.contextvars.get_contextvars().get("request_id")
        return "ok"

    result = await mw.on_call_tool(_FakeContext(), call_next)
    assert result == "ok"
    return captured


def test_middleware_mints_uuid_when_no_header():
    """No X-Request-ID header → middleware generates a 12-char hex id."""
    mw = CorrelationIdMiddleware()
    captured = asyncio.run(_call_middleware_and_return_rid(mw))
    rid = captured["rid"]
    assert rid is not None
    assert re.fullmatch(r"[0-9a-f]{12}", rid), f"expected 12-char hex, got {rid!r}"
    # Same id also bound into structlog's contextvars so log lines carry it.
    assert captured["log_rid"] == rid


def test_middleware_cleans_up_after_call():
    """ContextVar and structlog binding are reset after the call returns."""
    mw = CorrelationIdMiddleware()
    asyncio.run(_call_middleware_and_return_rid(mw))
    # After on_call_tool returns, nothing should remain bound.
    assert _request_id_var.get() is None
    assert "request_id" not in structlog.contextvars.get_contextvars()


def test_middleware_honors_upstream_x_request_id(monkeypatch):
    """When the HTTP client supplies X-Request-ID, propagate it instead of minting."""
    incoming = "upstream-trace-999"

    # Patch get_http_headers at its import site inside the middleware.
    import fastmcp.server.dependencies as deps

    monkeypatch.setattr(deps, "get_http_headers", lambda: {"x-request-id": incoming})

    mw = CorrelationIdMiddleware()
    captured = asyncio.run(_call_middleware_and_return_rid(mw))
    assert captured["rid"] == incoming
    assert captured["log_rid"] == incoming


def test_middleware_ignores_blank_header(monkeypatch):
    """Empty or whitespace-only header → fall back to generating a new id."""
    import fastmcp.server.dependencies as deps

    monkeypatch.setattr(deps, "get_http_headers", lambda: {"x-request-id": "   "})

    mw = CorrelationIdMiddleware()
    captured = asyncio.run(_call_middleware_and_return_rid(mw))
    rid = captured["rid"]
    assert rid is not None
    assert re.fullmatch(r"[0-9a-f]{12}", rid)


def test_middleware_tolerates_missing_http_context(monkeypatch):
    """stdio transport has no HTTP headers — get_http_headers raises.

    The middleware must catch that and fall back to minting a new id,
    otherwise every stdio tool call would blow up.
    """
    import fastmcp.server.dependencies as deps

    def _boom():
        raise RuntimeError("not in HTTP context")

    monkeypatch.setattr(deps, "get_http_headers", _boom)

    mw = CorrelationIdMiddleware()
    captured = asyncio.run(_call_middleware_and_return_rid(mw))
    rid = captured["rid"]
    assert rid is not None
    assert re.fullmatch(r"[0-9a-f]{12}", rid)


# ── end-to-end: envelope carries the id the middleware set ──────────────


def test_envelope_and_middleware_agree_end_to_end():
    """What the middleware binds is exactly what intent_response emits.

    This is the contract operators rely on: the id in the returned JSON is
    the same id that appears in log lines for that request.
    """
    mw = CorrelationIdMiddleware()

    async def call_next(_ctx):
        # Build the envelope inside the middleware's context so it sees the id.
        return intent_response("success", "ok")

    envelope = asyncio.run(mw.on_call_tool(_FakeContext(), call_next))
    assert "request_id" in envelope
    assert re.fullmatch(r"[0-9a-f]{12}", envelope["request_id"])


# ── isolation: concurrent calls get independent ids ─────────────────────


def test_concurrent_calls_get_independent_request_ids():
    """Two tool calls running concurrently must not share a request_id.

    This is the whole point of using a ContextVar rather than a module-global:
    asyncio.gather spawns tasks that each inherit a copy of the current
    context, so each middleware invocation binds into its own slot.
    """
    mw = CorrelationIdMiddleware()
    seen: list[str] = []

    async def call_next(_ctx):
        seen.append(_request_id_var.get())
        # Yield control so the tasks really interleave.
        await asyncio.sleep(0)
        seen.append(_request_id_var.get())
        return "done"

    async def run_both():
        await asyncio.gather(
            mw.on_call_tool(_FakeContext(), call_next),
            mw.on_call_tool(_FakeContext(), call_next),
        )

    asyncio.run(run_both())
    # Expect exactly two distinct request_ids (one per task) each appearing
    # twice (the two reads inside each call_next). The interleave order of
    # the appends depends on the event loop, but the multiset is invariant.
    assert len(seen) == 4
    distinct = set(seen)
    assert len(distinct) == 2, f"expected 2 distinct request_ids across 2 tasks, got {distinct}"
    for rid in distinct:
        assert seen.count(rid) == 2, f"expected each request_id to appear twice, got seen={seen}"
