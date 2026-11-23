"""Transform primitives operating on a `RawRequest` (CONTRACT §6).

Each YAML primitive's `transform` is a list of steps `{fn: <name>, args: {...}}`. The
functions here are the vocabulary. Every function takes the request as its first argument,
mutates a copy, and returns it. They are deliberately *generic* (parametric) so the
catalogue stays declarative and auditable, while the actual byte manipulation lives in one
tested place.

Design rule: these never silently "fix" the request to be well-formed. If a mutation
produces an odd path, encoded slash or wrong method, that is the point. The only
convenience is `_fix_content_length` for ops that rewrite the body (otherwise the server
blocks waiting for bytes that will never come, which tests transport, not binding).
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Callable, Dict, List, Tuple

from rawhttp.model import RawRequest

TransformFn = Callable[..., RawRequest]
REGISTRY: Dict[str, TransformFn] = {}


def register(name: str):
    def deco(fn: TransformFn):
        REGISTRY[name] = fn
        return fn
    return deco


def apply_steps(req: RawRequest, steps: List[dict]) -> RawRequest:
    """Apply an ordered list of {fn, args} steps to a copy of `req`."""
    out = req.copy()
    for step in steps:
        fn_name = step["fn"]
        args = step.get("args", {}) or {}
        fn = REGISTRY.get(fn_name)
        if fn is None:
            raise KeyError(f"unknown transform fn: {fn_name!r}")
        out = fn(out, **args)
    return out


def _fix_content_length(req: RawRequest) -> RawRequest:
    idx = req.header_index("content-length")
    if idx is not None:
        name, _ = req.headers[idx]
        req.headers[idx] = (name, str(len(req.body)))
    return req


def _split_target(target: str) -> Tuple[str, str, str]:
    """Return (path, query, fragment) with their separators stripped."""
    frag = ""
    hidx = target.find("#")
    if hidx != -1:
        frag = target[hidx + 1 :]
        target = target[:hidx]
    qidx = target.find("?")
    if qidx != -1:
        path = target[:qidx]
        query = target[qidx + 1 :]
    else:
        path = target
        query = ""
    return path, query, frag


def _join_target(path: str, query: str, frag: str) -> str:
    t = path
    if query:
        t += "?" + query
    if frag:
        t += "#" + frag
    return t


# ─────────────────────────── header transforms (G1 override, G3 trust) ──────────

@register("add_header")
def add_header(req: RawRequest, name: str, value: str) -> RawRequest:
    """Append a header verbatim (duplicates allowed)."""
    return req.add_header(name, value)


@register("set_header")
def set_header(req: RawRequest, name: str, value: str) -> RawRequest:
    """Replace the first case-insensitive match, else append."""
    return req.set_header(name, value)


@register("remove_header")
def remove_header(req: RawRequest, name: str) -> RawRequest:
    return req.remove_header(name)


@register("duplicate_header")
def duplicate_header(req: RawRequest, name: str, value: str, second: str) -> RawRequest:
    """Add two copies of a header with different values (header-smuggling / last-wins)."""
    req.add_header(name, value)
    req.add_header(name, second)
    return req


# ─────────────────────────── method / verb transforms (G1) ──────────────────────

@register("set_method")
def set_method(req: RawRequest, value: str) -> RawRequest:
    req.method = value
    return req


# ─────────────────────────── query transforms (G1 dispatch) ─────────────────────

@register("add_query_param")
def add_query_param(req: RawRequest, key: str, value: str) -> RawRequest:
    path, query, frag = _split_target(req.target)
    part = f"{key}={value}" if value != "" else key
    query = (query + "&" + part) if query else part
    req.target = _join_target(path, query, frag)
    return req


@register("set_query_param")
def set_query_param(req: RawRequest, key: str, value: str) -> RawRequest:
    """Replace the first occurrence of key= in the query, else append it."""
    path, query, frag = _split_target(req.target)
    pairs = query.split("&") if query else []
    replaced = False
    for i, p in enumerate(pairs):
        k = p.split("=", 1)[0]
        if k == key:
            pairs[i] = f"{key}={value}"
            replaced = True
            break
    if not replaced:
        pairs.append(f"{key}={value}")
    req.target = _join_target(path, "&".join(pairs), frag)
    return req


@register("remove_query_param")
def remove_query_param(req: RawRequest, key: str) -> RawRequest:
    path, query, frag = _split_target(req.target)
    pairs = [p for p in query.split("&") if p and p.split("=", 1)[0] != key]
    req.target = _join_target(path, "&".join(pairs), frag)
    return req


# ─────────────────────────── body transforms (G1 override/dispatch) ─────────────

@register("set_form_body")
def set_form_body(req: RawRequest, fields: Dict[str, str]) -> RawRequest:
    """Replace the body with a urlencoded form and set content-type/content-length."""
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req.body = body
    req.set_header("Content-Type", "application/x-www-form-urlencoded")
    if req.header_index("content-length") is None:
        req.add_header("Content-Length", str(len(body)))
    return _fix_content_length(req)


@register("append_form_field")
def append_form_field(req: RawRequest, key: str, value: str) -> RawRequest:
    """Append a field to an existing urlencoded body (or start one)."""
    extra = urllib.parse.urlencode({key: value}).encode("utf-8")
    req.body = (req.body + b"&" + extra) if req.body else extra
    return _fix_content_length(req)


@register("set_json_field")
def set_json_field(req: RawRequest, field: str, value) -> RawRequest:
    """Parse the JSON body, set one top-level field, re-serialise, fix length."""
    try:
        obj = json.loads(req.body.decode("utf-8")) if req.body else {}
    except (ValueError, UnicodeDecodeError):
        obj = {}
    obj[field] = value
    req.body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return _fix_content_length(req)


@register("inject_duplicate_json_field")
def inject_duplicate_json_field(req: RawRequest, field: str, value) -> RawRequest:
    """Inject a *second*, duplicate JSON key via raw string surgery (parsers disagree on
    which duplicate key wins). Falls back to set_json_field if the body is not an object."""
    text = req.body.decode("utf-8", errors="replace")
    stripped = text.strip()
    inject = json.dumps({field: value})[1:-1]  # "field":value  without the braces
    if stripped.startswith("{"):
        # insert right after the opening brace
        brace = text.find("{")
        new = text[: brace + 1] + inject + "," + text[brace + 1 :]
        req.body = new.encode("utf-8")
    else:
        return set_json_field(req, field=field, value=value)
    return _fix_content_length(req)


@register("set_content_type")
def set_content_type(req: RawRequest, value: str) -> RawRequest:
    return req.set_header("Content-Type", value)


# ─────────────────────────── path transforms (G2) ───────────────────────────────

@register("replace_in_path")
def replace_in_path(req: RawRequest, find: str, replace: str, count: int = 1) -> RawRequest:
    path, query, frag = _split_target(req.target)
    path = path.replace(find, replace, count)
    req.target = _join_target(path, query, frag)
    return req


@register("insert_before_last_segment")
def insert_before_last_segment(req: RawRequest, token: str) -> RawRequest:
    """Insert `token` just before the final path segment.

    /api/v1/accounts/acc-alice-1  --(token='..%2f')-->  /api/v1/accounts/..%2facc-alice-1
    """
    path, query, frag = _split_target(req.target)
    slash = path.rfind("/")
    if slash == -1:
        new_path = token + path
    else:
        new_path = path[: slash + 1] + token + path[slash + 1 :]
    req.target = _join_target(new_path, query, frag)
    return req


@register("insert_after_segment")
def insert_after_segment(req: RawRequest, segment: str, token: str) -> RawRequest:
    """Insert `token` immediately after the first occurrence of `/segment`."""
    path, query, frag = _split_target(req.target)
    anchor = "/" + segment
    idx = path.find(anchor)
    if idx != -1:
        cut = idx + len(anchor)
        path = path[:cut] + token + path[cut:]
    req.target = _join_target(path, query, frag)
    return req


@register("append_to_path")
def append_to_path(req: RawRequest, suffix: str) -> RawRequest:
    """Append raw text to the end of the path (before any query)."""
    path, query, frag = _split_target(req.target)
    req.target = _join_target(path + suffix, query, frag)
    return req


@register("encode_char_in_path")
def encode_char_in_path(req: RawRequest, char: str, encoding: str) -> RawRequest:
    """Percent-encode every occurrence of `char` in the path with `encoding`.

    e.g. char='/', encoding='%2F' turns path slashes into encoded slashes."""
    path, query, frag = _split_target(req.target)
    path = path.replace(char, encoding)
    req.target = _join_target(path, query, frag)
    return req


@register("uppercase_path")
def uppercase_path(req: RawRequest) -> RawRequest:
    path, query, frag = _split_target(req.target)
    req.target = _join_target(path.upper(), query, frag)
    return req


@register("swapcase_path")
def swapcase_path(req: RawRequest) -> RawRequest:
    path, query, frag = _split_target(req.target)
    req.target = _join_target(path.swapcase(), query, frag)
    return req


@register("add_trailing_slash")
def add_trailing_slash(req: RawRequest) -> RawRequest:
    path, query, frag = _split_target(req.target)
    if not path.endswith("/"):
        path = path + "/"
    req.target = _join_target(path, query, frag)
    return req


@register("double_leading_slash")
def double_leading_slash(req: RawRequest) -> RawRequest:
    path, query, frag = _split_target(req.target)
    if path.startswith("/"):
        path = "/" + path
    req.target = _join_target(path, query, frag)
    return req


@register("set_fragment")
def set_fragment(req: RawRequest, value: str) -> RawRequest:
    path, query, _ = _split_target(req.target)
    req.target = _join_target(path, query, value)
    return req


# ─────────────────────────── request-target / request-line transforms (G2) ──────

@register("to_absolute_form")
def to_absolute_form(req: RawRequest, authority: str = None, scheme: str = "http") -> RawRequest:
    """Rewrite the request target to absolute-form `scheme://authority<path?query>`.

    If `authority` is None, use the current Host header (origin-consistent absolute-form).
    A different authority creates a Host-vs-absolute-form conflict (RFC 7230 §5.4)."""
    if authority is None:
        authority = req.get_header("Host") or "api.bench.test"
    path, query, frag = _split_target(req.target)
    origin_form = _join_target(path, query, frag)
    req.target = f"{scheme}://{authority}{origin_form}"
    return req


@register("set_target")
def set_target(req: RawRequest, value: str) -> RawRequest:
    req.target = value
    return req


@register("set_line_sep")
def set_line_sep(req: RawRequest, value: str) -> RawRequest:
    """Change the whitespace separating request-line tokens (SP -> tab, double-SP, ...)."""
    req.line_sep = value
    return req


@register("set_version")
def set_version(req: RawRequest, value: str) -> RawRequest:
    req.version = value
    return req
