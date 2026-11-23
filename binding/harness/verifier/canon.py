"""HTU canonicalisation modes (CONTRACT section 4, HTU_CANON).

All modes drop the query and fragment from both sides before comparing (RFC 9449 section 4.3,
check 9: "htu ... ignoring any query and fragment parts").

  none     exact string comparison of the remaining strings
  rfc3986  RFC 3986 section 6.2.2 syntax-based normalisation (case of scheme/host and of
           percent-encoding hex digits, decoding of percent-encoded unreserved characters,
           remove_dot_segments) plus section 6.2.3 scheme-based normalisation (default port
           removed, empty port removed, empty path -> "/"). %2F and other reserved encodings
           are NOT decoded. Duplicate slashes are NOT collapsed (RFC 3986 has no such rule).
  strict   reject the request if the view (or htu) contains a non-canonical or ambiguous path:
           dot-segments (raw or %2E-encoded), "//", %2F, %5C, "\\", %00, %25 (double encoding),
           ";" (path parameters), encoded unreserved characters, lower-case percent hex,
           malformed percent escapes, control/space/non-ASCII bytes, userinfo. Remaining inputs
           are then compared after rfc3986 normalisation (so scheme/host case and default
           port still compare equal).
"""
from __future__ import annotations

import re
import string

MODES = ("rfc3986", "none", "strict")

_URI = re.compile(r"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$", re.S)  # RFC 3986 App. B
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
_DEFAULT_PORT = {"http": "80", "https": "443"}
_PCHAR_OK = frozenset(string.ascii_letters + string.digits + "-._~!$&'()*+,;=:@/%")


class NonCanonical(ValueError):
    """Raised in strict mode (or for unusable input) with a short reason code."""


def strip_query_fragment(u: str) -> str:
    return re.split(r"[?#]", u, maxsplit=1)[0]


def split(u: str) -> dict:
    m = _URI.match(u)
    return {"scheme": m.group(2), "authority": m.group(4), "path": m.group(5),
            "query": m.group(7), "fragment": m.group(9)}


def remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4."""
    inp, out = path, []
    while inp:
        if inp.startswith("../"):
            inp = inp[3:]
        elif inp.startswith("./"):
            inp = inp[2:]
        elif inp.startswith("/./"):
            inp = "/" + inp[3:]
        elif inp == "/.":
            inp = "/"
        elif inp.startswith("/../"):
            inp = "/" + inp[4:]
            if out:
                out.pop()
        elif inp == "/..":
            inp = "/"
            if out:
                out.pop()
        elif inp in (".", ".."):
            inp = ""
        else:
            i = inp.find("/", 1)
            seg, inp = (inp, "") if i == -1 else (inp[:i], inp[i:])
            out.append(seg)
    return "".join(out)


def normalise_pct(s: str) -> str:
    """Upper-case hex digits; decode octets that are unreserved characters."""
    def rep(m):
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()
    return _PCT.sub(rep, s)


def normalise_path(path: str, has_authority: bool = True) -> str:
    p = remove_dot_segments(normalise_pct(path))
    if has_authority and p == "":
        p = "/"
    return p


def normalise_rfc3986(u: str) -> str:
    """Normalise an absolute URI, dropping query and fragment."""
    c = split(u)
    if not c["scheme"] or c["authority"] is None:
        raise NonCanonical("not_absolute_uri")
    scheme = c["scheme"].lower()
    auth = c["authority"]
    userinfo, at, hostport = auth.rpartition("@")
    if hostport.startswith("["):
        end = hostport.find("]")
        host, rest = hostport[: end + 1], hostport[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = hostport.partition(":")
    host = normalise_pct(host).lower()
    if port == "" or (port.isdigit() and scheme in _DEFAULT_PORT and int(port) == int(_DEFAULT_PORT[scheme])):
        port_s = ""
    else:
        port_s = ":" + port
    authority = (normalise_pct(userinfo) + "@" if at else "") + host + port_s
    return f"{scheme}://{authority}{normalise_path(c['path'])}"


def strict_check(u: str) -> None:
    """Raise NonCanonical(reason) if the URI is not in canonical, unambiguous form."""
    c = split(u)
    if not c["scheme"] or c["authority"] is None:
        raise NonCanonical("strict_not_absolute")
    if "@" in c["authority"]:
        raise NonCanonical("strict_userinfo")
    path = c["path"]
    if not path.startswith("/"):
        raise NonCanonical("strict_path_not_absolute")
    if any(ch not in _PCHAR_OK for ch in path):
        raise NonCanonical("strict_illegal_char")
    if "//" in path:
        raise NonCanonical("strict_duplicate_slash")
    if ";" in path:
        raise NonCanonical("strict_path_parameter")
    if re.search(r"%(?![0-9A-Fa-f]{2})", path):
        raise NonCanonical("strict_bad_percent")
    for m in _PCT.finditer(path):
        hx = m.group(1)
        octet = int(hx, 16)
        if hx.upper() in ("2F", "5C"):
            raise NonCanonical("strict_encoded_slash")
        if hx.upper() == "00":
            raise NonCanonical("strict_encoded_nul")
        if hx.upper() == "25":
            raise NonCanonical("strict_double_encoding")
        if chr(octet) in _UNRESERVED:
            raise NonCanonical("strict_encoded_unreserved")
        if hx != hx.upper():
            raise NonCanonical("strict_lowercase_hex")
    for seg in path.split("/"):
        if seg in (".", ".."):
            raise NonCanonical("strict_dot_segment")


def compare(htu: str, view_url: str, mode: str) -> tuple[bool, str, str, str]:
    """Return (match, reason, canon_htu, canon_view). reason is "" on match."""
    if mode not in MODES:
        raise ValueError(f"unknown HTU_CANON mode {mode!r}")
    h, v = strip_query_fragment(htu), strip_query_fragment(view_url)
    if mode == "none":
        return (h == v, "" if h == v else "htu_mismatch", h, v)
    try:
        if mode == "strict":
            try:
                strict_check(v)
            except NonCanonical as e:
                return False, str(e), h, v
            try:
                strict_check(h)
            except NonCanonical as e:
                return False, "htu_" + str(e), h, v
        ch = normalise_rfc3986(h)
    except NonCanonical:
        return False, "htu_invalid", h, v
    try:
        cv = normalise_rfc3986(v)
    except NonCanonical:
        return False, "view_invalid", ch, v
    return (ch == cv, "" if ch == cv else "htu_mismatch", ch, cv)


def canon_path(uri: str) -> str:
    """Canonical path (no query) of an origin-form or absolute-form URI; used for VIEW_MAC."""
    if not uri.startswith("/") and re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", uri):
        return normalise_path(split(uri)["path"])
    return normalise_path(strip_query_fragment(uri))
