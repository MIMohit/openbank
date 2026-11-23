"""Raw HTTP request/response model.

`RawRequest` is the object the mutator transforms (CONTRACT.md §6: "operates on a raw
request model: method, target, headers list, body"). It is serialised to bytes with **no
normalisation whatsoever** — header order, duplicate headers, odd casing, unusual request
lines and absolute-form targets all survive to the wire.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, field, replace
from typing import List, Tuple, Optional


# A header is an ordered (name, value) pair. Duplicates and case are preserved verbatim.
Header = Tuple[str, str]


@dataclass
class RawRequest:
    """A byte-exact HTTP/1.1 request.

    Attributes:
        method:        the request method token, e.g. "GET". Arbitrary bytes allowed.
        target:        the request target exactly as it appears on the request line
                       (origin-form "/api/..", absolute-form "http://h/api/..", etc.).
        version:       the HTTP version token, default "HTTP/1.1".
        headers:       ordered list of (name, value); duplicates and casing preserved.
        body:          the entity body as raw bytes.
        line_sep:      separator between request-line tokens (default single SP). Used by
                       whitespace/tab request-line mutations (G2).
        eol:           line terminator. RFC says CRLF; kept configurable for mutation.
    """

    method: str = "GET"
    target: str = "/"
    version: str = "HTTP/1.1"
    headers: List[Header] = field(default_factory=list)
    body: bytes = b""
    line_sep: str = " "
    eol: str = "\r\n"

    # ---- header helpers (all preserve order / duplicates unless told otherwise) ----

    def copy(self) -> "RawRequest":
        return replace(self, headers=list(self.headers), body=bytes(self.body))

    def add_header(self, name: str, value: str) -> "RawRequest":
        """Append a header, allowing duplicates."""
        self.headers.append((name, value))
        return self

    def set_header(self, name: str, value: str) -> "RawRequest":
        """Replace the first case-insensitive match, else append."""
        lname = name.lower()
        for i, (n, _) in enumerate(self.headers):
            if n.lower() == lname:
                self.headers[i] = (name, value)
                return self
        self.headers.append((name, value))
        return self

    def remove_header(self, name: str) -> "RawRequest":
        lname = name.lower()
        self.headers = [(n, v) for (n, v) in self.headers if n.lower() != lname]
        return self

    def get_header(self, name: str) -> Optional[str]:
        lname = name.lower()
        for n, v in self.headers:
            if n.lower() == lname:
                return v
        return None

    def header_index(self, name: str) -> Optional[int]:
        lname = name.lower()
        for i, (n, _) in enumerate(self.headers):
            if n.lower() == lname:
                return i
        return None

    # ---- path/target helpers ----

    @property
    def path(self) -> str:
        """The path portion of an origin-form target (everything before ? and #)."""
        t = self.target
        for sep in ("?", "#"):
            idx = t.find(sep)
            if idx != -1:
                t = t[:idx]
        return t

    @property
    def query(self) -> str:
        """The query string (without the leading '?'); '' if absent."""
        t = self.target
        # strip fragment first
        hidx = t.find("#")
        if hidx != -1:
            t = t[:hidx]
        qidx = t.find("?")
        if qidx == -1:
            return ""
        return t[qidx + 1 :]

    # ---- serialisation ----

    def to_bytes(self) -> bytes:
        """Serialise to the exact bytes that go on the socket.

        We do NOT auto-insert Host, Content-Length or anything else. Callers (or the
        canonical-request builders) are responsible for the headers they want. This is
        deliberate: the mutations rely on the absence of library normalisation.
        """
        sep = self.line_sep
        eol = self.eol.encode("utf-8")
        # UTF-8 so that raw non-ASCII codepoints (e.g. fullwidth Unicode path mutations)
        # go on the wire as their UTF-8 bytes. For ASCII this is identical to latin-1; we
        # never place raw bytes 128-255 as literals (those mutations use percent-encoding).
        request_line = f"{self.method}{sep}{self.target}{sep}{self.version}".encode("utf-8")
        out = bytearray()
        out += request_line + eol
        for name, value in self.headers:
            out += f"{name}: {value}".encode("utf-8") + eol
        out += eol  # end of headers
        out += self.body
        return bytes(out)

    def to_b64(self) -> str:
        return base64.b64encode(self.to_bytes()).decode("ascii")

    @staticmethod
    def from_b64(s: str) -> "RawRequest":
        return RawRequest.parse(base64.b64decode(s))

    @staticmethod
    def parse(raw: bytes) -> "RawRequest":
        """Parse bytes back into a RawRequest (best effort; for round-tripping tests).

        Note: parsing is lossy for exotic line separators; the canonical path is to keep
        the RawRequest object. This exists mainly so the runner can reconstruct a request
        from `raw_request_b64` and then inject auth headers.
        """
        # Split headers / body on the first blank line.
        sep_idx = raw.find(b"\r\n\r\n")
        term = b"\r\n"
        if sep_idx == -1:
            sep_idx = raw.find(b"\n\n")
            term = b"\n"
            if sep_idx == -1:
                head = raw
                body = b""
            else:
                head = raw[:sep_idx]
                body = raw[sep_idx + 2 :]
        else:
            head = raw[:sep_idx]
            body = raw[sep_idx + 4 :]
        lines = head.split(term)
        request_line = lines[0].decode("latin-1")
        # Request line: METHOD SP TARGET SP VERSION (we assume single-space for parse)
        parts = request_line.split(" ")
        if len(parts) >= 3:
            method, target, version = parts[0], parts[1], parts[-1]
        elif len(parts) == 2:
            method, target, version = parts[0], parts[1], "HTTP/1.1"
        else:
            method, target, version = parts[0], "/", "HTTP/1.1"
        headers: List[Header] = []
        for line in lines[1:]:
            if not line:
                continue
            s = line.decode("latin-1")
            cidx = s.find(":")
            if cidx == -1:
                headers.append((s, ""))
            else:
                name = s[:cidx]
                value = s[cidx + 1 :]
                if value.startswith(" "):
                    value = value[1:]
                headers.append((name, value))
        return RawRequest(method=method, target=target, version=version,
                          headers=headers, body=body)


@dataclass
class RawResponse:
    """A parsed HTTP response."""

    status: int
    reason: str
    http_version: str
    headers: List[Header]
    body: bytes
    # Diagnostics: how the body length was determined and any transport note.
    framing: str = ""        # "content-length" | "chunked" | "close" | "none"
    error: Optional[str] = None  # set if a transport/timeout error occurred

    def header(self, name: str) -> Optional[str]:
        lname = name.lower()
        for n, v in self.headers:
            if n.lower() == lname:
                return v
        return None

    def text(self, encoding: str = "utf-8") -> str:
        try:
            return self.body.decode(encoding)
        except UnicodeDecodeError:
            return self.body.decode("latin-1", errors="replace")

    def json(self):
        import json as _json
        return _json.loads(self.body.decode("utf-8"))
