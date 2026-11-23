"""rawhttp: byte-exact HTTP/1.1 client and request model for the binding harness.

The whole point of this package is to *avoid* the normalisation that `http.client`,
`requests`, `urllib3`, `httpx`, etc. silently perform (path canonicalisation, header
casing, duplicate-header folding, `Host` synthesis). The mutator (G2/G3) depends on the
raw bytes reaching the socket exactly as authored. See CONTRACT.md §6.
"""
from .model import RawRequest, RawResponse
from .client import send, send_request

__all__ = ["RawRequest", "RawResponse", "send", "send_request"]
