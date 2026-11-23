# rawhttp — byte-exact HTTP/1.1 client + request model (W7)

Sends **exactly** the bytes it is given over a raw TCP socket and parses the response
without any HTTP library, so the G2/G3 mutations survive to the wire. Normal clients
(`requests`, `urllib3`, `http.client`) would canonicalise the path, re-case headers, fold
duplicates and synthesise `Host` — all of which would destroy the experiment.

## Contents
- `model.py` — `RawRequest` (method, target, version, ordered headers with duplicates/case
  preserved, body, request-line separator) and `RawResponse`. `RawRequest` is the object
  the mutator transforms (CONTRACT §6). `to_bytes()` serialises with no normalisation.
- `client.py` — `send(host, port, raw_bytes, timeout)` and `send_request(host, port, req)`.
  Handles Content-Length, `Transfer-Encoding: chunked`, and connection-close framing, plus
  connect/read timeouts. Transport errors/timeouts return `RawResponse(status=0, error=...)`
  rather than raising, so the runner records them per case.
- `h2client.py` — **optional** HTTP/2 (h2c prior-knowledge) via the `h2` library, for the
  H2→H1 downgrade primitives. If `h2` is not installed, `send_h2` raises ImportError and
  the runner marks the H2 path as skipped.

## Run / test
```
cd binding/harness
python -m pytest rawhttp/tests -q
```
No network is needed for the tests (they exercise the model and the response parser units).

## Limitations / contract interpretations
- **No `shutdown(SHUT_WR)`** after sending: a half-close makes some servers (nginx) reset
  and return zero bytes. Our requests are self-delimiting (no-body methods; bodies carry
  Content-Length), so the server sees the request end at the header terminator. Verified
  against a live nginx gateway.
- **UTF-8 serialisation** of the request line and headers. Identical to latin-1 for ASCII;
  it exists so raw non-ASCII codepoints (the fullwidth-Unicode G2 primitive) go on the wire
  as their UTF-8 bytes. Raw bytes 128–255 are always expressed via percent-encoding, never
  as literals.
- HTTP/2 is cleartext h2c only (the harness is TLS-free, CONTRACT §1). Gateways that
  negotiate H2 only over TLS/ALPN will not accept it; H2 coverage is therefore best-effort
  and marked per topology.
- `RawRequest.parse()` assumes a single-space request line (used only for b64 round-trip);
  the authoritative representation is the `RawRequest` object itself.
