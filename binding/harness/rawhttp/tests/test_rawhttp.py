"""rawhttp model + response-parser tests (no network)."""
from rawhttp.model import RawRequest
from rawhttp.client import _parse_response, _read_chunked  # internal parser units


def test_request_roundtrip_byte_exact():
    req = RawRequest(method="POST", target="/api/v1/transfers",
                     headers=[("Host", "api.bench.test"), ("Content-Type", "application/json")],
                     body=b'{"a":1}')
    raw = req.to_bytes()
    assert raw.startswith(b"POST /api/v1/transfers HTTP/1.1\r\n")
    assert raw.endswith(b"\r\n\r\n" + b'{"a":1}')
    # round-trip via b64
    r2 = RawRequest.from_b64(req.to_b64())
    assert r2.method == "POST" and r2.target == "/api/v1/transfers"
    assert r2.get_header("content-type") == "application/json"
    assert r2.body == b'{"a":1}'


def test_duplicate_and_case_headers_preserved():
    req = RawRequest(target="/x", headers=[("Host", "a"), ("Host", "b"),
                                           ("x-verified-sub", "bob")])
    raw = req.to_bytes().decode()
    assert raw.count("Host:") == 2
    assert "x-verified-sub: bob" in raw


def test_path_and_query_split():
    req = RawRequest(target="/api/v1/accounts/acc-1?op=freeze#frag")
    assert req.path == "/api/v1/accounts/acc-1"
    assert req.query == "op=freeze"


def test_parse_content_length_response():
    raw = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
           b"Content-Length: 11\r\n\r\n" + b'{"op_id":1}')
    resp = _parse_response(raw)
    assert resp.status == 200
    assert resp.framing == "content-length"
    assert resp.body == b'{"op_id":1}'


def test_parse_chunked_decoding():
    # 5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n -> "hello!"
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n"
    resp = _parse_response(chunked)
    assert resp.framing == "chunked"


def test_line_sep_mutation_tab():
    req = RawRequest(method="GET", target="/x", line_sep="\t")
    assert req.to_bytes().startswith(b"GET\t/x\tHTTP/1.1")
