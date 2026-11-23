import datetime as _dt

from . import bench


class BenchLogMiddleware:
    """Outermost middleware: records the raw method (before django-method-override's process_view
    runs) and writes one CONTRACT log line per request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        meta = request.META
        # gunicorn exposes the request-target exactly as received in RAW_URI
        raw_target = meta.get("RAW_URI") or request.get_full_path()
        raw_method = request.method
        trust = {}
        for k, v in meta.items():
            if k.startswith("HTTP_"):
                name = k[5:].lower().replace("_", "-")
                if name.startswith(bench.TRUST_PREFIXES):
                    trust[name] = v
        request.bh = {"op_id": "NOT_FOUND", "route_template": None, "path_params": {},
                      "denied": False, "raw_target": raw_target, "raw_method": raw_method}
        response = self.get_response(request)
        bench.write_log({
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "framework": bench.FRAMEWORK,
            "jti": bench.jti_from_dpop(meta.get("HTTP_DPOP")),
            "op_id": request.bh["op_id"],
            "route_template": request.bh["route_template"],
            "raw_method": raw_method,
            "effective_method": request.method,
            "raw_target": raw_target,
            "path_params": request.bh["path_params"],
            "query": meta.get("QUERY_STRING", ""),
            "trust_headers": trust,
            "denied": request.bh["denied"],
            "status": response.status_code,
        })
        return response
