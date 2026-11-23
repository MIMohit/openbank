import json
import os

from django.http import JsonResponse
from django.views import View

from . import bench

# ROUTES=v2 (default off) adds the richer v1 route space (W15 ext-routes). Off => :latest behaviour.
ROUTES = os.environ.get("ROUTES", "off").lower()


def not_found(request, exception=None):
    return JsonResponse({"op_id": "NOT_FOUND", "framework": bench.FRAMEWORK}, status=404)


def respond(request, op_id, template, params):
    bh = getattr(request, "bh", None) or {}
    bh.update(op_id=op_id, route_template=template, path_params=params)
    if bench.VERIFY_MODE != "off":
        if bench.VERIFY_MODE == "origin-raw":
            vm, vu = bh["raw_method"], bh["raw_target"]
        else:
            vm, vu = request.method, bench.canonical_path(template, params)
        ok = bench.call_verifier(vm, vu, request.META.get("HTTP_HOST", ""),
                                 request.META.get("HTTP_AUTHORIZATION"), request.META.get("HTTP_DPOP"))
        if not ok:
            bh["denied"] = True
            return JsonResponse({"op_id": op_id, "framework": bench.FRAMEWORK, "denied": True}, status=401)
    return JsonResponse({"op_id": op_id, "framework": bench.FRAMEWORK, "method": request.method,
                         "path_params": params})


class BenchView(View):
    """Class-based view: Django dispatches on request.method inside View.dispatch, i.e. AFTER URL
    resolution and AFTER middleware process_view (where django-method-override rewrites it)."""

    def http_method_not_allowed(self, request, *args, **kwargs):
        return not_found(request)  # CONTRACT: method mismatch is NOT_FOUND/404


class Accounts(BenchView):
    def get(self, request):
        return respond(request, "listAccounts", "/api/v1/accounts", {})


class Account(BenchView):
    T = "/api/v1/accounts/{id}"

    def get(self, request, id):
        return respond(request, "getAccount", self.T, {"id": id})

    def put(self, request, id):
        return respond(request, "updateAccount", self.T, {"id": id})

    def delete(self, request, id):
        return respond(request, "deleteAccount", self.T, {"id": id})

    if ROUTES == "v2":
        # POST sharing the /accounts/{id} path with GET/PUT/DELETE (django-method-override is POST-only).
        def post(self, request, id):
            return respond(request, "postAccount", self.T, {"id": id})


class AccountAction(BenchView):
    def post(self, request, id):
        op = request.GET.get("op")  # QueryDict.get: duplicate keys -> LAST value
        sub = op if op in ("freeze", "close") else "unknown"
        return respond(request, "accountAction." + sub, "/api/v1/accounts/{id}/actions", {"id": id})


class Transfers(BenchView):
    def post(self, request):
        return respond(request, "createTransfer", "/api/v1/transfers", {})


class GraphQL(BenchView):
    def post(self, request):
        name = None
        try:
            body = json.loads(request.body)
            if isinstance(body, dict):
                name = body.get("operationName")
        except Exception:
            name = None
        sub = name if name in ("getProfile", "deleteProfile") else "unknown"
        return respond(request, "graphql." + sub, "/api/v1/graphql", {})


class Me(BenchView):
    def get(self, request):
        return respond(request, "me", "/api/v1/me", {})


class AdminUsers(BenchView):
    def get(self, request):
        return respond(request, "adminListUsers", "/api/v1/admin/users", {})


class AdminUser(BenchView):
    def delete(self, request, id):
        return respond(request, "adminDeleteUser", "/api/v1/admin/users/{id}", {"id": id})


class Health(BenchView):
    def get(self, request):
        return respond(request, "health", "/api/v1/health", {})


class PublicFile(BenchView):
    def get(self, request, file):
        return respond(request, "publicFile", "/api/v1/public/{file}", {"file": file})


class AccountV2(BenchView):
    def get(self, request, id):
        return respond(request, "getAccountV2", "/api/v2/accounts/{id}", {"id": id})


# ---- ROUTES=v2 views (only wired into urls.py when ROUTES=v2) ----
class AccountStatements(BenchView):
    def get(self, request, id):
        return respond(request, "getStatements", "/api/v1/accounts/{id}/statements", {"id": id})


class AccountStatement(BenchView):
    def delete(self, request, id, sid):
        return respond(request, "deleteStatement", "/api/v1/accounts/{id}/statements/{sid}",
                       {"id": id, "sid": sid})


class CatchAllFile(BenchView):
    def get(self, request, path):
        return respond(request, "catchAllFile", "/api/v1/files/{path}", {"path": path})
