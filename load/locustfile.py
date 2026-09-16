"""
Locust load harness — legitimate traffic workload with optional context drift.

Run:
  locust -f load/locustfile.py --host http://localhost:9000 \
      --users 50 --spawn-rate 5 --run-time 60s --headless

Context drift profile: simulates a user who occasionally changes network/geo
(e.g., switches from office to mobile).  Used for E2 false-challenge measurement.
"""
import asyncio
import os
import random
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from locust import HttpUser, task, between, events
from client_sim.device import Device
from client_sim.flows import OAuthSession

CONTROLLER_URL = os.getenv("CONTROLLER_URL", "http://localhost:9000")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
ZT_MODE = os.getenv("ZT_MODE", "P").upper()
DRIFT_PROBABILITY = float(os.getenv("DRIFT_PROBABILITY", "0.05"))  # 5% drift requests
GLOBAL_SEED = int(os.getenv("GLOBAL_SEED", "42"))

_rng = random.Random(GLOBAL_SEED)


def _authenticate(device: Device) -> str:
    """
    Obtain a real, Keycloak-signed access token bound to `device`'s key.
    B0 uses the openbanking-b0 realm's public client (no DPoP); B1/P use the
    openbanking-fapi2 realm's harness-only direct-grant client (see
    keycloak/realm-fapi2.json: zt-harness-client) so the load test can get
    real cnf.jkt-bound tokens without a browser PAR+PKCE redirect. Tokens are
    verified by the ZT Controller exactly like any other request.
    """
    if ZT_MODE == "B0":
        session = OAuthSession(
            device=device,
            keycloak_url=KEYCLOAK_URL,
            realm=os.getenv("KC_REALM_B0", "openbanking-b0"),
            client_id="zt-client-b0",
            client_secret="",
            username="testuser",
            password="testpass",
            use_dpop=False,
        )
    else:
        session = OAuthSession(
            device=device,
            keycloak_url=KEYCLOAK_URL,
            realm=os.getenv("KC_REALM_FAPI2", "openbanking-fapi2"),
            client_id="zt-harness-client",
            client_secret="zt-harness-client-secret-local",
            username="testuser",
            password="testpass",
            use_dpop=True,
        )
    return asyncio.run(session.authenticate())


class OpenBankingUser(HttpUser):
    wait_time = between(0.1, 1.0)

    def on_start(self):
        self.device = Device(
            device_id=f"load_{self.environment.runner.user_count}_{uuid.uuid4().hex[:4]}",
            geo="AU",
            source_ip=f"10.{_rng.randint(0,255)}.{_rng.randint(0,255)}.{_rng.randint(1,254)}",
        )
        self.access_token = _authenticate(self.device)
        self.request_count = 0

    def _build_headers(self, method: str, path: str, drift: bool = False) -> dict:
        url = f"{CONTROLLER_URL}{path}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
        }
        if drift:
            # Simulate geo/IP change
            headers.update(self.device.context_headers(
                geo=_rng.choice(["AU", "NZ", "SG"]),
                source_ip=f"192.168.{_rng.randint(0,255)}.{_rng.randint(1,254)}",
            ))
        else:
            headers.update(self.device.context_headers())

        headers["DPoP"] = self.device.sign_dpop_proof(
            method=method,
            url=url,
            access_token=self.access_token,
        )
        return headers

    @task(5)
    def list_accounts(self):
        drift = _rng.random() < DRIFT_PROBABILITY
        headers = self._build_headers("GET", "/accounts", drift=drift)
        with self.client.get("/accounts", headers=headers, catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            elif resp.status_code in (401, 403):
                resp.failure(f"Blocked: {resp.status_code}")
            else:
                resp.failure(f"Unexpected: {resp.status_code}")

    @task(3)
    def list_transactions(self):
        headers = self._build_headers("GET", "/transactions?account_id=dummy")
        with self.client.get("/transactions?account_id=dummy",
                             headers=headers, catch_response=True) as resp:
            if resp.status_code in (200, 404):
                resp.success()
            elif resp.status_code in (401, 403):
                resp.failure(f"Blocked: {resp.status_code}")

    @task(1)
    def get_user_profile(self):
        headers = self._build_headers("GET", "/users")
        with self.client.get("/users", headers=headers, catch_response=True) as resp:
            if resp.status_code in (200, 404):
                resp.success()
            elif resp.status_code in (401, 403):
                resp.failure(f"Blocked: {resp.status_code}")
