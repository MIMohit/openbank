"""
OAuth 2.0 Authorization Code + PKCE + PAR + DPoP token acquisition.

For the testbed we use Keycloak's Resource Owner Password Credentials Grant
as a stand-in for the full browser-redirect flow (PAR+PKCE is enforced by
Keycloak; this module signs the DPoP proof for the token request).

In B1/P mode the token endpoint is called with:
  - DPoP header (proof for the token endpoint URI)
  - PKCE code_verifier
  - client_id / client_secret

Returned token will carry cnf.jkt matching the device keypair.

NOTE: FAPI2 DPoP support in Keycloak 26.4 requires the token request
itself to include a DPoP proof; that is what this module does.
"""
import base64
import hashlib
import os
import secrets
import urllib.parse
from typing import Optional

import httpx

from client_sim.device import Device


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class OAuthSession:
    """
    Manages the OAuth token lifecycle for one device.
    Supports B0 (plain bearer) and B1/P (DPoP-bound) modes.
    """

    def __init__(
        self,
        device: Device,
        keycloak_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        use_dpop: bool = True,
    ):
        self.device = device
        self.keycloak_url = keycloak_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.use_dpop = use_dpop
        self.access_token: Optional[str] = None
        self.token_endpoint = (
            f"{self.keycloak_url}/realms/{self.realm}"
            "/protocol/openid-connect/token"
        )

    async def authenticate(self) -> str:
        """
        Obtain an access token.  Returns the raw access token string.
        In DPoP mode, the token will carry cnf.jkt bound to the device keypair.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password,
            "scope": "openid accounts:read transactions:read",
        }
        if self.use_dpop:
            dpop_proof = self.device.sign_dpop_proof(
                method="POST",
                url=self.token_endpoint,
            )
            headers["DPoP"] = dpop_proof

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                self.token_endpoint,
                data=data,
                headers=headers,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Token request failed: {resp.status_code} {resp.text}"
                )
            token_resp = resp.json()

        self.access_token = token_resp["access_token"]
        return self.access_token

    def request_headers(
        self,
        method: str,
        url: str,
        extra_context: Optional[dict] = None,
    ) -> dict:
        """
        Build the full request headers for one API call:
          - Authorization: Bearer <at>
          - DPoP: <fresh proof>
          - Context metadata headers for telemetry
        """
        if not self.access_token:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        headers = {
            "Authorization": f"Bearer {self.access_token}",
        }
        if self.use_dpop:
            dpop_proof = self.device.sign_dpop_proof(
                method=method,
                url=url,
                access_token=self.access_token,
            )
            headers["DPoP"] = dpop_proof

        ctx = self.device.context_headers(**(extra_context or {}))
        headers.update(ctx)
        return headers
