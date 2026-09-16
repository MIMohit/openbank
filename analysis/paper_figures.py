"""
Publication figures for the manuscript.

Writes paper/figures/*.pdf (vector, for the manuscript) and *.png (400 dpi).
Two kinds of figure live here and are kept deliberately separate:

  Diagrams (Fig. 1-5) are drawn from the implementation. Every box is a module
  or container that exists in this repository and every edge is a call that the
  code actually makes; the docstring of each builder names the source files it
  was read from, so a reviewer can check the figure against the code.

  Result plots (Fig. 6-12) read only data/tables/*.csv and data/raw/*.jsonl.
  No value is entered by hand. Where a figure needs a number that is not in a
  table, it is recomputed here from the raw records and the computation is in
  the function.

Run: make figures   (or PYTHONPATH=. analysis/.venv/bin/python3 analysis/paper_figures.py)
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch, Rectangle

from analysis.figstyle import (
    COL1, COL15, COL2, C_B0, C_B1, C_P, C_ACCENT, C_ACCENT2, C_RULE, C_LIGHT,
    C_MID, C_BOX_IDP, C_BOX_PEP, C_BOX_PDP, C_BOX_RS, C_BOX_ADV, CONFIG_COLOR,
    apply_style, save, box, titled_box, stack, arrow, blank_axes,
)

RAW = Path("data/raw")
TBL = Path("data/tables")
CONFIGS = ["B0", "B1", "P"]
ATTACKS = ["A1", "A2", "A3", "A4", "A5", "A6"]
TAU_ALLOW, TAU_DENY = 0.40, 0.70


# ─── Data loading ────────────────────────────────────────────────────────────

def _jsonl(path: Path) -> list:
    if not path.is_file():
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def load_records(pattern: str) -> pd.DataFrame:
    rows = []
    for f in sorted(RAW.glob(pattern)):
        rows.extend(_jsonl(f))
    return pd.json_normalize(rows) if rows else pd.DataFrame()


def csv(name: str) -> pd.DataFrame:
    p = TBL / name
    return pd.read_csv(p) if p.is_file() else pd.DataFrame()


def _num(s):
    return pd.to_numeric(s, errors="coerce")


def _wilson(k: int, n: int):
    """Wilson 95% interval; duplicated from analysis.stats to keep this module
    importable without the analysis venv's scipy."""
    if n == 0:
        return 0.0, 0.0, 0.0
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - m), min(1.0, c + m)


# ─── Figure 1: system architecture ───────────────────────────────────────────

def fig1_architecture():
    """
    Read from: docker-compose.yml (services, networks, port exposure),
    zt-controller/app/main.py (stage order), token_verify.py, dpop_verify.py,
    telemetry.py, device_registry.py, risk.py, policy_client.py, proxy.py,
    opa/policies/zt.rego, mock-adr-api/app/auth.py, config.py (_MODES).
    """
    fig = plt.figure(figsize=(COL2, 4.05))
    ax = blank_axes(fig)

    ax.add_patch(Rectangle((0.152, 0.030), 0.845, 0.880, fill=False,
                           edgecolor=C_RULE, linewidth=0.8,
                           linestyle=(0, (4, 2)), zorder=1))
    ax.text(0.154, 0.918, "trust boundary — single Docker bridge network; the "
                          "resource server is not published to the host",
            ha="left", va="bottom", fontsize=6.2, style="italic", color=C_RULE)

    # ── client ──
    box(ax, 0.004, 0.395, 0.128, 0.175,
        "Client\nEC P-256 key pair\nsigns one DPoP proof\nper request",
        fc=C_BOX_ADV, fontsize=6.3)
    ax.text(0.068, 0.378, "untrusted", ha="center", va="top", fontsize=6.0,
            style="italic", color=C_RULE)
    ax.text(0.004, 0.640, "(1) token request\n      (DPoP-bound)", ha="left",
            va="center", fontsize=6.0, color=C_RULE, linespacing=1.3)
    ax.text(0.004, 0.318, "(2) API request:\n      Authorization + DPoP", ha="left",
            va="top", fontsize=6.0, color=C_RULE, linespacing=1.3)

    # ── IdP ──
    titled_box(ax, 0.170, 0.775, 0.300, 0.108,
               "Keycloak 26.4.4  —  identity provider",
               "realm profile: FAPI 2.0 DPoP  ·  PAR, PKCE (S256)\n"
               "issues access tokens carrying cnf.jkt, 300 s lifetime",
               fc=C_BOX_IDP, detail_size=5.9)

    # ── controller ──
    cx, cw = 0.170, 0.440
    box(ax, cx, 0.060, cw, 0.660, fc="white", ec=C_P, lw=1.1, zorder=2)
    ax.text(cx + cw / 2, 0.692, "Zero Trust Controller  —  PEP + PDP   "
                                "(FastAPI, port 9000)",
            ha="center", va="center", fontsize=7.0, weight="bold", color=C_P,
            zorder=4)

    ix, iw = cx + 0.016, cw - 0.032
    bands = stack(0.660, 0.078, [1.0, 1.18, 1.32, 1.0, 1.0], 0.016)
    specs = [
        ("1   token_verify",
         "JWKS signature  ·  issuer  ·  expiry  ·  cnf.jkt present", C_BOX_PEP),
        ("2   dpop_verify   (RFC 9449)",
         "ES256 JWS  ·  RFC 7638 thumbprint = cnf.jkt  ·  htm / htu\n"
         "iat within ±60 s  ·  jti replay cache  ·  ath", C_BOX_PEP),
        ("3   telemetry + device registry   (PIP)",
         "per-subject 60 s window: call rate, geo velocity,\n"
         "session continuity, DPoP-failure rate\n"
         "registry: has this subject used this cnf.jkt before?", C_BOX_PDP),
        ("4   risk",
         "six additive rules → risk ∈ [0,1],  belief b = 1 − risk", C_BOX_PDP),
        ("6   enforce",
         "ALLOW → proxy   ·   CHALLENGE → 401   ·   DENY → 403", C_BOX_RS),
    ]
    for (y, h), (title, detail, fc) in zip(bands, specs):
        titled_box(ax, ix, y, iw, h, title, detail, fc=fc, detail_size=5.9)
    for i in range(len(bands) - 1):
        arrow(ax, (cx + cw / 2, bands[i][0]),
              (cx + cw / 2, bands[i + 1][0] + bands[i + 1][1]))

    rx, rw = 0.640, 0.355

    # ── configuration legend (top right) ──
    ly, lh = 0.758, 0.152
    box(ax, rx, ly, rw, lh, fc="white", ec=C_MID, lw=0.6)
    ax.text(rx + 0.012, ly + lh - 0.026, "stages each configuration executes",
            ha="left", va="center", fontsize=6.4, weight="bold")
    yy = ly + lh - 0.060
    for name, desc, col in [("B0", "stage 6 only — plain bearer, no policy", C_B0),
                            ("B1", "stages 1, 2, 6 — FAPI 2.0 / DPoP baseline", C_B1),
                            ("P", "stages 1–6 — B1 plus continuous enforcement", C_P)]:
        ax.add_patch(Rectangle((rx + 0.014, yy - 0.009), 0.015, 0.018,
                               facecolor=col, edgecolor=C_RULE, linewidth=0.4))
        ax.text(rx + 0.036, yy, name, ha="left", va="center", fontsize=6.1,
                weight="bold")
        ax.text(rx + 0.060, yy, desc, ha="left", va="center", fontsize=5.9)
        yy -= 0.029
    ax.text(rx + 0.012, ly + 0.014, "one image; the configuration is selected by "
                                    "environment flags", ha="left", va="center",
            fontsize=5.8, color=C_RULE, style="italic")

    # ── OPA ──
    titled_box(ax, rx, 0.540, rw, 0.135, "5   OPA 0.70.0  —  zt.rego",
               "hard deny on any failed mandatory check; otherwise\n"
               "ALLOW / CHALLENGE / DENY by comparing risk to\n"
               "τ_allow = 0.40 and τ_deny = 0.70; unreachable → DENY",
               fc=C_BOX_PDP, detail_size=5.8)
    y4, h4 = bands[3]
    arrow(ax, (ix + iw, y4 + h4 * 0.70), (rx, 0.560), rad=0.16)
    arrow(ax, (rx, 0.595), (ix + iw, y4 + h4 * 0.30), rad=0.16, ls=(0, (2, 1.6)))

    # ── the keying decision, attached to the PIP band ──
    y3, h3 = bands[2]
    arrow(ax, (rx - 0.004, 0.410), (ix + iw + 0.003, y3 + h3 / 2), color=C_ACCENT,
          rad=0.10)
    ax.text(rx + 0.006, 0.410,
            "all continuous-trust state is keyed on the\n"
            "verified $sub$ claim and on $cnf.jkt$, never\n"
            "on a client-supplied header",
            ha="left", va="center", fontsize=6.0, color=C_ACCENT,
            linespacing=1.35)

    # ── resource server ──
    titled_box(ax, rx, 0.055, rw, 0.215, "Mock ADR API  (Basiq-isomorphic)",
               "/users   /accounts   /transactions   /consents\n\n"
               "object-level ownership enforced on every object\n"
               "synthetic data, seed 42: 100 users ×\n"
               "3 accounts × 200 transactions\n"
               "reachable only through the controller",
               fc=C_BOX_RS, detail_size=5.9)
    y6, h6 = bands[4]
    arrow(ax, (ix + iw, y6 + h6 / 2), (rx, 0.175))
    ax.text(rx, 0.300, "the controller strips Authorization and DPoP and asserts\n"
                       "the verified subject on an internal service header",
            ha="left", va="center", fontsize=5.8, color=C_RULE,
            linespacing=1.3)

    # ── client edges ──
    arrow(ax, (0.132, 0.552), (0.170, 0.800), rad=-0.18)
    arrow(ax, (0.132, 0.455), (ix, 0.455))
    arrow(ax, (0.320, 0.775), (0.320, 0.722), ls=(0, (2, 1.6)))
    ax.text(0.328, 0.749, "JWKS", ha="left", va="center", fontsize=5.9,
            color=C_RULE)

    save(fig, "fig1_architecture")


# ─── Figure 2: threat model ──────────────────────────────────────────────────

def fig2_threat_model():
    """
    Read from: the threat model as implemented — attacks/a1..a7 (what each
    adversary holds and sends), zt-controller/app/dpop_verify.py and
    device_registry.py (which control answers which), and the measured outcomes
    in data/tables/table1_taxonomy.csv and table9_adaptive_adversary.csv.
    """
    t1 = csv("table1_taxonomy.csv").set_index("Attack")
    t9 = csv("table9_adaptive_adversary.csv").set_index("Cell")

    fig = plt.figure(figsize=(COL2, 3.30))
    ax = blank_axes(fig)

    X_POS, W_POS = 0.004, 0.300
    X_ATK = 0.316
    X_CTRL = 0.456
    X_B1, X_P = 0.722, 0.780
    X_RIGHT, W_RIGHT = 0.804, 0.194

    ax.text(X_POS, 0.968, "Adversary position, what it can produce, and what "
                          "answers it", fontsize=7.4, weight="bold", ha="left",
            va="center")

    hy = 0.905
    for x, lab, ha in [(X_POS, "position and capability", "left"),
                       (X_ATK, "attack", "left"),
                       (X_CTRL, "the control that answers it", "left"),
                       (X_B1, "B1", "center"), (X_P, "P", "center")]:
        ax.text(x, hy, lab, fontsize=6.3, weight="bold", ha=ha, va="center",
                color=C_RULE)
    ax.plot([X_POS, 0.800], [hy - 0.022, hy - 0.022], color=C_MID, lw=0.6)

    rows = [
        ("P1   on the network path", "captured request bytes; no private key",
         "A1  replay", "jti replay cache and iat skew\n(stage 2)", "A1"),
        ("P2   client-storage exfiltration", "a valid access token; no private key",
         "A2  token theft", "cnf.jkt thumbprint comparison\n(stage 2)", "A2"),
        ("P3   resident on the enrolled device", "the account's own key; can sign any proof",
         "A3  key abuse\nA6  volume", "call-rate rule only\n(stage 4)", "A3"),
        ("P4   holds the account credentials", "own device, own key, own genuine token",
         "A4  ATO, new device", "per-subject device registry\n(stage 3)", "A4"),
        ("P5   authenticated as another user", "own valid session, other users' object ids",
         "A5  BOLA / BFLA", "object ownership at the\nresource server", "A5"),
    ]

    top, bottom, gap = 0.858, 0.150, 0.018
    h = (top - bottom - gap * (len(rows) - 1)) / len(rows)
    y = top
    for title, cap, atk, ctrl, aid in rows:
        y -= h
        box(ax, X_POS, y, W_POS, h, fc=C_BOX_ADV)
        ax.text(X_POS + 0.012, y + h * 0.68, title, fontsize=6.4, weight="bold",
                ha="left", va="center")
        ax.text(X_POS + 0.012, y + h * 0.28, cap, fontsize=6.0, ha="left",
                va="center", style="italic", color="#333333")
        ax.text(X_ATK, y + h / 2, atk, fontsize=6.2, ha="left", va="center",
                linespacing=1.35)
        ax.text(X_CTRL, y + h / 2, ctrl, fontsize=6.0, ha="left", va="center",
                linespacing=1.35)
        for xx, cfg in ((X_B1, "B1"), (X_P, "P")):
            v = float(str(t1.at[aid, f"{cfg}_success"]).split()[0])
            ax.text(xx, y + h / 2, f"{v:.2f}", fontsize=6.4, ha="center",
                    va="center", weight="bold" if v >= 0.30 else "normal",
                    color=("#2E6B2E" if v < 0.05 else
                           C_ACCENT if v >= 0.30 else "black"))
        y -= gap

    # adaptive row, set apart: same position as P4, different adversary behaviour
    ay = 0.070
    ax.plot([X_POS, 0.800], [ay + h * 0.72, ay + h * 0.72], color=C_MID, lw=0.6)
    ax.text(X_POS + 0.012, ay + h * 0.40,
            "A7 — P4 again, but adaptive: the adversary paces below the rate "
            "rule and mimics the victim's self-reported context",
            fontsize=6.1, ha="left", va="center", style="italic", color=C_ACCENT)
    for xx, cell in ((X_B1, "B1-adaptive"), (X_P, "P-adaptive-slow")):
        v = float(t9.at[cell, "A7_success_num"])
        ax.text(xx, ay + h * 0.40, f"{v:.2f}", fontsize=6.4, ha="center",
                va="center", weight="bold", color=C_ACCENT)

    ax.text(X_POS, 0.022, "Figures are measured attack success rates — the "
                          "fraction of 30 attempts that returned protected data. "
                          "Lower is better for the defence.",
            fontsize=5.9, ha="left", va="center", color=C_RULE)

    # ── right column: assets, trust assumptions, scope ──
    titled_box(ax, X_RIGHT, 0.638, W_RIGHT, 0.262, "Assets under protection",
               "•  account and transaction data\n     of 100 synthetic ADR users\n"
               "•  consent scope integrity\n"
               "•  the account's own device key\n"
               "•  availability of the API",
               fc=C_BOX_RS, title_size=6.3, detail_size=5.7, anchor="top")
    titled_box(ax, X_RIGHT, 0.308, W_RIGHT, 0.310, "Trusted by assumption",
               "•  ECDSA and JWT signatures are\n     unforgeable\n"
               "•  the IdP is not compromised and\n     its signing key stays secret\n"
               "•  controller, policy engine and\n     resource server execute as written\n"
               "•  the internal network is not\n     reachable by the adversary",
               fc=C_LIGHT, title_size=6.3, detail_size=5.7, anchor="top")
    titled_box(ax, X_RIGHT, 0.048, W_RIGHT, 0.240, "Out of scope",
               "•  OS or kernel compromise that\n     exfiltrates the device key\n"
               "•  attacks on the IdP or on the\n     cryptographic primitives\n"
               "•  denial of service",
               fc="white", title_size=6.3, detail_size=5.7, anchor="top")

    save(fig, "fig2_threat_model")


# ─── Figure 3: end-to-end request flow ───────────────────────────────────────

def fig3_request_flow():
    """
    Read from: zt-controller/app/main.py handle_request() — the branch structure
    and the HTTP status each branch returns — plus opa/policies/zt.rego for the
    hard-deny conditions and the threshold comparison.
    """
    fig = plt.figure(figsize=(COL2, 4.30))
    ax = blank_axes(fig)

    MX, MW = 0.028, 0.470          # main column
    RX, RW = 0.566, 0.428          # refusal column

    ax.text(MX, 0.975, "Per-request decision path in configuration P   "
                       "(B1 executes stages 1, 2 and 6 only; B0 stage 6 only)",
            fontsize=7.4, weight="bold", ha="left", va="center")

    specs = [
        (0.80, "request arrives", "Authorization: Bearer <access token>   ·   DPoP: <proof>",
         C_BOX_ADV),
        (1.00, "1   verify access token",
         "JWKS signature  ·  issuer  ·  expiry  ·  cnf.jkt present", C_BOX_PEP),
        (1.25, "2   verify DPoP proof   (RFC 9449)",
         "ES256 JWS over header.payload  ·  RFC 7638 thumbprint = cnf.jkt\n"
         "htm / htu  ·  iat within ±60 s  ·  jti not in replay cache  ·  ath",
         C_BOX_PEP),
        (1.40, "3   collect context   (PIP)",
         "per-subject sliding 60 s window: call rate, geo velocity,\n"
         "session continuity, DPoP-failure rate\n"
         "device registry: has this subject used this cnf.jkt before?", C_BOX_PDP),
        (1.00, "4   score risk",
         "sum the penalties of the rules that fired, capped at 1.0", C_BOX_PDP),
        (1.25, "5   policy decision   (OPA, out of process)",
         "hard deny if a mandatory check failed; otherwise\n"
         "ALLOW if risk < 0.40  ·  CHALLENGE if 0.40 ≤ risk < 0.70  ·  DENY if risk ≥ 0.70",
         C_BOX_PDP),
        (1.00, "6   proxy to the resource server",
         "the controller strips Authorization and DPoP and asserts the\n"
         "verified subject on an internal header", C_BOX_RS),
        (1.00, "object-level ownership check",
         "at the resource server: the object's owner must be the\n"
         "asserted subject", C_BOX_RS),
        (0.85, "200 OK — protected data returned",
         "this, and only this, counts as attack success", "#DCEAD8"),
    ]
    bands = stack(0.930, 0.030, [w for w, *_ in specs], 0.022)
    for (y, h), (_, title, detail, fc) in zip(bands, specs):
        titled_box(ax, MX, y, MW, h, title, detail, fc=fc, detail_size=5.9,
                   title_size=6.7)
    for i in range(len(bands) - 1):
        arrow(ax, (MX + MW / 2, bands[i][0]),
              (MX + MW / 2, bands[i + 1][0] + bands[i + 1][1]))

    def refuse(src_idx, title, detail, dy=0.0):
        y, h = bands[src_idx]
        rh = 0.062
        ry = y + h / 2 - rh / 2 + dy
        titled_box(ax, RX, ry, RW, rh, title, detail, fc=C_BOX_ADV,
                   title_size=6.4, detail_size=5.8)
        arrow(ax, (MX + MW, y + h / 2), (RX, ry + rh / 2))

    refuse(1, "token invalid  →  HTTP 401",
           "no risk scoring; the request is never seen by the PDP")
    refuse(2, "proof invalid  →  HTTP 401",
           "A1 (jti replay) and A2 (thumbprint mismatch) stop here")
    ax.text(RX, bands[2][0] - 0.020, "a failed proof is still recorded in this "
                                     "subject's DPoP-failure\nhistory before the refusal",
            fontsize=5.8, ha="left", va="top", color=C_RULE, linespacing=1.3)

    y5, h5 = bands[5]
    titled_box(ax, RX, y5 + h5 / 2 + 0.006, RW, 0.062,
               "CHALLENGE  →  HTTP 401", "step-up authentication required",
               fc=C_BOX_ADV, title_size=6.4, detail_size=5.8)
    titled_box(ax, RX, y5 + h5 / 2 - 0.074, RW, 0.062,
               "DENY  →  HTTP 403", "refused by policy",
               fc=C_BOX_ADV, title_size=6.4, detail_size=5.8)
    arrow(ax, (MX + MW, y5 + h5 * 0.62), (RX, y5 + h5 / 2 + 0.037))
    arrow(ax, (MX + MW, y5 + h5 * 0.38), (RX, y5 + h5 / 2 - 0.043))

    refuse(7, "not the owner  →  HTTP 403",
           "A5 stops here, identically in all three configurations")

    ax.text(MX, 0.012, "Every request emits one JSONL record carrying the stage "
                       "timings, the check outcomes, the rules that fired, the risk "
                       "score and the decision.",
            fontsize=5.9, ha="left", va="center", color=C_RULE)
    save(fig, "fig3_request_flow")


# ─── Figure 4: the risk mechanism, annotated with measured behaviour ─────────

def fig4_risk_mechanism():
    """
    Left panel read from zt-controller/app/risk.py (rules, penalties,
    thresholds) and config.py (thresholds); the firing rates beside each rule
    come from data/tables/table7_risk_components.csv. Right panel is the
    measured risk distribution, recomputed from data/raw/exp_P.jsonl and
    data/raw/atk_P.jsonl with the same warm-up exclusion the tables use.
    """
    t7 = csv("table7_risk_components.csv").set_index("population")
    legit_stable = t7.loc["legitimate (stable)"]
    legit_drift = t7.loc["legitimate (drift)"]
    a4 = t7.loc["attack A4"]

    fig = plt.figure(figsize=(COL2, 3.05))
    axd = fig.add_axes([0.004, 0.02, 0.560, 0.96])
    axd.set_xlim(0, 1); axd.set_ylim(0, 1); axd.axis("off")

    axd.text(0.0, 0.975, "(a)   rules, penalties and thresholds as implemented",
             fontsize=7.4, weight="bold", ha="left", va="center")
    for x, lab in ((0.660, "legitimate\nstable"), (0.790, "legitimate\ndrift"),
                   (0.910, "attack\nA4")):
        axd.text(x, 0.905, lab, fontsize=5.9, ha="center", va="center",
                 color=C_RULE, linespacing=1.25)
    axd.text(0.0, 0.905, "fraction of requests the rule fires on  →", fontsize=5.9,
             ha="left", va="center", color=C_RULE)

    rules = [
        ("R1", "presented key ≠ the token's cnf.jkt", 0.80, "device binding",
         "cnf_jkt_mismatch"),
        ("R2", "key or fingerprint unseen for this subject", 0.35, "device binding",
         "device_fp_changed"),
        ("R3", "implied geo velocity > 500 km/h", 0.60, "context", "impossible_velocity"),
        ("R5", "session continuity < 0.50", 0.20, "context", "low_session_continuity"),
        ("R6", "DPoP-failure rate > 0.10", 0.20, "context", "dpop_failure_elevated"),
        ("R4", "call rate > 30 req/min", 0.25, "velocity", "high_call_rate"),
    ]
    bands = stack(0.860, 0.345, [1.0] * len(rules), 0.014)
    for (y, h), (rid, desc, pen, group, col) in zip(bands, rules):
        fc = C_BOX_PEP if group == "device binding" else C_BOX_PDP
        box(axd, 0.0, y, 0.600, h, fc=fc)
        axd.text(0.014, y + h / 2, rid, fontsize=6.8, weight="bold", ha="left",
                 va="center")
        axd.text(0.056, y + h * 0.68, desc, fontsize=6.2, ha="left", va="center")
        axd.text(0.056, y + h * 0.27, f"penalty {pen:.2f}   ·   component: {group}",
                 fontsize=5.8, ha="left", va="center", color="#444444")
        for xx, src in ((0.660, legit_stable), (0.790, legit_drift), (0.910, a4)):
            v = float(src.get(col, 0.0))
            colr = C_ACCENT if v >= 0.9 else ("#2E6B2E" if v == 0.0 else "black")
            axd.text(xx, y + h / 2, f"{v:.3f}", fontsize=6.1, ha="center",
                     va="center", color=colr, weight="bold" if v >= 0.9 else "normal")

    axd.text(0.0, 0.285, "risk  =  min(1,  Σ penalties of the rules that fired)"
                         "        belief  b  =  1 − risk",
             fontsize=6.7, ha="left", va="center", weight="bold")
    axd.text(0.0, 0.215, "R1 never fires in B1 or P: a thumbprint mismatch is already "
                         "refused at stage 2.\n"
                         "R6 never crosses its threshold within one reset window.\n"
                         "The rules are deterministic and auditable; nothing is learned.\n"
                         "Bold marks a rule that fires on at least 90% of that population — "
                         "and therefore\ncarries almost no information about it.",
             fontsize=5.9, ha="left", va="top", color=C_RULE, linespacing=1.45)

    # ── (b) measured risk distribution ──
    ax = fig.add_axes([0.652, 0.255, 0.340, 0.660])

    def _risk(pattern, attack: bool):
        df = load_records(pattern)
        if attack:
            df = df[df["attack.is_attack"] == True]
        else:
            df = df[df["request.context_profile"].isin(["stable", "drift"])].copy()
            df["_ts"] = pd.to_datetime(df["ts"], format="ISO8601", utc=True,
                                       errors="coerce")
            df = df[df["_ts"] >= df["_ts"].min() + pd.Timedelta(seconds=5)]
        return _num(df["risk.risk"]).dropna().values

    lr = _risk("exp_P.jsonl", False)
    ar = _risk("atk_P.jsonl", True)

    bins = np.arange(0, 1.05, 0.05)
    ax.axvspan(TAU_ALLOW, TAU_DENY, color=C_MID, alpha=0.45, zorder=0)
    ax.hist(lr, bins=bins, weights=np.ones(len(lr)) / len(lr), color=C_P,
            edgecolor="white", linewidth=0.3, zorder=2,
            label=f"legitimate  (n = {len(lr)})")
    ax.hist(ar, bins=bins, weights=np.ones(len(ar)) / len(ar), color=C_ACCENT,
            alpha=0.66, edgecolor="white", linewidth=0.3, zorder=3,
            label=f"attack A1–A6  (n = {len(ar)})")
    for tau, lab in ((TAU_ALLOW, r"$\tau_{allow}$"), (TAU_DENY, r"$\tau_{deny}$")):
        ax.axvline(tau, color=C_RULE, lw=0.8, ls="--", zorder=4)
        ax.text(tau, 1.005, lab, ha="center", va="bottom", fontsize=6.2,
                transform=ax.get_xaxis_transform())
    ax.text(0.55, 0.42, "CHALLENGE\nband", ha="center", va="center", fontsize=5.9,
            color=C_RULE, transform=ax.get_xaxis_transform(), linespacing=1.25)
    ax.set_xlabel("risk score recorded on the request")
    ax.set_ylabel("fraction of requests")
    ax.set_xlim(-0.02, 1.0)
    ax.set_ylim(0, 1.0)
    ax.legend(loc="upper right", fontsize=6.0)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    fig.text(0.652, 0.972, "(b)   measured risk distribution", fontsize=7.4,
             weight="bold", ha="left", va="center")
    fig.text(0.652, 0.085, "The distribution is bimodal and the challenge band is "
                           "almost never occupied: an\nadditive rule set with six coarse "
                           "penalties does not produce the graded score\nthat step-up "
                           "authentication needs.",
             fontsize=5.9, ha="left", va="center", color=C_RULE, linespacing=1.45)
    save(fig, "fig4_risk_mechanism")


# ─── Figure 5: experimental setup and measurement pipeline ───────────────────

def fig5_experiment_setup():
    """
    Read from: Makefile (targets, run ids, run labels, per-cell flags),
    load/locustfile.py (workload shape, drift probability), attacks/runner.py
    (isolation and warm-up), scripts/sample_resources.sh, analysis/make_figures.py
    and analysis/paper_figures.py (which workload feeds which table or figure).
    """
    fig = plt.figure(figsize=(COL2, 3.45))
    ax = blank_axes(fig)

    XW, WW = 0.004, 0.330          # workloads
    XC, WC = 0.372, 0.298          # configuration cells
    XO, WO = 0.706, 0.290          # outputs

    for x, lab in ((XW, "Workloads"), (XC, "Configuration cells"),
                   (XO, "Records and analysis outputs")):
        ax.text(x, 0.968, lab, fontsize=7.2, weight="bold", ha="left", va="center")

    workloads = [
        ("legitimate load", "Locust, 20 clients, 60 s, think time 0.1–1.0 s;\n"
         "5% of requests drift geography and source network", "exp_*.jsonl"),
        ("load sweep", "5 / 10 / 20 / 40 clients, 30 s per cell", "scale_*.jsonl"),
        ("attack suite", "A1–A6, 30 attempts each; controller state reset and a\n"
         "10-request warm-up before every attack", "atk_*.jsonl"),
        ("adaptive adversary", "A7, 30 attempts, paced at 2.5 s and at 4.0 s",
         "adp_*.jsonl"),
        ("detection ceiling", "A1–A6 with the self-declaring oracle rule enabled",
         "orc_*.jsonl"),
        ("ablation", "A1–A6 and the drifting load, per component removed",
         "abl_*.jsonl"),
    ]
    wts = [1.25 if d.count("\n") else 1.0 for _, d, _ in workloads]
    bands = stack(0.912, 0.170, wts, 0.017)
    for (y, h), (name, detail, prefix) in zip(bands, workloads):
        titled_box(ax, XW, y, WW, h, name, detail, fc=C_BOX_ADV,
                   title_size=6.5, detail_size=5.9)
        ax.text(XW + WW - 0.010, y + h - 0.017, prefix, fontsize=5.7, ha="right",
                va="top", color=C_RULE, family="monospace", zorder=5)

    cells = [
        ("B0", "plain bearer, no policy", C_B0),
        ("B1", "FAPI 2.0 / DPoP", C_B1),
        ("P", "B1 + continuous enforcement", C_P),
        ("P − device-binding", "cnf.jkt check and R1/R2 off", C_MID),
        ("P − context", "telemetry PIP and R3/R5/R6 off", C_MID),
        ("P − velocity", "R4 off", C_MID),
        ("P, τ_allow = 0.30", "recalibrated operating point", C_ACCENT2),
    ]
    cbands = stack(0.912, 0.170, [1.0] * len(cells), 0.017)
    for (y, h), (name, detail, col) in zip(cbands, cells):
        box(ax, XC, y, WC, h, fc="white", ec=C_MID)
        ax.add_patch(Rectangle((XC, y), 0.009, h, facecolor=col,
                               edgecolor="none", zorder=4))
        ax.text(XC + 0.020, y + h * 0.66, name, fontsize=6.4, weight="bold",
                ha="left", va="center", zorder=5)
        ax.text(XC + 0.020, y + h * 0.28, detail, fontsize=5.9, ha="left",
                va="center", zorder=5)

    outs = [
        ("per-request JSONL record",
         "stage timings, check outcomes, rules fired,\nrisk score, decision, attack label"),
        ("resource samples",
         "docker stats at 1 s intervals, controller only"),
        ("attack summaries",
         "attempts, successes, stage at which refused"),
        ("statistics",
         "Wilson intervals, bootstrap CIs, Cliff's δ,\n"
         "risk difference and odds ratio, decisions\nrecomputed over other thresholds"),
        ("artefacts",
         "10 result tables and 12 figures, regenerated\nby one command from the raw records"),
    ]
    owts = [1.15 if d.count("\n") == 1 else (1.55 if d.count("\n") == 2 else 0.95)
            for _, d in outs]
    obands = stack(0.912, 0.170, owts, 0.017)
    for (y, h), (name, detail) in zip(obands, outs):
        titled_box(ax, XO, y, WO, h, name, detail, fc=C_BOX_RS,
                   title_size=6.4, detail_size=5.8)

    for yy in (0.79, 0.53, 0.28):
        arrow(ax, (XW + WW + 0.004, yy), (XC - 0.004, yy))
        arrow(ax, (XC + WC + 0.004, yy), (XO - 0.004, yy))

    ax.text(XW, 0.072, "Every cell is the same controller image with different "
                       "environment flags, so a measured difference is attributable to "
                       "the component rather than to a code difference.\n"
                       "The first 5 s of every workload is excluded as warm-up, and the "
                       "harness warm-up requests that establish a subject's baseline are "
                       "labelled and excluded from\nevery reported rate. Seeds are fixed "
                       "(GLOBAL_SEED = 42, MOCK_ADR_SEED = 42) and all service images are "
                       "pinned by version tag.",
            fontsize=5.9, ha="left", va="center", color=C_RULE, linespacing=1.5)
    save(fig, "fig5_experiment_setup")


# ─── Figure 6: attack outcomes ───────────────────────────────────────────────

def fig6_attack_success():
    t1 = csv("table1_taxonomy.csv")
    t1b = csv("table1b_oracle_ceiling.csv")
    short = ["replay", "token\ntheft", "device-\nresident", "ATO,\nnew device",
             "BOLA/\nBFLA", "volume"]
    fig, axes = plt.subplots(1, 2, figsize=(COL2, 2.45),
                             gridspec_kw={"width_ratios": [1.62, 1.0]})

    ax = axes[0]
    x = np.arange(len(ATTACKS))
    width = 0.27
    for i, cfg in enumerate(CONFIGS):
        rates, lo, hi = [], [], []
        for aid in ATTACKS:
            row = t1[t1["Attack"] == aid].iloc[0]
            p, l, h = _wilson(int(row[f"{cfg}_k"]), int(row[f"{cfg}_n"]))
            rates.append(p); lo.append(max(0.0, p - l)); hi.append(max(0.0, h - p))
        ax.bar(x + (i - 1) * width, rates, width, color=CONFIG_COLOR[cfg],
               edgecolor="white", linewidth=0.4, label=cfg, zorder=3,
               yerr=[lo, hi], capsize=1.8,
               error_kw={"linewidth": 0.6, "ecolor": "#555555", "zorder": 4})
        if cfg == "P":
            for xi, v, hh in zip(x + width, rates, hi):
                ax.text(xi, min(1.0, v + hh) + 0.035, f"{v:.2f}", ha="center",
                        va="bottom", fontsize=5.8, color=C_P, zorder=5)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{a}\n{s_}" for a, s_ in zip(ATTACKS, short)],
                       fontsize=6.0, linespacing=1.3)
    ax.set_ylabel("attack success rate")
    ax.set_ylim(0, 1.34)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.01), ncol=3,
              fontsize=6.4, columnspacing=1.6, handlelength=1.2)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.set_title("(a)   organic detection, 30 attempts per cell, Wilson 95% CI",
                 loc="left", fontsize=7.2, weight="bold")
    ax.annotate("the only attack whose\noutcome P changes",
                xy=(3 + width, 0.367), xytext=(4.05, 0.62), fontsize=5.9,
                color=C_ACCENT, ha="center", va="center", linespacing=1.3,
                arrowprops=dict(arrowstyle="-|>", color=C_ACCENT, lw=0.6,
                                shrinkA=2, shrinkB=2,
                                connectionstyle="arc3,rad=-0.25"))

    ax = axes[1]
    org, orc = [], []
    for aid in ATTACKS:
        r = t1b[t1b["Attack"] == aid].iloc[0]
        org.append(float(str(r["P_organic"]).split()[0]))
        orc.append(float(str(r["P_oracle"]).split()[0]))
    x = np.arange(len(ATTACKS))
    ax.bar(x - 0.19, org, 0.38, color=C_P, edgecolor="white", linewidth=0.4,
           label="P, organic detection", zorder=3)
    ax.bar(x + 0.19, orc, 0.38, color=C_ACCENT2, edgecolor="white",
           linewidth=0.4, label="P, perfect-detector ceiling", zorder=3)
    for xi, v in zip(x - 0.19, org):
        ax.text(xi, v + 0.03, f"{v:.2f}", ha="center", va="bottom", fontsize=5.6,
                color=C_P)
    for xi, v in zip(x + 0.19, orc):
        ax.text(xi, v + 0.03, f"{v:.2f}", ha="center", va="bottom", fontsize=5.6,
                color=C_ACCENT2)
    ax.set_xticks(x)
    ax.set_xticklabels(ATTACKS, fontsize=6.4)
    ax.set_ylim(0, 1.34)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_ylabel("attack success rate")
    ax.legend(loc="upper left", bbox_to_anchor=(0.0, 1.01), ncol=1,
              fontsize=6.2, handlelength=1.2)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.set_title("(b)   detection quality, not enforcement", loc="left",
                 fontsize=7.2, weight="bold")
    fig.tight_layout(pad=0.4)
    save(fig, "fig6_attack_success")


# ─── Figure 7: latency ───────────────────────────────────────────────────────

def fig7_latency():
    t3 = csv("table3_latency.csv").set_index("Config")
    legit = load_records("exp_*.jsonl")
    legit = legit[legit["request.context_profile"].isin(["stable", "drift"])].copy()
    legit["_ts"] = pd.to_datetime(legit["ts"], format="ISO8601", utc=True,
                                  errors="coerce")
    start = legit.groupby("run_id")["_ts"].transform("min")
    legit = legit[legit["_ts"] >= start + pd.Timedelta(seconds=5)]

    fig, axes = plt.subplots(1, 3, figsize=(COL2, 2.15),
                             gridspec_kw={"width_ratios": [1.0, 1.10, 0.92]})

    ax = axes[0]
    for cfg in CONFIGS:
        d = _num(legit.loc[legit["run_label"] == cfg, "latency_ms.total"]).dropna()
        xs = np.sort(d.values)
        ys = np.arange(1, len(xs) + 1) / len(xs)
        ax.plot(xs, ys, color=CONFIG_COLOR[cfg], label=cfg)
    ax.set_xscale("log")
    ax.set_xlabel("total request latency (ms)")
    ax.set_ylabel("cumulative fraction")
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower right")
    ax.grid(alpha=0.35)
    ax.set_title("(a)  latency CDF", loc="left", fontsize=7.0, weight="bold")

    ax = axes[1]
    stats = ["p50_ms", "p95_ms", "p99_ms"]
    x = np.arange(len(stats))
    for i, cfg in enumerate(CONFIGS):
        vals = [float(t3.at[cfg, s]) for s in stats]
        ax.bar(x + (i - 1) * 0.27, vals, 0.27, color=CONFIG_COLOR[cfg],
               edgecolor="white", linewidth=0.4, label=cfg)
        for xi, v in zip(x + (i - 1) * 0.27, vals):
            ax.text(xi, v + 1.0, f"{v:.1f}", ha="center", va="bottom", fontsize=5.6)
    ax.set_xticks(x)
    ax.set_xticklabels(["median", "p95", "p99"])
    ax.set_ylabel("latency (ms)")
    ax.set_ylim(0, 68)
    ax.grid(axis="y", alpha=0.35)
    ax.set_title("(b)  tail behaviour", loc="left", fontsize=7.0, weight="bold")

    ax = axes[2]
    stages = ["token_verify", "dpop_verify", "telemetry", "risk", "policy", "proxy"]
    labels = ["token verify", "DPoP verify", "telemetry +\ndevice registry",
              "risk", "policy (OPA)", "proxy to\nresource server"]
    hatches = ["", "", "", "", "//", ""]
    colors = ["#2E4F6B", "#6E8FB2", "#9DB6CC", "#C9D6E2", C_ACCENT, C_MID]
    bottoms = np.zeros(len(CONFIGS))
    for st, lab, col, ha_ in zip(stages, labels, colors, hatches):
        vals = np.array([float(t3.at[c, f"mean_{st}_ms"]) for c in CONFIGS])
        ax.bar(CONFIGS, vals, 0.55, bottom=bottoms, color=col, label=lab,
               edgecolor="white", linewidth=0.4, hatch=ha_)
        bottoms += vals
    ax.set_ylabel("mean stage latency (ms)")
    ax.set_ylim(0, 22.5)
    ax.legend(loc="center left", bbox_to_anchor=(1.02, 0.5), fontsize=5.9,
              labelspacing=0.45, handlelength=1.1, handleheight=0.9)
    ax.grid(axis="y", alpha=0.35)
    ax.set_title("(c)  where the time goes", loc="left", fontsize=7.0, weight="bold")
    pol = float(t3.at["P", "mean_policy_ms"])
    dpop = float(t3.at["P", "mean_dpop_verify_ms"])
    ax.annotate(f"one HTTP round trip to the\npolicy engine: {pol:.2f} ms\n"
                f"(DPoP verification: {dpop:.2f} ms)",
                xy=(1.76, 5.0), xytext=(-0.26, 22.1), fontsize=5.7,
                color=C_ACCENT, ha="left", va="top", linespacing=1.35,
                arrowprops=dict(arrowstyle="-|>", color=C_ACCENT, lw=0.6,
                                shrinkA=2, shrinkB=2,
                                connectionstyle="arc3,rad=-0.22"))
    fig.tight_layout(pad=0.4)
    save(fig, "fig7_latency")


# ─── Figure 8: scaling ───────────────────────────────────────────────────────

def fig8_scaling():
    t8 = csv("table8_scaling.csv")
    fig, axes = plt.subplots(1, 3, figsize=(COL2, 2.0))

    ax = axes[0]
    for cfg in CONFIGS:
        s = t8[t8["Config"] == cfg].sort_values("users")
        ax.plot(s["users"], s["p50_ms"], "o-", color=CONFIG_COLOR[cfg], label=cfg)
        ax.plot(s["users"], s["p95_ms"], "s--", color=CONFIG_COLOR[cfg],
                alpha=0.55, markersize=2.4)
    ax.set_xlabel("concurrent clients")
    ax.set_ylabel("latency (ms)")
    ax.set_xticks([5, 10, 20, 40])
    ax.grid(alpha=0.35)
    ax.legend(loc="center", bbox_to_anchor=(0.52, 0.56), ncol=3, fontsize=6.2,
              columnspacing=1.4, handlelength=1.6)
    ax.text(0.03, 0.96, "solid: median\ndashed: p95", transform=ax.transAxes,
            fontsize=5.8, va="top", color=C_RULE, linespacing=1.3)
    ax.set_title("(a)  latency vs load", loc="left", fontsize=7.0, weight="bold")

    ax = axes[1]
    b1 = t8[t8["Config"] == "B1"].sort_values("users").set_index("users")
    p = t8[t8["Config"] == "P"].sort_values("users").set_index("users")
    users = sorted(set(b1.index) & set(p.index))
    gap = [float(p.at[u, "p50_ms"]) - float(b1.at[u, "p50_ms"]) for u in users]
    ax.bar([str(u) for u in users], gap, 0.55, color=C_P, edgecolor="white",
           linewidth=0.4)
    for i, g in enumerate(gap):
        ax.text(i, g + 0.2, f"+{g:.1f}", ha="center", va="bottom", fontsize=5.9)
    ax.set_xlabel("concurrent clients")
    ax.set_ylabel("P − B1 median gap (ms)")
    ax.set_ylim(0, max(gap) * 1.32)
    ax.grid(axis="y", alpha=0.35)
    ax.set_title("(b)  the added cost is a fixed tax", loc="left", fontsize=7.0,
                 weight="bold")

    ax = axes[2]
    for cfg in CONFIGS:
        s = t8[t8["Config"] == cfg].sort_values("users")
        ax.plot(s["users"], _num(s["achieved_rps"]), "o-",
                color=CONFIG_COLOR[cfg], label=cfg)
    ax.set_xlabel("concurrent clients")
    ax.set_ylabel("achieved throughput (req/s)")
    ax.set_xticks([5, 10, 20, 40])
    ax.grid(alpha=0.35)
    ax.legend(loc="upper left", fontsize=6.2)
    ax.set_title("(c)  achieved rate, closed loop", loc="left", fontsize=7.0,
                 weight="bold")
    ax.text(0.97, 0.06, "offered load, not capacity:\nno configuration was driven\n"
                        "to saturation",
            transform=ax.transAxes, ha="right", va="bottom", fontsize=5.7,
            color=C_RULE, linespacing=1.3)
    fig.tight_layout(pad=0.4)
    save(fig, "fig8_scaling")


# ─── Figure 9: ablation ──────────────────────────────────────────────────────

def fig9_ablation():
    t5 = csv("table5_ablation.csv").set_index("Cell")
    order = ["B1", "P-minus-context", "P-minus-device-binding",
             "P-minus-velocity", "P"]
    labels = ["B1", "P −\ncontext", "P − device\nbinding", "P −\nvelocity", "P"]
    fig, axes = plt.subplots(1, 3, figsize=(COL2, 2.30),
                             gridspec_kw={"width_ratios": [1.05, 1.05, 1.0]})

    cols = [C_B1 if c == "B1" else (C_P if c == "P" else C_MID) for c in order]

    ax = axes[0]
    a4 = [float(t5.at[c, "A4_num"]) for c in order]
    ax.bar(range(len(order)), a4, 0.62, color=cols, edgecolor="white",
           linewidth=0.4, zorder=3)
    for i, v in enumerate(a4):
        ax.text(i, v + 0.025, f"{v:.3f}", ha="center", va="bottom", fontsize=6.0)
    ax.set_xticks(range(len(order)))
    ax.set_xticklabels(labels, fontsize=6.0, linespacing=1.3)
    ax.set_ylabel("A4 success rate")
    ax.set_ylim(0, 1.30)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.set_title("(a)   security: account takeover", loc="left", fontsize=7.2,
                 weight="bold", pad=14)
    ax.text(0.5, 1.02, "no single component is sufficient: detection is the "
                       "conjunction\nof two sub-threshold penalties crossing a "
                       "threshold",
            transform=ax.transAxes, ha="center", va="bottom", fontsize=5.7,
            color=C_ACCENT, linespacing=1.35)

    ax = axes[1]
    st = [float(t5.at[c, "friction_stable_num"]) for c in order]
    dr = [float(t5.at[c, "friction_drift_num"]) for c in order]
    x = np.arange(len(order))
    ax.bar(x - 0.19, st, 0.38, color=C_B1, edgecolor="white", linewidth=0.4,
           label="stable context", zorder=3)
    ax.bar(x + 0.19, dr, 0.38, color=C_ACCENT, edgecolor="white", linewidth=0.4,
           label="drifting context", zorder=3)
    for xi, v in zip(x + 0.19, dr):
        ax.text(xi, v + 0.025, f"{v:.3f}", ha="center", va="bottom", fontsize=5.8)
    for xi, v in zip(x - 0.19, st):
        if v > 0:
            ax.text(xi, v + 0.025, f"{v:.3f}", ha="center", va="bottom",
                    fontsize=5.5)
    ax.text(0.5, 0.055, "0.000 for B1 and P − context", transform=ax.transAxes,
            ha="center", va="bottom", fontsize=5.6, color=C_RULE)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=6.0, linespacing=1.3)
    ax.set_ylabel("legitimate requests refused")
    ax.set_ylim(0, 1.30)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.legend(loc="upper left", bbox_to_anchor=(-0.02, 1.02), fontsize=6.1)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.set_title("(b)   usability cost", loc="left", fontsize=7.2, weight="bold")

    ax = axes[2]
    base = float(t5.at["B1", "A4_num"])
    marks = {"P": ("o", C_P, (6, 2)), "P-minus-velocity": ("D", C_MID, (6, 2)),
             "P-minus-device-binding": ("^", C_MID, (6, -8)),
             "P-minus-context": ("s", C_MID, (6, 4)), "B1": ("v", C_B1, (6, -9))}
    short = {"P": "P", "P-minus-context": "P − context  (= B1)",
             "P-minus-device-binding": "P − device binding",
             "P-minus-velocity": "P − velocity", "B1": "B1"}
    for cell, (mk, col, off) in marks.items():
        gain = base - float(t5.at[cell, "A4_num"])
        fric = float(t5.at[cell, "friction_drift_num"])
        ax.scatter([fric], [gain], s=28, color=col, marker=mk, zorder=4,
                   edgecolor=C_RULE, linewidth=0.5)
        if cell == "B1":
            continue
        ax.annotate(short[cell], (fric, gain), textcoords="offset points",
                    xytext=off, fontsize=5.8,
                    ha="right" if cell == "P" else "left")
    ax.set_xlabel("legitimate drift requests refused")
    ax.set_ylabel("A4 success reduction vs B1")
    ax.set_xlim(-0.12, 1.28)
    ax.set_ylim(-0.10, 0.82)
    ax.grid(alpha=0.35)
    ax.set_title("(c)   what each cell buys and costs", loc="left", fontsize=7.2,
                 weight="bold")
    ax.text(0.03, 0.96, "the cheap direction is up-and-left;\n"
                        "no cell is there",
            transform=ax.transAxes, ha="left", va="top", fontsize=5.7,
            color=C_RULE, linespacing=1.35)
    fig.tight_layout(pad=0.4)
    save(fig, "fig9_ablation")


# ─── Figure 10: threshold sensitivity ────────────────────────────────────────

def fig10_threshold():
    t6 = csv("table6_threshold_sensitivity.csv")
    t9 = csv("table9_adaptive_adversary.csv")
    fig, axes = plt.subplots(1, 2, figsize=(COL2, 2.40),
                             gridspec_kw={"width_ratios": [1.45, 1.0]})

    ax = axes[0]
    tau = t6["tau_allow"].values
    ax.plot(tau, t6["A4_blocked"], "o-", color=C_P, label="A4 (ATO) refused")
    ax.plot(tau, t6["A3_blocked"], "^-", color=C_ACCENT,
            label="A3 (device-resident) refused")
    ax.plot(tau, _num(t6["legit_stable_friction"]), "s--", color=C_B1,
            label="legitimate, stable context")
    ax.plot(tau, _num(t6["legit_drift_friction"]), "d--", color=C_ACCENT2,
            label="legitimate, drifting context")
    for xv, lab, col in ((0.40, "shipped\n0.40", C_RULE),
                         (0.30, "recalibrated\n0.30", C_ACCENT2)):
        ax.axvline(xv, color=col, lw=0.8, ls=":")
        ax.text(xv + (0.012 if xv == 0.40 else -0.012), 0.55, lab, fontsize=5.9,
                color=col, ha="left" if xv == 0.40 else "right", va="center",
                linespacing=1.2,
                bbox=dict(facecolor="white", edgecolor="none", pad=0.8))
    ax.set_xlabel(r"challenge threshold $\tau_{allow}$")
    ax.set_ylabel("fraction of requests refused")
    ax.set_ylim(-0.05, 1.20)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_xlim(0.02, 1.03)
    ax.legend(loc="upper center", bbox_to_anchor=(0.62, 1.02), ncol=2,
              fontsize=6.0, columnspacing=1.2, handlelength=1.6)
    ax.grid(alpha=0.35)
    ax.set_title("(a)   decisions recomputed over the measured risk scores",
                 loc="left", fontsize=7.1, weight="bold")

    ax = axes[1]
    cells = ["B1-adaptive", "P-adaptive", "P-adaptive-slow",
             "P-adaptive-tau030", "P-adaptive-slow-tau030"]
    labels = ["B1\n2.5 s", "P, τ=0.40\n2.5 s", "P, τ=0.40\n4.0 s",
              "P, τ=0.30\n2.5 s", "P, τ=0.30\n4.0 s"]
    vals, cols = [], []
    for c in cells:
        r = t9[t9["Cell"] == c]
        vals.append(float(r["A7_success_num"].iloc[0]) if len(r) else np.nan)
        cols.append(C_B1 if c.startswith("B1") else
                    (C_ACCENT2 if "tau030" in c else C_ACCENT))
    ax.bar(range(len(cells)), vals, 0.6, color=cols, edgecolor="white",
           linewidth=0.4, zorder=3)
    for i, v in enumerate(vals):
        ax.text(i, v + 0.03, f"{v:.2f}", ha="center", va="bottom", fontsize=6.1)
    ax.set_xticks(range(len(cells)))
    ax.set_xticklabels(labels, fontsize=5.8, linespacing=1.3)
    ax.set_ylabel("A7 success rate")
    ax.set_ylim(0, 1.34)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.set_title("(b)   the adaptive adversary", loc="left", fontsize=7.1,
                 weight="bold")
    ax.text(0.98, 0.44, "the shipped operating point does\n"
                        "not resist an adversary who paces\n"
                        "and mimics; the recalibrated one\n"
                        "does, at no extra friction",
            transform=ax.transAxes, ha="right", va="top", fontsize=5.7,
            color=C_RULE, linespacing=1.4)
    fig.tight_layout(pad=0.4)
    save(fig, "fig10_threshold")


# ─── Figure 11: the per-request view of A4 and A7 ────────────────────────────

def fig11_ato_timeline():
    """
    The figure that explains A4's success rate. Reconstructed per request from
    data/raw/atk_P.jsonl (A4) and data/raw/adp_P-adaptive-slow.jsonl (A7): the
    rules that fired, the resulting risk, and the decision, in request order.
    Nothing here is aggregated, so the transient structure is visible.
    """
    def series(path: str, aid: str):
        recs = _jsonl(RAW / path)
        rs = [r for r in recs if r.get("attack", {}).get("attack_id") == aid]
        rows = []
        for i, r in enumerate(rs, 1):
            comp = r["risk"].get("score_components", {})
            rows.append({
                "i": i,
                "risk": r["risk"]["risk"],
                "decision": r["decision"],
                "R2": "device_fp_changed" in comp,
                "R5": "low_session_continuity" in comp,
                "R4": "high_call_rate" in comp,
                "R3": "impossible_velocity" in comp,
                "continuity": r["context"].get("session_continuity", np.nan),
                "rate": r["context"].get("call_rate", np.nan),
            })
        return pd.DataFrame(rows)

    a4 = series("atk_P.jsonl", "A4")
    a7 = series("adp_P-adaptive-slow.jsonl", "A7")

    fig, axes = plt.subplots(2, 2, figsize=(COL2, 3.0), sharex=False,
                             gridspec_kw={"height_ratios": [1.0, 0.58],
                                          "hspace": 0.32, "wspace": 0.17})

    for col, (df, title, sub) in enumerate([
        (a4, "(a)  A4 — adversary makes no attempt to evade",
         "caught only while a transient rule happens to fire"),
        (a7, "(b)  A7 — same takeover, adversary paces and mimics",
         "the unforgeable signal is left alone, and it is inert"),
    ]):
        ax = axes[0][col]
        ok = df["decision"] == "ALLOW"
        ax.step(df["i"], df["risk"], where="mid", color=C_P, lw=1.0, zorder=3)
        ax.scatter(df.loc[ok, "i"], df.loc[ok, "risk"], s=14, color=C_ACCENT,
                   zorder=4, label="ALLOW — adversary obtains data", marker="o",
                   edgecolor="white", linewidth=0.4)
        ax.scatter(df.loc[~ok, "i"], df.loc[~ok, "risk"], s=14, color="#2E6B2E",
                   zorder=4, label="refused (CHALLENGE / DENY)", marker="s",
                   edgecolor="white", linewidth=0.4)
        ax.axhspan(TAU_ALLOW, TAU_DENY, color=C_MID, alpha=0.40, zorder=0)
        ax.axhline(TAU_ALLOW, color=C_RULE, lw=0.7, ls="--")
        ax.axhline(TAU_DENY, color=C_RULE, lw=0.7, ls="--")
        for tau, lab in ((TAU_ALLOW, r"$\tau_{allow}=0.40$"),
                         (TAU_DENY, r"$\tau_{deny}=0.70$")):
            ax.text(len(df) + 1.2, tau, lab, fontsize=5.9, va="center",
                    ha="left", color=C_RULE,
                    bbox=dict(facecolor="white", edgecolor="none", pad=0.6))
        ax.set_ylim(-0.05, 1.08)
        ax.set_xlim(0.2, len(df) + 8.0)
        ax.set_ylabel("risk score")
        ax.set_title(title, loc="left", fontsize=7.0, weight="bold", pad=13)
        ax.text(0.0, 1.012, sub, transform=ax.transAxes, fontsize=6.0,
                color=C_ACCENT, va="bottom")
        ax.grid(axis="y", alpha=0.30)
        if col == 0:
            ax.legend(loc="lower right", fontsize=5.9)
            n_ok = int(ok.sum())
            ax.annotate(f"{n_ok} of 30 requests succeed — exactly the interval where\n"
                        "the unknown-device rule (0.35) is the only rule firing",
                        xy=(16, 0.35), xytext=(5.0, 0.90), fontsize=5.8,
                        color=C_ACCENT, ha="left", va="top", linespacing=1.35,
                        arrowprops=dict(arrowstyle="-|>", color=C_ACCENT, lw=0.6,
                                        shrinkA=1, shrinkB=2))
        else:
            ax.text(0.97, 0.90, f"{int(ok.sum())} of {len(df)} requests succeed",
                    transform=ax.transAxes, ha="right", va="top", fontsize=6.2,
                    color=C_ACCENT, weight="bold")
            ax.text(0.62, 0.58, "the unknown-device penalty of 0.35 is the only\n"
                                "rule firing, and 0.35 < 0.40",
                    transform=ax.transAxes, ha="center", va="center",
                    fontsize=5.8, color=C_RULE, linespacing=1.35)

        # rule-firing raster
        ax = axes[1][col]
        rules = [("R2", "unknown device key (0.35)"),
                 ("R5", "session continuity < 0.50 (0.20)"),
                 ("R4", "call rate > 30/min (0.25)"),
                 ("R3", "geo velocity > 500 km/h (0.60)")]
        for j, (key, lab) in enumerate(rules):
            yy = len(rules) - 1 - j
            fired = df.loc[df[key], "i"].values
            ax.scatter(fired, np.full(len(fired), yy), marker="s", s=9,
                       color=C_P if key == "R2" else C_ACCENT2)
            ax.axhline(yy, color=C_LIGHT, lw=3.0, zorder=0)
        ax.set_yticks(range(len(rules)))
        if col == 0:
            ax.set_yticklabels([lab for _, lab in rules][::-1], fontsize=5.9)
        else:
            ax.set_yticklabels([])
        ax.set_xlim(0.2, len(df) + 8.0)
        ax.set_ylim(-0.6, len(rules) - 0.4)
        ax.set_xlabel("request index within the attack (30 attempts)")
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)

    fig.text(0.005, -0.015,
             "Both flanking signals in (a) are artefacts of window bookkeeping rather "
             "than properties of the adversary: session continuity stops firing once the "
             "adversary's own traffic has\ndiluted the victim's baseline past 0.50, and "
             "call rate starts firing only once the shared 60 s window has accumulated "
             "more than 30 events. (b) removes both.",
             fontsize=5.9, ha="left", va="top", color=C_RULE, linespacing=1.45)
    save(fig, "fig11_ato_timeline")


# ─── Figure 12: friction anatomy on legitimate traffic ───────────────────────

def fig12_friction_anatomy():
    """
    Why the false-deny rate is roughly twice the drift rate, and why no request
    receives a step-up challenge. Recomputed from data/raw/exp_P.jsonl: the rule
    combination behind every decision, and the refusals split by the label the
    load generator attached to each request.
    """
    recs = _jsonl(RAW / "exp_P.jsonl")
    df = pd.DataFrame([{
        "profile": r["request"]["context_profile"],
        "decision": r["decision"],
        "risk": r["risk"]["risk"],
        "rules": tuple(sorted(k for k in r["risk"].get("score_components", {})
                              if k != "device_known")),
        "rate": r["context"].get("call_rate", np.nan),
        "ts": r["ts"],
    } for r in recs if r["request"]["context_profile"] in ("stable", "drift")])
    df["ts"] = pd.to_datetime(df["ts"], format="ISO8601", utc=True)
    df = df[df["ts"] >= df["ts"].min() + pd.Timedelta(seconds=5)]

    fig, axes = plt.subplots(1, 3, figsize=(COL2, 2.25),
                             gridspec_kw={"width_ratios": [1.0, 1.10, 1.10]})

    # (a) refusals by the label the workload attached
    ax = axes[0]
    refused = df["decision"] != "ALLOW"
    counts = [int((refused & (df["profile"] == p)).sum()) for p in ("drift", "stable")]
    totals = [int((df["profile"] == p).sum()) for p in ("drift", "stable")]
    ax.bar(["drift-\nlabelled", "stable-\nlabelled"], counts, 0.55,
           color=[C_ACCENT, C_B1], edgecolor="white", linewidth=0.4, zorder=3)
    for i, (c, t) in enumerate(zip(counts, totals)):
        ax.text(i, c + 2.0, f"{c} of {t}\n({c / t:.1%})", ha="center",
                va="bottom", fontsize=6.0, linespacing=1.25)
    ax.set_ylabel("legitimate requests refused")
    ax.set_ylim(0, max(counts) * 1.62)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.set_title("(a)   each excursion costs two refusals", loc="left",
                 fontsize=7.1, weight="bold")
    ax.text(0.5, 0.99, f"a per-request geo-velocity rule refuses the return\n"
                       f"leg as readily as the departure, so a "
                       f"{totals[0] / sum(totals):.1%} drift\nrate produces "
                       f"{sum(counts) / sum(totals):.1%} friction overall",
            transform=ax.transAxes, ha="center", va="top", fontsize=5.7,
            color=C_RULE, linespacing=1.4)

    # (b) the rule combination behind every decision
    ax = axes[1]
    name = {(): "no rule fired\n(risk 0.00)",
            ("high_call_rate",): "R4 alone\n(risk 0.25)",
            ("impossible_velocity",): "R3 alone\n(risk 0.60)",
            ("high_call_rate", "impossible_velocity"): "R3 + R4\n(risk 0.85)"}
    combos = df["rules"].value_counts()
    labels, allow, refuse_ = [], [], []
    for combo in combos.index:
        sub = df[df["rules"] == combo]
        labels.append(name.get(tuple(combo), " + ".join(combo)))
        allow.append(int((sub["decision"] == "ALLOW").sum()))
        refuse_.append(int((sub["decision"] != "ALLOW").sum()))
    y = np.arange(len(labels))
    ax.barh(y, allow, 0.5, color=C_MID, edgecolor="white", linewidth=0.4,
            label="ALLOW", zorder=3)
    ax.barh(y, refuse_, 0.5, left=allow, color=C_ACCENT, edgecolor="white",
            linewidth=0.4, label="refused", zorder=3)
    for i, (a, r) in enumerate(zip(allow, refuse_)):
        ax.text(a + r + 40, i, f"{a + r}", va="center", fontsize=6.0)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=6.0, linespacing=1.25)
    ax.set_xlabel("legitimate requests")
    ax.set_xlim(0, max(np.array(allow) + np.array(refuse_)) * 1.20)
    ax.legend(loc="lower right", fontsize=6.1)
    ax.grid(axis="x", alpha=0.35, zorder=0)
    ax.set_title("(b)   which rules produced which decision", loc="left",
                 fontsize=7.1, weight="bold")
    ax.text(0.98, 0.56, "no request scores inside the\n"
                        "[0.40, 0.70) challenge band:\n"
                        "the saturated rate rule carries\n"
                        "every geo-velocity event straight\n"
                        "past it into a denial",
            transform=ax.transAxes, ha="right", va="center", fontsize=5.7,
            color=C_RULE, linespacing=1.4)

    # (c) call-rate saturation
    ax = axes[2]
    rate = _num(df["rate"]).dropna()
    rate = rate[rate > 0]
    bins = np.logspace(np.log10(rate.min()), np.log10(rate.max()), 36)
    ax.hist(rate, bins=bins, color=C_P, edgecolor="white", linewidth=0.3,
            zorder=3)
    ax.axvline(30, color=C_ACCENT, lw=1.0, zorder=4)
    ax.set_xscale("log")
    ax.set_xlabel("per-subject call rate on the request (req/min)")
    ax.set_ylabel("legitimate requests")
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.set_title("(c)   the rate rule is saturated, not tripped", loc="left",
                 fontsize=7.1, weight="bold")
    above = float((rate > 30).mean())
    med = float(np.median(rate))
    ax.annotate("R4 threshold\n30 req/min", xy=(30, ax.get_ylim()[1] * 0.16),
                xytext=(4.5, ax.get_ylim()[1] * 0.30), fontsize=5.9,
                color=C_ACCENT, ha="left", va="center", linespacing=1.25,
                arrowprops=dict(arrowstyle="-|>", color=C_ACCENT, lw=0.6,
                                shrinkA=2, shrinkB=2))
    ax.text(0.04, 0.97, f"{above:.1%} of legitimate requests\n"
                        f"exceed the threshold; the median\n"
                        f"is {med:.0f} req/min, {med / 30:.0f}× the threshold",
            transform=ax.transAxes, ha="left", va="top", fontsize=5.7,
            color=C_RULE, linespacing=1.4)
    fig.tight_layout(pad=0.4)
    save(fig, "fig12_friction_anatomy")


# ─── main ────────────────────────────────────────────────────────────────────

BUILDERS = [
    fig1_architecture, fig2_threat_model, fig3_request_flow, fig4_risk_mechanism,
    fig5_experiment_setup, fig6_attack_success, fig7_latency, fig8_scaling,
    fig9_ablation, fig10_threshold, fig11_ato_timeline, fig12_friction_anatomy,
]


def main():
    apply_style()
    for fn in BUILDERS:
        fn()
    print(f"\n{len(BUILDERS)} figures written to paper/figures/ (PDF + PNG).")


if __name__ == "__main__":
    main()
