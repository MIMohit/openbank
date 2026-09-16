"""
Per-subject enrolled-device registry — the continuous device-binding signal.

Device identity is taken from the access token's `cnf.jkt` confirmation claim
(the SHA-256 thumbprint of the client's DPoP key), never from a client-supplied
header.  This matters: an adversary controls every `x-device-id` /
`x-device-fp` value they send, so keying device history on those headers makes
the whole device-binding signal evadable by simply inventing a new device id.
`cnf.jkt` is bound into a Keycloak-signed token and verified in stage 1, so it
is not attacker-choosable.

The registry answers one question per request: has this subject been seen using
this key before?  Note what B1 (FAPI 2.0/DPoP) can and cannot do here — B1
checks that the presented proof matches *the token's own* cnf.jkt, which a
fresh, legitimately issued token from an attacker's own device satisfies by
construction (attack A4).  The registry is the signal that separates the two.

Enrollment policy: the first key observed for a subject establishes that
subject's baseline and is enrolled.  Later unknown keys are reported as unknown
and are deliberately NOT auto-enrolled — auto-enrolling would make an
adversary's key "known" after a single request, so only the first request of a
new-device attack would ever score as anomalous.
"""
from __future__ import annotations

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# subject (token `sub`) -> set of enrolled cnf.jkt thumbprints
_subject_keys: dict = defaultdict(set)


def observe(subject: str, jkt: str) -> dict:
    """
    Record and classify the key used by `subject` on this request.

    Returns {"device_known": bool, "enrolled_device_count": int}.
    """
    if not subject or not jkt:
        # Nothing verifiable to bind to (B0 has no cnf.jkt at all).
        return {"device_known": True, "enrolled_device_count": 0}

    known = _subject_keys[subject]
    if not known:
        known.add(jkt)
        return {"device_known": True, "enrolled_device_count": len(known)}

    device_known = jkt in known
    if not device_known:
        logger.info({"event": "unknown_device_key", "subject": subject,
                     "jkt": jkt, "enrolled": len(known)})
    return {"device_known": device_known, "enrolled_device_count": len(known)}


def enroll(subject: str, jkt: str) -> None:
    """Explicitly enroll a key for a subject (used by the harness warm-up)."""
    if subject and jkt:
        _subject_keys[subject].add(jkt)


def reset() -> None:
    """Drop all enrolled-device state (harness control plane only)."""
    _subject_keys.clear()
