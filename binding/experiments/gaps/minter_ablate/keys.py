"""Key material for the harness (CONTRACT section 2).

`python -m minter.keys` generates, once, into harness/keys/:
  as_priv.jwk, as_pub.jwk              test AS signing key (ES256, P-256)
  client_<name>.jwk                     client DPoP private key
  client_<name>.pub.jwk                 client DPoP public key (convenience)
Existing files are never overwritten unless --force is given.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from .jose import ec_private_to_jwk, public_jwk, thumbprint

CLIENTS = ("alice", "bob")
DEFAULT_KEYS_DIR = Path(os.environ.get("BH_KEYS_DIR", Path(__file__).resolve().parent.parent / "keys"))


def keys_dir() -> Path:
    return Path(os.environ.get("BH_KEYS_DIR", DEFAULT_KEYS_DIR))


def new_ec_jwk() -> dict:
    jwk = ec_private_to_jwk(ec.generate_private_key(ec.SECP256R1()))
    jwk["kid"] = thumbprint(jwk)
    return jwk


def _write(path: Path, obj: dict, private: bool) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")
    if private:
        os.chmod(path, 0o600)


def generate(directory: Path | None = None, force: bool = False, clients=CLIENTS) -> list[Path]:
    d = Path(directory or keys_dir())
    d.mkdir(parents=True, exist_ok=True)
    written = []
    if force or not (d / "as_priv.jwk").exists():
        k = new_ec_jwk()
        k.update({"alg": "ES256", "use": "sig"})
        _write(d / "as_priv.jwk", k, True)
        pub = public_jwk(k)
        pub.update({"alg": "ES256", "use": "sig"})
        _write(d / "as_pub.jwk", pub, False)
        written += [d / "as_priv.jwk", d / "as_pub.jwk"]
    for c in clients:
        p = d / f"client_{c}.jwk"
        if force or not p.exists():
            k = new_ec_jwk()
            _write(p, k, True)
            _write(d / f"client_{c}.pub.jwk", public_jwk(k), False)
            written += [p, d / f"client_{c}.pub.jwk"]
    return written


def load(name: str, directory: Path | None = None) -> dict:
    """load('as_priv'), load('as_pub'), load('client_alice') ..."""
    return json.loads((Path(directory or keys_dir()) / f"{name}.jwk").read_text())


def client_key(client: str, directory: Path | None = None) -> dict:
    return load(f"client_{client}", directory)


def as_private(directory: Path | None = None) -> dict:
    return load("as_priv", directory)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", type=Path, default=None)
    ap.add_argument("--force", action="store_true", help="overwrite existing keys")
    a = ap.parse_args(argv)
    w = generate(a.dir, a.force)
    d = Path(a.dir or keys_dir())
    for f in w:
        print(f"wrote {f}")
    if not w:
        print(f"keys already present in {d} (use --force to regenerate)")
    for c in CLIENTS:
        print(f"{c}: jkt={thumbprint(client_key(c, d))}")
    print(f"as: kid={load('as_pub', d).get('kid')}")


if __name__ == "__main__":
    main()
