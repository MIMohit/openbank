import os
import sys
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HARNESS))


@pytest.fixture(scope="session", autouse=True)
def keys_dir(tmp_path_factory):
    """Hermetic keys: generate a fresh AS + alice/bob set for the test session."""
    d = tmp_path_factory.mktemp("keys")
    os.environ["BH_KEYS_DIR"] = str(d)
    from minter import keys as K
    K.generate(d)
    return d


@pytest.fixture
def cfg_factory(keys_dir):
    from minter import keys as K
    from verifier.core import Config

    def make(**kw):
        return Config(as_pub_jwk=K.load("as_pub", keys_dir), **kw)
    return make


@pytest.fixture
def cfg(cfg_factory):
    return cfg_factory()
