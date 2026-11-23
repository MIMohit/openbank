"""Tear a topology down.

    cd binding/harness && python -m orchestrator.down topologies/x.yaml   (or a topology id)
"""
import subprocess
import sys
from pathlib import Path

from orchestrator.compose import GENERATED, project_name
from orchestrator.topology import load


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    arg = argv[0]
    tid = load(arg)["id"] if Path(arg).suffix in (".yaml", ".yml") else arg
    path = GENERATED / tid / "docker-compose.yml"
    cmd = ["docker", "compose", "-p", project_name(tid)]
    if path.exists():
        cmd += ["-f", str(path)]
    return subprocess.run(cmd + ["down", "-v", "--remove-orphans", "-t", "5"]).returncode


if __name__ == "__main__":
    sys.exit(main())
