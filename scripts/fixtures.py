"""Shared output handling for the test-vector generators.

Each generator builds its files in memory, formats the Noir ones with
`nargo fmt` ($NARGO, else `nargo` on PATH) and then either writes them or,
with --check, fails if any committed file differs.
"""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"


def nargo():
    return os.environ.get("NARGO", "nargo")


def format_noir(sources):
    """Return each Noir source as `nargo fmt` formats it."""
    if not sources:
        return []
    with tempfile.TemporaryDirectory(prefix="fmt-") as scratch:
        package = Path(scratch)
        (package / "src").mkdir()
        (package / "Nargo.toml").write_text(
            '[package]\nname = "fmt_scratch"\ntype = "lib"\nauthors = [""]\n'
        )
        (package / "src/lib.nr").write_text("")
        for i, source in enumerate(sources):
            (package / f"src/file_{i}.nr").write_text(source)
        subprocess.run([nargo(), "fmt"], cwd=package, check=True)
        return [(package / f"src/file_{i}.nr").read_text() for i in range(len(sources))]


class Outputs:
    def __init__(self, description):
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "--check", action="store_true", help="fail if a committed file differs"
        )
        self.check = parser.parse_args().check
        self.files = {}

    def add(self, path, text):
        self.files[Path(path)] = text

    def finish(self):
        noir = [p for p in self.files if p.suffix == ".nr"]
        for path, text in zip(noir, format_noir([self.files[p] for p in noir])):
            self.files[path] = text
        stale = [
            p for p, text in self.files.items() if not p.is_file() or p.read_text() != text
        ]
        if self.check:
            if stale:
                names = ", ".join(str(p.relative_to(ROOT)) for p in stale)
                sys.exit(f"stale generated files: {names}")
            return
        for path in stale:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.files[path])
