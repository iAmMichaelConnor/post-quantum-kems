#!/usr/bin/env python3
"""Run every generator; with --check, write nothing and fail on drift.

- scripts/generate_acvp_tests.py: the ML-KEM ACVP tests and decode vectors,
  from reference/nist-acvp;
- scripts/generate_decapsulation_alias_cases.py: the ML-KEM alias tests, from
  kyber-py;
- scripts/generate_fips202_instance_tests.py: the FIPS 202 instance tests, from
  Python's hashlib;
- scripts/generate_kyber_kats.py: the Kyber known-answer tests, from
  reference/kyber-py;
- scripts/generate_lattice_vectors.py: the ML-KEM and Kyber vectors, from
  kyber-py.

Generated Noir is formatted with $NARGO, else nargo on PATH.
"""

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GENERATORS = [
    ["scripts/generate_acvp_tests.py"],
    ["scripts/generate_decapsulation_alias_cases.py"],
    ["scripts/generate_fips202_instance_tests.py"],
    ["scripts/generate_kyber_kats.py"],
    ["scripts/generate_lattice_vectors.py"],
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="write nothing; fail if a generated file is stale")
    args = parser.parse_args()
    failed = []
    for generator, *options in GENERATORS:
        command = [sys.executable, generator, *options] + (["--check"] if args.check else [])
        print(f"$ {' '.join(command[1:])}", flush=True)
        if subprocess.run(command, cwd=ROOT).returncode != 0:
            failed.append(generator)
    if failed:
        print(f"failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
