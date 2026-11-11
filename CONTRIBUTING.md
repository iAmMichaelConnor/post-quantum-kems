# Contributing

Thank you for your interest in contributing! This guide covers the
[layout](#layout), [setup](#setup), [tests](#tests), [benchmarks](#benchmarks),
[generated files](#generated-files), [releases](#releases) and how this
repository [differs from the noir-library-starter
template](#differences-from-the-noir-library-starter-template). Keep pull
requests focused, and open an issue first for anything substantial. Breaking
changes must update the README or the documentation. Run every command below
from the repository root.

## Layout

The repository is a Nargo workspace: the libraries are in `noir/<package>/`, the
test-vector generators in `scripts/`, their third-party reference inputs in
`reference/` (see NOTICE) and the correctness and optimisation notes in `docs/`.

## Setup

- Noir: install with [noirup](https://github.com/noir-lang/noirup), e.g.
  `noirup -v 1.0.0`. Either version CI tests works (see the README).
- Python 3 (standard library only), to regenerate test vectors.
- bb, only for benchmarks:
  `curl -L https://bbup.aztec.network | bash && ~/.bb/bbup -v 6.0.0`.

## Tests

```bash
nargo test --force-brillig --inliner-aggressiveness 0 --workspace       # every package, as pull requests run them
nargo test --force-brillig --inliner-aggressiveness 0 --package ml_kem  # one package
nargo test --package kyber --test-threads 4                             # one package constrained, as the nightly slow mode runs it
./scripts/check-core-visibility.sh                                      # lattice_kem_core API visibility
```

`nargo test` proves nothing: it compiles each test and executes it. Run as
written (constrained), each test compiles to an ACIR circuit, which for the KEM
operations takes minutes; with `--force-brillig` the same test compiles to
unconstrained bytecode and executes the same assertions in seconds, and
`--inliner-aggressiveness 0` shortens compiling that bytecode.

Pull requests run every package with both flags, one job per package and
toolchain. The nightly workflow runs the same set on Noir nightly, and every
package constrained on Noir 1.0.0 (the slow mode), so the constrained tests
(which pass their inputs through `std::hint::black_box` so that the compiler
cannot fold them away) execute their ACIR there. Memory grows with
`--test-threads` (nargo's default is one thread per core); CI passes 4, the
vCPUs of a hosted runner. Measured locally with Noir 1.0.0, as CI runs each
mode:

| Package | Tests | Per pull request: unconstrained, 4 threads | Nightly: constrained, 4 threads |
| --- | ---: | --- | --- |
| `fips202` | 118 | 1 s, 0.2 GB | 1 s, 0.2 GB |
| `lattice_kem_core` | 125 | 5 s, 0.5 GB | 2 min, 2.2 GB |
| `ml_kem` | 220 | 51 s, 2.1 GB | unmeasured (over 10 min) |
| `kyber` | 24 | 14 s, 1.3 GB | 2 min 25 s, 3.0 GB |

The constrained run of `ml_kem` has not been run to completion locally, so its
nightly job has a 120-minute timeout; the other nightly jobs have 30 minutes.

On a pull request the longest job is the benchmark workflow: the constrained
export of `ml_kem` and `kyber`, run side by side, took about 8.5 minutes locally
(their `--force-brillig` exports take seconds), so expect a pull request's
checks to finish in about 10 minutes when it touches a circuit, and in a minute
or two otherwise.

## Benchmarks

On pull requests the benchmark workflow runs only when a change can alter a
circuit (library sources, the workspace manifest, the report scripts or the
workflow itself); every push to `main` runs it.

Each KEM package has a `benchmarks.nr` module of `#[export]` functions, one per
operation and parameter set. See the README for the commands; the benchmark
workflow posts the gate and Brillig diffs on pull requests and records history
on the `gh-pages` branch, which must exist before the first workflow run.

## Generated files

The large Noir test modules are generated; do not edit them by hand.
`python3 scripts/generate.py` runs every generator, which rewrites its outputs;
with `--check` it writes nothing and fails if a committed file is stale (CI runs
it). Generated Noir is formatted with `nargo fmt` (`$NARGO`, else `nargo` on
`PATH`).

| Generator | Writes | From |
| --- | --- | --- |
| `generate_acvp_tests.py` | `ml_kem/src/acvp_tests.nr`, `lattice_kem_core/src/acvp_decode_tests.nr` | `reference/nist-acvp` |
| `generate_lattice_vectors.py` | `ml_kem/src/vectors.nr`, `kyber/src/vectors.nr` | kyber-py |
| `generate_kyber_kats.py` | `kyber/src/kyber_kats.nr` | `reference/kyber-py/PQCkemKAT_*.rsp`, kyber-py |
| `generate_decapsulation_alias_cases.py` | `ml_kem/src/alias_tests.nr` | kyber-py |
| `generate_fips202_instance_tests.py` | `fips202/src/instance_tests.nr` | Python `hashlib` |

## Releases

Pull request titles follow [Conventional
Commits](https://www.conventionalcommits.org/en/v1.0.0/), which drive the
changelog and version numbers:

```
<type>[optional scope]: <description>
```

- `feat:` new functionality (appears in the changelog);
- `fix:` bug fixes (appears in the changelog);
- `chore:` everything else (omitted from the changelog unless breaking).

Mark a breaking change with `!` after the type or scope, e.g.
`feat(ml_kem)!: Return the shared key first`. Use the package name as the scope
when a change touches one package.

[Release Please](https://github.com/googleapis/release-please) runs on every
push to `main`. It opens or updates a release pull request with the next version
and the changelog; merging that pull request tags the release. All packages
share one version and one tag. The first release is v0.1.0.

The release workflow uses the default `GITHUB_TOKEN`, and pull requests opened
with it do not trigger CI; to run the checks on release pull requests, replace
it in `release.yml` with a personal access token stored as a repository secret.

### Publishing checklist

Before the first release:

- create an empty `gh-pages` branch, where the benchmark workflow records
  history;
- enable private vulnerability reporting in the repository's security settings,
  for the README's reporting link.

## Differences from the noir-library-starter template

- **Workspace with packages under `noir/`.** The repository publishes several
  libraries (`ml_kem`, `kyber`, `fips202`) and a shared core, so consumers add a
  `directory` to the git dependency.
- **Two Noir versions per pull request.** The template tests every Noir release
  from the minimum supported version, and nightly, on each pull request. This
  repository tests the two ends, 1.0.0-rc.3 (the minimum, which Aztec 6.0.0
  ships) and 1.0.0 (the latest release), per pull request, and Noir nightly in
  the nightly workflow.
- **Tests run per package, with a thread cap, unconstrained on pull requests.**
  One CI job per package and toolchain runs `nargo test --force-brillig
  --inliner-aggressiveness 0 --test-threads 4`; the nightly workflow runs the
  tests constrained, one job per package.
- **No oracle server or differential tests.** The reference values are fixed
  known-answer vectors (NIST ACVP and kyber-py) generated into Noir tests, so
  there is no Node.js setup in CI.
- **Generated test vectors.** The format job also runs `scripts/generate.py
  --check`; Python is used only where a reference implementation is needed.
- **bb is installed by version.** `bbup -nv` cannot resolve Noir 1.0.0 (no entry
  in bbup's version map), so the benchmark workflow names bb 6.0.0 directly and
  measures with Noir 1.0.0 rather than the minimum version.
- **Release Please starts at 0.1.0** (`initial-version`), not at the template's
  0.0.0.
- **Workflows trigger on `main`**, not `master`, and third-party actions are
  pinned by commit.
