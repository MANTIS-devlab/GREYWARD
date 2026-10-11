# Building and validating GREYWARD

Start with `docs/INDEX.md`, `docs/REPOSITORY_MAP.md` and `docs/STATUS.md`.
The public repository contains generic runtime, package and installer sources;
private development VM accounts, host-control scripts and internal logs are
intentionally excluded. Contributors use their own disposable Fedora builder.

Run `pwsh -NoProfile -File tests/static.ps1` and
`pwsh -NoProfile -File tools/validate-repository.ps1`. Run
`python3 -m unittest tests.test_public_export` for the publication boundary.
Security Center commands and native dependencies are in `security-center/README.md`.
Use its Linux Rust checks, Python Context tests and frontend contracts.

Package owners are `packaging/` and `security-center/packaging/`.
The generic component builder is `environment/image/build-components.py`;
individual builders document their verified upstream inputs. Keep component
revisions, dependency requirements and `environment/production/dms-release.json`
consistent. Build artifacts and test evidence are not public source inputs.

Tests cannot establish graphical login, physical device behavior, installed
SELinux enforcement or encrypted recovery. Record those as unverified until
actually exercised. Do not relax security or use a production machine as a
disposable test root.
