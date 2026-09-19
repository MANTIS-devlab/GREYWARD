# Environment rules

`production/` is the single installed-system definition. Keep runtime packages,
session payloads, production repositories, encrypted-root installation inputs,
and installed GREYWARD components there.

`development/`, `greyward.pkr.hcl`, and the `greyward-dev` Kickstart templates
are disposable VM/factory infrastructure. They may add SSH, `stendev`,
passwordless sudo, Hyper-V agents, compilers, and diagnostics, but production
must never depend on them.

Before changing a provisioning path, check `docs/REPOSITORY_MAP.md`, search all
references with `rg`, and run `tests/static.ps1`. Do not turn the Hyper-V
factory into the production image definition.
