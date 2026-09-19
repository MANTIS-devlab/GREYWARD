# GREYWARD Security Context

This directory documents the GREYWARD Security Context services and their
implementation status. It is the bridge between Security Center and typed
user-bus/system-service boundaries; it is not a generic command executor.

## Current authorities

- [ARCHITECTURE.md](ARCHITECTURE.md) — service ownership and boundary.
- [LIVE_PRIVACY_CAPSULE.md](LIVE_PRIVACY_CAPSULE.md) — the bounded DMS live
  privacy activity contract and current signal coverage.
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) — implementation sessions
  and what remains.
- [OPENSNITCH.md](OPENSNITCH.md) — admitted application-network integration.
  This includes the GREYWARD-owned Feodo snapshot and Threat Protection
  projection while OpenSnitch remains the enforcement engine.
- [PORTMASTER.md](PORTMASTER.md) — rejected alternative and rationale.
- [../telemetry/README.md](../telemetry/README.md) — normalized event history,
  retention, privacy, and query contract.
- [../security/SECURE_DNS_IMPLEMENTATION_PLAN.md](../security/SECURE_DNS_IMPLEMENTATION_PLAN.md)
  — Secure DNS service contract.

The implementation lives under `security-center/security-context/`. Python
tests are under `security-center/security-context/tests/`. Use the commands in
`security-center/AGENTS.md` for local checks.

Session reports and older evidence belong to `docs/history/` when they are
retained; they do not override the architecture document or current code.
