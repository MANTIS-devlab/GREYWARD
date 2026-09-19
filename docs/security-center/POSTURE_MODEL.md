# Deterministic posture model

This file is the sole authority for posture semantics and aggregation.

## States

| State | Meaning |
|---|---|
| `PROTECTED` | Current, sufficient evidence confirms the check's declared protection condition. It does not mean the device is universally secure. |
| `REVIEW_NEEDED` | Evidence shows a meaningful improvement or review is recommended, but the condition is not an immediate required failure. |
| `ACTION_REQUIRED` | Evidence confirms that a required protection condition is not met or a security-relevant control failed. |
| `UNKNOWN` | The check should apply, but evidence is missing, stale, contradictory, denied, malformed, or the query failed. |
| `UNAVAILABLE` | The capability cannot be evaluated or controlled because the backend, API, package, or required hardware is absent. |
| `NOT_APPLICABLE` | The check intentionally does not apply to the evaluated system or workload, with a recorded reason. |

`UNKNOWN` is not safe and is not a failure claim. `UNAVAILABLE` describes
capability, not risk. `NOT_APPLICABLE` always requires an explicit applicability
rule; it must never be used to hide an inconvenient result.

## Domains

- `SYSTEM`: SELinux, boot chain, kernel, firmware, updates, and foundational
  platform protections.
- `APPLICATIONS`: sandboxing, Flatpak overrides, portals, and permission grants.
- `NETWORK`: connection trust, firewall state, DNS protection evidence, and VPN
  presence without claiming VPN quality.
- `DATA`: encryption and future sensitive-data capabilities.
- `DEVICES`: hardware security capability and USB trust visibility.
- `PRIVACY`: external services, local retention, and user-visible grants.

Activity and Recovery are cross-domain views. Their checks contribute to the
domain that owns the underlying protection rather than creating hidden seventh
or eighth scoring domains.

## Check policy

Each check definition has a stable ID, domain, applicability rule, requiredness,
protection predicate, state mapping, freshness policy, evidence schema, and
remediation capability. Definitions are versioned with the application.

Requiredness values:

- `REQUIRED`: unresolved or failed evidence prevents a protected domain.
- `RECOMMENDED`: a confirmed weakness may create `REVIEW_NEEDED` but does not by
  itself create `ACTION_REQUIRED` unless its policy explicitly says so.
- `INFORMATIONAL`: visible evidence that does not affect domain aggregation.

Requiredness is product policy, not inferred from whichever backend happens to
be installed.

## Evaluation order

For each check:

1. Evaluate applicability from typed local facts.
2. Confirm that the capability/backend is available.
3. Validate evidence type, provenance, completeness, and observation time.
4. Reject evidence older than the check's `fresh_until` time.
5. Apply the versioned protection predicate.
6. Emit exactly one semantic state and a reason code.

Adapters collect facts; they do not choose user-facing posture. The evaluator is
pure and deterministic. Backend errors become typed evidence failures rather
than ad-hoc UI messages.

## Domain aggregation

Only applicable checks participate. Apply these rules in order:

1. Any applicable required `ACTION_REQUIRED` check makes the domain
   `ACTION_REQUIRED`.
2. Otherwise, any applicable `REVIEW_NEEDED` check makes the domain
   `REVIEW_NEEDED`.
3. Otherwise, any applicable required `UNKNOWN` check makes the domain
   `UNKNOWN`.
4. Otherwise, if at least one applicable check is evaluable and every applicable
   required check is `PROTECTED`, the domain is `PROTECTED`.
5. If every potentially applicable check is `UNAVAILABLE`, the domain is
   `UNAVAILABLE`.
6. If all checks are explicitly `NOT_APPLICABLE`, the domain is
   `NOT_APPLICABLE`.
7. Any combination not resolved above is `UNKNOWN`.

An `UNAVAILABLE` recommended or informational check does not automatically
erase otherwise sufficient required evidence, but it remains visible. A product
policy may mark an absent backend as a required check; that check then maps to
`UNKNOWN` or `ACTION_REQUIRED` only if the policy and evidence justify it.

## Overall presentation

V0 does not calculate a hidden overall score. The dashboard presents the six
domain states independently and highlights the highest-priority actionable
finding. If a compact summary is needed, use the same ordered aggregation over
required domain states and label it “Device posture,” never a score.

For the compact dashboard posture, apply this explicit precedence after domain
aggregation:

1. Any `ACTION_REQUIRED` domain or review finding produces `REVIEW NEEDED`.
2. Required `UNKNOWN`/`UNAVAILABLE` evidence, or an `UNKNOWN` domain, produces
   `UNAVAILABLE` because a required protection cannot be claimed.
3. Otherwise, one or more `SECURE`/`PROTECTED` domains produces `SECURE` or
   `PROTECTED`; an unavailable recommended/informational check is retained as
   a visible limitation and does not downgrade the posture.
4. If no domain has evaluable protection, the compact posture is
   `UNAVAILABLE`.

This keeps a virtual machine with unavailable hardware-only recommendations
honest without presenting the whole device as unevaluable.

## Freshness

Each check owns a duration appropriate to its source. Event-driven adapters may
refresh immediately; firmware, update, and hardware evidence can have longer
windows. On resume, service restart, relevant D-Bus change, or network change,
affected checks are invalidated. Stale evidence is retained only for explanation
and displayed as stale; it evaluates to `UNKNOWN` where current evidence is
required.

Wall-clock changes must not make fresh evidence live indefinitely. Persist both
wall time and monotonic/session metadata where practical, and invalidate cached
results across boot when the check depends on boot state.

## Remediation semantics

Remediation availability is separate from posture. A check can be
`ACTION_REQUIRED` with recommendation-only remediation, or `PROTECTED` with an
optional configuration control. Remediation kinds are defined in
`DATA_MODEL.md`; authorization rules are defined in `PRIVILEGE_MODEL.md`.

After a control:

1. re-read authoritative backend state;
2. emit a new observation rather than editing the old result;
3. show success only if the expected state is verified;
4. retain the previous value solely for the bounded undo window; and
5. map mismatch, timeout, or partial application to `UNKNOWN` with explanation.

## Examples

- SELinux reports enforcing through `libselinux`: `PROTECTED`.
- SELinux is permissive when enforcing is required: `ACTION_REQUIRED`.
- The SELinux query is denied or contradictory: `UNKNOWN`.
- No TPM device exists: the TPM capability check is `UNAVAILABLE`; the product
  must not claim a TPM failure without an applicability policy.
- Root resolves to plain Btrfs with no encrypted parent: encryption check is
  `ACTION_REQUIRED` for the production policy.
- fwupd cannot produce HSI in a virtual machine: HSI check is `UNAVAILABLE` or
  `UNKNOWN` according to the returned capability evidence, never HSI:0 by
  inference.
