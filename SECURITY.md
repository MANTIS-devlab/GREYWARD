# Security policy

## Supported versions

GREYWARD is pre-release alpha/beta software. No version currently receives a
release-grade security-support commitment. Major functionality is implemented,
but broad bare-metal, adversarial, and independent security validation remain
incomplete.

The current threat boundary is documented in [THREAT_MODEL.md](THREAT_MODEL.md).
GREYWARD does not currently claim resistance to highly capable or state-level
attackers.

## Reporting a vulnerability

Use the repository host's private vulnerability-reporting feature when it is
available. Include:

- affected component, commit, package, or image;
- prerequisites and minimal reproduction steps;
- observed security impact;
- sanitized evidence;
- a suggested mitigation, if known.

If no private feature is available, open a public issue requesting a private
contact channel **without** exploit details, credentials, personal data, or
sensitive logs. Do not publish a proof of concept until the maintainer has
acknowledged the report and a disclosure path has been agreed.

There is currently no guaranteed response or remediation SLA. Reports involving
privilege boundaries, updates, file quarantine, network policy, installation,
recovery, signing, or secret exposure should be identified as
security-sensitive in the first private message.

Ordinary bugs, architecture challenges, and hardening suggestions that do not
require confidential handling should use the public issue forms.
