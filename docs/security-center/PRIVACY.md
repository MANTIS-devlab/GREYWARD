# Privacy contract

## Position

Security Center is local-first. It does not require an account, cloud service,
telemetry pipeline, device registration, remote model, or public-IP lookup to
calculate posture. It performs no background external request of its own.

The Privacy view also discloses network activity performed by other first-party
GREYWARD components and by security backends. Disclosure is not a claim that
those services are endorsed or harmless.

## Data inventory

| Data | Purpose | Default retention | Default display/export |
|---|---|---|---|
| Posture states and timestamps | Current UI and startup context | One bounded latest snapshot | Full states; evidence redacted by sensitivity |
| Backend versions/capabilities | Explain support and reproduce results | Latest snapshot | Full unless device-identifying |
| Network connection identity | Associate trust zone | In memory; redacted snapshot label | Friendly/redacted label |
| Portal grants | Explain application access | Current query; bounded snapshot | App ID and grant category; paths redacted |
| Device attributes | Explain availability/trust | Current query only in V0 | Class/vendor summary; serial/hash hidden |
| Security activity | Live explanation and approved investigation history | 30-minute live buffer; 7-day investigation and 30-day semantic policy | Normalized/redacted event only |
| Undo state | Revert a confirmed action | Memory-only short window | Exact affected setting, no secrets |
| User preferences | Presentation and consent | Until user resets/removes app | Local only |

Security Center must not retain full DNS histories, browsing histories, process
command lines, environment variables, complete journal records, device serials,
device public-IP history, credentials, access tokens, encryption keys, recovery
keys, or contents/classifications of user files in V0.

## External-service registry

The UI presents for each known service:

- owning component;
- purpose;
- endpoint/operator;
- trigger and cadence;
- data necessarily disclosed by the network connection;
- stored response and lifetime;
- fallback behavior;
- whether it affects posture;
- disable path; and
- last known attempt/result when locally observable without new traffic.

The registry is built from a reviewed first-party manifest plus detected backend
configuration. Detection failures are shown; absence of evidence is not “no
external services.”

## GREYWARD public-IP disclosure

The canonical DMS Network Identity plugin is enabled by default. Its bar pill
shows the public and local IP side by side and exposes a `Public IP check`
switch in its popout. The switch is persisted locally. Turning it off prevents
all public-IP provider requests, including after shell or system restart; only
turning the same switch on re-enables them. Local-address discovery continues
because it only consults the local routing table and interfaces.

When public checking is enabled, the repository implementation:

- calls `https://ipapi.co/json/` approximately two seconds after shell startup;
- falls back to `https://ipwho.is/` on failure;
- requests public IP and country code;
- refreshes approximately every 20 minutes and after network changes;
- clears the prior result while a fresh lookup is running and reports
  `Unavailable` if both providers fail instead of presenting stale or local
  data as the public IP; and
- keeps the current public IP and country only in shell memory, with no IP
  history or address cache persisted across restart.

The connection necessarily reveals the device's public source IP, request time,
TLS/transport metadata, and the configured `curl` user agent to each contacted
provider. Security Center must show both providers and identify the persistent
pill switch as the disable route. It must not re-run the lookup merely to
populate the disclosure.

Default-enabled with a persistent user opt-out is a recorded product decision,
not a precedent for other external services. Any change in endpoints, fields,
cadence, persistence, or fallback requires updating the manifest and
`DECISIONS.md`.

The pinned upstream DMS 1.5.3 backend separately contains an unconditional
cleartext `http://ip-api.com/json/` geolocation seed. GREYWARD does not use that
result for Network Identity. The canonical `greyward-dms.service` blocks all
non-local plain-HTTP egress from the DMS process tree through a closed loopback
proxy, while allowing local HTTP and reviewed HTTPS traffic. Consequently the
upstream seed fails locally without disclosing an address to `ip-api.com` or
adding its former network timeout. This mitigation must remain until the pinned
DMS binary is replaced by an upstream version with an explicit opt-in.

## Metadata refreshes

fwupd/LVFS, DNF repositories, Portmaster intelligence, OpenSnitch additions, or
other remote metadata may generate network traffic. V0 collection reads cached
local state only. A refresh is a separate visible action that states the owner,
destination category, expected download, and that results may change. V0 does
not implement package or firmware application.

## Logging

Logs use stable event IDs and safe reason codes. They may contain backend name,
interface version, duration, result class, and redacted object correlation. They
must not contain:

- public/local IP addresses, SSIDs, domain histories, full filesystem paths, or
  device serials by default;
- D-Bus tokens, Polkit details containing secrets, recovery material, or full
  backend payloads;
- raw malformed input that could inject terminal/journal control characters.

Debug logging is an explicit temporary user choice, visibly indicated, bounded,
and still redacts secrets. Support export previews the exact artifact.

## Exports

Exports use the existing fixed local destination and the Security Center shows
the exact path returned by the backend after a successful write. The default
report:

- includes schema, application version, policy profile, timestamps, states,
  reason codes, and safe evidence summaries;
- removes secret evidence and redacts device/user evidence;
- omits full activity records and undo tokens;
- labels stale, unknown, unavailable, and virtual-machine evidence; and
- warns before the user saves a less-redacted advanced report.

No automatic upload or “share with GREYWARD” endpoint exists in V0.

## User controls

Users can clear the cached posture snapshot and reset Security Center
preferences without administrative authority. Clearing Security Center state
does not erase authoritative system logs, portal grants, backend history, or
security configuration. The UI explains this boundary.

## Future features

Normalized GREYWARD telemetry uses three separate retention layers: the live
OpenSnitch working set, bounded 7-day investigation history, and bounded
30-day semantic events. The historical store contains only approved redacted
fields and is defined in [the telemetry storage contract](../telemetry/PRIVACY_STORAGE.md).

- A V1 DMS widget receives summary states only.
- OpenSnitch application-network evidence is bounded, local, redacted, and
  exposed through the separate `greyward.security.network/v1` projection. It
  may include application executable identity and destination domain/IP when
  the daemon reports them, but never process arguments, environment, cwd, raw
  protobuf, or raw nftables.
- Interactive application-network prompts require a separate end-to-end
  security and timeout validation before activation.
- Sensitive Files cannot upload file names, content, embeddings, or labels.
- AI assistance is local-only by default and cannot transmit evidence without a
  separate future product decision and explicit per-use consent.
