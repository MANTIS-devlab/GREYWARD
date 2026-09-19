# Telemetry sources

| Source | Current evidence | Normalized history |
|---|---|---|
| OpenSnitch | bounded redacted activity and health in `control_plane.py` | Approved network projection; 7-day history |
| Security Context | bounded ad-hoc events in `user_bus.py` and related modules | Adapter migration required |
| Update Center/DNF5 | operation and transaction state files/D-Bus | Semantic update phases and failures |
| Recovery/Restic | metadata and operation results | Semantic recovery and backup events |
| Secure DNS | desired/effective state and reconciler results | State changes and degradation |
| NetworkManager/firewalld | typed Rust state adapters | State transitions; no raw nftables |
| USBGuard/ClamAV/PipeWire | bounded typed observations | Safe external-device lifecycle, scan, and sensor events; device identity is local HMAC and low-confidence when stable metadata is absent |
| systemd/boot/kernel | native journal and kernel evidence | Selective adapters; no broad log copy |
| audit/authentication | native evidence where accessible | Raw-only until privacy and access gates pass |
| DNS requests/browsing | not a reliable current history source | Not collected in V1 |

Adapters must report `AVAILABLE`, `STALE`, `UNAVAILABLE`, `PERMISSION_DENIED`,
`MALFORMED`, or `NOT_COLLECTED`. An empty result must not hide collection
failure.

Native sources remain available through their normal facilities. The normalized
record stores only a safe source reference such as a journal cursor, source ID,
unit, boot ID, and timestamp.
