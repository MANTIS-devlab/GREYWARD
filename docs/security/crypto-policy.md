# GREYWARD cryptographic policy

## Scope

Production applies Fedora's system-wide `DEFAULT` policy plus
`environment/production/crypto-policy/GREYWARD.pmod`:

```text
DEFAULT:GREYWARD
```

This affects applications that honor Fedora crypto-policies. Applications with
bundled cryptography or explicit overrides may not follow it. It is not a FIPS
claim and does not replace isolation, access control, firewalling, or storage
encryption.

## Exact module delta

Fedora DEFAULT is an evolving upstream baseline; the comparison below describes
the settings GREYWARD overrides, not a frozen copy of every Fedora value. The
authoritative build-time comparison must use the Fedora 44
`/usr/share/crypto-policies/policies/DEFAULT.pol` installed in the candidate
image and the generated back-end files.

| Setting | Fedora DEFAULT | GREYWARD override | Rationale | Compatibility impact | Validation |
|---|---|---|---|---|---|
| General hash | SHA-1 may remain for limited non-signature uses | `hash = -SHA1` | Avoid new direct SHA-1 hash use where the policy backend honors this class | Legacy protocols/tools requiring raw SHA-1 may fail | inspect generated back ends; exercise SSH/VPN/package/TLS clients |
| Signatures | SHA-1 signatures are excluded by current DEFAULT, subject to backend exceptions | `sign = -*-SHA1`; `sha1_in_certs = 0`; OpenSSL SHA-1 block enabled | Make the intended no-SHA-1-signature policy explicit across supported generators | Old certificates, peers, and signed artifacts may fail | negative SHA-1 certificate/signature tests per backend |
| TLS cipher mode | DEFAULT permits AES-CBC in supported configurations | `cipher@TLS = -AES-*-CBC` | Require AEAD-style TLS suites and remove CBC-specific attack surface | Older TLS peers without AEAD fail | generated OpenSSL/GnuTLS/NSS suites and legacy-peer negative test |
| TLS/static RSA key exchange | DEFAULT includes RSA key exchange | `key_exchange = -RSA` | Require forward-secret ECDHE/DHE-style TLS negotiation where supported | Static-RSA-only servers fail | TLS negotiation matrix; confirm RSA signatures still work |
| Camellia | DEFAULT may expose Camellia outside TLS | `cipher = -CAMELLIA-*` | Reduce algorithm surface; no project-specific weakness is claimed | Camellia-only peers/data fail | generated backend diff and known-vector/provider availability check |
| Finite-field DH groups | DEFAULT includes FFDHE-2048 and larger | `group = -FFDHE-2048` | Remove the lowest accepted standard FFDHE group | FFDHE-2048-only peers fail | group enumeration and handshake tests |
| Minimum finite-field DH | 2048 bits | `min_dh_size = 3072` | Raise classical finite-field strength; benefit is limited when ECDHE is already used | Older SSH/TLS/IPsec peers may fail or negotiate another group | 2048 negative and 3072 positive tests |
| Minimum RSA | 2048 bits | `min_rsa_size = 2048` | Preserve Fedora compatibility; this line documents rather than strengthens DEFAULT | None beyond DEFAULT | confirm generated value remains 2048 |
| TLS versions | TLS 1.2 and 1.3 | no override | GREYWARD adds no version delta | Same as Fedora DEFAULT | protocol enumeration |

Upstream Fedora describes DEFAULT as its general supported baseline and
recommends layered subpolicies rather than copying the whole policy. GREYWARD
follows that mechanism, but each override still needs independent justification.

## Assessment

- Removing TLS CBC and static RSA has a clear transport-security property but a
  measurable legacy interoperability cost.
- Removing SHA-1 signatures largely reinforces current Fedora behavior; its
  value is consistency across backends, not a novel protection.
- Raising DH to 3072 is defensible only where finite-field DH is actually used.
  It must not be presented as a broad system-security upgrade.
- Removing Camellia primarily reduces supported algorithm surface. The repository
  currently contains no evidence that this delivers a material risk reduction;
  it is an open policy question.
- Repeating `min_rsa_size = 2048` is not hardening beyond Fedora DEFAULT. It
  preserves compatibility and makes the non-adoption of FUTURE's higher minimum
  explicit.

Compatibility breakage is acceptable only when it buys a stated and tested
property. The Camellia removal and redundant RSA setting should be reconsidered
after Fedora 44 generated-policy and real VPN/SSH/TLS compatibility testing.

## Runtime verification

```bash
update-crypto-policies --show
update-crypto-policies --is-applied
grep -R . /etc/crypto-policies/back-ends/
```

Validate at least Fedora package operations, browser/Flatpak HTTPS, Git, SSH,
Secure DNS, supported VPNs, and any product-supported enterprise/local peers.
Store the Fedora package NEVRA and generated-policy diff with the result.

Emergency compatibility rollback:

```bash
sudo update-crypto-policies --set DEFAULT
```

Restart affected applications/services or reboot. Do not use `LEGACY` as a
general workaround.

## Sources

- repository module: `environment/production/crypto-policy/GREYWARD.pmod`
- application path: `environment/production/provision.sh`
- upstream policy project:
  <https://gitlab.com/redhat-crypto/fedora-crypto-policies>
- upstream DEFAULT definition:
  <https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/blob/master/policies/DEFAULT.pol>
