# Security Center local rules

The Tauri webview is presentation-only. Security truth, evidence, privacy
state, and bounded controls belong to the Rust domain/backends or the typed
Security Context boundary. Do not add arbitrary shell, filesystem, D-Bus,
`sudo`, or generic command execution from the UI.

Read `docs/security-center/README.md` and `docs/REPOSITORY_MAP.md` before
changing a contract. Update the owning canonical document and tests with any
interface or behavior change.

Typical checks from this directory are:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
node --test tauri/frontend/ux-contract.test.mjs
python3 -m unittest discover -s security-context/tests -p 'test_*.py'
```
