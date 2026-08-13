# jupiter-agent

Lightweight, cross-platform endpoint agent for Jupiter. **v1 scope: enrollment
only.** Everything else in the eventual design — inventory collection,
scheduled/on-demand reporting, OS-service installation — is deliberately not
built yet. See "What's NOT here" below before assuming anything works beyond
what's listed.

## What's implemented

- **`jupiter-agent enroll --server <url> --token <token>`** — redeems a
  single-use, dashboard-issued enrollment token (`POST
  /clients/:id/devices/enrollment-tokens` on the server, `SECURITY_ADMIN`
  only), generates an Ed25519 keypair *on the device* (the private key never
  leaves the machine, not even transiently — the server only ever sees the
  public half), and stores the resulting device identity locally. Then
  immediately calls `whoami` to prove the credential actually authenticates a
  real request, not just that enrollment returned a 201.
- **`jupiter-agent whoami`** — re-runs that same signed self-test using the
  already-stored identity. Useful for confirming a device hasn't been revoked
  without waiting for the next scheduled check-in (which doesn't exist yet).
- **`jupiter-agent uninstall`** — deletes the locally stored private key and
  config. Does **not** contact the server or revoke the device record there —
  revoke from the dashboard if a device needs to stop being trusted
  immediately, don't rely on uninstall alone for that.

No X.509/TLS certificates anywhere in this design — nothing here validates a
certificate chain, so one would just be attack surface with no corresponding
check. Ed25519 throughout instead: raw 32-byte keys and 64-byte signatures,
base64 on the wire, matching exactly what `ed25519-dalek` produces natively
and what the server's `src/modules/agents/ca.ts` / `device-auth.middleware.ts`
expect. See the root project's README ("Per-tenant encryption keys" section's
neighbor, "Endpoint agent enrollment") for the full leak-scenario reasoning
behind this design.

## What's NOT here — deliberately, not by oversight

- **Inventory collection.** No OS version, installed software, running
  process, or firewall-status collection yet. This was explicitly scoped as
  phase two, after the enrollment/auth layer was solid — see the project
  brief this was built from.
- **Reporting.** No scheduled check-in loop, no "check in now" trigger. Follows
  from the above — there's nothing to report yet.
- **Remote command execution, file access, process control, malware
  scanning/quarantine.** None of this is planned for this agent at all
  without a separate, explicit design pass — v1's `requireDeviceAuth`
  middleware on the server only guards a `whoami` read, nothing privileged.
- **OS-service installation** (Windows Service / launchd daemon / systemd
  unit). Registering as a background service inherently needs admin/root —
  that's unavoidable on every OS, not a Jupiter design choice — and this
  scaffold deliberately stops short of it pending explicit confirmation
  (flagged, not silently skipped). Today, `enroll`/`whoami`/`uninstall` are
  ordinary user-run CLI commands.
- **Auto-update.** Manual reinstall only. Auto-update is a separate,
  security-critical mechanism (an update channel is itself a privileged
  code-delivery path) that deserves its own careful design, not something
  bolted on early.
- **Code signing.** Unsigned builds will be blocked by Windows Defender
  SmartScreen and macOS Gatekeeper. Known v1 limitation — the fix is a real
  code-signing certificate and process, not a workaround to route around the
  OS's own protection.

## Building

```
cargo build --release
```

**Windows-specific build note, confirmed the hard way while scaffolding
this:** the `x86_64-pc-windows-gnu` target needs an actual MinGW-w64
toolchain (`gcc.exe`, `dlltool.exe`) on `PATH` — `rustup`'s
`stable-x86_64-pc-windows-gnu` toolchain install provides the Rust standard
library for that target but *not* the underlying C toolchain, which several
dependencies' build scripts need (`ring`, transitively via `reqwest`'s
`rustls-tls`; `windows-sys`, transitively via `tokio`/`keyring`). The
`x86_64-pc-windows-msvc` target avoids this but needs Visual Studio Build
Tools (the "C++ build tools" workload) instead. Pick whichever you already
have, or already prefer — this project doesn't require one over the other.

**What was actually verified while building this, and how:** the full CLI
binary (network calls, OS keychain integration) could not be compiled in the
sandboxed environment this was scaffolded in — neither prerequisite above was
present. The Ed25519 signing/verification core (`src/crypto.rs`) *was*
compiled and run in isolation (it has zero dependencies that need a C
compiler), and its own unit tests pass. More importantly, a signature it
produced was independently verified against the real, unmodified server-side
verification code (`src/modules/agents/ca.ts`'s `verifyDeviceSignature`,
copied into a throwaway Node script) and matched — confirming the wire
contract between agent and server is actually correct, not just internally
self-consistent. Compile the full binary yourself before relying on it
further; the crypto core is the part with no room for error, and that part's
confirmed.

## Configuration & storage

- Config (server URL, device ID, client ID): platform config dir /
  `jupiter-agent/config.json` (e.g. `%APPDATA%\jupiter-agent\config.json` on
  Windows, `~/.config/jupiter-agent/config.json` on Linux).
- Private key: Windows Credential Manager / macOS Keychain via the `keyring`
  crate. **Linux is different on purpose**: `keyring`'s Secret Service
  backend assumes a desktop session with `gnome-keyring`/`kwallet` running,
  which a headless server — a very plausible place to run this — doesn't
  have. Linux falls back to a `0600`-permission file in the config directory
  instead. Anyone with read access to that file (root, or whatever account
  runs this agent) can read the key; that's a real, documented v1 limitation,
  not a hidden gap.
