# jupiter-agent

Lightweight, cross-platform endpoint agent for Jupiter. **v1 scope: enrollment
+ read-only inventory check-in.** OS-service installation, remote command
execution, file access, and auto-update are all deliberately not built. See
"What's NOT here" before assuming anything works beyond what's listed.

## What's implemented

- **`jupiter-agent enroll --server <url> --token <token>`** — redeems a
  single-use, dashboard-issued enrollment token, generates an Ed25519 keypair
  *on the device* (the private key never leaves the machine, not even
  transiently — the server only ever sees the public half), stores the
  resulting device identity locally, then immediately calls `whoami` to prove
  the credential actually authenticates a real request.
- **`jupiter-agent whoami`** — re-runs that signed self-test using the
  already-stored identity.
- **`jupiter-agent checkin`** — collects a read-only inventory snapshot (OS
  info, installed software, process names, firewall state, network
  interfaces) and sends it to `POST /internal/agents/checkin`, signed the
  same way every other agent request is. One-shot: collects once, sends once,
  exits. Retries on failure (5s / 30s / 120s backoff) and then gives up —
  **deliberately no offline queue**; a failed snapshot is dropped, not
  persisted, and the next invocation collects a fresh one instead. This is
  also what a scheduler would invoke periodically once one exists (see "What's
  NOT here").
- **`jupiter-agent uninstall`** — deletes the locally stored private key and
  config. Does **not** contact the server or revoke the device record —
  revoke from the dashboard if a device needs to stop being trusted
  immediately.

No X.509/TLS certificates anywhere — nothing here validates a certificate
chain, so a real one would be attack surface with no corresponding check.
Ed25519 throughout instead, matching the server's `src/modules/agents/ca.ts` /
`device-auth.middleware.ts` exactly. See the root README's "Endpoint agent
enrollment" section for the full leak-scenario reasoning.

## What's NOT here — deliberately, not by oversight

- **Remote command execution, file access, process control, malware
  scanning/quarantine.** Not planned for this agent without a separate,
  explicit design pass. `requireDeviceAuth` on the server only guards reads
  (`whoami`, `checkin`) — nothing privileged.
- **A persistent scheduler.** `checkin` collects and sends once per
  invocation. Running it on an interval (every 6–12h, per the original brief)
  is an OS-scheduler (cron / Task Scheduler / a systemd timer) or
  service-installation concern — not built yet, see next point.
- **OS-service installation** (Windows Service / launchd daemon / systemd
  unit). Registering a background service needs admin/root on every
  platform, unavoidably — flagged, not built, pending explicit confirmation.
  Today every command here is an ordinary user-run CLI invocation.
- **Auto-update.** Manual reinstall only — a separate, security-critical
  design of its own (an update channel is itself a privileged code-delivery
  path).
- **Code signing.** Unsigned builds will be blocked/warned by Windows
  Defender SmartScreen and macOS Gatekeeper. For a single-client managed
  fleet (cloud VMs, provisioned via IaC) this is a one-time allow-list step
  at provisioning, not the blocker it would be for public distribution — but
  it's still not solved here, just lower-stakes.

## Privilege model — what needs elevation, and what doesn't

Everything here runs as an ordinary user by design; nothing requests
elevation or prompts for a password. Per platform:

| | Windows | macOS | Linux |
|---|---|---|---|
| Installed software | Unprivileged (`HKLM\...\Uninstall` is world-readable) | Unprivileged (`system_profiler`) | Unprivileged (`dpkg-query`/`rpm`) |
| Process names | Unprivileged | Unprivileged | Unprivileged |
| Network interfaces | Unprivileged | Unprivileged | Unprivileged |
| Firewall state | Unprivileged (`netsh advfirewall`) | Unprivileged (`socketfilterfw --getglobalstate`) | **Needs root** (`ufw status`) |

Linux firewall state is the one field that's genuinely blocked without
either elevation or a one-time grant. Given this fleet is provisioned via
IaC (cloud VMs, not manually), the answer chosen here is a **provisioning-time
privilege grant, not a runtime one**: the agent runs `sudo -n ufw status`
(non-interactive — fails immediately rather than hanging on a password
prompt that will never come) and degrades to `"UNAVAILABLE"` if that's not
set up. Add this to the machine's provisioning script (Terraform
`user_data`, a Packer image, cloud-init, whatever builds the box) once, and
the agent itself never elevates:

```
# /etc/sudoers.d/jupiter-agent — grants exactly one command, nothing else
jupiter-agent ALL=(root) NOPASSWD: /usr/sbin/ufw status
```

Replace `jupiter-agent` with whatever user account actually runs the agent.
This is scoped to one read-only command, not broad sudo access — the same
least-privilege discipline the rest of this project applies to IAM/KMS.

## Building

```
cargo build --release
```

**Windows-specific build note:** the `x86_64-pc-windows-gnu` target needs an
actual MinGW-w64 toolchain (`gcc.exe`, `dlltool.exe`) on `PATH` —
`rustup`'s toolchain install provides the Rust standard library for that
target but not the underlying C toolchain, which `ring` (via `reqwest`'s
`rustls-tls`) needs to build. `x86_64-pc-windows-msvc` avoids this but needs
Visual Studio Build Tools instead. Pick whichever you already have.

**What was actually verified while building this, and how — updated:**

- **The full binary, fully live, no more caveats.** A real MinGW-w64
  toolchain was installed, the entire binary (`reqwest`, `keyring`, every
  dependency) compiled clean, and it was run as **separate OS processes**
  against a real running Jupiter server backed by a real Postgres database:
  `enroll` (redeemed a real single-use token, generated a keypair, persisted
  it, called `whoami` in-process to confirm), then — critically, as a
  **fresh process** — `whoami` again and `checkin`. The fresh-process step
  is what matters: it's the only way to prove the private key actually
  survived to disk/OS storage rather than just living in the enrolling
  process's memory.
- **That fresh-process step caught a real bug.** `keyring = "3"` with no
  feature flags silently resolves to the crate's in-memory **mock**
  backend on every platform — `set_secret`/`get_secret` both return `Ok`,
  so a single-process test (like the old "enroll, which calls whoami
  in-process" check) looks completely correct while persisting nothing.
  The bug only showed up when `whoami` ran as a second process and got "no
  device key found." Fixed by adding `features = ["windows-native",
  "apple-native"]` to the `keyring` dependency in `Cargo.toml`. Re-verified
  after the fix: fresh-process `whoami` succeeded, `cmdkey /list` showed a
  real `LegacyGeneric:target=device-private-key.jupiter-agent` entry in
  Windows Credential Manager, and `checkin` sent a real inventory snapshot
  (14 software entries, 306 processes, 6 interfaces, firewall `ENABLED`)
  that landed in Postgres correctly envelope-encrypted
  (`iv`/`authTag`/`kmsKeyId`/`ciphertext`/`keyVersion`/`encryptedDataKey`
  all present) and readable back through the server's decrypt path.
  `apple-native` is the same class of fix for macOS but is unverified —
  no Mac was available to test the actual Keychain write.
- **Crypto core** (`src/crypto.rs`) — compiled and tested in isolation, and
  a signature it produced was independently checked against the real,
  unmodified server verification code and matched.
- **Inventory collection** (`src/inventory/`) — the Windows collection path
  ran live and produced real data (see above). The macOS and Linux
  collection paths (`system_profiler`, `dpkg-query`/`rpm`,
  `socketfilterfw`, `ufw`) were **not** run live — no machine of either OS
  was available — but they shell out to each OS's own standard tooling the
  same way the Windows path's `netsh` call does, and degrade to
  empty/`UNAVAILABLE` rather than erroring if a tool is missing.

## Configuration & storage

- Config (server URL, device ID, client ID): platform config dir /
  `jupiter-agent/config.json` (e.g. `%APPDATA%\jupiter-agent\config.json` on
  Windows, `~/.config/jupiter-agent/config.json` on Linux).
- Private key: Windows Credential Manager / macOS Keychain via the `keyring`
  crate. **Linux is different on purpose**: `keyring`'s Secret Service
  backend assumes a desktop session with `gnome-keyring`/`kwallet` running,
  which a headless server doesn't have. Linux falls back to a
  `0600`-permission file instead — a real, documented v1 limitation, not a
  hidden gap.
- Inventory: not stored locally at all — collected fresh on every `checkin`
  invocation and sent immediately, nothing written to disk.
