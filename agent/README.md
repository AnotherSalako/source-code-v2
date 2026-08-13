# jupiter-agent

Lightweight, cross-platform endpoint agent for Jupiter. **Scope: enrollment,
read-only inventory check-in, and a background schedule for that check-in
(a repeating loop, plus OS-service installation so the loop survives a
reboot).** Remote command execution, file access, and auto-update are all
deliberately not built. See "What's NOT here" before assuming anything works
beyond what's listed.

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
  persisted, and the next scheduled run just collects a fresh one instead.
- **`jupiter-agent run [--interval-hours N]`** (default 12) — runs `checkin`
  on a repeating interval in the foreground until stopped (Ctrl-C, or
  SIGTERM/SIGHUP on Unix — the `ctrlc` crate's "termination" feature, because
  that's what `systemctl stop` actually sends, not SIGINT). Sleeps in
  1-second increments internally so a stop request is honored within about a
  second rather than waiting out whatever's left of the interval. Logs to
  both stderr (if a console is attached) and a rolling `agent.log` file in
  the config directory — this is the process an installed OS service wraps;
  running `run` directly is for testing the schedule without installing
  anything system-level.
- **`jupiter-agent service install [--interval-hours N]`** /
  **`service uninstall`** — registers (or removes) `run`'s loop as a real
  background OS service, so it survives a reboot without anyone staying
  logged in: a genuine Windows Service via the Service Control Manager on
  Windows, a LaunchDaemon via `launchctl` on macOS, a systemd unit via
  `systemctl` on Linux. **Needs Administrator/root** — the one and only
  place this agent asks for elevated privilege, and only at install time;
  the running service itself never elevates further than that. See "Privilege
  model" below for exactly what each platform's install step does and needs.
- **`jupiter-agent uninstall`** — deletes the locally stored private key and
  config. Does **not** contact the server or revoke the device record, and
  does **not** remove an installed OS service either — run `service
  uninstall` first if one's installed, then this.

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
- **Auto-update.** Manual reinstall only — a separate, security-critical
  design of its own (an update channel is itself a privileged code-delivery
  path).
- **Automatic restart-on-crash for the Windows Service.** The systemd unit
  sets `Restart=on-failure` and the macOS plist sets `KeepAlive`; the
  Windows Service registration doesn't configure SC_ACTION failure actions
  (a real, separate `ChangeServiceConfig2` call). Under normal operation
  this doesn't matter — `run`'s loop never exits on its own — but a crash
  won't self-heal on Windows the way it would on the other two platforms.
  Flagged, not silently uneven.
- **A dedicated least-privilege service account.** The Windows Service runs
  as LocalSystem (the same account that already had unprompted access to
  everything this agent's inventory collection reads); the systemd unit has
  no `User=` directive, so it also runs as root. Neither is a privilege
  *increase* over what enrollment already required to install the service
  in the first place, but a scoped-down service account is real follow-up
  work, not something to fake here with a config flag that doesn't actually
  reduce what the process can touch.
- **Code signing.** Unsigned builds will be blocked/warned by Windows
  Defender SmartScreen and macOS Gatekeeper. For a single-client managed
  fleet (cloud VMs, provisioned via IaC) this is a one-time allow-list step
  at provisioning, not the blocker it would be for public distribution — but
  it's still not solved here, just lower-stakes.

## Privilege model — what needs elevation, and what doesn't

Every command except `service install`/`service uninstall` runs as an
ordinary user; nothing else requests elevation or prompts for a password.
Per platform, for inventory collection specifically:

| | Windows | macOS | Linux |
|---|---|---|---|
| Installed software | Unprivileged (`HKLM\...\Uninstall` is world-readable) | Unprivileged (`system_profiler`) | Unprivileged (`dpkg-query`/`rpm`) |
| Process names | Unprivileged | Unprivileged | Unprivileged |
| Network interfaces | Unprivileged | Unprivileged | Unprivileged |
| Firewall state | Unprivileged (`netsh advfirewall`) | Unprivileged (`socketfilterfw --getglobalstate`) | **Needs root** (`ufw status`) |

`service install`/`service uninstall` are the one deliberate exception —
registering (or removing) a background service is inherently an OS-level
privileged operation on every platform, not something to route around:

| | Windows | macOS | Linux |
|---|---|---|---|
| Mechanism | Service Control Manager (`windows-service` crate) | `launchctl load/unload` on a LaunchDaemon plist | `systemctl enable/disable` on a systemd unit |
| Needs | Administrator (elevated prompt) | root (`sudo`) | root (`sudo`) |
| Verified live? | **Yes** — see "Building" below | No machine available | No machine available |

The install step asks for elevation exactly once, at install time — the
resulting service (or its `run` loop, if you invoke that directly instead of
installing) never elevates itself again afterward.

Linux firewall state is the one inventory field that's genuinely blocked without
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
- **The scheduler and Windows Service, live.** `run` was started as a real
  background process, completed a genuine first check-in cycle
  immediately (collected inventory, sent it, got accepted), and wrote a
  real timestamped `agent.log`; the server-side `Device` row's
  `lastCheckInAt` updated to match. `service install`, run **without**
  Administrator privileges on purpose, reached the real Windows Service
  Control Manager API and correctly failed with `Access is denied (os
  error 5)` wrapped in a clear "run this from an elevated prompt" message —
  proof the code path is real and the error handling works, not proof a
  truly-elevated install succeeds end to end (that step still needs
  someone to actually run it from an Administrator prompt). One honest gap
  in what got tested: the loop was stopped with a hard `TerminateProcess`
  during this verification pass, not a real Ctrl-C/SIGTERM — so the
  `ctrlc`-based graceful-shutdown code path compiled and is structurally
  correct but wasn't itself exercised live. The macOS LaunchDaemon and
  Linux systemd paths are entirely unverified — no such machines were
  available — but follow each platform's own documented, years-stable
  format (`launchd.plist(5)`, `systemd.service(5)`) the same way the
  Windows path follows the real `windows-service` crate API (every
  signature used was checked against the crate's actual docs before
  writing this, not assumed from memory).
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
