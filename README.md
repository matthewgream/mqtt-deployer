# mqtt-deployer

Content-addressed, MQTT-native artifact deployment for fleets of small devices.
A master publishes content-addressed, **Ed25519-signed** artifacts as **retained**
MQTT messages; each device runs a tiny C client that pulls only what it needs,
verifies it, and seats it crash-safely. No HTTP, no agent on the master, no
per-device push — the broker's retained store is the distribution point and
devices pull when ready.

It is deliberately generic: nothing here is application-specific. A fleet is just
one config (an `arch`, a `prefix`, a set of profiles); the same binary serves any
fleet. (`client/` has a lift-and-shift sample config + systemd unit.)

```
master (CI/dev box)                  broker (retained)               device
  make + test                        <prefix>/<arch>/meta   <--sub--  mqtt-deployer
  mqtt-deploy-publish  --pub-->       …/meta/<macid>         <--sub--  (merges both)
                                      …/dist/<profile>[/<macid>] <--   verify -> seat
  watch fleet  <--sub--              <status-topic> (per device) <--   report inventory
```

## Topics

| topic | retained | meaning |
|-------|----------|---------|
| `<prefix>/<arch>/meta` | yes | **global** manifest: `{ "<profile>": {version,size,sha,csha,csize,method,type,ts,sig?} }` |
| `<prefix>/<arch>/meta/<macid>` | yes | **per-machine** manifest, same shape — only this device subscribes |
| `<prefix>/<arch>/dist/<profile>` | yes | the xz-compressed blob (global) |
| `<prefix>/<arch>/dist/<profile>/<macid>` | yes | the blob for a per-machine artifact |
| `<status-topic>` | yes | the device's installed inventory (on start + after every change) |

`<arch>` segments both *what runs here* and the *memory class* (chunk policy,
later). Use `armv6`, `aarch64`, `esp32`, … — never `armhf` (ambiguous: Debian
armhf = ARMv7, Raspbian armhf = ARMv6). `<macid>` is the device's MAC (hex, no
colons), derived from `eth0`/`wlan0` or set explicitly with `macid =`.

## Two streams + precedence

Every device merges two retained manifests — the **global** one and its own
**per-machine** one (`…/meta/<macid>`, a topic no other device subscribes to).
Per profile it picks one effective entry:

- a profile flagged **`machine-specific = true`** is taken **only** from the
  per-machine stream; a global entry for it is ignored. This is how per-device
  identity/config (a unique id, per-box settings) deploys without a global push
  ever clobbering it.
- otherwise the entry with the **higher `ts`** wins (ties → per-machine). `ts` is
  a monotonic publish counter (epoch seconds from the single master), so a newer
  global push automatically retires an older per-machine pin — and it doubles as a
  human-readable stamp you can line up against your pushes and the journal.

So: push a per-machine binary to pin one box to a debug build; push a newer global
to supersede it everywhere; mark a profile machine-specific to make it per-device
and immune to global pushes.

## Client

One binary + one INI config. It connects to the master (directly — so blobs are
never cached on a local broker), subscribes to both meta streams, and for each
configured profile whose **effective** entry's `sha` differs from the installed
file:

1. (signatures on) verify the entry's `sig` against its topic+ts — **before fetch**
2. pull the retained blob, verify `csha`, `xz -d`, verify `sha`
3. write `<file>.new`, run the profile's `verify` against it (**pre-swap gate** —
   a bad artifact never goes live)
4. swap (`<file>` → `<file>.bak`, `<file>.new` → `<file>` — the rename is the
   commit point, so a power loss leaves the old file intact)
5. optionally (re)start the profile's systemd service, health-check, roll back on fail
6. report the installed inventory upstream (retained)

**Rollback** is "deploy the old bytes again" — content-addressing makes that a
normal forward deploy, no dependence on local state. The `.bak` is a best-effort
local courtesy. On a *first* deploy with no `.bak`, a failed health-check drops the
override so the service falls back to its baked copy instead of being stuck.

```
mqtt-deployer --config <file>          # run the daemon
mqtt-deployer --check  <file>          # validate the config, list profiles
mqtt-deployer --config <file> --status # one-shot: per-profile table (for diagnostics)
```

`--status` prints `profile · version · installed · advertised · pushed(ts) · src
(global|machine) · sig · state · [service:active]`.

Runtime deps on the device: `xz` (xz-utils), `sha256sum` (coreutils), and
`libmosquitto` + `libcjson` + `libcrypto` (the last already present for TLS).

## Config reference

The `[deployer]` block (broker, `arch`, `prefix`, `status-topic`, `pubkey`,
optional `macid`, retry/jitter) plus one `[profile:<name>]` per artifact. See
`client/mqtt-deployer.cfg` for a fully-annotated sample. Profile options:

| option | default | meaning |
|--------|---------|---------|
| `file` | (required) | where the artifact is seated on the device |
| `mode` | `0644` | octal perms for the seated file (`0755` for a binary/script) |
| `service` | — | systemd unit. Binary: stop → swap → start, then `is-active` gates rollback. Omit for a plain file/script |
| `verify` | — | command run against the **candidate** (`<file>.new`, via `%candidate%`) *before* the swap; non-zero ⇒ reject, live file untouched. e.g. `<binary> --check %candidate%`, `%candidate% --help`, `/bin/sh -n %candidate%` |
| `live-replace` | `false` | `true` for configs / the deployer's own files — swap while running, restart to reload (don't stop the service first) |
| `machine-specific` | `false` | honour only the per-`<macid>` entry; ignore global |
| `on-fail` | `rollback` | `rollback` (restore `.bak`/fall back to baked) · `retry` (after retry-normal/urgent) · `leave` |
| `retain-bak` | `true` | keep `<file>.bak` after success as a standing local revert |

The artifact's **systemd unit should prefer the override**, so a read-only root
still updates and a rollback reverts — pick binary and config independently
(`client/mqtt-deployer.service` shows the pattern):

```
ExecStart=/bin/sh -c 'BIN=/opt/system/data/myapp; [ -x "$$BIN" ] || BIN=/usr/local/bin/myapp; \
  CFG=/opt/system/data/myapp.cfg; [ -f "$$CFG" ] || CFG=/etc/default/myapp; exec "$$BIN" --config "$$CFG"'
```

## Signatures (authenticity)

`sha` gives **integrity** (the bytes are what the meta says). For **authenticity**
add an Ed25519 signature:

- The master holds a private key; each meta entry is signed over the canonical
  `"<meta-topic>\n<profile>\n<sha>\n<size>\n<ts>"`. Binding the **topic** stops a
  per-machine artifact being replayed onto another box (or into global); binding
  **ts** stops precedence tampering; `sha` binds the bytes (the blob's own sha is
  re-checked after download). The base64 signature rides in the entry's `sig`.
- The device carries the matching **public key inline** in its config (`pubkey`).
  **Its presence flips enforcement on**: a device with `pubkey` rejects any entry
  that is unsigned or mis-signed *before it even fetches the blob* (fail-closed); a
  device without it ignores `sig`. A malformed `pubkey` is a hard config error.
- Verification uses `libcrypto`'s one-shot Ed25519 — no extra runtime dep. The
  private key never leaves the master/CI.

```sh
master/mqtt-deploy-keygen      # make the keypair; prints the `pubkey = …` line to paste
```

Once the key exists next to the publish script (`./iotdata-deploy-sign.key`, or
`KEY=`), every publish signs automatically (prints `signed: yes`).

## Master tools

One-time: `install -m644 master/mosquitto-persistence.conf /etc/mosquitto/conf.d/`
so the broker keeps retained data across restarts; then `master/mqtt-deploy-keygen`.

```
mqtt-deploy-publish [--macid <hex>] [--revoke] <arch> <profile> <file> \
                    [method] [normal|urgent] [version]

mqtt-deploy-revoke  <arch> [<macid>] [--profile P | --all-machines | --all]
```

- **publish** writes the blob first (retained), then merges the entry into the
  manifest and republishes it (the commit) — auto-signed, idempotent (unchanged
  sha ships nothing). `--macid` targets a device's per-machine stream; `--revoke`
  (global push only) also clears any per-machine override of that profile.
- **revoke** clears retained state (publishing a zero-length retained message
  deletes it): one machine, one profile everywhere, all per-machine, or `--all`
  (blank slate). This is the re-image lever and the way to retire a pin.
- Env: `PREFIX` (default `iotdata/firmware`), `HOST` (default `localhost`), `PORT`,
  `KEY` (the signing key).

## HOWTO

Assume `arch=armv6`, a profile `myapp` (binary) with `myapp-cfg` (config), and a
device `macid=aabbccddeeff`. From `master/`:

**(a) deploy a new mqtt-deployer binary, globally** — the deployer self-updates
(its own profile is `live-replace`: swap while running, then restart):
```sh
./mqtt-deploy-publish armv6 mqtt-deployer ../mqtt-deployer.armhf file normal 2026.06.1
```

**(b) deploy a new global config:**
```sh
./mqtt-deploy-publish armv6 myapp-cfg myapp.cfg file normal 2026.06.1
# every device pulls it, --check-verifies, live-replaces, restarts the service
```

**(c) deploy a machine-specific config** (just this box; others never see it):
```sh
./mqtt-deploy-publish --macid aabbccddeeff armv6 myapp-cfg ./myapp.this-box.cfg
# lands on …/meta/aabbccddeeff — wins on that box (per-machine precedence), invisible elsewhere
```

**(d) deploy a new global, revoking the machine-specific pins of that profile:**
```sh
./mqtt-deploy-publish --revoke armv6 myapp ../myapp.armhf file urgent 2026.06.2
# global wins by higher ts AND --revoke clears every per-machine myapp override + its blob
```

**(e) revoke all deployments** (blank slate — e.g. after cutting a new image, so
devices fall back to baked):
```sh
./mqtt-deploy-revoke armv6 --all
# or narrower: revoke one box,    ./mqtt-deploy-revoke armv6 aabbccddeeff
#              one profile fleet, ./mqtt-deploy-revoke armv6 --profile myapp
#              all per-machine,   ./mqtt-deploy-revoke armv6 --all-machines
```

**Watch any of it land:**
```sh
mosquitto_sub -t 'myfleet/status/+' -v          # whole fleet inventory
mqtt-deployer --config /etc/default/mqtt-deployer.cfg --status   # on a device
```

**Onboard a new artifact** (one-time): add a `[profile:<name>]` block to the
config, give its service the override-preferring ExecStart above, then roll the
config out the normal way — `mqtt-deploy-publish armv6 <deployer-cfg-profile>
<the-config>` — and every device learns the new profile on the next config apply.

**Rollback**: there is no rollback command — re-publish the previous bytes. Content
addressing makes an older artifact just another forward deploy:
```sh
./mqtt-deploy-publish armv6 myapp /path/to/previous-myapp.armhf file urgent <oldver>
```

## Roadmap

**method=file** (whole blob in one retained message — fine for binaries/configs/
scripts) with content-addressing, two-stream per-machine targeting, ts-precedence,
and Ed25519 signatures. Planned: **chunked/byte-range** methods for large images
(memory-constrained + duty-cycled devices pull at their own pace); mosquitto
**ACLs** so only the publisher can write firmware; richer presence + heartbeat.
