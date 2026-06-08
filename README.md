# mqtt-deployer

Content-addressed, MQTT-native artifact deployment for fleets of small devices.
A master publishes signed-by-sha artifacts as **retained** MQTT messages; each
device runs a tiny C client that pulls only what it needs, verifies it, and
seats it crash-safely. No HTTP, no agent on the master, no per-device push — the
broker's retained store is the distribution point and devices pull when ready.

It is deliberately generic: nothing here is application-specific. The iotdata
fleet is just one config (`arch=armv6`, `prefix=iotdata/firmware`, a set of
profiles); the same binary serves any fleet.

```
master (CI)                         broker (retained)                 device
  make + test                       <prefix>/<arch>/meta   <--sub--   mqtt-deployer
  mqtt-deploy-publish  --pub-->      <prefix>/<arch>/dist/<name>  <--   (per profile)
                                                                        verify -> seat
  watch fleet  <--sub--             <status-topic> (per device)  <--   report inventory
```

## Topics

| topic | retained | meaning |
|-------|----------|---------|
| `<prefix>/<arch>/meta` | yes | suite manifest: `{ "<profile>": {version,size,sha,csha,csize,method,type} }` |
| `<prefix>/<arch>/dist/<profile>` | yes | the xz-compressed artifact blob |
| `<status-topic>` | yes | the device's installed inventory (reported on start + after every change) |

`<arch>` segments both *what runs here* and the *memory class* (chunk policy,
later). Use `armv6`, `aarch64`, `esp32`, … — never `armhf` (ambiguous: Debian
armhf = ARMv7, Raspbian armhf = ARMv6).

## Client

One binary + one INI config. It connects to the master (directly — so blobs are
never cached on a local broker), subscribes to `meta`, and for each configured
profile whose advertised `sha` differs from the installed file:

1. pull the retained blob, verify `csha`, `xz -d`, verify `sha`
2. write `<file>.new`, run the profile's `verify` against it (**pre-swap gate** —
   a bad artifact never goes live)
3. swap (`<file>` → `<file>.bak`, `<file>.new` → `<file>` — the rename is the
   commit point, so a power loss leaves the old file intact)
4. optionally (re)start the profile's systemd service
5. report the installed inventory upstream (retained)

**Rollback** is "deploy the old bytes again" — content-addressing makes that a
normal forward deploy, with no dependence on local state. The `.bak` is a
best-effort local courtesy, never a contract.

```ini
[deployer]
broker       = 192.168.0.37
port         = 8883
tls          = true
cafile       = /usr/local/share/iotdata/fleet-ca.crt
username     = fleet
password     = ...
arch         = armv6
prefix       = iotdata/firmware
status-topic = iotdata/machine/%mac%/firmware/status   ; %mac% / %host% substituted
retry-normal = 10800        ; seconds; backoff after a failed apply
retry-urgent = 300          ; used when the meta entry's type=urgent
jitter       = 0            ; random pre-apply delay (avoid fleet-wide herd)

[profile:iotdata-deploy]
file         = /opt/system/data/iotdata-deploy.cfg
service      = iotdata-deploy            ; restart after seating (optional)
verify       = /usr/local/bin/iotdata-deploy --check %candidate%
live-replace = true                      ; config/self: swap while running, then restart
on-fail      = rollback                  ; rollback | retry | leave
retain-bak   = true                      ; keep <file>.bak as a standing local revert
```

Run: `mqtt-deployer --config <file>` · validate: `mqtt-deployer --check <file>`.

Runtime deps on the device: `xz` (xz-utils), `sha256sum` (coreutils), and
`libmosquitto` + `libcjson`. (xz is the v1 codec; lighter codecs per-arch later.)

## Master

```sh
# one-time: make the broker keep retained data across restarts
install -m644 master/mosquitto-persistence.conf /etc/mosquitto/conf.d/

# publish an artifact (blob first, then meta — meta is the commit)
master/mqtt-deploy-publish <arch> <profile> <file> [file] [normal|urgent] [version]
```

The publish is idempotent (re-running ships nothing if the sha is unchanged) and
content-addressed, so deploying an older artifact is how you roll the fleet back.

## Status / roadmap

v1 is **sha-only** and **method=file** (whole blob in one retained message — fine
for binaries/configs). Planned, in order: Ed25519 **signature** over the meta
entry (authenticity, key baked read-only); **chunked/byte-range** methods for
large images (memory-constrained + duty-cycled devices pull at their own pace);
mosquitto **ACLs** so only the publisher can write firmware; a richer
`{online,ts}` presence + heartbeat. See the iotdata fleet design notes.
