mqtt-deployer — onboarding an artifact and deploying versions
=============================================================

Worked example: bring the iotdata-hostmon binary under deployment control, then
push new versions of it from the master. Two parts:
  A. add a PROFILE so devices know how to seat the artifact (one-time)
  B. PUBLISH versions of it from the master (every release)


Prerequisite (one-time, per artifact)
-------------------------------------
The artifact's systemd service must prefer the writable /opt/system/data copy,
so a read-only root can still be updated. iotdata-gateway/console/machine/deploy
already do this. For a service that runs a fixed path (e.g. a stock
iotdata-hostmon.service that execs /usr/local/bin/iotdata-hostmon), change its
ExecStart to the override-fallback form:

  ExecStart=/bin/sh -c 'BIN=/opt/system/data/iotdata-hostmon; [ -x "$BIN" ] || BIN=/usr/local/bin/iotdata-hostmon; exec "$BIN" --config /etc/default/iotdata-hostmon'

Now the deployer's seated copy at /opt/system/data is what actually runs, and a
rollback (or a missing override) falls back to the baked /usr/local/bin binary.


PART A — add the profile (one-time)
-----------------------------------
1. Pin the artifact's properties:
     target  : /opt/system/data/iotdata-hostmon   (the override path)
     kind    : a binary — executable, "busy" while the service runs
     service : iotdata-hostmon
   A binary is NOT live-replace: stop before the swap, start after, seat it
   executable (mode 0755).

2. Add a [profile:...] block to the deployer config. The profile NAME is the key
   used everywhere (config, meta, topic, deploy command) — keep it stable:

     [profile:iotdata-hostmon]
     file         = /opt/system/data/iotdata-hostmon
     mode         = 0755
     service      = iotdata-hostmon
     verify       = %candidate% --help
     on-fail      = rollback
     retain-bak   = true

   Option reference:
     file         (required)   where the artifact is seated on the device.
     mode         (def 0644)    octal perms for the seated file. 0755 for a binary.
     service      (optional)    systemd unit. Binary: stop -> swap -> start, then a
                                health check (is it active?) gates rollback. Omit
                                for a plain file with no service.
     verify       (optional)    command run against the CANDIDATE (the staged
                                <file>.new) BEFORE the swap; non-zero = reject and
                                the live file is left untouched. %candidate% expands
                                to the .new path. Use a real self-check if one
                                exists (a config: "<binary> --check %candidate%");
                                a binary with no check can use "%candidate% --help"
                                to confirm it at least executes (catches wrong-arch
                                / corrupt). Omit it to rely on the post-swap health
                                check instead.
     live-replace (def false)   true ONLY for configs / the deployer's own files —
                                swap while running, restart to reload. False for
                                binaries.
     on-fail      (def rollback) rollback | retry | leave. rollback restores
                                <file>.bak; retry re-attempts after retry-normal /
                                retry-urgent; leave does nothing.
     retain-bak   (def true)    keep <file>.bak after a successful update as a
                                standing local revert target.

3. The deployer config is ITSELF deployment-managed (the [profile:iotdata-deploy]
   block), so roll the new profile out the normal way — deploy the updated config.
   Edit the master copy, add the block, then publish it (see Part B):

     cd <mqtt-deployer>/master
     ./mqtt-deploy-publish armv6 iotdata-deploy \
         ../../sensor-depth-snow/images/gateway/tools/iotdata-deploy.cfg file normal v5

   Each device pulls the new config, --check-verifies it, seats it, and restarts
   the deployer — which now knows the iotdata-hostmon profile.
   (Single-box bootstrap: you may instead edit /opt/system/data/iotdata-deploy.cfg
   directly and `systemctl restart iotdata-deploy`.)


PART B — deploy a new version of hostmon (every release)
--------------------------------------------------------
4. Build + test on your dev box, then cross-build for the target arch:

     cd <sensor-depth-snow>/toolchain
     make hostmon                 # -> ../../hostmon/hostmon.armhf   (ARMv6, v6KZ)

5. Publish it from the master (blob first, then meta — the script does that):

     cd <mqtt-deployer>/master
     ./mqtt-deploy-publish armv6 iotdata-hostmon ../../hostmon/hostmon.armhf file normal 2026.06.1

     usage: mqtt-deploy-publish <arch> <profile> <file> [method] [normal|urgent] [version]
       arch     armv6            the firmware line (matches the device's arch=)
       profile  iotdata-hostmon  matches the [profile:...] from Part A
       file     the binary to ship
       method   file             (only method supported now)
       type     normal | urgent  urgent uses the shorter retry interval on failure
       version  free text        for humans/observability; the sha is the truth

   Idempotent: re-running with an unchanged binary ships nothing (same sha).
   Env overrides: PREFIX (default iotdata/firmware), HOST (default localhost).

6. Watch the fleet apply it. Each device pulls the blob, verifies csha+sha, stops
   iotdata-hostmon, swaps the binary (0755) keeping <file>.bak, starts it,
   health-checks, and reports its inventory:

     mosquitto_sub -t 'iotdata/machine/+/firmware/status' -v          # whole fleet
     mosquitto_sub -t 'iotdata/machine/<mac>/firmware/status' -C 1    # one device

   A device already at the published sha does nothing. A device offline at publish
   time applies it when it next connects (blob + meta are retained on the master).


Rollback
--------
There is no rollback command — deploy the PREVIOUS binary again. Because the
device keys on sha, an older artifact is just another forward deploy:

     ./mqtt-deploy-publish armv6 iotdata-hostmon /path/to/previous-hostmon.armhf file urgent <oldver>

The local <file>.bak is a best-effort safety net only; the authoritative revert
is re-publishing known-good bytes from the master.
