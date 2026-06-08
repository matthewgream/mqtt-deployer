/* -----------------------------------------------------------------------------------------------------------------------------------------
 * mqtt-deployer — content-addressed, MQTT-native artifact deployer.
 *
 * A device runs this against a fleet master broker. It subscribes to a retained
 * suite manifest (<prefix>/<arch>/meta), and for each locally-configured profile
 * whose advertised sha differs from the installed file, it pulls the retained
 * blob (<prefix>/<arch>/dist/<profile>), verifies it, and seats it crash-safely:
 *
 *     fetch -> verify csha -> xz -d -> verify sha -> write <file>.new
 *           -> run the profile's `verify` against <file>.new (pre-swap gate)
 *           -> swap (<file> -> <file>.bak, <file>.new -> <file>)
 *           -> (optional) restart the profile's systemd service
 *           -> on failure: restore <file>.bak (best-effort)
 *
 * The swap is the commit point, so a power loss leaves the old file intact and
 * the device just retries. Rollback at the fleet level is "deploy the old bytes
 * again" (content-addressing makes that a normal forward deploy). After every
 * evaluation the device reports its installed inventory (retained) upstream.
 *
 * Integrity is content-addressed (sha). Authenticity is optional: set `pubkey`
 * in the config (the manufacturer's ed25519 public key, inline base64) and every
 * meta entry must carry a valid `sig` over "<arch>\n<profile>\n<sha>\n<size>" or
 * it is rejected before the blob is even fetched. method=file (whole blob in one
 * retained message). Generic — iotdata is just one config.
 * --------------------------------------------------------------------------------------------------------------------------------------- */
#define _GNU_SOURCE
#include <cjson/cJSON.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <mosquitto.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PROFILES   32
#define SHA_HEX        65 /* 64 hex + NUL */
#define PATH_MAX_      512

/* ---- config ------------------------------------------------------------- */

typedef enum { ONFAIL_ROLLBACK, ONFAIL_RETRY, ONFAIL_LEAVE } onfail_t;

typedef struct {
    char     name[64];
    char     file[PATH_MAX_];
    char     service[64];      /* systemd unit; empty = none */
    char     verify[PATH_MAX_]; /* command; %candidate% substituted; empty = none */
    onfail_t on_fail;
    bool     retain_bak;
    bool     live_replace;     /* file swappable while service runs (config, or self) */
    mode_t   mode;             /* permissions for the seated file (default 0644) */
    /* runtime state */
    char   installed_sha[SHA_HEX]; /* sha of the seated file (cache) */
    char   version[64];            /* last applied version from meta */
    char   last_result[16];        /* "ok" | "fail" | "pending" | "none" */
    time_t next_retry;             /* 0 = none */
    bool   pending_restart;        /* live-replace: restart deferred until after report */
} profile_t;

typedef struct {
    char       broker[128];
    int        port;
    bool       tls;
    char       cafile[PATH_MAX_];
    char       username[64];
    char       password[128];
    char       arch[32];
    char       prefix[64];        /* default iotdata/firmware */
    char       status_topic[256]; /* %mac% / %host% substituted */
    char       client_id[96];
    int        retry_normal;
    int        retry_urgent;
    int        jitter;
    bool          sign_enabled;  /* a pubkey was configured => signatures enforced */
    unsigned char sign_pub[32];  /* raw ed25519 public key */
    profile_t  profiles[MAX_PROFILES];
    int        nprofiles;
} config_t;

static config_t      g_cfg;
static struct mosquitto *g_mosq;
static volatile sig_atomic_t g_stop;
static char          g_meta_topic[128];
static cJSON        *g_meta;       /* latest parsed meta (owned) */
static bool          g_meta_dirty; /* set on new meta, cleared after evaluate */
static bool          g_report_due;

static void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "mqtt-deployer: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ---- small helpers ------------------------------------------------------ */

static void rstrip(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}
static char *lstrip(char *s) {
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

/* device MAC (eth0 else wlan0), hex lowercase — same derivation as set-hostname */
static void get_mac(char *buf, size_t bufsz) {
    buf[0]              = '\0';
    const char *ifs[]   = {"eth0", "wlan0", NULL};
    for (int i = 0; ifs[i]; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifs[i]);
        FILE *f = fopen(path, "re");
        if (!f)
            continue;
        char line[32] = "";
        if (fgets(line, sizeof(line), f)) {
            size_t o = 0;
            for (const char *p = line; *p && o + 1 < bufsz; p++)
                if (*p != ':' && *p != '\n' && *p != '\r')
                    buf[o++] = (char)tolower((unsigned char)*p);
            buf[o] = '\0';
        }
        (void)fclose(f);
        if (buf[0])
            return;
    }
    snprintf(buf, bufsz, "%s", "unknown");
}

/* substitute %mac% and %host% in a template into out */
static void subst(const char *tmpl, char *out, size_t outsz) {
    char mac[32], host[128];
    get_mac(mac, sizeof(mac));
    if (gethostname(host, sizeof(host)) != 0)
        snprintf(host, sizeof(host), "device");
    size_t o = 0;
    for (const char *p = tmpl; *p && o + 1 < outsz;) {
        if (strncmp(p, "%mac%", 5) == 0) {
            o += (size_t)snprintf(out + o, outsz - o, "%s", mac);
            p += 5;
        } else if (strncmp(p, "%host%", 6) == 0) {
            o += (size_t)snprintf(out + o, outsz - o, "%s", host);
            p += 6;
        } else {
            out[o++] = *p++;
        }
    }
    out[o < outsz ? o : outsz - 1] = '\0';
}

/* run argv, capture stdout into buf (NUL-terminated). returns exit code or -1 */
static int run_capture(char *const argv[], char *buf, size_t bufsz) {
    int pipefd[2];
    if (buf)
        buf[0] = '\0';
    if (pipe(pipefd) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    size_t n = 0;
    if (buf) {
        ssize_t r;
        while (n + 1 < bufsz && (r = read(pipefd[0], buf + n, bufsz - 1 - n)) > 0)
            n += (size_t)r;
        buf[n] = '\0';
    }
    /* drain */
    char drain[256];
    while (read(pipefd[0], drain, sizeof(drain)) > 0)
        ;
    close(pipefd[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* run argv, no capture, return exit code */
static int run_cmd(char *const argv[]) { return run_capture(argv, NULL, 0); }

/* sha256 hex of a file into out[SHA_HEX]. returns 0 ok, -1 missing/error */
static int sha256_of(const char *path, char out[SHA_HEX]) {
    out[0] = '\0';
    if (access(path, R_OK) != 0)
        return -1;
    char        buf[256];
    char *const argv[] = {"sha256sum", (char *)path, NULL};
    if (run_capture(argv, buf, sizeof(buf)) != 0)
        return -1;
    int i = 0;
    for (; i < 64 && isxdigit((unsigned char)buf[i]); i++)
        out[i] = (char)tolower((unsigned char)buf[i]);
    out[i] = '\0';
    return i == 64 ? 0 : -1;
}

static long file_size(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

/* write len bytes to path atomically-ish (caller renames). returns 0/-1 */
static int write_all(const char *path, const void *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    const char *p = data;
    while (len) {
        ssize_t w = write(fd, p, len);
        if (w <= 0) {
            close(fd);
            return -1;
        }
        p += w;
        len -= (size_t)w;
    }
    int rc = fsync(fd);
    return close(fd) == 0 && rc == 0 ? 0 : -1;
}

/* xz -dc in > out (no shell). returns 0/-1 */
static int xz_decompress(const char *in, const char *out) {
    int ofd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ofd < 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(ofd);
        return -1;
    }
    if (pid == 0) {
        dup2(ofd, STDOUT_FILENO);
        close(ofd);
        char *const argv[] = {"xz", "-dc", (char *)in, NULL};
        execvp(argv[0], argv);
        _exit(127);
    }
    close(ofd);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

/* ---- signatures (ed25519 over the meta entry) --------------------------- */

/* base64-decode in -> out (max outsz). returns decoded length, or -1.
 * EVP_DecodeBlock pads the output to a multiple of 3, so we subtract the
 * input's '=' padding to recover the true length. */
static int b64decode(const char *in, unsigned char *out, int outsz) {
    int inlen = (int)strlen(in);
    if (inlen <= 0 || inlen % 4 != 0)
        return -1;
    if (inlen / 4 * 3 > outsz)
        return -1;
    int n = EVP_DecodeBlock(out, (const unsigned char *)in, inlen);
    if (n < 0)
        return -1;
    if (in[inlen - 1] == '=')
        n--;
    if (in[inlen - 2] == '=')
        n--;
    return n;
}

/* Verify the manufacturer's ed25519 signature over the canonical meta entry
 * "<arch>\n<profile>\n<sha>\n<size>\n". Returns true when signing is NOT
 * enforced (no pubkey configured), or when the signature is present and valid;
 * false (fail-closed) when enforced and the signature is missing/bad. The bytes
 * are bound by <sha>, so a valid signature authorises exactly those bytes — the
 * blob's own sha is checked separately after download. */
static bool sig_ok(const char *profile, const char *sha, long size, const char *sig_b64) {
    if (!g_cfg.sign_enabled)
        return true;
    if (!sig_b64 || !*sig_b64) {
        logmsg("[%s] signature required but none advertised -> reject", profile);
        return false;
    }
    unsigned char sig[80];
    int           siglen = b64decode(sig_b64, sig, (int)sizeof(sig));
    if (siglen != 64) {
        logmsg("[%s] malformed signature -> reject", profile);
        return false;
    }
    char payload[300];
    int  plen = snprintf(payload, sizeof(payload), "%s\n%s\n%s\n%ld\n", g_cfg.arch, profile, sha, size);
    if (plen <= 0 || plen >= (int)sizeof(payload))
        return false;
    EVP_PKEY   *pk  = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, g_cfg.sign_pub, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool        ok  = false;
    if (pk && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pk) == 1)
        ok = EVP_DigestVerify(ctx, sig, (size_t)siglen, (const unsigned char *)payload, (size_t)plen) == 1;
    if (ctx)
        EVP_MD_CTX_free(ctx);
    if (pk)
        EVP_PKEY_free(pk);
    if (!ok)
        logmsg("[%s] SIGNATURE VERIFICATION FAILED -> reject", profile);
    return ok;
}

/* ---- INI config --------------------------------------------------------- */

static onfail_t parse_onfail(const char *v) {
    if (strcmp(v, "retry") == 0)
        return ONFAIL_RETRY;
    if (strcmp(v, "leave") == 0)
        return ONFAIL_LEAVE;
    return ONFAIL_ROLLBACK;
}
static bool parse_bool(const char *v) {
    return strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0;
}

static void config_defaults(config_t *c) {
    memset(c, 0, sizeof(*c));
    c->port = 1883;
    snprintf(c->broker, sizeof(c->broker), "%s", "localhost");
    snprintf(c->prefix, sizeof(c->prefix), "%s", "iotdata/firmware");
    snprintf(c->arch, sizeof(c->arch), "%s", "armv6");
    c->retry_normal = 10800; /* 3h */
    c->retry_urgent = 300;   /* 5m */
    c->jitter       = 0;
}

/* returns 0 ok, -1 parse/validation error (msg to stderr) */
static int config_load(config_t *c, const char *path, bool verbose) {
    config_defaults(c);
    FILE *f = fopen(path, "re");
    if (!f) {
        if (verbose)
            logmsg("cannot open config %s: %s", path, strerror(errno));
        return -1;
    }
    char       line[1024];
    int        in_deployer = 0;
    profile_t *prof        = NULL;
    int        lineno      = 0;
    int        err         = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = lstrip(line);
        rstrip(s);
        if (*s == '\0' || *s == '#' || *s == ';')
            continue;
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) {
                if (verbose)
                    logmsg("%s:%d: bad section", path, lineno);
                err = 1;
                continue;
            }
            *end           = '\0';
            char *sec      = s + 1;
            in_deployer    = 0;
            prof           = NULL;
            if (strcmp(sec, "deployer") == 0) {
                in_deployer = 1;
            } else if (strncmp(sec, "profile:", 8) == 0) {
                if (c->nprofiles >= MAX_PROFILES) {
                    if (verbose)
                        logmsg("too many profiles");
                    err = 1;
                    continue;
                }
                prof = &c->profiles[c->nprofiles++];
                snprintf(prof->name, sizeof(prof->name), "%s", sec + 8);
                prof->on_fail    = ONFAIL_ROLLBACK;
                prof->retain_bak = true;
                prof->mode       = 0644;
                snprintf(prof->last_result, sizeof(prof->last_result), "%s", "none");
            } else {
                if (verbose)
                    logmsg("%s:%d: unknown section [%s]", path, lineno, sec);
                err = 1;
            }
            continue;
        }
        char *eq = strchr(s, '=');
        if (!eq) {
            if (verbose)
                logmsg("%s:%d: expected key=value", path, lineno);
            err = 1;
            continue;
        }
        *eq       = '\0';
        char *key = s;
        rstrip(key);
        char *val = lstrip(eq + 1);
        if (in_deployer) {
            if (strcmp(key, "broker") == 0)
                snprintf(c->broker, sizeof(c->broker), "%s", val);
            else if (strcmp(key, "port") == 0)
                c->port = atoi(val);
            else if (strcmp(key, "tls") == 0)
                c->tls = parse_bool(val);
            else if (strcmp(key, "cafile") == 0)
                snprintf(c->cafile, sizeof(c->cafile), "%s", val);
            else if (strcmp(key, "username") == 0)
                snprintf(c->username, sizeof(c->username), "%s", val);
            else if (strcmp(key, "password") == 0)
                snprintf(c->password, sizeof(c->password), "%s", val);
            else if (strcmp(key, "arch") == 0)
                snprintf(c->arch, sizeof(c->arch), "%s", val);
            else if (strcmp(key, "prefix") == 0)
                snprintf(c->prefix, sizeof(c->prefix), "%s", val);
            else if (strcmp(key, "status-topic") == 0)
                snprintf(c->status_topic, sizeof(c->status_topic), "%s", val);
            else if (strcmp(key, "client-id") == 0)
                snprintf(c->client_id, sizeof(c->client_id), "%s", val);
            else if (strcmp(key, "retry-normal") == 0)
                c->retry_normal = atoi(val);
            else if (strcmp(key, "retry-urgent") == 0)
                c->retry_urgent = atoi(val);
            else if (strcmp(key, "jitter") == 0)
                c->jitter = atoi(val);
            else if (strcmp(key, "pubkey") == 0) {
                /* inline base64 of the manufacturer's 32-byte ed25519 public
                 * key. Its mere presence turns signature enforcement ON. */
                unsigned char raw[48];
                if (b64decode(val, raw, (int)sizeof(raw)) == 32) {
                    memcpy(c->sign_pub, raw, 32);
                    c->sign_enabled = true;
                } else {
                    if (verbose)
                        logmsg("%s:%d: pubkey must be base64 of a 32-byte ed25519 key", path, lineno);
                    err = 1; /* fail-closed: a broken pubkey is a hard error */
                }
            } else if (verbose)
                logmsg("%s:%d: unknown [deployer] key '%s'", path, lineno, key);
        } else if (prof) {
            if (strcmp(key, "file") == 0)
                snprintf(prof->file, sizeof(prof->file), "%s", val);
            else if (strcmp(key, "service") == 0)
                snprintf(prof->service, sizeof(prof->service), "%s", val);
            else if (strcmp(key, "verify") == 0)
                snprintf(prof->verify, sizeof(prof->verify), "%s", val);
            else if (strcmp(key, "on-fail") == 0)
                prof->on_fail = parse_onfail(val);
            else if (strcmp(key, "retain-bak") == 0)
                prof->retain_bak = parse_bool(val);
            else if (strcmp(key, "live-replace") == 0)
                prof->live_replace = parse_bool(val);
            else if (strcmp(key, "mode") == 0)
                prof->mode = (mode_t)strtol(val, NULL, 8);
            else if (verbose)
                logmsg("%s:%d: unknown [profile] key '%s'", path, lineno, key);
        } else {
            if (verbose)
                logmsg("%s:%d: key=value outside a section", path, lineno);
            err = 1;
        }
    }
    (void)fclose(f);
    /* validate */
    for (int i = 0; i < c->nprofiles; i++) {
        if (c->profiles[i].file[0] == '\0') {
            if (verbose)
                logmsg("profile '%s' has no file", c->profiles[i].name);
            err = 1;
        }
    }
    if (c->arch[0] == '\0' || c->prefix[0] == '\0') {
        if (verbose)
            logmsg("arch and prefix are required");
        err = 1;
    }
    return err ? -1 : 0;
}

/* ---- seating ------------------------------------------------------------ */

/* split a command string into argv (whitespace), substituting %candidate% */
static int build_argv(const char *cmd, const char *candidate, char *store, size_t storesz,
                      char *argv[], int maxargv) {
    char tmp[1024];
    size_t o = 0;
    for (const char *p = cmd; *p && o + 1 < sizeof(tmp);) {
        if (strncmp(p, "%candidate%", 11) == 0) {
            o += (size_t)snprintf(tmp + o, sizeof(tmp) - o, "%s", candidate);
            p += 11;
        } else {
            tmp[o++] = *p++;
        }
    }
    tmp[o] = '\0';
    /* tokenize into store */
    int   argc = 0;
    char *w    = store;
    snprintf(store, storesz, "%s", tmp);
    char *tok = strtok(w, " \t");
    while (tok && argc < maxargv - 1) {
        argv[argc++] = tok;
        tok          = strtok(NULL, " \t");
    }
    argv[argc] = NULL;
    return argc;
}

static int svc(const char *action, const char *unit) {
    char *const argv[] = {"systemctl", (char *)action, (char *)unit, NULL};
    return run_cmd(argv);
}
static bool svc_active(const char *unit) {
    char *const argv[] = {"systemctl", "is-active", (char *)unit, NULL};
    char        out[32];
    run_capture(argv, out, sizeof(out));
    return strncmp(out, "active", 6) == 0;
}

/* seat a decompressed candidate at prof->file. returns 0 ok / -1 fail. */
static int seat(profile_t *prof, const char *candidate) {
    char bak[PATH_MAX_ + 8], newpath[PATH_MAX_ + 8];
    snprintf(bak, sizeof(bak), "%s.bak", prof->file);
    snprintf(newpath, sizeof(newpath), "%s.new", prof->file);

    /* move candidate into place as <file>.new (same dir = same fs for rename) */
    if (rename(candidate, newpath) != 0) {
        logmsg("[%s] cannot stage %s: %s", prof->name, newpath, strerror(errno));
        return -1;
    }
    (void)chmod(newpath, prof->mode); /* e.g. 0755 for a binary, before verify/swap */

    /* pre-swap verify gate (static) — a bad artifact never goes live */
    if (prof->verify[0]) {
        char store[1100], *argv[64];
        build_argv(prof->verify, newpath, store, sizeof(store), argv, 64);
        if (run_cmd(argv) != 0) {
            logmsg("[%s] verify FAILED on candidate -> reject (live file untouched)", prof->name);
            (void)unlink(newpath);
            return -1;
        }
        logmsg("[%s] verify ok", prof->name);
    }

    /* Executables must be stopped before replace (busy file); configs/self use
     * live-replace = swap-while-running then restart-to-reload (and we can't
     * stop our own service mid-seat anyway). */
    bool use_stop   = prof->service[0] && !prof->live_replace;
    bool was_active = prof->service[0] && svc_active(prof->service);
    if (use_stop && was_active)
        (void)svc("stop", prof->service);

    /* commit: old -> .bak, .new -> live (rename is atomic) */
    if (access(prof->file, F_OK) == 0)
        (void)rename(prof->file, bak);
    if (rename(newpath, prof->file) != 0) {
        logmsg("[%s] swap FAILED: %s", prof->name, strerror(errno));
        if (access(bak, F_OK) == 0)
            (void)rename(bak, prof->file); /* put it back */
        if (use_stop && was_active)
            (void)svc("start", prof->service);
        return -1;
    }
    logmsg("[%s] seated %s", prof->name, prof->file);

    if (prof->service[0]) {
        if (prof->live_replace) {
            /* defer the restart to after the inventory report (works for self) */
            prof->pending_restart = true;
        } else {
            (void)svc("start", prof->service);
            struct timespec ts = {1, 0};
            (void)nanosleep(&ts, NULL);
            if (!svc_active(prof->service)) {
                logmsg("[%s] service %s not active after start", prof->name, prof->service);
                if (prof->on_fail == ONFAIL_ROLLBACK) {
                    if (access(bak, F_OK) == 0) {
                        logmsg("[%s] rolling back to .bak", prof->name);
                        (void)rename(bak, prof->file);
                    } else {
                        /* first deploy: no .bak to restore. Drop the override so
                         * the service falls back to its baked /usr/local/bin copy
                         * rather than being stuck on a broken candidate. */
                        logmsg("[%s] no .bak; removing override to fall back to baked", prof->name);
                        (void)unlink(prof->file);
                    }
                    (void)svc("restart", prof->service);
                }
                return -1;
            }
        }
    }

    if (!prof->retain_bak && !prof->pending_restart)
        (void)unlink(bak);
    return 0;
}

/* ---- inventory report --------------------------------------------------- */

static void report_inventory(void) {
    if (g_cfg.status_topic[0] == '\0')
        return;
    cJSON *root  = cJSON_CreateObject();
    cJSON *profs = cJSON_AddObjectToObject(root, "profiles");
    char   mac[32];
    get_mac(mac, sizeof(mac));
    cJSON_AddStringToObject(root, "mac", mac);
    cJSON_AddStringToObject(root, "arch", g_cfg.arch);
    cJSON_AddNumberToObject(root, "ts", (double)time(NULL));
    for (int i = 0; i < g_cfg.nprofiles; i++) {
        profile_t *p = &g_cfg.profiles[i];
        char       sha[SHA_HEX];
        if (sha256_of(p->file, sha) != 0)
            snprintf(sha, sizeof(sha), "%s", "absent");
        cJSON *e = cJSON_AddObjectToObject(profs, p->name);
        cJSON_AddStringToObject(e, "sha", sha);
        cJSON_AddStringToObject(e, "version", p->version[0] ? p->version : "?");
        cJSON_AddStringToObject(e, "result", p->last_result);
    }
    char topic[256];
    subst(g_cfg.status_topic, topic, sizeof(topic));
    char *s = cJSON_PrintUnformatted(root);
    if (s) {
        (void)mosquitto_publish(g_mosq, NULL, topic, (int)strlen(s), s, 1, true);
        logmsg("reported inventory -> %s", topic);
        free(s);
    }
    cJSON_Delete(root);
}

/* ---- profile evaluation + fetch ----------------------------------------- */

static profile_t *find_profile(const char *name) {
    for (int i = 0; i < g_cfg.nprofiles; i++)
        if (strcmp(g_cfg.profiles[i].name, name) == 0)
            return &g_cfg.profiles[i];
    return NULL;
}

/* does the installed file already match the meta entry's sha/size? */
static bool up_to_date(profile_t *prof, cJSON *entry) {
    cJSON *jsha  = cJSON_GetObjectItem(entry, "sha");
    cJSON *jsize = cJSON_GetObjectItem(entry, "size");
    if (!cJSON_IsString(jsha))
        return false;
    long want_size = cJSON_IsNumber(jsize) ? (long)jsize->valuedouble : -1;
    if (want_size >= 0 && file_size(prof->file) != want_size)
        return false; /* cheap reject */
    char have[SHA_HEX];
    if (sha256_of(prof->file, have) != 0)
        return false; /* absent -> needs install */
    return strcmp(have, jsha->valuestring) == 0;
}

/* subscribe to a profile's dist topic to pull the retained blob */
static void request_blob(profile_t *prof) {
    char topic[256];
    snprintf(topic, sizeof(topic), "%s/%s/dist/%s", g_cfg.prefix, g_cfg.arch, prof->name);
    snprintf(prof->last_result, sizeof(prof->last_result), "%s", "pending");
    (void)mosquitto_subscribe(g_mosq, NULL, topic, 1);
    logmsg("[%s] update needed -> subscribing %s", prof->name, topic);
}

/* evaluate all profiles against the current meta */
static void evaluate_meta(void) {
    if (!g_meta)
        return;
    for (int i = 0; i < g_cfg.nprofiles; i++) {
        profile_t *p     = &g_cfg.profiles[i];
        cJSON     *entry = cJSON_GetObjectItem(g_meta, p->name);
        if (!entry)
            continue; /* nothing advertised for this profile */
        cJSON *jver = cJSON_GetObjectItem(entry, "version");
        if (cJSON_IsString(jver))
            snprintf(p->version, sizeof(p->version), "%s", jver->valuestring);
        if (up_to_date(p, entry)) {
            /* installed file matches the advertised sha => healthy, whatever the
             * prior state. This also clears a stale "fail" once known-good bytes
             * are re-published (the content-addressed rollback path). */
            snprintf(p->last_result, sizeof(p->last_result), "%s", "ok");
            continue;
        }
        if (strcmp(p->last_result, "pending") == 0)
            continue; /* already fetching */
        /* signature gate: don't even fetch the blob unless the manufacturer
         * signed this (arch, profile, sha, size). The downloaded bytes are then
         * bound to <sha> by the post-download check in handle_blob(). */
        cJSON      *jsha  = cJSON_GetObjectItem(entry, "sha");
        cJSON      *jsize = cJSON_GetObjectItem(entry, "size");
        cJSON      *jsig  = cJSON_GetObjectItem(entry, "sig");
        const char *sha   = cJSON_IsString(jsha) ? jsha->valuestring : "";
        long        size  = cJSON_IsNumber(jsize) ? (long)jsize->valuedouble : -1;
        const char *sig   = cJSON_IsString(jsig) ? jsig->valuestring : NULL;
        if (!sig_ok(p->name, sha, size, sig)) {
            snprintf(p->last_result, sizeof(p->last_result), "%s", "fail");
            continue;
        }
        request_blob(p);
    }
    g_report_due = true;
}

/* process a received blob for a profile */
static void handle_blob(profile_t *prof, const void *payload, int len) {
    char tmpl[PATH_MAX_ + 8], tmpx[PATH_MAX_ + 8];
    snprintf(tmpl, sizeof(tmpl), "%s.dl", prof->file);  /* uncompressed candidate */
    snprintf(tmpx, sizeof(tmpx), "%s.dlx", prof->file); /* compressed download */

    /* unsubscribe so we don't reprocess */
    char topic[256];
    snprintf(topic, sizeof(topic), "%s/%s/dist/%s", g_cfg.prefix, g_cfg.arch, prof->name);
    (void)mosquitto_unsubscribe(g_mosq, NULL, topic);

    cJSON *entry = g_meta ? cJSON_GetObjectItem(g_meta, prof->name) : NULL;
    cJSON *jsha  = entry ? cJSON_GetObjectItem(entry, "sha") : NULL;
    cJSON *jcsha = entry ? cJSON_GetObjectItem(entry, "csha") : NULL;

    int rc = -1;
    do {
        if (write_all(tmpx, payload, (size_t)len) != 0) {
            logmsg("[%s] cannot write download", prof->name);
            break;
        }
        char got[SHA_HEX];
        if (cJSON_IsString(jcsha)) {
            if (sha256_of(tmpx, got) != 0 || strcmp(got, jcsha->valuestring) != 0) {
                logmsg("[%s] compressed sha mismatch -> bad transfer", prof->name);
                break;
            }
        }
        if (xz_decompress(tmpx, tmpl) != 0) {
            logmsg("[%s] decompress failed", prof->name);
            break;
        }
        if (cJSON_IsString(jsha)) {
            if (sha256_of(tmpl, got) != 0 || strcmp(got, jsha->valuestring) != 0) {
                logmsg("[%s] uncompressed sha mismatch", prof->name);
                break;
            }
        }
        rc = seat(prof, tmpl); /* consumes tmpl (renames it) */
    } while (0);

    (void)unlink(tmpx);
    (void)unlink(tmpl);
    snprintf(prof->last_result, sizeof(prof->last_result), "%s", rc == 0 ? "ok" : "fail");
    if (rc != 0 && prof->on_fail == ONFAIL_RETRY) {
        cJSON *jt   = entry ? cJSON_GetObjectItem(entry, "type") : NULL;
        bool   urge = jt && cJSON_IsString(jt) && strcmp(jt->valuestring, "urgent") == 0;
        prof->next_retry = time(NULL) + (urge ? g_cfg.retry_urgent : g_cfg.retry_normal);
    }
    g_report_due = true;
}

/* ---- mqtt callbacks ----------------------------------------------------- */

static void on_connect(struct mosquitto *m, void *u, int rc) {
    (void)u;
    if (rc != 0) {
        logmsg("connect failed: %s", mosquitto_connack_string(rc));
        return;
    }
    logmsg("connected to %s:%d", g_cfg.broker, g_cfg.port);
    (void)mosquitto_subscribe(m, NULL, g_meta_topic, 1);
}

static void on_message(struct mosquitto *m, void *u, const struct mosquitto_message *msg) {
    (void)m;
    (void)u;
    if (strcmp(msg->topic, g_meta_topic) == 0) {
        cJSON *parsed = cJSON_ParseWithLength(msg->payload, (size_t)msg->payloadlen);
        if (!parsed) {
            logmsg("meta parse failed");
            return;
        }
        if (g_meta)
            cJSON_Delete(g_meta);
        g_meta       = parsed;
        g_meta_dirty = true;
        logmsg("meta received (%d bytes)", msg->payloadlen);
        return;
    }
    /* must be a dist blob: <prefix>/<arch>/dist/<profile> */
    const char *base = strrchr(msg->topic, '/');
    if (base) {
        profile_t *p = find_profile(base + 1);
        if (p && strcmp(p->last_result, "pending") == 0) {
            logmsg("[%s] blob received (%d bytes)", p->name, msg->payloadlen);
            handle_blob(p, msg->payload, msg->payloadlen);
        }
    }
}

/* ---- main --------------------------------------------------------------- */

static void on_sig(int s) { (void)s; g_stop = 1; }

static int run_check(const char *cfgpath) {
    config_t c;
    if (config_load(&c, cfgpath, true) != 0) {
        printf("CHECK FAILED: %s\n", cfgpath);
        return 1;
    }
    printf("ok: %s — %d profile(s), signatures %s\n", cfgpath, c.nprofiles,
           c.sign_enabled ? "ENFORCED (pubkey present)" : "off (no pubkey)");
    for (int i = 0; i < c.nprofiles; i++)
        printf("  - %s -> %s%s%s\n", c.profiles[i].name, c.profiles[i].file,
               c.profiles[i].service[0] ? " [svc:" : "", c.profiles[i].service);
    return 0;
}

/* one-shot: connect, pull the retained meta, print a per-profile status table,
 * then exit. No daemon required — meant for diagnostics (iotdata-checks calls
 * `iotdata-deploy --config X --status`). Degrades gracefully if the broker is
 * down (shows on-disk state, marks the broker unreachable). */
static int run_status(const char *cfgpath) {
    if (config_load(&g_cfg, cfgpath, false) != 0) {
        printf("status: config invalid: %s\n", cfgpath);
        return 1;
    }
    snprintf(g_meta_topic, sizeof(g_meta_topic), "%s/%s/meta", g_cfg.prefix, g_cfg.arch);
    mosquitto_lib_init();
    char cid[96], mac[32];
    get_mac(mac, sizeof(mac));
    snprintf(cid, sizeof(cid), "mqtt-deployer-status-%s", mac);
    g_mosq = mosquitto_new(cid, true, NULL);
    if (!g_mosq) {
        printf("status: mosquitto_new failed\n");
        return 1;
    }
    if (g_cfg.username[0])
        mosquitto_username_pw_set(g_mosq, g_cfg.username, g_cfg.password);
    if (g_cfg.tls)
        (void)mosquitto_tls_set(g_mosq, g_cfg.cafile[0] ? g_cfg.cafile : NULL, NULL, NULL, NULL, NULL);
    mosquitto_connect_callback_set(g_mosq, on_connect);
    mosquitto_message_callback_set(g_mosq, on_message);
    bool connected = mosquitto_connect(g_mosq, g_cfg.broker, g_cfg.port, 30) == MOSQ_ERR_SUCCESS;
    for (int i = 0; i < 60 && connected && !g_meta; i++)
        if (mosquitto_loop(g_mosq, 50, 1) != MOSQ_ERR_SUCCESS) {
            connected = false;
            break;
        }

    printf("deployer status — arch=%s prefix=%s signatures=%s\n",
           g_cfg.arch, g_cfg.prefix, g_cfg.sign_enabled ? "ENFORCED" : "off");
    printf("broker %s:%d — %s\n", g_cfg.broker, g_cfg.port,
           g_meta ? "connected, meta received" : (connected ? "connected, no meta published" : "UNREACHABLE"));
    printf("%-20s %-12s %-13s %-13s %-8s %s\n", "profile", "version", "installed", "advertised", "sig", "state");
    for (int i = 0; i < g_cfg.nprofiles; i++) {
        profile_t *p       = &g_cfg.profiles[i];
        char       isha[SHA_HEX];
        bool       present = sha256_of(p->file, isha) == 0;
        cJSON     *e       = g_meta ? cJSON_GetObjectItem(g_meta, p->name) : NULL;
        cJSON     *jv      = e ? cJSON_GetObjectItem(e, "version") : NULL;
        cJSON     *js      = e ? cJSON_GetObjectItem(e, "sha") : NULL;
        cJSON     *jsig    = e ? cJSON_GetObjectItem(e, "sig") : NULL;
        cJSON     *jsz     = e ? cJSON_GetObjectItem(e, "size") : NULL;
        const char *ver    = (jv && cJSON_IsString(jv)) ? jv->valuestring : "-";
        const char *advsha = (js && cJSON_IsString(js)) ? js->valuestring : NULL;

        const char *sig;
        if (!g_cfg.sign_enabled)
            sig = "off";
        else if (!e)
            sig = "-";
        else if (!(jsig && cJSON_IsString(jsig)))
            sig = "MISSING";
        else {
            long sz = (jsz && cJSON_IsNumber(jsz)) ? (long)jsz->valuedouble : -1;
            sig     = sig_ok(p->name, advsha ? advsha : "", sz, jsig->valuestring) ? "valid" : "INVALID";
        }

        const char *state;
        if (!e)
            state = present ? "installed (not advertised)" : "absent, not advertised";
        else if (!present)
            state = "ABSENT (advertised)";
        else if (advsha && strcmp(isha, advsha) == 0)
            state = "up-to-date";
        else
            state = "UPDATE AVAILABLE";

        char svcbuf[96] = "";
        if (p->service[0])
            snprintf(svcbuf, sizeof(svcbuf), " [%s:%s]", p->service, svc_active(p->service) ? "active" : "inactive");

        char ib[13], ab[13];
        snprintf(ib, sizeof(ib), "%.12s", present ? isha : "absent");
        snprintf(ab, sizeof(ab), "%.12s", advsha ? advsha : "-");
        printf("%-20s %-12s %-13s %-13s %-8s %s%s\n", p->name, ver, ib, ab, sig, state, svcbuf);
    }
    mosquitto_disconnect(g_mosq);
    mosquitto_destroy(g_mosq);
    mosquitto_lib_cleanup();
    return 0;
}

static void usage(const char *a0) {
    printf("usage: %s --config <file> [--status] | --check <file> | --help\n", a0);
}

int main(int argc, char **argv) {
    const char *cfgpath     = NULL;
    bool        want_status = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--check") == 0 && i + 1 < argc)
            return run_check(argv[++i]);
        else if (strcmp(argv[i], "--status") == 0)
            want_status = true;
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            cfgpath = argv[++i];
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!cfgpath) {
        usage(argv[0]);
        return 2;
    }
    if (want_status)
        return run_status(cfgpath);
    if (config_load(&g_cfg, cfgpath, true) != 0) {
        logmsg("invalid config %s", cfgpath);
        return 1;
    }

    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);
    signal(SIGPIPE, SIG_IGN);

    snprintf(g_meta_topic, sizeof(g_meta_topic), "%s/%s/meta", g_cfg.prefix, g_cfg.arch);

    mosquitto_lib_init();
    char cid[96];
    if (g_cfg.client_id[0])
        subst(g_cfg.client_id, cid, sizeof(cid));
    else {
        char mac[32];
        get_mac(mac, sizeof(mac));
        snprintf(cid, sizeof(cid), "mqtt-deployer-%s", mac);
    }
    g_mosq = mosquitto_new(cid, true, NULL);
    if (!g_mosq) {
        logmsg("mosquitto_new failed");
        return 1;
    }
    if (g_cfg.username[0])
        mosquitto_username_pw_set(g_mosq, g_cfg.username, g_cfg.password);
    if (g_cfg.tls) {
        if (mosquitto_tls_set(g_mosq, g_cfg.cafile[0] ? g_cfg.cafile : NULL, NULL, NULL, NULL, NULL) != MOSQ_ERR_SUCCESS)
            logmsg("WARN tls_set failed");
    }
    mosquitto_connect_callback_set(g_mosq, on_connect);
    mosquitto_message_callback_set(g_mosq, on_message);
    mosquitto_reconnect_delay_set(g_mosq, 2, 30, true);

    logmsg("starting: broker %s:%d arch=%s prefix=%s profiles=%d",
           g_cfg.broker, g_cfg.port, g_cfg.arch, g_cfg.prefix, g_cfg.nprofiles);
    if (mosquitto_connect(g_mosq, g_cfg.broker, g_cfg.port, 60) != MOSQ_ERR_SUCCESS)
        logmsg("initial connect failed; will retry");

    bool reported_startup = false;
    while (!g_stop) {
        int rc = mosquitto_loop(g_mosq, 1000, 1);
        if (rc != MOSQ_ERR_SUCCESS) {
            struct timespec ts = {2, 0};
            (void)nanosleep(&ts, NULL);
            (void)mosquitto_reconnect(g_mosq);
            continue;
        }
        if (g_meta_dirty) {
            g_meta_dirty = false;
            evaluate_meta();
        }
        /* retry due profiles */
        time_t now = time(NULL);
        for (int i = 0; i < g_cfg.nprofiles; i++) {
            profile_t *p = &g_cfg.profiles[i];
            if (p->next_retry && now >= p->next_retry) {
                p->next_retry = 0;
                if (g_meta) {
                    cJSON *e = cJSON_GetObjectItem(g_meta, p->name);
                    if (e && !up_to_date(p, e))
                        request_blob(p);
                }
            }
        }
        if (g_report_due || !reported_startup) {
            /* report once meta has been seen (or after a short grace at startup) */
            if (g_meta || reported_startup) {
                report_inventory();
                g_report_due     = false;
                reported_startup = true;
            } else if (!reported_startup) {
                static int grace = 0;
                if (++grace > 3) { /* ~3s with no meta: report anyway */
                    report_inventory();
                    reported_startup = true;
                }
            }
        }
        /* deferred live-replace restarts run AFTER the report, so a self-restart
         * doesn't kill us before the inventory is sent. --no-block lets systemd
         * cycle us cleanly via our SIGTERM handler. */
        for (int i = 0; i < g_cfg.nprofiles; i++) {
            profile_t *p = &g_cfg.profiles[i];
            if (p->pending_restart) {
                p->pending_restart = false;
                logmsg("[%s] restarting %s to apply", p->name, p->service);
                char *const ra[] = {"systemctl", "--no-block", "restart", (char *)p->service, NULL};
                (void)run_cmd(ra);
            }
        }
    }

    logmsg("stopping");
    if (g_meta)
        cJSON_Delete(g_meta);
    mosquitto_destroy(g_mosq);
    mosquitto_lib_cleanup();
    return 0;
}
