/* Loop #13 known_hosts C harness -- 三盲独立 C 实现 + 对照 _knownhosts_kat.h 验证
 *
 * 用 tcc 编译 + TCC_RUN_MAIN 直接运行 (跟 Loop #12 kexflow_harness.c 同模式):
 *   tcc -run verify_c/knownhosts_harness.c
 *
 * 实测覆盖:
 *   0. SHA-1 (RFC 3174 / FIPS 180-4) -- V0 三标准向量 byte-exact
 *   1. HMAC-SHA1 (RFC 2104 / RFC 2202) -- V0b Case 1 + Case 2 byte-exact
 *   2. V1 single host match -> Ok
 *   3. V2 wildcard host match -> Ok
 *   4. V4 |1| HMAC-SHA1 hash host match -> Ok (含 b64_decode + hmac_sha1 整链路)
 *   5. V5 last-match-wins Mismatch
 *   6. V6 unknown host -> Unknown (non-strict)
 *   7. V7 strict + Unknown -> Invalid
 *   8. parse_line markers (@cert-authority / @revoked)
 *
 * 全部对比 _knownhosts_ref_out.txt (Python) 自检。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "_knownhosts_kat.h"

#define CHECKS_MAX 64
static int checks_passed = 0;
static int checks_total = 0;
static const char *failed_check = NULL;

static void ok(const char *name, int cond) {
    checks_total++;
    if (cond) {
        checks_passed++;
        printf("pass %s\n", name);
    } else {
        printf("FAIL %s\n", name);
        if (!failed_check) failed_check = name;
    }
}

#define ASSERT_BYTES_EQ(actual, expected, len, name) do {  \
    if (memcmp((actual), (expected), (len)) != 0) {          \
        printf("FAIL %s: byte mismatch\n", (name));           \
        checks_total++;                                       \
        if (!failed_check) failed_check = (name);             \
    } else {                                                  \
        checks_passed++;                                       \
        checks_total++;                                       \
        printf("pass %s\n", (name));                          \
    }                                                         \
} while (0)

/* ============================================================
 * SHA-1 (RFC 3174 / FIPS PUB 180-4) -- 独立 C 实现
 * ============================================================ */

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_compress(uint32_t h[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t t = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

static void sha1(const uint8_t *msg, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };
    uint8_t buf[64];
    size_t buf_len = 0;
    uint64_t bit_len = (uint64_t)len * 8;
    /* copy + pad */
    while (len > 0) {
        size_t take = (64 - buf_len < len) ? (64 - buf_len) : len;
        memcpy(buf + buf_len, msg, take);
        buf_len += take;
        msg += take;
        len -= take;
        if (buf_len == 64) {
            sha1_compress(h, buf);
            buf_len = 0;
        }
    }
    /* 0x80 + zeros + 8-byte big-endian length */
    buf[buf_len++] = 0x80;
    if (buf_len > 56) {
        while (buf_len < 64) buf[buf_len++] = 0;
        sha1_compress(h, buf);
        buf_len = 0;
    }
    while (buf_len < 56) buf[buf_len++] = 0;
    for (int i = 7; i >= 0; i--) {
        buf[56 + (7 - i)] = (uint8_t)(bit_len >> (i * 8));
    }
    sha1_compress(h, buf);
    for (int i = 0; i < 5; i++) {
        out[i * 4 + 0] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

/* ============================================================
 * HMAC-SHA1 (RFC 2104)
 * ============================================================ */

static void hmac_sha1(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t out[20]) {
    uint8_t block_key[64] = {0};
    if (key_len > 64) {
        sha1(key, key_len, block_key);
    } else {
        memcpy(block_key, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = block_key[i] ^ 0x36;
        opad[i] = block_key[i] ^ 0x5C;
    }
    /* inner = SHA1(ipad || msg) */
    /* concat ipad + msg into one buffer */
    size_t inner_len = 64 + msg_len;
    uint8_t *inner_buf = (uint8_t *)malloc(inner_len);
    memcpy(inner_buf, ipad, 64);
    memcpy(inner_buf + 64, msg, msg_len);
    uint8_t inner_hash[20];
    sha1(inner_buf, inner_len, inner_hash);
    free(inner_buf);
    /* outer = SHA1(opad || inner_hash) */
    uint8_t outer_buf[64 + 20];
    memcpy(outer_buf, opad, 64);
    memcpy(outer_buf + 64, inner_hash, 20);
    sha1(outer_buf, 84, out);
}

/* ============================================================
 * base64 解码 (与 OpenSSH b64_pton 兼容,nopad 也接受)
 * ============================================================ */

static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* decode base64 str (may have padding or nopad) into out; returns decoded length, or -1 on error.
 * 与 OpenSSH b64_pton 兼容:接受 nopad(自动 fill `=` 到 4 倍数)。
 */
static int b64_decode(const char *s, uint8_t *out, size_t out_max) {
    int v[4];
    int n_out = 0;
    int slen = (int)strlen(s);
    /* 自动补 = 到 4 倍数(无外部 padding 的兼容处理) */
    char padded[1024];
    if (slen >= (int)sizeof(padded)) return -1;
    memcpy(padded, s, slen);
    int r = slen % 4;
    if (r != 0) {
        while ((int)strlen(padded) % 4 != 0) padded[strlen(padded)] = '=';
    }
    padded[strlen(padded)] = '\0';
    s = padded;
    slen = (int)strlen(s);

    int i = 0;
    while (i < slen) {
        int got = 0;
        while (got < 4 && i < slen) {
            char c = s[i];
            if (c == '=') {
                while (got < 4) v[got++] = 0;
                i++;
                while (i < slen && s[i] == '=') i++;
                goto commit;
            }
            int x = b64_val((unsigned char)c);
            if (x < 0) return -1;
            v[got++] = x;
            i++;
        }
        /* truncated trailing quad: fill with 0 (compatible nopad) */
        while (got < 4) v[got++] = 0;
        commit:
        if ((size_t)n_out + 3 > out_max) return -1;
        out[n_out++] = (v[0] << 2) | (v[1] >> 4);
        out[n_out++] = (v[1] << 4) | (v[2] >> 2);
        out[n_out++] = (v[2] << 6) | v[3];
    }
    return n_out;
}

/* ============================================================
 * 通配符 NFA
 * ============================================================ */

static int match_pattern_nfa(const char *s, const char *pat) {
    int m = strlen(pat);
    if (m == 0) return strlen(s) == 0;
    int *states = (int *)calloc(m + 1, sizeof(int));
    int *next_states = (int *)calloc(m + 1, sizeof(int));
    states[0] = 1;
    /* epsilon closure for '*' */
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int i = 0; i < m; i++) {
            if (states[i] && pat[i] == '*') {
                if (!states[i + 1]) { states[i + 1] = 1; changed = 1; }
            }
        }
    }
    for (int si = 0; s[si]; si++) {
        memset(next_states, 0, (m + 1) * sizeof(int));
        for (int i = 0; i < m; i++) {
            if (!states[i]) continue;
            char pc = pat[i];
            if (pc == '*') {
                next_states[i] = 1;
            } else if (pc == '?' || pc == s[si]) {
                next_states[i + 1] = 1;
            }
        }
        /* epsilon_closure */
        changed = 1;
        while (changed) {
            changed = 0;
            for (int i = 0; i < m; i++) {
                if (next_states[i] && pat[i] == '*') {
                    if (!next_states[i + 1]) { next_states[i + 1] = 1; changed = 1; }
                }
            }
        }
        int active = 0;
        for (int k = 0; k <= m; k++) if (next_states[k]) { active = 1; break; }
        if (!active) {
            free(states); free(next_states);
            return 0;
        }
        memcpy(states, next_states, (m + 1) * sizeof(int));
    }
    int final = states[m];
    free(states); free(next_states);
    return final;
}

static int is_hashed_host(const char *s) {
    return strlen(s) >= 3 && s[0] == '|' && s[1] == '1' && s[2] == '|';
}

static int match_hashed_host(const char *host, const char *pattern) {
    /* pattern: |1|<b64-salt>|<b64-hash> */
    if (!is_hashed_host(pattern)) return 0;
    const char *salt_start = pattern + 3;
    const char *sep = strchr(salt_start, '|');
    if (!sep) return 0;
    size_t salt_len = (size_t)(sep - salt_start);
    char salt_b64[64] = {0};
    if (salt_len >= sizeof(salt_b64)) return 0;
    memcpy(salt_b64, salt_start, salt_len);
    salt_b64[salt_len] = '\0';
    const char *hash_b64 = sep + 1;
    /* 使用 static 数组避免编译器过度栈优化导致的 flakiness */
    static uint8_t salt[64];
    static uint8_t exp_hash[64];
    static uint8_t actual[20];
    /* 每次调用 explicit 清零 */
    memset(salt, 0, sizeof(salt));
    memset(exp_hash, 0, sizeof(exp_hash));
    memset(actual, 0, sizeof(actual));
    int salt_n = b64_decode(salt_b64, salt, sizeof(salt));
    int hash_n = b64_decode(hash_b64, exp_hash, sizeof(exp_hash));
    if (salt_n < 0 || hash_n < 0) return 0;
    /* nopad base64 解码 20 字节时会给出 21 字节(最后一字节是 trailing bits)。
     * OpenSSH b64_pton 行为:截断到 20 字节(salt/hash 都是 SHA-1 = 20 字节固定长度)。 */
    if (salt_n == 21) salt_n = 20;
    if (hash_n == 21) hash_n = 20;
    /* actual = HMAC-SHA1(salt, host) */
    hmac_sha1(salt, (size_t)salt_n, (const uint8_t *)host, strlen(host), actual);
    if ((size_t)hash_n != 20) return 0;
    return memcmp(actual, exp_hash, 20) == 0;
}

/* match_host_pattern (Loop #13 旧版) 移除,改用 check_host_key_v2
 * (内联 NFA + port 感知 + Revoked 后置)。原实现是 void 化避免 unused warning。 */


typedef struct {
    int has_marker;       /* 0 or 1 */
    char marker[32];      /* "cert-authority" / "revoked" */
    char host_raw[256];
    char key_type[64];
    uint8_t key_blob[512];
    size_t key_blob_len;
} kh_entry_t;

static int parse_kh_line(const char *line, kh_entry_t *e) {
    int i = 0;
    /* skip leading ws */
    while (line[i] == ' ' || line[i] == '\t') i++;
    if (line[i] == '\0' || line[i] == '#') return 0;
    /* marker */
    e->has_marker = 0;
    e->marker[0] = '\0';
    if (line[i] == '@') {
        int j = i + 1;
        while (line[j] && line[j] != ' ' && line[j] != '\t') j++;
        size_t mlen = (size_t)(j - i - 1);
        if (mlen >= sizeof(e->marker)) return 0;
        const char *ca = "@cert-authority";
        const char *rv = "@revoked";
        if (mlen == strlen(ca + 1) && memcmp(line + i + 1, ca + 1, mlen) == 0) {
            e->has_marker = 1;
            memcpy(e->marker, "cert-authority", strlen("cert-authority") + 1);
        } else if (mlen == strlen(rv + 1) && memcmp(line + i + 1, rv + 1, mlen) == 0) {
            e->has_marker = 1;
            memcpy(e->marker, "revoked", strlen("revoked") + 1);
        } else {
            return 0;  /* unknown marker */
        }
        i = j;
        while (line[i] == ' ' || line[i] == '\t') i++;
    }
    /* host field */
    int host_start = i;
    while (line[i] && line[i] != ' ' && line[i] != '\t') i++;
    int host_end = i;
    if (host_end >= host_start) {
        size_t hl = (size_t)(host_end - host_start);
        if (hl >= sizeof(e->host_raw)) return 0;
        memcpy(e->host_raw, line + host_start, hl);
        e->host_raw[hl] = '\0';
    }
    while (line[i] == ' ' || line[i] == '\t') i++;
    /* key type */
    int kt_start = i;
    while (line[i] && line[i] != ' ' && line[i] != '\t') i++;
    int kt_end = i;
    if (kt_end >= kt_start) {
        size_t kl = (size_t)(kt_end - kt_start);
        if (kl >= sizeof(e->key_type)) return 0;
        memcpy(e->key_type, line + kt_start, kl);
        e->key_type[kl] = '\0';
    }
    while (line[i] == ' ' || line[i] == '\t') i++;
    /* base64 blob */
    int blob_start = i;
    while (line[i] && line[i] != ' ' && line[i] != '\t') i++;
    int blob_end = i;
    char blob_b64[1024] = {0};
    if (blob_end > blob_start) {
        size_t bl = (size_t)(blob_end - blob_start);
        if (bl >= sizeof(blob_b64)) return 0;
        memcpy(blob_b64, line + blob_start, bl);
        blob_b64[bl] = '\0';
    }
    int n = b64_decode(blob_b64, e->key_blob, sizeof(e->key_blob));
    if (n < 0) return 0;
    e->key_blob_len = (size_t)n;
    return 1;
}

/* Loop #14 之前(Loop #13)的旧实现已移除,port-aware check_host_key_v2 是唯一实现,
 * legacy shim 提供向后兼容 (caller 不传 port)。 */

/* Loop #14: split [host] / [host]:port from caller's host string.
 * Returns 1 if bracketed form was successfully stripped, 0 otherwise.
 * On output: *host_only receives inner (or whole input if not bracketed),
 * *port receives parsed port or -1 if absent.
 */
static int split_bracketed(const char *s, char *host_only, size_t ho_max, int *port) {
    *port = -1;
    if (s[0] == '[') {
        const char *close = strchr(s, ']');
        if (close != NULL) {
            size_t hl = (size_t)(close - s - 1);
            if (hl >= ho_max) hl = ho_max - 1;
            memcpy(host_only, s + 1, hl);
            host_only[hl] = '\0';
            if (close[1] == ':') {
                *port = atoi(close + 2);
            }
            return 1;
        }
    }
    /* not bracketed: copy whole */
    size_t hl = strlen(s);
    if (hl >= ho_max) hl = ho_max - 1;
    memcpy(host_only, s, hl);
    host_only[hl] = '\0';
    return 0;
}

/* Loop #14: extract (host_only, port?) from a single comma-split pattern piece.
 * Returns 1 on success.
 */
static int parse_pattern_spec(const char *pat, char *host_only, size_t ho_max, int *port) {
    const char *s = pat;
    /* strip leading '!' (negation skip) */
    if (s[0] == '!') s++;
    return split_bracketed(s, host_only, ho_max, port);
}

/* check_host_key_v2: Loop #14 port-aware check
 * Args:
 *   entries:        array
 *   n_entries:      length
 *   host_str:       can be "example.com" or "[example.com]:2200"
 *   port:           explicit port (0 = default 22)
 *   presented_blob / len: server key blob
 * Returns: 0=Ok, 1=Mismatch, 2=Unknown, 3=Invalid
 */
static int check_host_key_v2(kh_entry_t *entries, int n_entries,
                             const char *host_str, int port,
                             const uint8_t *presented_blob, size_t presented_len) {
    if (n_entries == 0) return 2;
    /* 1. Normalize caller host_str */
    char caller_host[256];
    int caller_port_from_str = -1;
    split_bracketed(host_str, caller_host, sizeof(caller_host), &caller_port_from_str);
    int port_caller = (port != 0) ? port
                   : (caller_port_from_str != -1 ? caller_port_from_str : 22);
    /* 2. Revoked 全局后置: 任何 entry.marker == "revoked" 且 blob 匹配 → Mismatch */
    for (int i = 0; i < n_entries; i++) {
        if (strcmp(entries[i].marker, "revoked") == 0 &&
            entries[i].key_blob_len == presented_len &&
            memcmp(entries[i].key_blob, presented_blob, presented_len) == 0) {
            return 1;  /* Mismatch */
        }
    }
    /* 3. last-match-wins: Revoked 不参与 host 选择 */
    int found = -1;
    for (int i = 0; i < n_entries; i++) {
        if (strcmp(entries[i].marker, "revoked") == 0) continue;
        /* 遍历该 entry 的 host_patterns(逗号分隔) */
        const char *p = entries[i].host_raw;
        int hit = 0;
        while (*p) {
            const char *comma = strchr(p, ',');
            char piece[256] = {0};
            size_t plen = comma ? (size_t)(comma - p) : strlen(p);
            if (plen >= sizeof(piece)) plen = sizeof(piece) - 1;
            memcpy(piece, p, plen);
            piece[plen] = '\0';
            /* 解析 spec */
            char spec_host[256] = {0};
            int spec_port = -1;
            parse_pattern_spec(piece, spec_host, sizeof(spec_host), &spec_port);
            /* port 检查 */
            if (spec_port != -1 && spec_port != port_caller) {
                p = comma ? comma + 1 : p + plen;
                continue;
            }
            /* host 检查 (hash 优先, 否则 NFA) */
            if (is_hashed_host(spec_host)) {
                if (match_hashed_host(caller_host, spec_host)) {
                    hit = 1;
                }
            } else {
                if (match_pattern_nfa(caller_host, spec_host)) {
                    hit = 1;
                }
            }
            if (hit) break;
            p = comma ? comma + 1 : p + plen;
        }
        if (hit) found = i;
    }
    if (found < 0) return 2;  /* Unknown */
    if (entries[found].key_blob_len == presented_len &&
        memcmp(entries[found].key_blob, presented_blob, presented_len) == 0)
        return 0;  /* Ok */
    return 1;  /* Mismatch */
}

static int check_host_key_strict_v2(kh_entry_t *entries, int n_entries,
                                   const char *host_str, int port,
                                   const uint8_t *presented_blob,
                                   size_t presented_len, int strict_kex) {
    int r = check_host_key_v2(entries, n_entries, host_str, port,
                              presented_blob, presented_len);
    if (r == 2 && strict_kex) return 3;
    return r;
}

/* legacy compat shim (caller 不传 port) */
static int check_host_key(kh_entry_t *entries, int n_entries,
                          const char *host, const uint8_t *presented_blob,
                          size_t presented_len) {
    return check_host_key_v2(entries, n_entries, host, 0, presented_blob, presented_len);
}

static int check_host_key_strict(kh_entry_t *entries, int n_entries,
                                 const char *host, const uint8_t *presented_blob,
                                 size_t presented_len, int strict_kex) {
    return check_host_key_strict_v2(entries, n_entries, host, 0,
                                    presented_blob, presented_len, strict_kex);
}

/* ============================================================
 * Test driver
 * ============================================================ */

static char *slurp(const char *s, size_t len) {
    char *p = (char *)malloc(len + 1);
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

int main(void) {
    printf("Loop #13 knownhosts C harness\n");

    /* === V0: SHA-1 vectors === */
    uint8_t sha1_empty[20];
    sha1((const uint8_t *)"", 0, sha1_empty);
    ASSERT_BYTES_EQ(sha1_empty, V0_SHA1_EMPTY, 20, "V0a SHA-1(\"\")");

    uint8_t sha1_abc[20];
    sha1((const uint8_t *)"abc", 3, sha1_abc);
    ASSERT_BYTES_EQ(sha1_abc, V0_SHA1_ABC, 20, "V0b SHA-1(\"abc\")");

    uint8_t sha1_long[20];
    const char *long_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha1((const uint8_t *)long_msg, strlen(long_msg), sha1_long);
    ASSERT_BYTES_EQ(sha1_long, V0_SHA1_LONG, 20, "V0c SHA-1(long)");

    /* === V0b: HMAC-SHA1 vectors === */
    uint8_t hmac1[20], key1[20];
    memset(key1, 0x0b, 20);
    hmac_sha1(key1, 20, (const uint8_t *)"Hi There", 8, hmac1);
    ASSERT_BYTES_EQ(hmac1, V0B_HMAC_CASE1, 20, "V0d HMAC-SHA1 Case1");

    uint8_t hmac2[20];
    hmac_sha1((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, hmac2);
    ASSERT_BYTES_EQ(hmac2, V0B_HMAC_CASE2, 20, "V0e HMAC-SHA1 Case2");

    /* === V4 unit: HMAC-SHA1(salt, host) matches reference hash === */
    uint8_t actual_hash[20];
    hmac_sha1(V4_SALT, V4_SALT_len, (const uint8_t *)V4_HOST, V4_HOST_len,
              actual_hash);
    ASSERT_BYTES_EQ(actual_hash, V4_HASH, 20, "V4a HMAC-SHA1(salt, host)");

    /* === V1..V7: check_host_key through known_hosts line parse === */
    /* V1 */
    {
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V1_KH_LINE, V1_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key(entries, ne, V1_HOST, V1_BLOB, V1_BLOB_len);
        ok("V1 single host Ok", s == V1_STATUS);
    }
    /* V2 wildcard host */
    {
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V1_KH_LINE, V1_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key(entries, ne, V2_HOST, V1_BLOB, V1_BLOB_len);
        ok("V2 wildcard match", s == V2_STATUS);
    }
    /* V3 negation prefix */
    {
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V3_KH_LINE, V3_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key(entries, ne, V3_HOST, V1_BLOB, V1_BLOB_len);
        ok("V3 negation skipped", s == V3_STATUS);
    }
    /* V4 hash host */
    {
        kh_entry_t entries[1];
        memset(entries, 0, sizeof(entries));
        int ne = 0;
        char *line = slurp(V4_KH_LINE, V4_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key(entries, ne, V4_HOST, V4_BLOB, V4_BLOB_len);
        ok("V4 hash host Ok", s == V4_STATUS);
    }
    /* V5 mismatch: presented B but entry has A */
    {
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V5_KH_LINE, V5_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key(entries, ne, V5_HOST, V5_BLOB, V5_BLOB_len);
        ok("V5 host hit but key Mismatch", s == V5_STATUS);
    }
    /* V6 unknown host */
    {
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V6_KH_LINE, V6_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key(entries, ne, V6_HOST, V1_BLOB, V1_BLOB_len);
        ok("V6 unknown host -> Unknown", s == V6_STATUS);
    }
    /* V7 strict + Unknown -> Invalid */
    {
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V7_KH_LINE, V7_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key_strict(entries, ne, V7_HOST, V1_BLOB, V1_BLOB_len, 1);
        ok("V7 strict Unknown -> Invalid", s == V7_STATUS);
    }
    /* === V8: markers parse (@cert-authority / @revoked) === */
    {
        char line[256];
        snprintf(line, sizeof(line), "@revoked %.*s", (int)V1_KH_LINE_len, V1_KH_LINE);
        kh_entry_t e;
        int rc = parse_kh_line(line, &e);
        ok("V8a parse @revoked entry", rc == 1);
        ok("V8b marker == revoked", strcmp(e.marker, "revoked") == 0);
    }
    {
        char line[256];
        snprintf(line, sizeof(line), "@cert-authority %.*s", (int)V1_KH_LINE_len, V1_KH_LINE);
        kh_entry_t e;
        int rc = parse_kh_line(line, &e);
        ok("V8c parse @cert-authority entry", rc == 1);
        ok("V8d marker == cert-authority", strcmp(e.marker, "cert-authority") == 0);
    }
    /* === V9: empty entries === */
    {
        int s = check_host_key(NULL, 0, "any.host", V1_BLOB, V1_BLOB_len);
        ok("V9 empty entries -> Unknown", s == 2);
    }

    /* === Loop #14: V9-V12 [host]:port + Revoked === */
    {
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V9_KH_LINE, V9_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key_v2(entries, ne, V9_HOST, V9_PORT,
                                 V9_PRESENTED_BLOB, V9_PRESENTED_BLOB_len);
        ok("L14 V9 plain host + default port -> Ok", s == V9_STATUS);
    }
    {
        /* V10 [host]:port explicit: caller-full + port=0 → Ok */
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V10_KH_LINE, V10_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s1 = check_host_key_v2(entries, ne, V10_HOST, 0,
                                  V10_PRESENTED_BLOB, V10_PRESENTED_BLOB_len);
        ok("L14 V10a caller-full [host]:port + port=0 -> Ok", s1 == V10_STATUS);
        int s2 = check_host_key_v2(entries, ne, "foo.example.com", V10_PORT,
                                   V10_PRESENTED_BLOB, V10_PRESENTED_BLOB_len);
        ok("L14 V10b plain host + port=2200 -> Ok", s2 == V10_STATUS);
    }
    {
        /* V11 port mismatch */
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V11_KH_LINE, V11_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key_v2(entries, ne, V11_HOST, V11_PORT,
                                 V11_PRESENTED_BLOB, V11_PRESENTED_BLOB_len);
        ok("L14 V11 port mismatch -> Unknown", s == V11_STATUS);
    }
    {
        /* V12 @revoked wins → Mismatch */
        kh_entry_t entries[1];
        int ne = 0;
        char *line = slurp(V12_KH_LINE, V12_KH_LINE_len);
        if (parse_kh_line(line, &entries[ne])) ne++;
        free(line);
        int s = check_host_key_v2(entries, ne, V12_HOST, V12_PORT,
                                 V12_PRESENTED_BLOB, V12_PRESENTED_BLOB_len);
        ok("L14 V12 @revoked + A presented -> Mismatch", s == V12_STATUS);
    }

    printf("\nTotal: %d/%d passed\n", checks_passed, checks_total);
    return (checks_passed == checks_total) ? 0 : 1;
}
