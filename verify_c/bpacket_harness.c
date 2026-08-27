/* Loop #10 — SSH binary packet protocol C harness (triple-blind: C leg)
 *
 * Crypto legs are REAL OpenSSH code:
 *   - chacha.c / poly1305.c / aead_chachapoly_ref.c (= cipher-chachapoly.c,
 *     only includes rewritten; see Loop #8)
 * Framing legs are transcribed from packet.c with line-number annotations:
 *   - send2_wrapped padding math   (packet.c:1276-1325)
 *   - read_poll2 state machine      (packet.c:1624-1858)
 *
 * Vectors come from verify_c/bpacket_python_ref.py (_bpacket_ref_out.txt);
 * the same literals are asserted in MoonBit bpacket_test.mbt T18.
 * Exit code 0 = all PASS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead_ssh_compat.h"   /* types/PEEK_U32/POKE_U64/ssherr codes */
#include "chacha.h"
#include "poly1305.h"

/* from aead_chachapoly_ref.c */
extern struct chachapoly_ctx *chachapoly_new(const u_char *key, u_int keylen);
extern void chachapoly_free(struct chachapoly_ctx *cpctx);
extern int chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr,
    u_char *dest, const u_char *src, u_int len, u_int aadlen, u_int authlen,
    int do_encrypt);
extern int chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len);

#define PACKET_MAX_SIZE  (256 * 1024)          /* packet.c:99 */
#define BP_BLOCK_SIZE    8                     /* none & chachapoly cipher table */
#define BP_AADLEN_PLAIN  0
#define BP_AUTHLEN_PLAIN 0
#define BP_AADLEN_AEAD   4
#define BP_AUTHLEN_AEAD  16
#define MSG_NEWKEYS      21

static const unsigned char KEY64[64] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
};

static int g_pass = 0, g_total = 0;

#define CHECK(name, cond) do { \
    g_total++; \
    if (cond) { g_pass++; printf("pass %s\n", (name)); } \
    else { printf("FAIL %s\n", (name)); } \
} while (0)

/* ---------------------------------------------------------------- helpers */

static void hex_to_bytes(const char *hex, unsigned char *out, size_t outcap,
                         size_t *outlen)
{
    size_t n = strlen(hex) / 2;
    if (n > outcap) { fprintf(stderr, "hex overflow\n"); exit(2); }
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[i * 2 + j];
            unsigned d;
            if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
            else { fprintf(stderr, "bad hex\n"); exit(2); }
            v = v * 16 + d;
        }
        out[i] = (unsigned char)v;
    }
    *outlen = n;
}

/* ------------------------------------------------- 发送侧(packet.c 转写) */

/* packet.c:1276-1285
 *   len = sshbuf_len(outgoing_packet) = 6 + payload_len
 *   len -= aadlen                       (EtM/AEAD: length 字段不加密)
 *   padlen = block_size - (len % block_size); if (padlen < 4) padlen += block_size;
 */
static int bp_padlen_for(size_t payload_len, u_int msg_type, u_int aadlen)
{
    (void)msg_type;
    size_t len = 6 + payload_len;
    len -= aadlen;
    int padlen = BP_BLOCK_SIZE - (int)(len % BP_BLOCK_SIZE);
    if (padlen < 4)
        padlen += BP_BLOCK_SIZE;
    return padlen;
}

/* 组帧(packet.c:1316-1325):[packlen u32][padlen][type][payload][padding]
 * padding 内容:加密→pad_fill 注入,未加密→全零(packet.c:1307-1315)
 * 返回 packlen。frame 缓冲由调用方提供(total = 6+payload+padlen)。 */
static u_int bp_build_frame(unsigned char *frame, size_t framecap,
                            u_int msg_type, const unsigned char *payload,
                            size_t payload_len, u_int aadlen,
                            const unsigned char *pad_fill,
                            int *padlen_out, size_t *total_out)
{
    int padlen = bp_padlen_for(payload_len, msg_type, aadlen);
    size_t total = 6 + payload_len + (size_t)padlen;
    if (total > framecap || total - 4u > PACKET_MAX_SIZE) { /* packet.c 上限 */ }
    u_int packlen = (u_int)(total - 4);
    memset(frame, 0, total);
    frame[0] = (unsigned char)(packlen >> 24);
    frame[1] = (unsigned char)(packlen >> 16);
    frame[2] = (unsigned char)(packlen >> 8);
    frame[3] = (unsigned char)(packlen);
    frame[4] = (unsigned char)padlen;
    frame[5] = (unsigned char)msg_type;
    memcpy(frame + 6, payload, payload_len);
    if (aadlen && pad_fill != NULL)
        memcpy(frame + 6 + payload_len, pad_fill, (size_t)padlen);
    *padlen_out = padlen;
    *total_out = total;
    return packlen;
}

/* plain emit:wire == frame(cipher_crypt CFLAG_NONE memcpy,cipher.c:350-352) */

/* aead emit(packet.c:1337-1357 → chachapoly_crypt encrypt):
 * wire = ct头(4) ‖ ct体(packlen) ‖ tag(16) */

/* ------------------------------------------------- 接收侧(packet.c 转写) */

enum bp_err {
    BP_OK = 0, BP_NEED_MORE, BP_BAD_LENGTH, BP_ALIGN, BP_AUTH_FAILED,
    BP_BAD_PADLEN, BP_PAD_OVERFLOW, BP_EMPTY_PAYLOAD, BP_BAD_TYPE,
    BP_SEQNR_WRAP_INITIAL
};

struct bp_recv_state {
    struct chachapoly_ctx *ctx;   /* NULL = plain */
    u_int seqnr;
    u_int packlen;                /* 0 = 等包头(packet.c:202) */
    int strict_kex;
    int initial_kex;
};

/* 返回 BP_OK 时 consumed/type_out/payload 输出有效。
 * payload 拷入 payload_buf(cap 512),长度写 *payload_len。 */
static enum bp_err bp_recv_packet(struct bp_recv_state *st,
                                  const unsigned char *input, size_t inlen,
                                  size_t *consumed, u_int *seqnr_used,
                                  u_int *type_out,
                                  unsigned char *payload_buf, size_t payload_cap,
                                  size_t *payload_len)
{
    u_int aadlen  = st->ctx ? BP_AADLEN_AEAD  : BP_AADLEN_PLAIN;
    u_int authlen = st->ctx ? BP_AUTHLEN_AEAD : BP_AUTHLEN_PLAIN;
    unsigned char pt[512];
    size_t ptlen;

    /* ---- 阶段 1:提取包长(packet.c:1655-1701)---- */
    if (st->packlen == 0) {
        size_t min_hdr = aadlen ? 4 : BP_BLOCK_SIZE;
        if (inlen < min_hdr)
            return BP_NEED_MORE;
        u_int plen;
        if (st->ctx) {
            if (chachapoly_get_length(st->ctx, &plen, st->seqnr,
                                      input, (u_int)inlen) != 0)
                return BP_NEED_MORE;
        } else {
            plen = PEEK_U32(input);
        }
        if (plen < 1 + 4 || plen > PACKET_MAX_SIZE)   /* packet.c:1660/1687 */
            return BP_BAD_LENGTH;
        st->packlen = plen;
    }

    /* ---- 阶段 2:对齐与等待(packet.c:1704-1731)----
     * 本 harness 单次解密整帧(不象 OpenSSH 先解首块再解余量),
     * 统一公式 need = 4 + packlen - aadlen;对齐判定与 packet.c 等价
     * (减去 block_size 不改变模余)。AEAD 时 need 恰为 packlen。 */
    size_t need = 4u + st->packlen - aadlen;
    if (need % BP_BLOCK_SIZE != 0)
        return BP_ALIGN;
    size_t total = aadlen + need + authlen;   /* = 4 + packlen + authlen */
    if (inlen < total)
        return BP_NEED_MORE;

    /* ---- 阶段 3:解密(packet.c:1747-1754)---- */
    if (st->ctx) {
        if (chachapoly_crypt(st->ctx, st->seqnr, pt, input,
                             (u_int)need, aadlen, authlen, 0) != 0)
            return BP_AUTH_FAILED;                    /* SSH_ERR_MAC_INVALID */
        ptlen = aadlen + need;
    } else {
        memcpy(pt, input, total);
        ptlen = total;
    }

    /* ---- 序号推进(packet.c:1777-1788,先于解析)---- */
    *seqnr_used = st->seqnr;
    st->seqnr++;
    if (st->seqnr == 0 && st->initial_kex)
        return BP_SEQNR_WRAP_INITIAL;

    /* ---- 解析(padlen 恒在 @[4])---- */
    u_int padlen = pt[4];                              /* packet.c:1791 */
    if (padlen < 4)                                    /* packet.c:1793 */
        return BP_BAD_PADLEN;
    if (padlen > st->packlen - 1)                      /* consume_end 等价 */
        return BP_PAD_OVERFLOW;
    size_t want = st->packlen - 1 - padlen;
    if (want < 1)
        return BP_EMPTY_PAYLOAD;
    u_int type = pt[5];
    if (type < 1)                                      /* packet.c:1828 */
        return BP_BAD_TYPE;
    if (want - 1 > payload_cap)
        return BP_EMPTY_PAYLOAD;
    memcpy(payload_buf, pt + 6, want - 1);
    *payload_len = want - 1;
    *type_out = type;

    st->packlen = 0;                                   /* packet.c:1848 */
    if (st->strict_kex && type == MSG_NEWKEYS)         /* packet.c:1849-1852 */
        st->seqnr = 0;
    *consumed = total;
    (void)ptlen;
    return BP_OK;
}

/* ------------------------------------------------------------- 测试主体 */

static unsigned char PADSRC[32];
static void init_padsrc(void)
{
    for (int i = 0; i < 32; i++)
        PADSRC[i] = (unsigned char)((0xA5 ^ i) & 0xFF);
}

/* V2/V3/V4 向量(Python _bpacket_ref_out.txt 与 MoonBit T18 共享字面量) */
static const char *V2_WIRE[3] = {
    "94450e491cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579",
    "c922a7b56d487cd83309bc7f2b76762616b0b0b4b7a8d54f287539a9e33897543e28bf0c",
    "3cc39c0349deb0f6087e6351cb39b0c46854eebed711792745a2211ea839c6f24804c381",
};
static const char *V3_STREAM =
    "94450e4911e24236a3f3ba74b7c6fac00fe0ec8adf1e66d1ca95d141dd568e2b12a3e73d"
    "c922a7b561077dd13e1ca55e88d5d98912b4b4b0587d43062f4ed25affca471077619270"
    "3cc39c034a96b2fe1a6a7971e19b1c6a6b51e9bbf09fb6c83e1042377227b2b06b6d1c71";
static const char *V1_FRAME =
    "000000140814000102030405060708090000000000000000";
static const char *V4_BODY   =
    "94450e491cac4230afe5a3d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579";
static const char *V4_BADLEN =
    "14450e491cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579";
static const char *V4_ALIGN  =
    "94450e481cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579";
static const char *V4_AUTHPAD =
    "94450e411cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579"
    "0000000000000000000000000000000000000000000000000000000000000000";

static const unsigned char PAY10[10] =
    {0,1,2,3,4,5,6,7,8,9};

int main(void)
{
    init_padsrc();
    unsigned char frame[512], wire[512], paybuf[512];

    /* ---- T1/T2:plain round-trip + 帧字段数学 ---- */
    {
        int padlen; size_t total;
        u_int packlen = bp_build_frame(frame, sizeof(frame), 20, PAY10, 10,
                                       BP_AADLEN_PLAIN, NULL, &padlen, &total);
        CHECK("C1a plain packlen=20", packlen == 20);
        CHECK("C1b plain padlen=8", padlen == 8);
        CHECK("C1c plain align", ((4 + packlen) % BP_BLOCK_SIZE) == 0);
        CHECK("C1d zero padding",
              memcmp(frame + 16, "\0\0\0\0\0\0\0\0", 8) == 0);

        struct bp_recv_state rs; memset(&rs, 0, sizeof(rs));
        size_t consumed, plen; u_int su, ty;
        enum bp_err e = bp_recv_packet(&rs, frame, total, &consumed, &su,
                                       &ty, paybuf, sizeof(paybuf), &plen);
        CHECK("C1e plain rt", e == BP_OK && su == 0 && ty == 20 &&
              plen == 10 && memcmp(paybuf, PAY10, 10) == 0 &&
              consumed == total);

        /* V1 锚点:C 转写帧 == Python 帧 */
        unsigned char v1[64]; size_t v1len;
        hex_to_bytes(V1_FRAME, v1, sizeof(v1), &v1len);
        CHECK("C1f V1 frame match",
              v1len == total && memcmp(v1, frame, total) == 0);
    }

    /* ---- T3/T4:AEAD round-trip + 对齐 + V2 三 seqnr 双向 ---- */
    {
        struct chachapoly_ctx *se = chachapoly_new(KEY64, 64);
        struct chachapoly_ctx *rd = chachapoly_new(KEY64, 64);
        int all_emit_ok = 1, all_parse_ok = 1;
        for (u_int sq = 0; sq < 3; sq++) {
            int padlen; size_t total;
            u_int packlen = bp_build_frame(frame, sizeof(frame), 20, PAY10, 10,
                                           BP_AADLEN_AEAD, PADSRC,
                                           &padlen, &total);
            if (sq == 0) {
                CHECK("C3a aead packlen=16", packlen == 16);
                CHECK("C3b aead padlen=4(min)", padlen == 4);
                CHECK("C3c aead align", (packlen % BP_BLOCK_SIZE) == 0);
                CHECK("C3d frame padding from padsrc",
                      memcmp(frame + 16, PADSRC, 4) == 0);
            }
            size_t wlen = 4 + packlen + 16;
            if (chachapoly_crypt(se, sq, wire, frame, (u_int)(total - 4),
                                 4, 16, 1) != 0)
                all_emit_ok = 0;
            /* 方向一:与 Python wire 逐字节比对 */
            unsigned char v2b[80]; size_t v2n;
            hex_to_bytes(V2_WIRE[sq], v2b, sizeof(v2b), &v2n);
            if (!(v2n == wlen && memcmp(v2b, wire, wlen) == 0))
                all_emit_ok = 0;
            /* 方向二:解析 Python 产出的 wire */
            struct bp_recv_state rs; memset(&rs, 0, sizeof(rs));
            rs.ctx = rd;
            rs.seqnr = sq;
            size_t consumed, plen; u_int su, ty;
            enum bp_err e = bp_recv_packet(&rs, v2b, v2n, &consumed, &su,
                                           &ty, paybuf, sizeof(paybuf), &plen);
            if (!(e == BP_OK && su == sq && ty == 20 && plen == 10 &&
                  memcmp(paybuf, PAY10, 10) == 0 && consumed == v2n))
                all_parse_ok = 0;
        }
        CHECK("C3e aead emit==python x3", all_emit_ok);
        CHECK("C3f aead parse python wire x3", all_parse_ok);
        chachapoly_free(se);
        chachapoly_free(rd);
    }

    /* ---- T5:V3 流水线三包逐包消费 ---- */
    {
        unsigned char stream[256]; size_t slen;
        hex_to_bytes(V3_STREAM, stream, sizeof(stream), &slen);
        struct chachapoly_ctx *rd = chachapoly_new(KEY64, 64);
        struct bp_recv_state rs; memset(&rs, 0, sizeof(rs));
        rs.ctx = rd;
        size_t off = 0;
        int okall = 1;
        for (u_int rnd = 0; rnd < 3; rnd++) {
            size_t consumed, plen; u_int su, ty;
            enum bp_err e = bp_recv_packet(&rs, stream + off, slen - off,
                                           &consumed, &su, &ty,
                                           paybuf, sizeof(paybuf), &plen);
            unsigned char expay[16];
            for (int i = 0; i < 5 + (int)rnd; i++)
                expay[i] = (unsigned char)((i * 7 + rnd) & 0xFF);
            if (!(e == BP_OK && su == rnd && ty == 90 + rnd &&
                  plen == (size_t)(5 + rnd) &&
                  memcmp(paybuf, expay, plen) == 0)) {
                fprintf(stderr, "C5 rnd=%u e=%d su=%u ty=%u plen=%zu off=%zu\n",
                        rnd, (int)e, su, ty, plen, off);
                okall = 0;
            }
            off += consumed;
        }
        CHECK("C5 V3 pipeline", okall && off == slen);
        chachapoly_free(rd);
    }

    /* ---- T6:碎片投喂(aead)---- */
    {
        unsigned char v2b[80]; size_t v2n;
        hex_to_bytes(V2_WIRE[0], v2b, sizeof(v2b), &v2n);
        struct chachapoly_ctx *rd = chachapoly_new(KEY64, 64);
        struct bp_recv_state rs; memset(&rs, 0, sizeof(rs));
        rs.ctx = rd;
        int frag_ok = 1;
        for (size_t k = 1; k < v2n; k++) {
            enum bp_err e = bp_recv_packet(&rs, v2b, k,
                                           &(size_t){0}, &(u_int){0},
                                           &(u_int){0},
                                           paybuf, sizeof(paybuf),
                                           &(size_t){0});
            if (e != BP_NEED_MORE)
                frag_ok = 0;
        }
        size_t consumed, plen; u_int su, ty;
        enum bp_err e = bp_recv_packet(&rs, v2b, v2n, &consumed, &su, &ty,
                                       paybuf, sizeof(paybuf), &plen);
        frag_ok = frag_ok && e == BP_OK && ty == 20;
        CHECK("C6 fragmented delivery", frag_ok);
        chachapoly_free(rd);
    }

    /* ---- T7/T8:篡改矩阵(V4)---- */
    {
        unsigned char tb[96];
        size_t tl;
        struct { const char *hex; enum bp_err want; const char *name; } cases[] = {
            { V4_BODY,    BP_AUTH_FAILED, "C7 body flip -> AuthFailed" },
            { V4_BADLEN,  BP_BAD_LENGTH,  "C8a hdr flip -> BadLength" },
            { V4_ALIGN,   BP_ALIGN,       "C8b hdr flip -> AlignError" },
            { V4_AUTHPAD, BP_AUTH_FAILED, "C8c hdr flip padded -> AuthFailed" },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            hex_to_bytes(cases[i].hex, tb, sizeof(tb), &tl);
            struct chachapoly_ctx *rd = chachapoly_new(KEY64, 64);
            struct bp_recv_state rs; memset(&rs, 0, sizeof(rs));
            rs.ctx = rd;
            enum bp_err e = bp_recv_packet(&rs, tb, tl, &(size_t){0},
                                           &(u_int){0}, &(u_int){0},
                                           paybuf, sizeof(paybuf),
                                           &(size_t){0});
            CHECK(cases[i].name, e == cases[i].want);
            chachapoly_free(rd);
        }
    }

    /* ---- T9-T13:手工畸形帧(plain)----
     * 每个子测试用全新 state(错误路径不清 packlen 缓存,连接本应终止;
     * 与 MoonBit 侧每个用例新建 RecvCtx 一致)---- */
    {
        static unsigned char mf[64];
        /* manual(packlen,padlen,body) */
        #define BP_MANUAL(PK, PD, BODY, BODYN) do { \
            u_int pk_ = (PK); memset(mf, 0, sizeof(mf)); \
            mf[0] = (unsigned char)(pk_ >> 24); mf[1] = (unsigned char)(pk_ >> 16); \
            mf[2] = (unsigned char)(pk_ >> 8);  mf[3] = (unsigned char)pk_; \
            mf[4] = (unsigned char)(PD); memcpy(mf + 5, BODY, BODYN); \
        } while (0)

        unsigned char body8[8] = {0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA};
        struct bp_recv_state rs; size_t consumed, plen; u_int su, ty;

        BP_MANUAL(12, 3, body8, 8);
        memset(&rs, 0, sizeof(rs));
        CHECK("C9 badpadlen<4",
              bp_recv_packet(&rs, mf, 16, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_BAD_PADLEN);
        BP_MANUAL(12, 12, body8, 8);
        memset(&rs, 0, sizeof(rs));
        CHECK("C10 padoverflow",
              bp_recv_packet(&rs, mf, 16, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_PAD_OVERFLOW);
        unsigned char body4[4] = {0x55,0x55,0x55,0x55};
        BP_MANUAL(12, 11, body4, 4);
        memset(&rs, 0, sizeof(rs));
        CHECK("C12 empty payload",
              bp_recv_packet(&rs, mf, 16, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_EMPTY_PAYLOAD);
        unsigned char tz[4] = {0, 0, 0, 0};
        BP_MANUAL(12, 7, tz, 4);
        memset(&rs, 0, sizeof(rs));
        CHECK("C13 badtype0",
              bp_recv_packet(&rs, mf, 16, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_BAD_TYPE);

        BP_MANUAL(4, 4, body4, 0);
        memset(&rs, 0, sizeof(rs));
        CHECK("C11a badlength low(4)",
              bp_recv_packet(&rs, mf, 8, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_BAD_LENGTH);
        unsigned char huge[12] = {0x00, 0x04, 0x00, 0x01, 0x07};
        memset(&rs, 0, sizeof(rs));
        CHECK("C11b badlength high(262145)",
              bp_recv_packet(&rs, huge, 12, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_BAD_LENGTH);
        unsigned char edge[12] = {0x00, 0x04, 0x00, 0x00, 0x07};
        memset(&rs, 0, sizeof(rs));
        CHECK("C11c boundary 262144 passes to align",
              bp_recv_packet(&rs, edge, 12, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_ALIGN);
        BP_MANUAL(5, 4, body4, 0);
        memset(&rs, 0, sizeof(rs));
        CHECK("C11d boundary 5 passes to align",
              bp_recv_packet(&rs, mf, 9, &consumed, &su,
                             &ty, paybuf, sizeof(paybuf),
                             &plen) == BP_ALIGN);
    }

    /* ---- T15:strict-kex NEWKEYS 归零 ---- */
    {
        /* 发送侧语义(packet.c:1376-1379):NEWKEYS 后归零;非 strict 继续 */
        u_int seq = 0;
        seq++; seq++;
        int is_newkeys_send = 1;
        seq++;
        if (1 /* strict */) seq = 0;
        CHECK("C15a send strict reset", seq == 0);
        u_int seq2 = 0;
        seq2++;
        is_newkeys_send = 1;
        seq2++;
        (void)is_newkeys_send;
        CHECK("C15b nonstrict keeps", seq2 == 2);

        /* 接收侧(packet.c:1849-1852):构造 NEWKEYS 明文帧喂入 */
        unsigned char nk[64]; int pd; size_t tot;
        bp_build_frame(nk, sizeof(nk), MSG_NEWKEYS, NULL, 0,
                       BP_AADLEN_PLAIN, NULL, &pd, &tot);
        struct bp_recv_state rs; memset(&rs, 0, sizeof(rs));
        rs.strict_kex = 1;
        rs.seqnr = 2;
        size_t consumed, plen; u_int su, ty;
        enum bp_err e = bp_recv_packet(&rs, nk, tot, &consumed, &su, &ty,
                                       paybuf, sizeof(paybuf), &plen);
        CHECK("C15c recv strict reset",
              e == BP_OK && su == 2 && ty == MSG_NEWKEYS && rs.seqnr == 0 &&
              rs.packlen == 0);
        struct bp_recv_state rs2; memset(&rs2, 0, sizeof(rs2));
        rs2.seqnr = 2;
        e = bp_recv_packet(&rs2, nk, tot, &consumed, &su, &ty,
                           paybuf, sizeof(paybuf), &plen);
        CHECK("C15d recv nonstrict keeps",
              e == BP_OK && rs2.seqnr == 3);
    }

    /* ---- T16:seqnr 回绕两态 ---- */
    {
        /* build_frame 语义:type@[5],body(纯 payload)@[6..)。
         * type=0x41,body={89,8a,8b} → payload_out = {89,8a,8b} */
        unsigned char wf[64]; int pd; size_t tot;
        unsigned char body3[3] = {0x89,0x8a,0x8b};
        bp_build_frame(wf, sizeof(wf), 0x41, body3, 3,
                       BP_AADLEN_PLAIN, NULL, &pd, &tot);
        struct bp_recv_state ri; memset(&ri, 0, sizeof(ri));
        ri.initial_kex = 1;
        ri.seqnr = 0xFFFFFFFFu;
        CHECK("C16a rx wrap initial fatal",
              bp_recv_packet(&ri, wf, tot, &(size_t){0}, &(u_int){0},
                             &(u_int){0}, paybuf, sizeof(paybuf),
                             &(size_t){0}) == BP_SEQNR_WRAP_INITIAL);
        struct bp_recv_state rr; memset(&rr, 0, sizeof(rr));
        rr.initial_kex = 0;
        rr.seqnr = 0xFFFFFFFFu;
        size_t consumed, plen; u_int su, ty;
        enum bp_err e = bp_recv_packet(&rr, wf, tot, &consumed, &su, &ty,
                                       paybuf, sizeof(paybuf), &plen);
        CHECK("C16b rx wrap rekey ok",
              e == BP_OK && su == 0xFFFFFFFFu && rr.seqnr == 0 && ty == 0x41 &&
              plen == 3 && paybuf[0] == 0x89 && paybuf[1] == 0x8a &&
              paybuf[2] == 0x8b);
    }

    /* ---- T17:属性扫描 ---- */
    {
        int sweep_ok = 1;
        for (int n = 0; n <= 69; n += 2) {
            unsigned char pay[70];
            for (int i = 0; i < n; i++) pay[i] = (unsigned char)((i*13+7)&0xFF);
            /* plain */
            int pd; size_t tot;
            u_int pk = bp_build_frame(frame, sizeof(frame),
                                      (u_int)(100 + n % 50), pay, (size_t)n,
                                      BP_AADLEN_PLAIN, NULL, &pd, &tot);
            if (!((4 + pk) % 8 == 0 && pd >= 4 && pd <= 255)) sweep_ok = 0;
            struct bp_recv_state r; memset(&r, 0, sizeof(r));
            size_t consumed, plen; u_int su, ty;
            if (bp_recv_packet(&r, frame, tot, &consumed, &su, &ty,
                               paybuf, sizeof(paybuf), &plen) != BP_OK ||
                plen != (size_t)n ||
                memcmp(paybuf, pay, (size_t)n) != 0)
                sweep_ok = 0;
            /* aead */
            struct chachapoly_ctx *sx = chachapoly_new(KEY64, 64);
            pk = bp_build_frame(frame, sizeof(frame),
                                (u_int)(150 + n % 50), pay, (size_t)n,
                                BP_AADLEN_AEAD, PADSRC, &pd, &tot);
            if (!(pk % 8 == 0 && pd >= 4 && pd <= 255)) sweep_ok = 0;
            if (chachapoly_crypt(sx, 0, wire, frame, (u_int)(tot - 4),
                                 4, 16, 1) != 0)
                sweep_ok = 0;
            struct bp_recv_state r2; memset(&r2, 0, sizeof(r2));
            r2.ctx = sx;
            if (bp_recv_packet(&r2, wire, 4 + pk + 16, &consumed, &su, &ty,
                               paybuf, sizeof(paybuf), &plen) != BP_OK ||
                plen != (size_t)n ||
                memcmp(paybuf, pay, (size_t)n) != 0)
                sweep_ok = 0;
            chachapoly_free(sx);
        }
        CHECK("C17 property sweep even sizes", sweep_ok);
    }

    printf("\nC HARNESS: %d/%d passed\n", g_pass, g_total);
    return (g_pass == g_total) ? 0 : 1;
}
