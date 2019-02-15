// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef PTLS_OPENSSL
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <picotls/openssl.h>
#endif

#include <khash.h>
#include <picotls/minicrypto.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "bitset.h"
#include "conn.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


#ifdef PTLS_OPENSSL
#define CIPHER_SUITE ptls_openssl_aes128gcmsha256
#else
#define CIPHER_SUITE ptls_minicrypto_aes128gcmsha256
#endif


struct tls_ticket {
    char * sni;
    char * alpn;
    uint8_t * ticket;
    size_t ticket_len;
    struct transport_params tp;
    uint32_t vers;
    uint8_t _unused[4];
    splay_entry(tls_ticket) node;
};


struct tickets_by_peer {
    splay_head(, tls_ticket);
    char file_name[MAXPATHLEN];
};

static int __attribute__((nonnull))
tls_ticket_cmp(const struct tls_ticket * const a,
               const struct tls_ticket * const b)
{
    int diff = strcmp(a->sni, b->sni);
    if (diff)
        return diff;

    diff = strcmp(a->alpn, b->alpn);
    return diff;
}


SPLAY_PROTOTYPE(tickets_by_peer, tls_ticket, node, tls_ticket_cmp)
SPLAY_GENERATE(tickets_by_peer, tls_ticket, node, tls_ticket_cmp)

ptls_context_t tls_ctx = {0};
static struct tickets_by_peer tickets = {splay_initializer(tickets), {"\0"}};

#ifdef PTLS_OPENSSL
static ptls_openssl_sign_certificate_t sign_cert = {0};
static ptls_openssl_verify_certificate_t verifier = {0};
#endif

// first entry is client default, if not otherwise specified
static const ptls_iovec_t alpn[] = {{(uint8_t *)"hq-18", 5},
                                    {(uint8_t *)"h3-18", 5}};
static const size_t alpn_cnt = sizeof(alpn) / sizeof(alpn[0]);

static struct cipher_ctx dec_tckt;
static struct cipher_ctx enc_tckt;

static FILE * tls_log_file;


#define QUIC_TP 0xffa5

#define TP_OCID 0x00    ///< original_connection_id
#define TP_IDTO 0x01    ///< idle_timeout
#define TP_SRT 0x02     ///< stateless_reset_token
#define TP_MPS 0x03     ///< max_packet_size
#define TP_IMD 0x04     ///< initial_max_data
#define TP_IMSD_BL 0x05 ///< initial_max_stream_data_bidi_local
#define TP_IMSD_BR 0x06 ///< initial_max_stream_data_bidi_remote
#define TP_IMSD_U 0x07  ///< initial_max_stream_data_uni
#define TP_IMSB 0x08    ///< initial_max_streams_bidi
#define TP_IMSU 0x09    ///< initial_max_streams_uni
#define TP_ADE 0x0a     ///< ack_delay_exponent
#define TP_MAD 0x0b     ///< max_ack_delay
#define TP_DMIG 0x0c    ///< disable_migration
#define TP_PRFA 0x0d    ///< preferred_address
#define TP_MAX (TP_PRFA + 1)


// quicly shim
#define AEAD_BASE_LABEL PTLS_HKDF_EXPAND_LABEL_PREFIX "quic "
#define st_quicly_cipher_context_t cipher_ctx
#define quicly_hexdump(a, b, c) hex2str(a, b)
#define QUICLY_DEBUG 0


// from quicly
void dispose_cipher(struct st_quicly_cipher_context_t * ctx)
{
    if (ctx->aead) {
        ptls_aead_free(ctx->aead);
        ctx->aead = 0;
    }
    if (ctx->header_protection) {
        ptls_cipher_free(ctx->header_protection);
        ctx->header_protection = 0;
    }
}


// from quicly (with mods for key update)
static int setup_cipher(ptls_cipher_context_t ** hp_ctx,
                        ptls_aead_context_t ** aead_ctx,
                        ptls_aead_algorithm_t * aead,
                        ptls_hash_algorithm_t * hash,
                        int is_enc,
                        const void * secret)
{
    uint8_t hpkey[PTLS_MAX_SECRET_SIZE] = {0};
    int ret;

    // *hp_ctx = NULL;
    // *aead_ctx = NULL;

    if (hp_ctx) {
        if ((ret = ptls_hkdf_expand_label(
                 hash, hpkey, aead->ctr_cipher->key_size,
                 ptls_iovec_init(secret, hash->digest_size), "quic hp",
                 ptls_iovec_init(NULL, 0), NULL)) != 0)
            goto Exit;
        if ((*hp_ctx = ptls_cipher_new(aead->ctr_cipher, is_enc, hpkey)) ==
            NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
    }
    if ((*aead_ctx = ptls_aead_new(aead, hash, is_enc, secret,
                                   AEAD_BASE_LABEL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (QUICLY_DEBUG) {
        char *secret_hex = quicly_hexdump(secret, hash->digest_size, SIZE_MAX),
             *hpkey_hex =
                 quicly_hexdump(hpkey, aead->ctr_cipher->key_size, SIZE_MAX);
        fprintf(stderr, "%s:\n  aead-secret: %s\n  hp-key: %s\n", __func__,
                secret_hex, hpkey_hex);
        // free(secret_hex);
        // free(hpkey_hex);
    }

    ret = 0;
Exit:
    if (ret != 0) {
        if (*aead_ctx != NULL) {
            ptls_aead_free(*aead_ctx);
            *aead_ctx = NULL;
        }
        if (hp_ctx && *hp_ctx != NULL) {
            ptls_cipher_free(*hp_ctx);
            *hp_ctx = NULL;
        }
    }
    ptls_clear_memory(hpkey, sizeof(hpkey));
    return ret;
}


// from quicly (with mods for key update)
static int setup_initial_key(struct st_quicly_cipher_context_t * ctx,
                             ptls_cipher_suite_t * cs,
                             const void * master_secret,
                             const char * label,
                             int is_enc,
                             void * new_secret)
{
    uint8_t _aead_secret[PTLS_MAX_DIGEST_SIZE];
    uint8_t * const aead_secret = new_secret ? new_secret : _aead_secret;

    int ret;

    if ((ret = ptls_hkdf_expand_label(
             cs->hash, aead_secret, cs->hash->digest_size,
             ptls_iovec_init(master_secret, cs->hash->digest_size), label,
             ptls_iovec_init(NULL, 0), NULL)) != 0)
        goto Exit;
    if ((ret =
             setup_cipher(new_secret ? 0 : &ctx->header_protection, &ctx->aead,
                          cs->aead, cs->hash, is_enc, aead_secret)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(aead_secret, sizeof(aead_secret));
    return ret;
}


// from quicly (with mods to the setup_initial_key call)
static int setup_initial_encryption(struct st_quicly_cipher_context_t * ingress,
                                    struct st_quicly_cipher_context_t * egress,
                                    ptls_cipher_suite_t ** cipher_suites,
                                    ptls_iovec_t cid,
                                    int is_client)
{
    static const uint8_t salt[] = {0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70,
                                   0xc4, 0x1b, 0xef, 0xcf, 0x80, 0x31, 0x33,
                                   0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0};
    static const char * labels[2] = {"client in", "server in"};
    ptls_cipher_suite_t ** cs;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* find aes128gcm cipher */
    for (cs = cipher_suites;; ++cs) {
        assert(cs != NULL);
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            break;
    }

    /* extract master secret */
    if ((ret = ptls_hkdf_extract((*cs)->hash, secret,
                                 ptls_iovec_init(salt, sizeof(salt)), cid)) !=
        0)
        goto Exit;

    /* create aead contexts */
    if ((ret = setup_initial_key(ingress, *cs, secret, labels[is_client], 0,
                                 0)) != 0)
        goto Exit;
    if ((ret = setup_initial_key(egress, *cs, secret, labels[!is_client], 1,
                                 0)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

static int __attribute__((nonnull))
on_ch(ptls_on_client_hello_t * const self __attribute__((unused)),
      ptls_t * const tls,
      ptls_on_client_hello_parameters_t * const params)
{
    if (params->server_name.len) {
        // TODO verify the SNI instead of accepting whatever the client sent
        warn(INF, "\tSNI = %.*s", (int)params->server_name.len,
             params->server_name.base);
        ensure(ptls_set_server_name(tls, (const char *)params->server_name.base,
                                    params->server_name.len) == 0,
               "ptls_set_server_name");
    } else
        warn(INF, "\tSNI = ");

    if (params->negotiated_protocols.count == 0) {
        warn(WRN, "\tALPN = ");
        return 0;
    }

    size_t j;
    for (j = 0; j < alpn_cnt; j++)
        for (size_t i = 0; i < params->negotiated_protocols.count; i++)
            if (memcmp(params->negotiated_protocols.list[i].base, alpn[j].base,
                       MIN(params->negotiated_protocols.list[i].len,
                           alpn[j].len)) == 0)
                goto done;

    if (j == alpn_cnt) {
        warn(WRN, "\tALPN = %.*s (and maybe others, none supported, ignoring)",
             (int)params->negotiated_protocols.list[0].len,
             params->negotiated_protocols.list[0].base);
        return 0;
    }

done:
    // mark this ALPN as negotiated
    ptls_set_negotiated_protocol(tls, (char *)alpn[j].base, alpn[j].len);
    warn(INF, "\tALPN = %.*s", (int)alpn[j].len, alpn[j].base);

    return 0;
}


static int filter_tp(ptls_t * tls __attribute__((unused)),
                     struct st_ptls_handshake_properties_t * properties
                     __attribute__((unused)),
                     uint16_t type)
{
    return type == QUIC_TP;
}


static uint16_t chk_tp_clnt(struct q_conn * const c,
                            const uint8_t * const buf,
                            const uint16_t len,
                            const uint16_t pos)
{
    uint16_t i = pos;

    uint32_t neg_vers = 0;
    i = dec(&neg_vers, buf, len, i, sizeof(neg_vers), "0x%08x");

    // validate that the negotiated version is in use
    if (unlikely(neg_vers != c->vers)) {
        err_close(c, ERR_VERSION_NEGOTIATION, FRM_CRY,
                  "neg vers 0x%08x != used vers 0x%08x", neg_vers, c->vers);
        return 0;
    }

    // parse server versions
    uint8_t n;
    i = dec(&n, buf, len, i, sizeof(n), "%u");
    const uint16_t vpos = i;
    bool found = false;
    for (uint16_t v = n; v > 0; v -= sizeof(uint32_t)) {
        uint32_t vers = 0;
        i = dec(&vers, buf, len, i, sizeof(vers), "0x%08x");
        if (vers == c->vers)
            found = true;
    }

    // validate that the negotiated version was found
    if (unlikely(found == false)) {
        err_close(c, ERR_VERSION_NEGOTIATION, FRM_CRY,
                  "neg vers 0x%08x not found in tp", c->vers);
        return 0;
    }

    // validate that version negotiation on these values has same result
    const uint32_t verify_vers = clnt_vneg(&buf[vpos], n);
    if (unlikely(verify_vers != c->vers)) {
        err_close(c, ERR_VERSION_NEGOTIATION, FRM_CRY,
                  "would have picked 0x%08x instead of 0x%08x", verify_vers,
                  c->vers);
        return 0;
    }

    return i;
}


static uint16_t chk_tp_serv(struct q_conn * const c,
                            const uint8_t * const buf,
                            const uint16_t len,
                            const uint16_t pos)
{
    uint16_t i = pos;

    uint32_t vers_initial;
    i = dec(&vers_initial, buf, len, i, sizeof(vers_initial), "0x%08x");

    if (c->vers != vers_initial && unlikely(vers_supported(vers_initial))) {
        err_close(c, ERR_VERSION_NEGOTIATION, FRM_CRY,
                  "vers_initial 0x%08x is supported - MITM?", vers_initial);
        return 0;
    }

    return i;
}


#define dec_tp(var)                                                            \
    __extension__({                                                            \
        uint16_t _l;                                                           \
        i = dec(&_l, buf, len, i, sizeof(_l), "%u");                           \
        ensure(_l <= sizeof(uint64_t), "invalid len %u", _l);                  \
        if (_l)                                                                \
            i = dec((var), buf, len, i, 0, "%u");                              \
        _l;                                                                    \
    })

#define dec_tp_buf(var, w)                                                     \
    __extension__({                                                            \
        uint16_t _l;                                                           \
        i = dec(&_l, buf, len, i, sizeof(_l), "%u");                           \
        ensure(_l <= (w), "invalid len %u", _l);                               \
        if (_l)                                                                \
            i = dec_buf((var), buf, len, i, _l);                               \
        _l;                                                                    \
    })


static int chk_tp(ptls_t * tls __attribute__((unused)),
                  ptls_handshake_properties_t * properties,
                  ptls_raw_extension_t * slots)
{
    ensure(slots[0].type == QUIC_TP, "have tp");
    ensure(slots[1].type == UINT16_MAX, "have end");

    // get connection based on properties pointer
    struct q_conn * const c =
        (void *)((char *)properties - offsetof(struct tls, tls_hshk_prop) -
                 offsetof(struct q_conn, tls));

    // set up parsing
    const uint8_t * const buf = slots[0].data.base;
    uint16_t len = (uint16_t)slots[0].data.len;
    uint16_t i = 0;

    if (c->is_clnt)
        i = chk_tp_clnt(c, buf, len, i);
    else
        i = chk_tp_serv(c, buf, len, i);
    if (unlikely(i == 0))
        return i;

    uint16_t tpl;
    i = dec(&tpl, buf, len, i, sizeof(tpl), "%u");
    if (tpl != len - i) {
        err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY, "tp len %u incorrect",
                  tpl);
        return 1;
    }
    len = i + tpl;

    // keep track of which transport parameters we've seen before
    bitset_define(tp_list, TP_MAX);
    struct tp_list tp_list = bitset_t_initializer(0);

    while (i < len) {
        uint16_t tp = 0;
        i = dec(&tp, buf, len, i, sizeof(tp), "0x%04x");

        // skip unknown TPs
        if (tp >= TP_MAX) {
            uint16_t unknown_len;
            i = dec(&unknown_len, buf, len, i, sizeof(unknown_len), "%u");
            warn(WRN, "skipping unknown tp 0x%04x w/len %u", tp, unknown_len);
            i += unknown_len;
            continue;
        }

        // check if this transport parameter is a duplicate
        if (bit_isset(TP_MAX, tp, &tp_list)) {
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "duplicate tp 0x%04x", tp);
            return 1;
        }
        bit_set(TP_MAX, tp, &tp_list);

        switch (tp) {
        case TP_IMSD_U:
            dec_tp(&c->tp_out.max_strm_data_uni);
            warn(INF, "\tinitial_max_stream_data_uni = %" PRIu64,
                 c->tp_out.max_strm_data_uni);
            break;

        case TP_IMSD_BL:
            dec_tp(&c->tp_out.max_strm_data_bidi_remote);
            warn(INF, "\tinitial_max_stream_data_bidi_local = %" PRIu64,
                 c->tp_out.max_strm_data_bidi_remote);
            break;

        case TP_IMSD_BR:
            // this is RX'ed as _remote, but applies to streams we open, so:
            dec_tp(&c->tp_out.max_strm_data_bidi_local);
            warn(INF, "\tinitial_max_stream_data_bidi_remote = %" PRIu64,
                 c->tp_out.max_strm_data_bidi_local);
            break;

        case TP_IMD:
            dec_tp(&c->tp_out.max_data);
            warn(INF, "\tinitial_max_data = %" PRIu64, c->tp_out.max_data);
            break;

        case TP_IMSB:
            dec_tp(&c->tp_out.max_streams_bidi);
            warn(INF, "\tinitial_max_streams_bidi = %" PRIu64,
                 c->tp_out.max_streams_bidi);
            break;

        case TP_IMSU:
            dec_tp(&c->tp_out.max_streams_uni);
            warn(INF, "\tinitial_max_streams_uni = %" PRIu64,
                 c->tp_out.max_streams_uni);
            break;

        case TP_IDTO:
            dec_tp(&c->tp_out.idle_to);
            warn(INF, "\tidle_timeout = %" PRIu64, c->tp_out.idle_to);
            break;

        case TP_MPS:
            dec_tp(&c->tp_out.max_pkt);
            warn(INF, "\tmax_packet_size = %" PRIu64, c->tp_out.max_pkt);
            if (c->tp_out.max_pkt < 1200) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "tp_out.max_pkt %" PRIu64 " invalid (< 1200)",
                          c->tp_out.max_pkt);
                return 1;
            }
            break;

        case TP_ADE:;
            uint64_t ade = 0;
            dec_tp(&ade);
            warn(INF, "\tack_delay_exponent = %" PRIu64, ade);
            if (ade > 20) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "ack_delay_exponent %" PRIu64 " invalid", ade);
                return 1;
            }
            c->tp_out.ack_del_exp = (uint8_t)ade;
            break;

        case TP_MAD:;
            dec_tp(&c->tp_out.max_ack_del);
            warn(INF, "\tmax_ack_delay = %" PRIu64, c->tp_out.max_ack_del);
            break;

        case TP_OCID:
            if (c->is_clnt == false) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "rx original_connection_id tp at serv");
                return 1;
            }
            c->tp_out.orig_cid.len = (uint8_t)dec_tp_buf(
                &c->tp_out.orig_cid.id, sizeof(c->tp_out.orig_cid.id));
            warn(INF, "\toriginal_connection_id = %s",
                 cid2str(&c->tp_out.orig_cid));
            break;

        case TP_DMIG:;
            uint16_t dmig;
            dec_tp(&dmig);
            warn(INF, "\tdisable_migration = true");
            c->tp_out.disable_migration = true;
            break;

        case TP_SRT:
            if (c->is_clnt == false) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "rx stateless_reset_token tp at serv");
                return 1;
            }
            uint16_t l;
            i = dec(&l, buf, len, i, sizeof(l), "%u");
            struct cid * const dcid = c->dcid;
            if (l != sizeof(dcid->srt)) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "illegal srt len %u", l);
                return 1;
            }
            memcpy(dcid->srt, &buf[i], sizeof(dcid->srt));
            warn(INF, "\tstateless_reset_token = %s",
                 hex2str(dcid->srt, sizeof(dcid->srt)));
            i += sizeof(dcid->srt);
            break;

        case TP_PRFA:
            i = dec(&l, buf, len, i, sizeof(l), "%u");

            struct pref_addr * const pa = &c->tp_out.pref_addr;
            i = dec(&pa->ip_vers, buf, len, i, sizeof(pa->ip_vers), "%u");
            i = dec(&pa->ip_len, buf, len, i, sizeof(pa->ip_len), "%u");

            if ((pa->ip_vers != 4 || pa->ip_len != 4) &&
                (pa->ip_vers != 6 || pa->ip_len != 16)) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "IPv%u len %u illegal", pa->ip_vers, pa->ip_len);
                return 1;
            }

            memcpy(&pa->ip, &buf[i], pa->ip_len);
            i += pa->ip_len;

            i = dec(&pa->port, buf, len, i, sizeof(pa->port), "%u");

            i = dec(&pa->cid.len, buf, len, i, sizeof(pa->cid.len), "%u");
            memcpy(pa->cid.id, &buf[i], pa->cid.len);
            i += pa->cid.len;
            pa->cid.seq = 1;
            add_dcid(c, &pa->cid);

            memcpy(pa->cid.srt, &buf[i], sizeof(pa->cid.srt));
            i += sizeof(pa->cid.srt);

            char ipstr[INET6_ADDRSTRLEN];
            inet_ntop(pa->ip_vers == 4 ? AF_INET : AF_INET6, &pa->ip, ipstr,
                      sizeof(ipstr));
            warn(INF, "\tpreferred_address = IPv%u %s%s%s:%u cid %s srt %s",
                 pa->ip_vers, pa->ip_vers == 6 ? "[" : "", ipstr,
                 pa->ip_vers == 6 ? "]" : "", pa->port, cid2str(&pa->cid),
                 hex2str(&pa->cid.srt, sizeof(pa->cid.srt)));
            break;

        default:
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "unsupported tp 0x%04x", tp);
            return 1;
        }
    }


    ensure(i == len, "out of parameters");

    if (i != len) {
        err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY, "tp data left over");
        return 1;
    }

    // if we did a RETRY, check that we got orig_cid and it matches
    if (c->is_clnt && c->tok_len) {
        if (c->tp_out.orig_cid.len == 0) {
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "no original_connection_id tp received");
            return 1;
        }

        if (cid_cmp(&c->tp_out.orig_cid, &c->odcid)) {
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "cid mismatch %s != %s", cid2str(&c->tp_out.orig_cid),
                      cid2str(&c->odcid));
            return 1;
        }
    }

    // apply these parameter to all current non-crypto streams
    // cppcheck-suppress variableScope
    struct q_stream * s;
    kh_foreach (s, c->streams_by_id)
        apply_stream_limits(s);

    return 0;
}


#define enc_tp(c, tp, var)                                                     \
    do {                                                                       \
        const uint16_t param = (tp);                                           \
        i = enc((c)->tls.tp_buf, len, i, &param, sizeof(param), 0, "%u");      \
        const uint16_t bytes = varint_size_needed(var);                        \
        i = enc((c)->tls.tp_buf, len, i, &bytes, sizeof(bytes), 0, "%u");      \
        const uint64_t tmp_var = (var);                                        \
        i = enc((c)->tls.tp_buf, len, i, &tmp_var, 0, 0, "%u");                \
    } while (0)


#define enc_tp_buf(c, tp, var, w)                                              \
    do {                                                                       \
        const uint16_t param = (tp);                                           \
        i = enc((c)->tls.tp_buf, len, i, &param, sizeof(param), 0, "%u");      \
        const uint16_t bytes = (w);                                            \
        i = enc((c)->tls.tp_buf, len, i, &bytes, sizeof(bytes), 0, "%u");      \
        if (w)                                                                 \
            i = enc_buf((c)->tls.tp_buf, len, i, (var), (w));                  \
    } while (0)


void init_tp(struct q_conn * const c)
{
    uint16_t i = 0;
    const uint16_t len = sizeof(c->tls.tp_buf);

    if (c->is_clnt) {
        i = enc(c->tls.tp_buf, len, i, &c->vers_initial,
                sizeof(c->vers_initial), 0, "0x%08x");
    } else {
        i = enc(c->tls.tp_buf, len, i, &c->vers, sizeof(c->vers), 0, "0x%08x");

        // don't include "force vneg" versions
        uint8_t vl = 0;
        for (uint8_t n = 0; n < ok_vers_len; n++)
            if (is_force_vneg_vers(ok_vers[n]) == false)
                vl += sizeof(ok_vers[n]);
        i = enc(c->tls.tp_buf, len, i, &vl, sizeof(vl), 0, "%u");
        for (uint8_t n = 0; n < ok_vers_len; n++)
            if (is_force_vneg_vers(ok_vers[n]) == false)
                i = enc(c->tls.tp_buf, len, i, &ok_vers[n], sizeof(ok_vers[n]),
                        0, "0x%08x");
    }

    // keep track of encoded length
    const uint16_t enc_len_pos = i;
    i += sizeof(uint16_t);

    enc_tp(c, TP_IMSB, (uint64_t)c->tp_in.max_streams_bidi);
    enc_tp(c, TP_IMSU, (uint64_t)c->tp_in.max_streams_uni);
    enc_tp(c, TP_IDTO, c->tp_in.idle_to);
    enc_tp(c, TP_IMSD_BR, c->tp_in.max_strm_data_bidi_remote);
    enc_tp(c, TP_IMSD_BL, c->tp_in.max_strm_data_bidi_local);
    enc_tp(c, TP_IMSD_U, c->tp_in.max_strm_data_uni);
    enc_tp(c, TP_IMD, c->tp_in.max_data);
    enc_tp(c, TP_ADE, c->tp_in.ack_del_exp);
    enc_tp(c, TP_MAD, c->tp_in.max_ack_del);
    enc_tp(c, TP_MPS, w_mtu(c->w));

    if (!c->is_clnt) {
        enc_tp_buf(c, TP_SRT, c->scid->srt, sizeof(c->scid->srt));
        if (c->odcid.len)
            enc_tp_buf(c, TP_OCID, c->odcid.id, c->odcid.len);
    }

    // encode length of all transport parameters
    const uint16_t enc_len = i - enc_len_pos - sizeof(enc_len);
    i = enc_len_pos;
    enc(c->tls.tp_buf, len, i, &enc_len, 2, 0, "%u");

    c->tls.tp_ext[0] = (ptls_raw_extension_t){
        QUIC_TP, {c->tls.tp_buf, enc_len + enc_len_pos + sizeof(enc_len)}};
    c->tls.tp_ext[1] = (ptls_raw_extension_t){UINT16_MAX};
}


static void init_ticket_prot(void)
{
    const ptls_cipher_suite_t * const cs = &CIPHER_SUITE;
    uint8_t output[PTLS_MAX_SECRET_SIZE] = {0};
    memcpy(output, quant_commit_hash,
           MIN(quant_commit_hash_len, sizeof(output)));
    setup_cipher(&dec_tckt.header_protection, &dec_tckt.aead, cs->aead,
                 cs->hash, 0, output);
    setup_cipher(&enc_tckt.header_protection, &enc_tckt.aead, cs->aead,
                 cs->hash, 1, output);
    ptls_clear_memory(output, sizeof(output));
}


static int encrypt_ticket_cb(ptls_encrypt_ticket_t * self
                             __attribute__((unused)),
                             ptls_t * tls,
                             int is_encrypt,
                             ptls_buffer_t * dst,
                             ptls_iovec_t src)
{
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    uint64_t tid;
    if (ptls_buffer_reserve(dst, src.len + quant_commit_hash_len + sizeof(tid) +
                                     enc_tckt.aead->algo->tag_size))
        return -1;

    if (is_encrypt) {
        warn(INF, "creating new 0-RTT session ticket for %s conn %s (%s %s)",
             conn_type(c), cid2str(c->scid), ptls_get_server_name(tls),
             ptls_get_negotiated_protocol(tls));

        // prepend git commit hash
        memcpy(dst->base + dst->off, quant_commit_hash, quant_commit_hash_len);
        dst->off += quant_commit_hash_len;

        // prepend ticket id
        ptls_openssl_random_bytes(&tid, sizeof(tid));
        memcpy(dst->base + dst->off, &tid, sizeof(tid));
        dst->off += sizeof(tid);

        // now encrypt ticket
        dst->off += ptls_aead_encrypt(enc_tckt.aead, dst->base + dst->off,
                                      src.base, src.len, tid, 0, 0);

    } else {
        if (src.len < quant_commit_hash_len + sizeof(tid) +
                          dec_tckt.aead->algo->tag_size ||
            memcmp(src.base, quant_commit_hash, quant_commit_hash_len) != 0) {
            warn(WRN,
                 "could not verify 0-RTT session ticket for %s conn %s (%s %s)",
                 conn_type(c), cid2str(c->scid), ptls_get_server_name(tls),
                 ptls_get_negotiated_protocol(tls));
            c->did_0rtt = false;
            return -1;
        }
        uint8_t * src_base = src.base + quant_commit_hash_len;
        size_t src_len = src.len - quant_commit_hash_len;

        memcpy(&tid, src_base, sizeof(tid));
        src_base += sizeof(tid);
        src_len -= sizeof(tid);

        const size_t n = ptls_aead_decrypt(dec_tckt.aead, dst->base + dst->off,
                                           src_base, src_len, tid, 0, 0);

        if (n > src_len) {
            warn(
                WRN,
                "could not decrypt 0-RTT session ticket for %s conn %s (%s %s)",
                conn_type(c), cid2str(c->scid), ptls_get_server_name(tls),
                ptls_get_negotiated_protocol(tls));
            c->did_0rtt = false;
            return -1;
        }
        dst->off += n;

        warn(INF, "verified 0-RTT session ticket for %s conn %s (%s %s)",
             conn_type(c), cid2str(c->scid), ptls_get_server_name(tls),
             ptls_get_negotiated_protocol(tls));
        c->did_0rtt = true;
    }

    return 0;
}


static int save_ticket_cb(ptls_save_ticket_t * self __attribute__((unused)),
                          ptls_t * tls,
                          ptls_iovec_t src)
{
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    warn(NTE, "saving TLS tickets to %s", tickets.file_name);

    FILE * const fp = fopen(tickets.file_name, "wbe");
    ensure(fp, "could not open ticket file %s", tickets.file_name);

    // write git hash
    ensure(fwrite(&quant_commit_hash_len, sizeof(quant_commit_hash_len), 1, fp),
           "fwrite");
    ensure(fwrite(quant_commit_hash, quant_commit_hash_len, 1, fp), "fwrite");

    char * s = 0;
    if (ptls_get_server_name(tls))
        s = strdup(ptls_get_server_name(tls));
    else
        s = calloc(1, sizeof(char));
    char * a = 0;
    if (ptls_get_negotiated_protocol(tls))
        a = strdup(ptls_get_negotiated_protocol(tls));
    else
        a = calloc(1, sizeof(char));
    const struct tls_ticket which = {.sni = s, .alpn = a};
    struct tls_ticket * t = splay_find(tickets_by_peer, &tickets, &which);
    if (t == 0) {
        // create new ticket
        t = calloc(1, sizeof(*t));
        ensure(t, "calloc");
        t->sni = s;
        t->alpn = a;
        ensure(splay_insert(tickets_by_peer, &tickets, t) == 0, "inserted");
    } else {
        // update current ticket
        free(t->ticket);
        free(s);
        free(a);
    }

    memcpy(&t->tp, &c->tp_out, sizeof(t->tp));
    t->vers = c->vers;

    t->ticket_len = src.len;
    t->ticket = calloc(1, t->ticket_len);
    ensure(t->ticket, "calloc");
    memcpy(t->ticket, src.base, src.len);

    // write all tickets
    // XXX this currently dumps the entire cache to file on each connection!
    splay_foreach (t, tickets_by_peer, &tickets) {
        warn(INF, "writing TLS ticket for %s conn %s (%s %s)", conn_type(c),
             cid2str(c->scid), t->sni, t->alpn);

        size_t len = strlen(t->sni) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->sni, sizeof(*t->sni), len, fp), "fwrite");

        len = strlen(t->alpn) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->alpn, sizeof(*t->alpn), len, fp), "fwrite");

        ensure(fwrite(&t->tp, sizeof(t->tp), 1, fp), "fwrite");
        ensure(fwrite(&t->vers, sizeof(t->vers), 1, fp), "fwrite");

        ensure(fwrite(&t->ticket_len, sizeof(t->ticket_len), 1, fp), "fwrite");
        ensure(fwrite(t->ticket, sizeof(*t->ticket), t->ticket_len, fp),
               "fwrite");
    }

    fclose(fp);
    return 0;
}


static ptls_save_ticket_t save_ticket = {.cb = save_ticket_cb};
static ptls_encrypt_ticket_t encrypt_ticket = {.cb = encrypt_ticket_cb};


void init_tls(struct q_conn * const c, const char * const clnt_alpn)
{
    if (c->tls.t)
        // we are re-initializing during version negotiation
        free_tls(c, true);
    ensure((c->tls.t = ptls_new(&tls_ctx, !c->is_clnt)) != 0, "ptls_new");
    *ptls_get_data_ptr(c->tls.t) = c;
    if (c->is_clnt)
        ensure(ptls_set_server_name(c->tls.t, c->peer_name, 0) == 0,
               "ptls_set_server_name");

    ptls_handshake_properties_t * const hshk_prop = &c->tls.tls_hshk_prop;

    hshk_prop->additional_extensions = c->tls.tp_ext;
    hshk_prop->collect_extension = filter_tp;
    hshk_prop->collected_extensions = chk_tp;

    if (c->is_clnt) {
        if (clnt_alpn == 0 || *clnt_alpn == 0) {
            c->tls.alpn = alpn[0];
            warn(NTE, "using default ALPN %.*s", (int)c->tls.alpn.len,
                 c->tls.alpn.base);
        } else if (clnt_alpn != (char *)c->tls.alpn.base) {
            free(c->tls.alpn.base);
            c->tls.alpn = ptls_iovec_init(strdup(clnt_alpn), strlen(clnt_alpn));
        }
        hshk_prop->client.negotiated_protocols.list = &c->tls.alpn;
        hshk_prop->client.negotiated_protocols.count = 1;
        hshk_prop->client.max_early_data_size = &c->tls.max_early_data;

        // try to find an existing session ticket
        struct tls_ticket which = {.sni = c->peer_name,
                                   // this works, because of strdup() allocation
                                   .alpn = (char *)c->tls.alpn.base};
        struct tls_ticket * t = splay_find(tickets_by_peer, &tickets, &which);
        if (t == 0) {
            // if we couldn't find a ticket, try without an alpn
            which.alpn = "";
            t = splay_find(tickets_by_peer, &tickets, &which);
        }
        if (t) {
            hshk_prop->client.session_ticket =
                ptls_iovec_init(t->ticket, t->ticket_len);
            memcpy(&c->tp_out, &t->tp, sizeof(t->tp));
            c->vers_initial = c->vers = t->vers;
            c->try_0rtt = 1;
        }
    }

    init_prot(c);
}


static void __attribute__((nonnull)) free_prot(struct q_conn * const c)
{
    dispose_cipher(&c->pn_init.in);
    dispose_cipher(&c->pn_init.out);
    dispose_cipher(&c->pn_hshk.in);
    dispose_cipher(&c->pn_hshk.out);
    dispose_cipher(&c->pn_data.in_0rtt);
    dispose_cipher(&c->pn_data.out_0rtt);
    dispose_cipher(&c->pn_data.in_1rtt[0]);
    dispose_cipher(&c->pn_data.out_1rtt[0]);
    dispose_cipher(&c->pn_data.in_1rtt[1]);
    dispose_cipher(&c->pn_data.out_1rtt[1]);
}


void free_tls(struct q_conn * const c, const bool keep_alpn)
{
    if (c->tls.t)
        ptls_free(c->tls.t);
    ptls_clear_memory(c->tls.secret, sizeof(c->tls.secret));
    free_prot(c);
    if (keep_alpn == false && c->tls.alpn.base != alpn[0].base)
        free(c->tls.alpn.base);
}


void init_prot(struct q_conn * const c)
{
    struct cid * const scid = c->scid;
    struct cid * const dcid = c->dcid;
    const ptls_iovec_t cid = {
        .base = (uint8_t *)(c->is_clnt ? &dcid->id : &scid->id),
        .len = c->is_clnt ? dcid->len : scid->len};
    ptls_cipher_suite_t * cs = &CIPHER_SUITE;
    setup_initial_encryption(&c->pn_init.in, &c->pn_init.out, &cs, cid,
                             c->is_clnt);
}


int tls_io(struct q_stream * const s, struct w_iov * const iv)
{
    struct q_conn * const c = s->c;
    const size_t in_len = iv ? iv->len : 0;
    const epoch_t ep_in = strm_epoch(s);
    size_t epoch_off[5] = {0};
    ptls_buffer_t tls_io;
    uint8_t tls_io_buf[4096];
    ptls_buffer_init(&tls_io, tls_io_buf, sizeof(tls_io_buf));

    const int ret =
        ptls_handle_message(c->tls.t, &tls_io, epoch_off, ep_in,
                            iv ? iv->buf : 0, in_len, &c->tls.tls_hshk_prop);
    // warn(DBG,
    //      "epoch %u, in %u (off %u), gen %u (%u-%u-%u-%u-%u), ret %u, left
    //      %u", ep_in, iv ? iv->len : 0, iv ? meta(iv).stream_off : 0,
    //      tls_io.off, epoch_off[0], epoch_off[1], epoch_off[2], epoch_off[3],
    //      epoch_off[4], ret, iv ? iv->len - in_len : 0);

    if (ret == 0 && c->state != conn_estb) {
        if (ptls_is_psk_handshake(c->tls.t) && c->is_clnt)
            c->did_0rtt =
                c->try_0rtt &&
                c->tls.tls_hshk_prop.client.early_data_accepted_by_peer;

    } else if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS &&
               ret != PTLS_ERROR_STATELESS_RETRY) {
        err_close(c, ERR_TLS(PTLS_ERROR_TO_ALERT(ret)), FRM_CRY,
                  "picotls error %u", ret);
        return ret;
    }

    if (tls_io.off == 0)
        return ret;

    // enqueue for TX
    for (epoch_t e = ep_init; e <= ep_data; e++) {
        const size_t out_len = epoch_off[e + 1] - epoch_off[e];
        if (out_len == 0)
            continue;
        // warn(DBG, "epoch %u: off %u len %u", e, epoch_off[e], out_len);
        struct w_iov_sq o = w_iov_sq_initializer(o);
        alloc_off(w_engine(c->sock), &o, (uint32_t)out_len,
                  DATA_OFFSET + c->tok_len);
        const uint8_t * data = tls_io.base + epoch_off[e];
        struct w_iov * ov = 0;
        sq_foreach (ov, &o, next) {
            memcpy(ov->buf, data, ov->len);
            data += ov->len;
        }
        concat_out(c->cstreams[e], &o);
        c->needs_tx = true;
    }
    return ret;
}


static void read_tickets()
{
    FILE * const fp = fopen(tickets.file_name, "rbe");
    if (fp == 0) {
        warn(WRN, "could not read TLS tickets from %s", tickets.file_name);
        return;
    }

    warn(INF, "reading TLS tickets from %s", tickets.file_name);

    // read and verify git hash
    size_t hash_len;
    ensure(fread(&hash_len, sizeof(quant_commit_hash_len), 1, fp), "fread");
    uint8_t buf[8192];
    ensure(fread(buf, sizeof(uint8_t), hash_len, fp), "fread");
    if (hash_len != quant_commit_hash_len ||
        memcmp(buf, quant_commit_hash, hash_len) != 0) {
        warn(WRN, "TLS tickets were stored by different %s version, removing",
             quant_name);
        ensure(unlink(tickets.file_name) == 0, "unlink");
        goto done;
    }

    for (;;) {
        // try and read the SNI len
        size_t len;
        if (fread(&len, sizeof(len), 1, fp) != 1)
            // we read all the tickets
            break;

        struct tls_ticket * const t = calloc(1, sizeof(*t));
        ensure(t, "calloc");
        t->sni = calloc(1, len);
        ensure(t->sni, "calloc");
        ensure(fread(t->sni, sizeof(*t->sni), len, fp), "fread");

        ensure(fread(&len, sizeof(len), 1, fp), "fread");
        t->alpn = calloc(1, len);
        ensure(t->alpn, "calloc");
        ensure(fread(t->alpn, sizeof(*t->alpn), len, fp), "fread");

        ensure(fread(&t->tp, sizeof(t->tp), 1, fp), "fread");
        ensure(fread(&t->vers, sizeof(t->vers), 1, fp), "fread");

        ensure(fread(&len, sizeof(len), 1, fp), "fread");
        t->ticket_len = len;
        t->ticket = calloc(len, sizeof(*t->ticket));
        ensure(t->ticket, "calloc");
        ensure(fread(t->ticket, sizeof(*t->ticket), len, fp), "fread");

        ensure(splay_insert(tickets_by_peer, &tickets, t) == 0, "inserted");
        warn(INF, "got TLS ticket %s %s", t->sni, t->alpn);
    }

done:
    fclose(fp);
}


static void fprinthex(FILE * const fp, const ptls_iovec_t vec)
{
    for (size_t i = 0; i != vec.len; ++i)
        fprintf(fp, "%02x", vec.base[i]);
}


static void log_secret_cb(ptls_log_secret_t * const self
                          __attribute__((unused)),
                          ptls_t * const tls,
                          const char * const label,
                          ptls_iovec_t secret)
{
    fprintf(tls_log_file, "%s ", label);
    fprinthex(tls_log_file, ptls_get_client_random(tls));
    fprintf(tls_log_file, " ");
    fprinthex(tls_log_file, secret);
    fprintf(tls_log_file, "\n");
    fflush(tls_log_file);
}


static int update_traffic_key_cb(ptls_update_traffic_key_t * const self
                                 __attribute__((unused)),
                                 ptls_t * const tls,
                                 const int is_enc,
                                 const size_t epoch,
                                 const void * const secret)
{
    // warn(CRT, "update_traffic_key %s %u", is_enc ? "tx" : "rx", epoch);
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    ptls_cipher_suite_t * const cipher = ptls_get_cipher(c->tls.t);
    struct cipher_ctx * ctx;

    switch (epoch) {
    case ep_0rtt:
        ctx = is_enc ? &c->pn_data.out_0rtt : &c->pn_data.in_0rtt;
        break;

    case ep_hshk:
        ctx = is_enc ? &c->pn_hshk.out : &c->pn_hshk.in;
        break;

    case ep_data:
        memcpy(c->tls.secret[is_enc], secret, cipher->hash->digest_size);
        ctx = is_enc ? &c->pn_data.out_1rtt[c->pn_data.out_kyph]
                     : &c->pn_data.in_1rtt[c->pn_data.in_kyph];
        break;

    default:
        die("epoch %zu unknown", epoch);
    }

    if (is_enc)
        c->tls.epoch_out = (uint8_t)epoch;

    return setup_cipher(&ctx->header_protection, &ctx->aead, cipher->aead,
                        cipher->hash, is_enc, secret);
}


void init_tls_ctx(const struct q_conf * const conf)
{
    if (conf && conf->tls_key) {
#ifdef PTLS_OPENSSL
        FILE * const fp = fopen(conf->tls_key, "rbe");
        ensure(fp, "could not open key %s", conf->tls_key);
        EVP_PKEY * const pkey = PEM_read_PrivateKey(fp, 0, 0, 0);
        fclose(fp);
        ensure(pkey, "failed to load private key");
        ptls_openssl_init_sign_certificate(&sign_cert, pkey);
        EVP_PKEY_free(pkey);
#else
        // XXX ptls_minicrypto_load_private_key() only works for ECDSA keys
        const int ret =
            ptls_minicrypto_load_private_key(&tls_ctx, conf->tls_key);
        ensure(ret == 0, "could not open key %s", conf->tls_key);
#endif
    }

    if (conf && conf->tls_cert) {
        const int ret = ptls_load_certificates(&tls_ctx, conf->tls_cert);
        ensure(ret == 0, "ptls_load_certificates");
    }

    if (conf && conf->ticket_store) {
        strncpy(tickets.file_name, conf->ticket_store,
                sizeof(tickets.file_name));
        tls_ctx.save_ticket = &save_ticket;
        read_tickets();
    } else {
        tls_ctx.encrypt_ticket = &encrypt_ticket;
        tls_ctx.max_early_data_size = 0xffffffff;
        tls_ctx.ticket_lifetime = 60 * 60 * 24;
        tls_ctx.require_dhe_on_psk = 0;
    }

    if (conf && conf->tls_log) {
        tls_log_file = fopen(conf->tls_log, "wbe");
        ensure(tls_log_file, "could not open TLS log %s", conf->tls_log);
    }

#ifdef PTLS_OPENSSL
    ensure(ptls_openssl_init_verify_certificate(&verifier, 0) == 0,
           "ptls_openssl_init_verify_certificate");
#endif

    static ptls_key_exchange_algorithm_t * key_exchanges[] = {
#ifdef PTLS_OPENSSL
        &ptls_openssl_secp256r1,
#endif
        &ptls_minicrypto_x25519, 0};
    static ptls_on_client_hello_t on_client_hello = {on_ch};
    static ptls_log_secret_t log_secret = {log_secret_cb};
    static ptls_update_traffic_key_t update_traffic_key = {
        update_traffic_key_cb};

    tls_ctx.cipher_suites =
#ifdef PTLS_OPENSSL
        ptls_openssl_cipher_suites;
#else
        ptls_minicrypto_cipher_suites;
#endif
    tls_ctx.key_exchanges = key_exchanges;
    tls_ctx.on_client_hello = &on_client_hello;
    tls_ctx.update_traffic_key = &update_traffic_key;
    if (conf && conf->tls_log)
        tls_ctx.log_secret = &log_secret;
    tls_ctx.random_bytes =
#ifdef PTLS_OPENSSL
        ptls_openssl_random_bytes;
#else
        ptls_minicrypto_random_bytes;
#endif

#ifdef PTLS_OPENSSL
    tls_ctx.sign_certificate = &sign_cert.super;
    if (conf && conf->enable_tls_cert_verify)
        tls_ctx.verify_certificate = &verifier.super;
#endif
    tls_ctx.get_time = &ptls_get_time;
    tls_ctx.omit_end_of_early_data = true;

    init_ticket_prot();
}


void free_tls_ctx(void)
{
    dispose_cipher(&dec_tckt);
    dispose_cipher(&enc_tckt);

    // free ticket cache
    struct tls_ticket *t, *tmp;
    for (t = splay_min(tickets_by_peer, &tickets); t != 0; t = tmp) {
        tmp = splay_next(tickets_by_peer, &tickets, t);
        ensure(splay_remove(tickets_by_peer, &tickets, t), "removed");
        free(t->sni);
        free(t->alpn);
        free(t->ticket);
        free(t);
    }
}


static const struct cipher_ctx * __attribute__((nonnull))
which_cipher_ctx_out(const struct q_conn * const c, const uint8_t flags)
{
    switch (pkt_type(flags)) {
    case LH_INIT:
    case LH_RTRY:
        return &c->pn_init.out;
    case LH_0RTT:
        return &c->pn_data.out_0rtt;
    case LH_HSHK:
        return &c->pn_hshk.out;
    default:
        // warn(ERR, "out cipher for kyph %u", is_set(SH_KYPH, flags));
        return &c->pn_data.out_1rtt[is_set(SH_KYPH, flags)];
    }
}


uint16_t dec_aead(const struct w_iov * const xv,
                  const struct w_iov * const v,
                  const uint16_t len,
                  const struct cipher_ctx * const ctx)
{
    const uint16_t hdr_len = meta(v).hdr.hdr_len;
    if (unlikely(hdr_len == 0 || hdr_len > len))
        return 0;

    const size_t ret =
        ptls_aead_decrypt(ctx->aead, &v->buf[hdr_len], &xv->buf[hdr_len],
                          len - hdr_len, meta(v).hdr.nr, xv->buf, hdr_len);
    if (unlikely(ret == SIZE_MAX))
        return 0;
    memcpy(v->buf, xv->buf, hdr_len);

#ifdef DEBUG_MARSHALL
    warn(DBG, "dec %s AEAD over [%u..%u] in [%u..%u]",
         pkt_type_str(meta(v).hdr.type, &meta(v).hdr.vers), hdr_len,
         len - AEAD_LEN - 1, len - AEAD_LEN, len - 1);
#endif

    return hdr_len + len;
}


uint16_t enc_aead(struct q_conn * const c,
                  const struct w_iov * const v,
                  struct w_iov * const xv,
                  const uint16_t pkt_nr_pos)
{
    const struct cipher_ctx * ctx = which_cipher_ctx_out(c, meta(v).hdr.flags);
    if (unlikely(ctx == 0 || ctx->aead == 0)) {
        warn(NTE, "no %s crypto context",
             pkt_type_str(meta(v).hdr.type, &meta(v).hdr.vers));
        return 0;
    }

    const uint16_t hdr_len = meta(v).hdr.hdr_len;
    memcpy(xv->buf, v->buf, hdr_len); // copy pkt header

    const uint16_t plen = v->len - hdr_len + AEAD_LEN;
    xv->len = hdr_len + (uint16_t)ptls_aead_encrypt(
                            ctx->aead, &xv->buf[hdr_len], &v->buf[hdr_len],
                            plen - AEAD_LEN, meta(v).hdr.nr, v->buf, hdr_len);

    // apply packet protection
    ctx = which_cipher_ctx_out(
        c,
        // the pp context does not depend on the SH kyph bit
        is_lh(meta(v).hdr.flags) ? meta(v).hdr.flags
                                 : meta(v).hdr.flags & ~SH_KYPH);
    if (likely(pkt_nr_pos) &&
        unlikely(xor_hp(xv, v, ctx, pkt_nr_pos, true) == false))
        return 0;

#ifdef DEBUG_MARSHALL
    warn(DBG, "enc %s AEAD over [%u..%u] in [%u..%u]",
         pkt_type_str(meta(v).hdr.type, &meta(v).hdr.vers), hdr_len,
         hdr_len + plen - AEAD_LEN - 1, hdr_len + plen - AEAD_LEN,
         hdr_len + plen - 1);
#endif
    return xv->len;
}


static ptls_hash_context_t * __attribute__((nonnull))
prep_hash_ctx(const struct q_conn * const c,
              const ptls_cipher_suite_t * const cs)
{
    // create hash context
    ptls_hash_context_t * const hc = cs->hash->create();
    ensure(hc, "could not create hash context");

    // hash our git commit hash and the peer IP address
    hc->update(hc, quant_commit_hash, quant_commit_hash_len);
    hc->update(hc, &c->peer.sin_addr, sizeof(c->peer.sin_addr));

    return hc;
}


void make_rtry_tok(struct q_conn * const c)
{
    const ptls_cipher_suite_t * const cs = &CIPHER_SUITE;
    ptls_hash_context_t * const hc = prep_hash_ctx(c, cs);

    // hash current scid
    struct cid * const scid = c->scid;
    hc->update(hc, scid->id, scid->len);
    hc->final(hc, c->tok, PTLS_HASH_FINAL_MODE_FREE);

    // append scid to hashed token
    memcpy(&c->tok[cs->hash->digest_size], scid->id, scid->len);
    // update max_frame_len() when this changes:
    c->tok_len = (uint16_t)cs->hash->digest_size + scid->len;
}


bool verify_rtry_tok(struct q_conn * const c,
                     const uint8_t * const tok,
                     const uint16_t tok_len)
{
    const ptls_cipher_suite_t * const cs = &CIPHER_SUITE;
    ptls_hash_context_t * const hc = prep_hash_ctx(c, cs);

    // hash current cid included in token
    hc->update(hc, tok + cs->hash->digest_size,
               tok_len - cs->hash->digest_size);
    uint8_t buf[MAX_HASH_LEN + MAX_CID_LEN];
    hc->final(hc, buf, PTLS_HASH_FINAL_MODE_FREE);

    if (memcmp(buf, tok, cs->hash->digest_size) == 0) {
        c->odcid.len = (uint8_t)(tok_len - cs->hash->digest_size);
        memcpy(&c->odcid.id, tok + cs->hash->digest_size, c->odcid.len);
        return true;
    }
    return false;
}


void flip_keys(struct q_conn * const c, const bool out)
{
    const bool new_kyph = !(out ? c->pn_data.out_kyph : c->pn_data.in_kyph);
    // warn(DBG, "flip %s kyph %u -> %u", out ? "out" : "in",
    //      out ? c->pn_data.out_kyph : c->pn_data.in_kyph, new_kyph);

    const ptls_cipher_suite_t * const cs = ptls_get_cipher(c->tls.t);
    if (unlikely(cs == 0)) {
        warn(ERR, "cannot obtain cipher suite");
        return;
    }

    uint8_t new_secret[PTLS_MAX_DIGEST_SIZE];
    static const char flip_label[] = "traffic upd";
    if (c->pn_data.in_1rtt[new_kyph].aead)
        ptls_aead_free(c->pn_data.in_1rtt[new_kyph].aead);
    if (setup_initial_key(&c->pn_data.in_1rtt[new_kyph], cs, c->tls.secret[0],
                          flip_label, 0, new_secret))
        return;
    memcpy(c->tls.secret[0], new_secret, cs->hash->digest_size);
    if (c->pn_data.out_1rtt[new_kyph].aead)
        ptls_aead_free(c->pn_data.out_1rtt[new_kyph].aead);
    if (setup_initial_key(&c->pn_data.out_1rtt[new_kyph], cs, c->tls.secret[1],
                          flip_label, 1, new_secret) != 0)
        return;
    memcpy(c->tls.secret[1], new_secret, cs->hash->digest_size);

    if (out == false)
        c->pn_data.in_kyph = new_kyph;
    c->pn_data.out_kyph = new_kyph;
}


void maybe_flip_keys(struct q_conn * const c, const bool out)
{
    if (c->key_flips_enabled == false || likely(c->do_key_flip == false))
        return;

    if (c->pn_data.out_kyph != c->pn_data.in_kyph)
        return;

    flip_keys(c, out);
    c->do_key_flip = false;
}
