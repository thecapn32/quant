#include <inttypes.h>
#include <sys/param.h>

#include "fnv_1a.h"
#include "frame.h"
#include "pkt.h"
#include "util.h"


static const q_tag prst = {.as_str = "PRST"}, rnon = {.as_str = "RNON"},
                   rseq = {.as_str = "RSEQ"}, cadr = {.as_str = "CADR"};


/// Decode the packet number length information in the flags field of the public
/// header.
///
/// @param[in]  flags  The flags in a public header
///
/// @return     Length of the packet number field in bytes.
///
inline static uint8_t __attribute__((const)) dec_pkt_nr_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x30) >> 4;
    assert(/* l >= 0 && */ l <= 3, "cannot decode packet number length %d", l);
    const uint8_t dec[] = {1, 2, 3, 6};
    return dec[l];
}

/// Encode a byte length @p n into a representation that can be or'ed into the
/// public header flags.
///
/// @param[in]  n     Byte length to encode.
///
/// @return     Encoded byte length suitable for or'ing into the public header
///             flags.
///
inline static uint8_t __attribute__((const)) enc_pkt_nr_len(const uint8_t n)
{
    assert(n == 1 || n == 2 || n == 4 || n == 6,
           "cannot encode packet number length %d", n);
    static const uint8_t enc[] = {0xFF, 0, 1, 0xFF, 3, 0xFF, 4}; // 0xFF invalid
    return enc[n];
}


/// Calculate the minimum number of bytes needed to encode packet number @p n.
///
/// @param[in]  n     A packet number.
///
/// @return     The minimum number of bytes needed to encode @p n.
///
inline static uint8_t __attribute__((const))
calc_req_pkt_nr_len(const uint64_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    if (n < UINT32_MAX)
        return 4;
    return 6;
}


uint16_t __attribute__((nonnull)) dec_pub_hdr(struct q_pub_hdr * const ph,
                                              const uint8_t * const buf,
                                              const uint16_t len,
                                              struct q_conn ** const c)
{
    ph->flags = buf[0];
    warn(debug, "ph->flags = 0x%02x", ph->flags);
    uint16_t i = 1;

    if (ph->flags & F_CID)
        decode(ph->cid, buf, len, i, 0, "%" PRIu64); // XXX: no ntohll()?
    *c = get_conn(ph->cid);

    if (ph->flags & F_VERS)
        decode(ph->vers.as_int, buf, len, i, 0, "0x%08x");

    if (ph->flags & F_PUB_RST) {
        warn(err, "public reset");
        uint32_t tag;
        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == prst.as_int, "PRST tag mismatch 0x%04x != 0x%04x", tag,
               prst.as_int);

        uint8_t n;
        decode(n, buf, len, i, 0, "%d");
        assert(n == 3, "got %d tags in PRST", n);
        i += n; // XXX: undocumented in draft-hamilton

        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == rnon.as_int, "RNON tag mismatch 0x%04x != 0x%04x", tag,
               rnon.as_int);
        uint64_t val;
        decode(val, buf, len, i, 0, "0x%" PRIx64);

        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == rseq.as_int, "RSEQ tag mismatch 0x%04x != 0x%04x", tag,
               rseq.as_int);
        decode(val, buf, len, i, 0, "0x%" PRIx64);

        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == cadr.as_int, "CADR tag mismatch 0x%04x != 0x%04x", tag,
               cadr.as_int);
        // decode(val, buf, len, i, 0, "0x%" PRIx64);

        return i;
    }

    if ((ph->flags & F_NONCE) && *c) {
        ph->nonce_len = (uint8_t)MIN(len - i, MAX_NONCE_LEN);
        decode(ph->nonce, buf, len, i, ph->nonce_len, "%s");
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    if (ph->flags & F_VERS && i == len)
        // this is a version negotiation packet from the server
        return i;

    ph->nr_len = dec_pkt_nr_len(ph->flags);
    decode(ph->nr, buf, len, i, ph->nr_len, "%" PRIu64); // XXX: no ntohll()?

    if (ph->flags & (F_MULTIPATH | F_UNUSED))
        die("unsupported flag set");

    if (i <= len) {
        // if there are bytes left, there must be a hash to verify
        const uint128_t hash = fnv_1a(buf, len, i, HASH_LEN);
        if (memcmp(&buf[i], &hash, HASH_LEN))
            die("hash mismatch");
        else
            warn(debug, "hash OK");
        i += HASH_LEN;
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    return i;
}


uint16_t __attribute__((nonnull))
enc_pkt(struct q_conn * const c, uint8_t * const buf, const uint16_t len)
{
    uint16_t i = 0;

    // XXX: omit cid to force a PRST
    const uint8_t flags = F_CID;
    encode(buf, len, i, &flags, 0, "0x%02x");

    encode(buf, len, i, &c->id, 0, "%" PRIu64); // XXX: no htonll()?

    if (c->state < CONN_ESTB || c->state == CONN_FINW) {
        buf[0] |= F_VERS;
        if (vers[c->vers].as_int)
            encode(buf, len, i, &vers[c->vers].as_int, 0, "0x%08x");
        else {
            warn(info, "sending version negotiation server response");
            encode(buf, len, i, &vers[0].as_int, vers_len, "0x%08x");
            return i;
        }
    } else
        warn(info, "not including negotiated version %.4s",
             vers[c->vers].as_str);

    const uint8_t req_pkt_nr_len = calc_req_pkt_nr_len(c->out);
    buf[0] |= enc_pkt_nr_len(req_pkt_nr_len);
    encode(buf, len, i, &c->out, req_pkt_nr_len, "%" PRIu64);

    const uint16_t hash_pos = i;
    i += HASH_LEN;

    if (c->state == CONN_FINW)
        i += enc_conn_close_frame(&buf[i], len - i);

    // stream frames must be last, because they can extend to end of packet
    i += enc_stream_frames(c, &buf[i], len - i);

    const uint128_t hash = fnv_1a(buf, i, hash_pos, HASH_LEN);
    warn(debug, "inserting %d-byte hash at pos %d", HASH_LEN, hash_pos);
    memcpy(&buf[hash_pos], &hash, HASH_LEN);

    warn(debug, "ph->flags = 0x%02x", buf[0]);

    return i;
}
