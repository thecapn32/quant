#pragma once

#include "quic.h"

#define MAX_PKT_LEN 1350
#define MAX_NONCE_LEN 32
#define HASH_LEN 12

/// A QUIC packet.
struct q_pkt {
    uint8_t flags;
    uint8_t nonce_len;
    uint8_t nr_len;
    uint8_t _unused;
    q_tag vers;
    uint64_t cid;
    uint64_t nr;
    uint8_t nonce[32];
    list frames;
};


#define F_VERS 0x01
#define F_PUB_RST 0x02
#define F_NONCE 0x04
#define F_CID 0x08
#define F_MULTIPATH 0x40 // reserved
#define F_UNUSED 0x80    // reserved (must be 0)


#define decode(dst, buf, buf_len, pos, len, fmt)                               \
    do {                                                                       \
        const size_t __len = len ? len : sizeof(dst);                          \
        assert(pos + __len <= buf_len,                                         \
               "attempting to decode %zu byte%c starting at " #buf "["         \
               "%d], which is past " #buf_len " = %d",                         \
               __len, __len == 1 ? 0 : 's', pos, buf_len);                     \
        memcpy(&dst, &buf[pos], __len);                                        \
        warn(debug, "decoding %zu byte%c from pos %d into " #dst " = " fmt,    \
             __len, __len == 1 ? 0 : 's', pos, dst);                           \
        pos += __len;                                                          \
    } while (0)


#define encode(buf, buf_len, pos, src, src_len, fmt)                           \
    do {                                                                       \
        const size_t __len = src_len ? src_len : sizeof(src);                  \
        assert(pos + __len <= buf_len,                                         \
               "attempting to encode %zu byte%c starting at " #buf "["         \
               "%d], which is past " #buf_len " = %d",                         \
               __len, __len == 1 ? 0 : 's', pos, buf_len);                     \
        memcpy(&buf[pos], &src, __len);                                        \
        warn(debug, "encoding " #src " = " fmt " into %zu byte%c from pos %d", \
             src, __len, __len == 1 ? 0 : 's', pos);                           \
        pos += __len;                                                          \
    } while (0)


uint16_t dec_pub_hdr(struct q_pkt * const p,
                     const uint8_t * restrict const buf,
                     const uint16_t len);

uint16_t enc_init_pkt(const struct q_conn * const c,
                      uint8_t * restrict const buf,
                      const uint16_t len);

void free_pkt(struct q_pkt * restrict const p);
