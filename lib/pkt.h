#pragma once

// #include <stdbool.h>
// #include <stdint.h>

#include "quic.h"


#define MAX_PKT_LEN 1350
#define MAX_NONCE_LEN 32
#define HASH_LEN 12

/// A QUIC packet.
struct q_pkt {
    uint8_t flags;
    uint8_t nonce_len;
    uint8_t _unused[2];
    union q_vers vers;
    uint64_t cid;
    uint64_t nr;
    uint8_t nonce[32];
};


#define F_VERS 0x01
#define F_PUB_RST 0x02
#define F_NONCE 0x04
#define F_CID 0x08
#define F_MULTIPATH 0x40 // reserved
#define F_UNUSED 0x80    // reserved (must be 0)


uint16_t dec_pub_hdr(struct q_pkt * const p,
                     const uint8_t * restrict const buf,
                     const uint16_t len);

uint16_t enc_init_pkt(const struct q_conn * const c,
                      uint8_t * restrict const buf,
                      const uint16_t len);
