#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "quic.h"


#define F_STREAM 0x80
#define F_STREAM_FIN 0x40
#define F_STREAM_DATA_LEN 0x20

#define F_ACK 0x02

#define T_PADDING 0x00
#define T_RST_STREAM 0x01
#define T_CONNECTION_CLOSE 0x02
#define T_GOAWAY 0x03
#define T_WINDOW_UPDATE 0x04
#define T_BLOCKED 0x05
#define T_STOP_WAITING 0x06
#define T_PING 0x07


struct q_stream_frame {
    // SLIST_ENTRY(q_frame) next;
    uint8_t type;
    uint8_t _unused[7];

    uint64_t off;
    uint32_t sid;
    uint16_t dlen;
    uint8_t _unused2[2];
    const uint8_t * data;
};

// struct q_frame {
//     // SLIST_ENTRY(q_frame) next;
//     uint8_t type;
//     uint8_t _unused[7];

//     union {
//         struct q_stream_frame sf;
//     };
// };

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
