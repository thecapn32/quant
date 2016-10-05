#pragma once

#include <stdint.h>
#include <sys/queue.h>


#define F_STREAM 0x01
#define F_STREAM_FIN 0x02
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
    SLIST_ENTRY(q_frame) next;
    uint8_t type;
    uint8_t _unused[7];

    uint64_t        off;
    uint32_t        sid;
    uint16_t        dlen;
    uint8_t         _unused2[2];
    const uint8_t * data;
};

struct q_frame {
    SLIST_ENTRY(q_frame) next;
    uint8_t type;
    uint8_t _unused[7];

    union {
        struct q_stream_frame sf;
    };
};

#ifndef _UINT128_T
typedef unsigned __int128 uint128_t;
#endif

#define MAX_PKT_LEN 1350
#define MAX_NONCE_LEN 32
#define HASH_LEN 12

//! A QUIC packet.
struct q_pkt {
    uint16_t  len; //!< Total length of the message.
    uint8_t   flags;
    uint8_t   nonce_len;
    uint32_t  vers;
    uint64_t  cid;
    uint8_t   nonce[32];
    uint128_t hash;
    uint64_t  nr;
    uint8_t   buf[MAX_PKT_LEN]; //!< Payload bytes of the message.
    uint16_t  _unused;
    SLIST_HEAD(fh, q_frame) fl;
    uint8_t _unused2[8];
};


#define F_VERS 0x01
#define F_PUB_RST 0x02
#define F_NONCE 0x04
#define F_CID 0x08
#define F_MULTIPATH 0x40 // reserved
#define F_UNUSED 0x80    // reserved (must be 0)


// #define quic_vers 0x51303235 // "Q025"
#define quic_vers 0x51303336 // "Q036"

#define vers_to_ascii(v)                                                       \
    {                                                                          \
        ((v) >> 24) & 0xFF, ((v) >> 16) & 0xFF, ((v) >> 8) & 0xFF, (v)&0xFF, 0 \
    }
