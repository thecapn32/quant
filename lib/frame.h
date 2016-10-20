#pragma once

#include "tommy.h"

#define F_STREAM 0x80
#define F_STREAM_FIN 0x40
#define F_STREAM_DATA_LEN 0x20

#define F_ACK 0x40
#define F_ACK_N 0x20
#define F_ACK_UNUSED 0x10

#define T_PADDING 0x00
#define T_RST_STREAM 0x01
#define T_CONNECTION_CLOSE 0x02
#define T_GOAWAY 0x03
#define T_WINDOW_UPDATE 0x04
#define T_BLOCKED 0x05
#define T_STOP_WAITING 0x06
#define T_PING 0x07


struct q_stream_frame {
    uint64_t off;
    uint32_t sid;
    uint16_t dlen;
    uint8_t _unused2[2];
    const uint8_t * data;
};


/// Define an IEEE-754 16-bt floating type (backed by gcc/clang F16C)
// typedef __fp16 float16_t;


struct q_ack_frame {
    uint64_t lg_ack;
    // float16_t lg_ack_delta_t;
    uint16_t lg_ack_delta_t;
    uint8_t ack_blocks;
    uint8_t ts_blocks;

    uint8_t _unused2[4];
    const uint8_t * data;
};


struct q_stop_waiting_frame {
    uint64_t lst_unacked;
};


struct q_conn_close_frame {
    uint32_t err;
    uint16_t reason_len;
    uint8_t _unused2[2];
    uint8_t * reason;
};


struct q_frame {
    node node;
    uint8_t type;
    uint8_t _unused[7];

    union {
        struct q_stream_frame sf;
        struct q_ack_frame af;
        struct q_stop_waiting_frame swf;
        struct q_conn_close_frame ccf;
    };
};


struct q_pkt;

uint16_t __attribute__((nonnull))
dec_frames(struct q_pkt * const p __attribute__((unused)),
           const uint8_t * restrict const buf,
           const uint16_t len __attribute__((unused)));

uint16_t __attribute__((nonnull))
enc_stream_frame(uint8_t * restrict const buf, const uint16_t len);

uint16_t __attribute__((nonnull))
enc_padding_frame(uint8_t * restrict const buf, const uint16_t len);
