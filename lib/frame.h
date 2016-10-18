#pragma once

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

struct q_pkt;

uint16_t __attribute__((nonnull))
dec_frames(struct q_pkt * const p __attribute__((unused)),
           const uint8_t * restrict const buf,
           const uint16_t len __attribute__((unused)));
