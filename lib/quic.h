#pragma once

#include <stdbool.h>
#include <stdint.h>

// #include "tommy.h"

#ifndef _UINT128_T
typedef unsigned __int128 uint128_t;
#endif

// struct q_socket {
//  uint32_t k;
//  node hash_node;
// };


// enum stream_state { idle, reserved, open, half_closed, closed };

struct public_hdr {
    uint8_t   flags;
    uint32_t  version;       // if flags & flag_version
    uint64_t  conn_id;       // if flags & flag_conn_id
    uint8_t   div_nonce[32]; // if flags & flag_div_nonce
    uint8_t   div_nonce_len; // if flags & flag_div_nonce
    uint8_t   pkt_nr_len;
    uint64_t  pkt_nr;
    uint128_t hash;
};


#define flag_version 0x01
#define flag_public_reset 0x02
#define flag_div_nonce 0x04
#define flag_conn_id 0x08

// convert pkt_nr length encoded in flags to bytes
#define decode_pkt_nr_len_flags(f) (((f)&0x30) >> 4 ? 2 * (((f)&0x30) >> 4) : 1)

// convert pkt_nr length in bytes into flags
#define encode_pkt_nr_len_flags(n) ((uint8_t)(((n) / 2) << 4))

#define flag_multipath 0x40 // reserved
#define flag_unused 0x80    // reserved (must be 0)

// #define quic_version     0x51303235  // "Q025"
#define quic_version 0x51303336 // "Q036"

#define quic_version_to_ascii(v)                                               \
    {                                                                          \
        ((v) >> 24) & 0xFF, ((v) >> 16) & 0xFF, ((v) >> 8) & 0xFF, (v)&0xFF, 0 \
    }

struct stream_frame {
    uint8_t  type;
    uint32_t id;
    uint64_t off;
    uint16_t data_len;
};

#define flag_stream 0x01
#define flag_stream_fin 0x02
#define flag_stream_data_len 0x04

#define decode_stream_off_len_flags(f)                                         \
    ((((f)&0x38) >> 3 == 0)                                                    \
         ? 0                                                                   \
         : (((f)&0x38) >> 3 == 1) ? 2 : (((f)&0x38) >> 3) + 1)

#define encode_stream_off_len_flags(n) ((n) ? (uint8_t)(((n)-1) << 3) : 0)

#define decode_stream_id_len_flags(f) ((((f)&0xc0) >> 6) + 1)

#define encode_stream_id_len_flags(n) ((uint8_t)(((n)-1) << 6))


#define flag_ack 0x02

#define type_padding 0x00
#define type_rst_stream 0x01
#define type_connection_close 0x02
#define type_goaway 0x03
#define type_window_update 0x04
#define type_blocked 0x05
#define type_stop_waiting 0x06
#define type_ping 0x07


void q_connect(const int s);

void q_serve(const int s);
