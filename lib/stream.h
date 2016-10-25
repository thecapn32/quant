#pragma once

#include "tommy.h"


struct q_stream {
    node stream_node;

    uint32_t id;
    uint8_t state;
    uint8_t _unused[3];

    uint8_t * out;
    uint64_t out_len;
    uint64_t out_off;

    uint8_t * in;
    uint64_t in_len;
    uint64_t in_off;
};

// SND_UNA


// #define STRM_IDLE 0
// #define STRM_RESV 1
// #define STRM_OPEN 2
// #define STRM_HFCL_REM 3
// #define STRM_HFCL_LOC 4
// #define STRM_CLSD 5


struct q_conn;

uint16_t enc_stream_frames(struct q_conn * restrict const c,
                           uint8_t * restrict const buf,
                           const uint16_t len);

struct q_stream * get_stream(struct q_conn * restrict const c,
                             const uint32_t id);

struct q_stream * new_stream(struct q_conn * restrict const c,
                             const uint32_t id);
