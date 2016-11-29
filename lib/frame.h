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

#define QUIC_INTERNAL_ERROR 1
#define QUIC_INVALID_VERSION 20

/// Define an IEEE-754 16-bt floating type (backed by gcc/clang F16C)
// typedef __fp16 float16_t;


struct q_pub_hdr;
struct q_conn;
struct q_stream;

uint16_t dec_frames(struct q_conn * const c,
                    const struct q_pub_hdr * const p,
                    const uint8_t * const buf,
                    const uint16_t len);

uint16_t enc_stream_frame(struct q_stream * const s,
                          uint8_t * const buf,
                          const uint16_t len);

uint16_t enc_padding_frame(uint8_t * const buf, const uint16_t len);

uint16_t enc_conn_close_frame(uint8_t * const buf, const uint16_t len);

uint16_t enc_ack_frame(uint8_t * const buf, const uint16_t len);
