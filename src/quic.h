#ifndef _quic_h_
#define _quic_h_

#include <stdint.h>
#include <stdbool.h>

#include "tommy.h"

// struct q_socket {
// 	uint32_t k;
// 	node hash_node;
// };


// enum stream_state { idle, reserved, open, half_closed, closed };

struct public_hdr {
	uint8_t		flags;
	uint32_t	version;		// if flags & flag_version
	uint64_t	conn_id;		// if flags & flag_conn_id
	uint8_t		div_nonce[32];		// if flags & flag_div_nonce
	uint8_t		div_nonce_len;		// if flags & flag_div_nonce
	uint32_t	pkt_nr;
};


#define flag_version		0x01
#define flag_public_reset	0x02
#define flag_div_nonce		0x04
#define flag_conn_id		0x08

#define flag_pkt_nr_len_1	0x10
#define flag_pkt_nr_len_2	0x20

#define flag_multipath		0x40		// reserved
#define flag_unused		0x80		// reserved (must be 0)

// #define quic_version		0x51303235	// "Q025"
#define quic_version		0x51303336	// "Q036"


struct stream_frame {
	uint8_t		type;
	uint32_t	id;
	uint64_t	off;
	uint16_t	data_len;
};

#define flag_stream		0x01
#define flag_fin		0x02
#define flag_data_len		0x04
#define flag_off_len1		0x08
#define flag_off_len2		0x10
#define flag_off_len3		0x20
#define flag_id_len1		0x40
#define flag_id_len2		0x80


void
q_connect(const int s);

void
q_serve(const int s);


void
parse_public_hdr(const uint8_t * const msg,
                 struct public_hdr * const hdr,
                 const uint16_t len);

uint16_t
make_public_hdr(const struct public_hdr * const hdr,
                uint8_t * const msg,
                const uint16_t len);

uint16_t
make_stream_frame(const uint32_t id,
		  const uint64_t off,
		  const uint16_t data_len,
		  uint8_t * const msg,
                  const uint16_t len);

#endif
