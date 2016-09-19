#include <stdint.h>
#include <stdbool.h>

enum stream_state { idle, reserved, open, half_closed, closed };

struct public_hdr {
	uint8_t		flags;
	uint8_t		unused[3];
	uint32_t	version;	// if flags & flag_version
	uint64_t	conn_id;	// if flags & flag_conn_id
	uint8_t		div_nonce[32];	// if flags & flag_div_nonce
	uint64_t	pkt_nr;
};

#define flag_version		0x01
#define flag_public_reset	0x02
#define flag_div_nonce		0x04
#define flag_conn_id		0x08

#define flag_pkt_nr_len_2	0x10
#define flag_pkt_nr_len_4	0x20

#define flag_multipath		0x40	// reserved
#define flag_unused		0x80	// reserved (must be 0)


void parse_public_hdr(const char * const pkt, struct public_hdr * const hdr);
