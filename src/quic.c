#include "debug.h"
#include "quic.h"


void
parse_public_hdr(const char * const pkt,
                 struct public_hdr * const hdr)
{
	uint8_t i = 0;

	hdr->flags = (uint8_t)pkt[i++];

	if (hdr->flags & flag_public_reset) {
		warn(err, "public reset");
	}

	if (hdr->flags & flag_conn_id) {
		hdr->conn_id = (uint64_t)pkt[i];
		i += sizeof(uint64_t);
		warn(debug, "conn_id %lld, i %d", hdr->conn_id, i);
	}

	if (hdr->flags & flag_version) {
		hdr->version = (uint32_t)pkt[i];
		i += sizeof(uint32_t);
		warn(debug, "version %d", hdr->version);
	}

	if (hdr->flags & flag_div_nonce) {
		warn(debug, "div nonce");
		hexdump(&pkt[i], 32);
		i += 32;
	}

	if (hdr->flags & flag_pkt_nr_len_4) {
		if (hdr->flags & flag_pkt_nr_len_2) {
			warn(debug, "pkt_nr_len 6");
		} else {
			warn(debug, "pkt_nr_len 4");
		}
	} else {
		if (hdr->flags & flag_pkt_nr_len_2) {
			warn(debug, "pkt_nr_len 2");
		} else {
			warn(debug, "pkt_nr_len 1");
		}
	}

}


void
make_public_hdr(const struct public_hdr * const hdr,
                char * const msg,
                const ssize_t len)
{
	uint8_t i = 1;

	if (hdr->flags & flag_version) {
		msg[0] |= flag_version;
		*(uint32_t *)&msg[i] = hdr->version;
		warn(debug, "version %d", hdr->version);
		i += sizeof(uint32_t);
	}

}
