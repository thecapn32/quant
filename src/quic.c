#include "debug.h"
#include "quic.h"
#include "tommy.h"

// The master hash of all QUIC sockets
static hash sockets;


// Compare socket hash keys
static int
hash_cmp(const void * const arg, const void * const obj)
{
        return *(const uint32_t*)arg != ((const struct q_socket *)obj)->k;
}


void
q_connect(const int s)
{
	hash_search(&sockets, hash_cmp, &s, (hash_t)s);
}



void
parse_public_hdr(const char * const msg,
                 struct public_hdr * const hdr,
                 const uint16_t len)
{
	uint8_t i = 0;

	hdr->flags = (uint8_t)msg[i++];
	if (i >= len)
		return;

	if (hdr->flags & flag_public_reset) {
		warn(err, "public reset");
		return;
	}

	if (hdr->flags & flag_conn_id) {
		hdr->conn_id = *(uint64_t *)&msg[i];
		i += sizeof(uint64_t);
		warn(debug, "conn_id %lld", hdr->conn_id);
	}
	if (i >= len)
		return;

	if (hdr->flags & flag_version) {
		hdr->version = *(uint32_t *)&msg[i];
		i += sizeof(uint32_t);
		warn(debug, "version %d", hdr->version);
	}
	if (i >= len)
		return;

	if (hdr->flags & flag_div_nonce) {
		warn(debug, "div nonce");
		hexdump(&msg[i], 32);
		i += 32;
	}
	if (i >= len)
		return;

	if (hdr->flags & flag_pkt_nr_len_4)
		if (hdr->flags & flag_pkt_nr_len_2) {
			warn(debug, "pkt_nr_len 6");
		} else {
			warn(debug, "pkt_nr_len 4");
		}
	else
		if (hdr->flags & flag_pkt_nr_len_2) {
			warn(debug, "pkt_nr_len 2");
		} else {
			warn(debug, "pkt_nr_len 1");
		}

	if (hdr->flags & flag_multipath)
		warn(warn, "flag multipath");

	if (hdr->flags & flag_unused)
		warn(err, "flag unused");
}


uint16_t
make_public_hdr(const struct public_hdr * const hdr,
                char * const msg,
                const uint16_t len)
{
	uint16_t i = 0;

	msg[i++] = hdr->flags;

	if (hdr->flags & flag_conn_id && len - i - sizeof(uint64_t) > 0) {
		*(uint64_t *)(&msg[i]) = hdr->conn_id;
		warn(debug, "conn_id %lld", hdr->conn_id);
		i += sizeof(uint64_t);
	} else
		die("cannot encode conn_id");

	if (hdr->flags & flag_version && len - i - sizeof(uint32_t) > 0) {
		*(uint32_t *)(&msg[i]) = hdr->version;
		warn(debug, "version 0x%08x", hdr->version);
		i += sizeof(uint32_t);
	} else
		die("cannot encode version");

	if (hdr->pkt_nr < UINT8_MAX && len - i - sizeof(uint8_t) > 0) {
		msg[i] = (uint8_t)hdr->pkt_nr;
		warn(debug, "1-byte pkt_nr %lld", hdr->pkt_nr);
		i += sizeof(uint8_t);
	} else
		die("TODO");

	return i;
}
