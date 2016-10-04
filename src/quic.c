#include <poll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "debug.h"
#include "quic.h"


#define MAX_PKT_LEN	2048

static uint32_t qs = 0;


static uint128_t
fnv_1a(const uint8_t *data,
       const uint16_t len,
       const uint16_t skip,
       const uint16_t skip_len)
{
	static const uint128_t prime =
		(((uint128_t)0x0000000001000000) << 64) | 0x000000000000013B;
	uint128_t hash =
		(((uint128_t)0x6C62272E07BB0142) << 64) | 0x62B821756295C58D;
	for (uint16_t i = 0; i < len; i++)
		if (i < skip || i >= skip + skip_len) {
			hash ^= data[i];
			hash *= prime;
		}
	return hash;
}


static uint16_t
decode_public_hdr(const uint8_t * const msg,
                 const bool is_initial,
                 struct public_hdr * const hdr,
                 const uint16_t len)
{
	uint16_t i = 0;

	hdr->flags = (uint8_t)msg[i++];
	warn(debug, "flags 0x%02x", hdr->flags);

	if (hdr->flags & flag_public_reset)
		warn(err, "public reset");

	if (i >= len)
		die("public header length only %d", len);

	if (hdr->flags & flag_conn_id) {
		// XXX no ntohll() applied, at least not by wireshark
		hdr->conn_id = *(const uint64_t *)(const void *)&msg[i];
		i += sizeof(uint64_t);
		warn(debug, "conn_id %llu", hdr->conn_id);
		if (i >= len)
			die("public header length only %d", len);
	}

	if (hdr->flags & flag_version) {
		hdr->version = ntohl(*(const uint32_t *)(const void *)&msg[i]);
		i += sizeof(uint32_t);
		const uint8_t v[5] = quic_version_to_ascii(hdr->version);
		warn(debug, "version 0x%08x %s", hdr->version, v);
		if (i >= len)
			die("public header length only %d", len);
	}

	if (hdr->flags & flag_div_nonce) {
		hdr->div_nonce_len = (uint8_t)MIN(len - i, 32);
		warn(debug, "div nonce len %d", hdr->div_nonce_len);
		hexdump(&msg[i], hdr->div_nonce_len);

		if (hdr->flags & flag_public_reset) {
			// interpret public reset packet
			if (memcmp("PRST", &msg[i], 4) == 0) {
				const uint32_t tag_len = *&msg[i + 4];
				warn(debug, "PRST with %d tags", tag_len);
				i += 8;

				for (uint32_t t = 0; t < tag_len; t++){
					char tag[5];
					memcpy(tag, &msg[i], 4);
					tag[4] = 0;
					uint64_t value = *&msg[i + 4];
					i += 8;
					warn(debug, "%s = %llu", tag, value);

				}

			} else
				die("cannot parse PRST");
			// return i;
		}

		i += hdr->div_nonce_len;
		if (i >= len)
			die("public header length only %d", len);
	}

	hdr->pkt_nr_len = decode_pkt_nr_len_flags(hdr->flags);
	warn(debug, "pkt_nr_len %d", hdr->pkt_nr_len);

	memcpy(&hdr->pkt_nr, &msg[i], hdr->pkt_nr_len);
	warn(debug, "pkt_nr %lld", hdr->pkt_nr);
	i += hdr->pkt_nr_len;
	if (i >= len)
		die("public header length only %d", len);

	if (hdr->flags & flag_multipath)
		warn(warn, "flag multipath");

	if (hdr->flags & flag_unused)
		warn(err, "flag unused");

	if (is_initial) {
		warn(debug, "i %d, len %d", i, len);
		hdr->hash = fnv_1a(msg, len, i, 12);
		if (memcmp(&msg[i], &hdr->hash, 12)) {
			die("hash mismatch");
		}
	}

	return i;
}


static uint16_t
encode_public_hdr(const struct public_hdr * const hdr,
                uint8_t * const msg,
                const uint16_t len)
{
	uint16_t i = 0;

	msg[i++] = hdr->flags;

	if (hdr->flags & flag_conn_id && len - i - sizeof(uint64_t) > 0) {
		// XXX no htonll() applied?
		*(uint64_t *)((void *)&msg[i]) = hdr->conn_id;
		warn(debug, "conn_id %lld", hdr->conn_id);
		i += sizeof(uint64_t);
	} else
		die("cannot encode conn_id");

	if (hdr->flags & flag_version && len - i - sizeof(uint32_t) > 0) {
		*(uint32_t *)((void *)&msg[i]) = htonl(hdr->version);
		const uint8_t v[5] = quic_version_to_ascii(hdr->version);
		warn(debug, "version 0x%08x %s", hdr->version, v);
		i += sizeof(uint32_t);
	} else
		die("cannot encode version");

	if (len - i - sizeof(uint32_t) > 0) {
		const uint8_t pkt_nr_len = 4;
		*(uint32_t *)((void *)&msg[i]) = htonl(hdr->pkt_nr);
		msg[0] |= encode_pkt_nr_len_flags(pkt_nr_len);
		warn(debug, "%d-byte pkt_nr %d", pkt_nr_len, (uint32_t)hdr->pkt_nr);
		i += sizeof(uint32_t);
	} else
		die("TODO");

	return i;
}


static uint16_t
encode_stream_frame(const uint32_t id,
		  const uint64_t off,
		  const uint16_t data_len,
		  uint8_t * const msg,
                  const uint16_t len)
{
	uint16_t i = 0;

	msg[i++] = flag_stream;
	if (len - i - sizeof(uint32_t) > 0) {
		*(uint32_t *)((void *)&msg[i]) = htonl(id);
		warn(debug, "4-byte id %d", id);
		msg[0] |= encode_stream_id_len_flags(4);
		i += sizeof(uint32_t);
	} else
		die("cannot encode id");

	if (len - i - sizeof(uint64_t) > 0) {
		*(uint64_t *)((void *)&msg[i]) = htonl(off);
		warn(debug, "8-byte off %lld", off);
		msg[0] |= encode_stream_off_len_flags(8);
		i += sizeof(uint64_t);
	} else
		die("cannot encode off");

	if (len - i - sizeof(uint16_t) > 0) {
		*(uint16_t *)((void *)&msg[i]) = htons(data_len);
		warn(debug, "2-byte data_len %d", data_len);
		msg[0] |= flag_stream_data_len;
		i += sizeof(uint16_t);
	} else
		die("cannot encode data_len");

	// XXX FIN bit

	return i;
}


static uint16_t
decode_stream_frame(uint8_t * const msg,
              const uint16_t len,
              const struct public_hdr * const hdr)
{
	warn(debug, "here");
	return len;
}


static uint16_t
decode_ack_frame(uint8_t * const msg,
              const uint16_t len,
              const struct public_hdr * const hdr)
{
	warn(debug, "here");
	return len;
}


static uint16_t
decode_regular_frame(uint8_t * const msg,
              const uint16_t len,
              const struct public_hdr * const hdr)
{
	uint16_t i = len;

	warn(debug, "here");
	switch (msg[0]) {
	case type_padding:
		warn(debug, "padding frame");
		break;
	case type_rst_stream:
		warn(debug, "rst_stream frame");
		break;
	case type_connection_close:
		warn(debug, "connection_close frame");
		break;
	case type_goaway:
		warn(debug, "goaway frame");
		break;
	case type_window_update:
		warn(debug, "window_update frame");
		break;
	case type_blocked:
		warn(debug, "blocked frame");
		break;

	case type_stop_waiting: {
		uint64_t delta = 0;
		memcpy(&delta, &msg[i], hdr->pkt_nr_len);
		warn(debug, "stop_waiting frame, delta %llu",
		     hdr->pkt_nr - delta);
		i += hdr->pkt_nr_len;
		break;
	}

	case type_ping:
		warn(debug, "ping frame");
		break;
	default:
		die("unknown frame type 0x%02x", msg[0]);
	}
	return i;
}


static uint16_t
decode_frames(uint8_t * const msg,
              const uint16_t len,
              const struct public_hdr * const hdr)
{
	uint16_t i = len;
	while (len)
		if (msg[0] & flag_stream)
			i -= decode_stream_frame(msg, len, hdr);
		else if (msg[0] & (!flag_stream|flag_ack))
			i -= decode_ack_frame(msg, len, hdr);
		else
			i -= decode_regular_frame(msg, len, hdr);
	return i;
}

void
q_connect(const int s)
{
	if (qs)
		die("can only handle a single connection");

	qs = (uint32_t)s;

	struct public_hdr hdr = {
		.flags = flag_version|flag_conn_id,
		.version = quic_version,
		.conn_id = 0xCC,
		.pkt_nr = 1
	};
	uint8_t msg[MAX_PKT_LEN];
	uint16_t len = encode_public_hdr(&hdr, msg, MAX_PKT_LEN);

	// leave space for hash
	const uint16_t hash_pos = len;
	len += 12;

	char data[] = "GET /";
	len += encode_stream_frame(1, 0, (uint16_t)strlen(data), msg + len,
	                         MAX_PKT_LEN-len);
	memcpy(msg + len, "GET /", strlen(data));
	len += strlen(data);

	const uint128_t hash = fnv_1a(msg, len, hash_pos, 12);
	memcpy(&msg[hash_pos], &hash, 12);

	warn(debug, "sending");
	hexdump(msg, (uint32_t)len);
	ssize_t n = send(s, msg, len, 0);
	if (n < 0)
		die("send");

	struct pollfd fds = { .fd = s, .events = POLLIN };
	do {
		n = poll(&fds, 1, 1000);
		if (n < 0)
			die("poll");
	} while (n == 0);

	warn(debug, "receiving");
	n = recv(s, msg, MAX_PKT_LEN, 0);
	if (n < 0)
		die("recv");
	hexdump(msg, (uint32_t)n);

	len = decode_public_hdr(msg, true, &hdr, (uint16_t)n);
	decode_frames(&msg[len], (uint16_t)n - len, &hdr);

	if (hdr.flags & flag_version) {
		const uint8_t v[5] = quic_version_to_ascii(quic_version);
		die("server didn't accept our version 0x%08x %s",
		    quic_version, v);
	}

}

void
q_serve(const int s)
{
	if (qs)
		die("can only handle a single connection");

	qs = (uint32_t)s;

	struct pollfd fds = { .fd = s, .events = POLLIN };
	ssize_t n;
	do {
		n = poll(&fds, 1, 1000);
		if (n < 0)
			die("poll");
	} while (n == 0);

	warn(debug, "receiving");
	uint8_t msg[MAX_PKT_LEN];
	n = recv(s, msg, MAX_PKT_LEN, 0);
	if (n < 0)
		die("recv");
	hexdump(msg, (uint32_t)n);

	struct public_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));
	decode_public_hdr(msg, true, &hdr, (uint16_t)n);

}



