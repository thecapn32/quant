#include <poll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "debug.h"
#include "quic.h"
// #include "tommy.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// The master hash of all QUIC sockets
// static hash sockets;
static uint32_t qs = 0;

// Compare socket hash keys
// static int
// hash_cmp(const void * const arg, const void * const obj)
// {
// 	warn(debug, "hash_cmp");
//         return *(const uint32_t *)arg != ((const struct q_socket *)obj)->k;
// }


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
		.pkt_nr = 0x0
	};
	uint8_t msg[1024];
	uint16_t len = make_public_hdr(&hdr, msg, 1024);
	char data[] = "GET /";
	len += make_stream_frame(1, 0, (uint16_t)strlen(data), msg + len, 1024-len);
	memcpy(msg + len, "GET /", strlen(data));
	len += strlen(data);

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
	n = recv(s, msg, 1024, 0);
	if (n < 0)
		die("recv");

	parse_public_hdr(msg, &hdr, (uint16_t)n);

	if (hdr.flags & flag_version)
		die("server didn't accept our version %s",
		    TOSTRING(quic_version));

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
	uint8_t msg[1024];
	n = recv(s, msg, 1024, 0);
	if (n < 0)
		die("recv");

	struct public_hdr hdr;
	parse_public_hdr(msg, &hdr, (uint16_t)n);

}



void
parse_public_hdr(const uint8_t * const msg,
                 struct public_hdr * const hdr,
                 const uint16_t len)
{
	uint16_t i = 0;

	hdr->flags = (uint8_t)msg[i++];
	if (i >= len)
		return;

	if (hdr->flags & flag_public_reset) {
		warn(err, "public reset");
		return;
	}

	if (hdr->flags & flag_conn_id) {
		hdr->conn_id = ntohll(*(const uint64_t *)(const void *)&msg[i]);
		i += sizeof(uint64_t);
		warn(debug, "conn_id %lld", hdr->conn_id);
	}
	if (i >= len)
		return;

	if (hdr->flags & flag_version) {
		hdr->version = ntohl(*(const uint32_t *)(const void *)&msg[i]);
		i += sizeof(uint32_t);
		warn(debug, "version 0x%08x", hdr->version);
	}
	if (i >= len)
		return;

	if (hdr->flags & flag_div_nonce) {
		hdr->div_nonce_len = (uint8_t)MIN(len - i, 32);
		warn(debug, "div nonce len %d", hdr->div_nonce_len);
		hexdump(&msg[i], hdr->div_nonce_len);
		i += hdr->div_nonce_len;
	}
	if (i >= len)
		return;

	if (hdr->flags & flag_pkt_nr_len_2)
		if (hdr->flags & flag_pkt_nr_len_1) {
			warn(debug, "pkt_nr_len 6");
		} else {
			warn(debug, "pkt_nr_len 4");
		}
	else
		if (hdr->flags & flag_pkt_nr_len_1) {
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
                uint8_t * const msg,
                const uint16_t len)
{
	uint16_t i = 0;

	msg[i++] = hdr->flags;

	if (hdr->flags & flag_conn_id && len - i - sizeof(uint64_t) > 0) {
		*(uint64_t *)((void *)&msg[i]) = hdr->conn_id;
		warn(debug, "conn_id %lld", hdr->conn_id);
		i += sizeof(uint64_t);
	} else
		die("cannot encode conn_id");

	if (hdr->flags & flag_version && len - i - sizeof(uint32_t) > 0) {
		*(uint32_t *)((void *)&msg[i]) = htonl(hdr->version);
		warn(debug, "version 0x%08x", hdr->version);
		i += sizeof(uint32_t);
	} else
		die("cannot encode version");

	// if (hdr->pkt_nr < UINT8_MAX && len - i - sizeof(uint8_t) > 0) {
	if (len - i - sizeof(uint32_t) > 0) {
		*(uint32_t *)((void *)&msg[i]) = htonl(hdr->pkt_nr);
		msg[0] |= flag_pkt_nr_len_2;
		warn(debug, "32-bit pkt_nr %d", hdr->pkt_nr);
		i += sizeof(uint32_t);
	} else
		die("TODO");

	return i;
}


uint16_t
make_stream_frame(const uint32_t id,
		  const uint64_t off,
		  const uint16_t data_len,
		  uint8_t * const msg,
                  const uint16_t len)
{
	uint16_t i = 0;

	msg[i++] = flag_stream|flag_data_len;

	// XXX FIN bit

	// stream id 8 bits = 0x00
	// if (id > UINT8_MAX && id < UINT16_MAX)
	// 	// stream id 16 bits = 0x01
	// 	msg[0] |= flag_id_len1;
	// else if (id < UINT16_MAX * UINT8_MAX)
	// 	// stream id 24 bits = 0x10
	// 	msg[0] |= flag_id_len2;
	// else if (id < UINT32_MAX)
		// stream id 32 bits = 0x11
		msg[0] |= flag_id_len1|flag_id_len2;

	// off 8 bits = 0x000
	// if (off > UINT8_MAX && off < UINT16_MAX)
	// 	// off 16 bits = 0x001
	// 	msg[0] |= flag_off_len1;
	// else if (off < UINT16_MAX * UINT8_MAX)
	// 	// off 24 bits = 0x010
	// 	msg[0] |= flag_off_len2;
	// else if (off < UINT32_MAX)
	// 	// off 32 bits = 0x011
	// 	msg[0] |= flag_off_len1|flag_off_len2;
	// else if (off < UINT32_MAX * UINT8_MAX)
	// 	// off 40 bits = 0x100
	// 	msg[0] |= flag_off_len3;
	// else if (off < UINT32_MAX * UINT16_MAX)
	// 	// off 48 bits = 0x101
	// 	msg[0] |= flag_off_len1|flag_off_len3;
	// else if (off < UINT32_MAX * UINT16_MAX * UINT8_MAX)
	// 	// off 56 bits = 0x110
	// 	msg[0] |= flag_off_len2|flag_off_len3;
	// else if (off < UINT64_MAX)
		// off 64 bits = 0x111
		msg[0] |= flag_off_len1|flag_off_len2|flag_off_len3;

	if (len - i - sizeof(uint32_t) > 0) {
		*(uint32_t *)((void *)&msg[i]) = htonl(id);
		warn(debug, "32-bit id %d", id);
		i += sizeof(uint32_t);
	} else
		die("cannot encode id");

	if (len - i - sizeof(uint64_t) > 0) {
		*(uint64_t *)((void *)&msg[i]) = htonl(off);
		warn(debug, "64-bit off %lld", off);
		i += sizeof(uint64_t);
	} else
		die("cannot encode off");

	if (len - i - sizeof(uint16_t) > 0) {
		*(uint16_t *)((void *)&msg[i]) = htons(data_len);
		warn(debug, "16-bit data_len %d", data_len);
		i += sizeof(uint16_t);
	} else
		die("cannot encode off");

	return i;
}
