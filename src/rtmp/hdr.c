/**
 * @file rtmp/hdr.c  Real Time Messaging Protocol (RTMP) -- Headers
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_rtmp.h>
#include "rtmp.h"


enum {
	RTMP_CHUNK_ID_CONTROL =     2,

	RTMP_CHUNK_ID_MIN     =     3,
	RTMP_CHUNK_ID_MAX     = 65599,  /* 65535 + 64*/
};


/* XXX: move to utils */
static int mbuf_write_u24_hton(struct mbuf *mb, uint32_t u)
{
	int err = 0;

	err |= mbuf_write_u8(mb, u >> 16);
	err |= mbuf_write_u8(mb, u >> 8);
	err |= mbuf_write_u8(mb, u >> 0);

	return err;
}


/* XXX: move to utils */
static uint32_t mbuf_read_u24_ntoh(struct mbuf *mb)
{
	uint32_t u;

	u  = (uint32_t)mbuf_read_u8(mb) << 16;
	u |= (uint32_t)mbuf_read_u8(mb) << 8;
	u |= (uint32_t)mbuf_read_u8(mb) << 0;

	return u;
}


static int encode_basic_hdr(struct mbuf *mb, unsigned fmt,
			    uint32_t chunk_id)
{
	uint8_t v;
	int err = 0;

	if (chunk_id >= 320) {

		const uint16_t cs_id = chunk_id - 64;

		v = fmt<<6 | 1;

		err |= mbuf_write_u8(mb, v);
		err |= mbuf_write_u16(mb, htons(cs_id));
	}
	else if (chunk_id >= 64) {

		const uint8_t cs_id = chunk_id - 64;

		v = fmt<<6 | 0;

		err |= mbuf_write_u8(mb, v);
		err |= mbuf_write_u8(mb, cs_id);
	}
	else {
		v = fmt<<6 | chunk_id;

		err |= mbuf_write_u8(mb, v);
	}

	return err;
}


int rtmp_header_encode(struct mbuf *mb, const struct rtmp_header *hdr)
{
	int err = 0;

	if (!mb || !hdr)
		return EINVAL;

	err = encode_basic_hdr(mb, hdr->format, hdr->chunk_id);
	if (err)
		return err;

	switch (hdr->format) {

	case 0:
		err |= mbuf_write_u24_hton(mb, hdr->timestamp);
		err |= mbuf_write_u24_hton(mb, hdr->length);
		err |= mbuf_write_u8(mb, hdr->type_id);
		err |= mbuf_write_u32(mb, htonl(hdr->stream_id));
		break;

	case 1:
		err |= mbuf_write_u24_hton(mb, hdr->timestamp_delta);
		err |= mbuf_write_u24_hton(mb, hdr->length);
		err |= mbuf_write_u8(mb, hdr->type_id);
		break;

	case 2:
		err |= mbuf_write_u24_hton(mb, hdr->timestamp_delta);
		break;

	case 3:
		break;
	}

	return err;
}


int rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb)
{
	uint8_t chunk_magic;
	uint8_t v;

	if (!hdr || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < 1)
		return ENODATA;

	v = mbuf_read_u8(mb);

	hdr->format = v>>6;

	chunk_magic = v & 0x3f;

	/* XXX: use switch */
	if (chunk_magic == 0) {

		if (mbuf_get_left(mb) < 1)
			return ENODATA;

		v = mbuf_read_u8(mb);

		hdr->chunk_id = v + 64;
	}
	else if (chunk_magic == 1) {

		uint16_t cs;

		if (mbuf_get_left(mb) < 2)
			return ENODATA;

		cs = ntohs(mbuf_read_u16(mb));

		hdr->chunk_id = cs + 64;
	}
	else if (chunk_magic == RTMP_CHUNK_ID_CONTROL) {

		hdr->chunk_id = chunk_magic;
	}
	else {
		hdr->chunk_id = chunk_magic;
	}

	switch (hdr->format) {

	case 0:
		if (mbuf_get_left(mb) < 11)
			return ENODATA;

		hdr->timestamp = mbuf_read_u24_ntoh(mb);
		hdr->length    = mbuf_read_u24_ntoh(mb);
		hdr->type_id   = mbuf_read_u8(mb);
		hdr->stream_id = ntohl(mbuf_read_u32(mb));
		break;

	case 1:
		if (mbuf_get_left(mb) < 7)
			return ENODATA;

		hdr->timestamp_delta = mbuf_read_u24_ntoh(mb);
		hdr->length          = mbuf_read_u24_ntoh(mb);
		hdr->type_id         = mbuf_read_u8(mb);
		break;

	case 2:
		if (mbuf_get_left(mb) < 3)
			return ENODATA;

		hdr->timestamp_delta = mbuf_read_u24_ntoh(mb);
		break;

	case 3:
		/* no payload */
		break;

	default:
		re_printf("rtmp: decode: header format not supported (%d)\n",
			  hdr->format);
		return ENOTSUP;
	}

	return 0;
}


int rtmp_header_print(struct re_printf *pf, const struct rtmp_header *hdr)
{
	int err = 0;

	if (!hdr)
		return 0;

	err |= re_hprintf(pf, "format:     %u\n", hdr->format);
	err |= re_hprintf(pf, "chunk_id:   %u\n", hdr->chunk_id);

	switch (hdr->format) {

	case 0:
		err |= re_hprintf(pf, "timestamp:  %u\n", hdr->timestamp);
		err |= re_hprintf(pf, "msg_length: %u\n", hdr->length);
		err |= re_hprintf(pf, "msg_type:   %u\n", hdr->type_id);
		err |= re_hprintf(pf, "stream_id:  %u\n", hdr->stream_id);
		break;

	case 1:
		err |= re_hprintf(pf, "timestamp_delta:  %u\n",
				  hdr->timestamp_delta);
		err |= re_hprintf(pf, "msg_length:       %u\n",
				  hdr->length);
		err |= re_hprintf(pf, "msg_type:         %u\n",
				  hdr->type_id);
		break;

	case 2:
		err |= re_hprintf(pf, "timestamp_delta:  %u\n",
				  hdr->timestamp_delta);
		break;

	case 3:
		err |= re_hprintf(pf, "(no payload)\n");
		break;
	}

	return err;
}
