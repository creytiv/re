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
#include <re_list.h>
#include <re_sys.h>
#include <re_rtmp.h>
#include "rtmp.h"


enum {
	RTMP_CHUNK_ID_MIN     = 3,
	RTMP_CHUNK_ID_MAX     = 65599,  /* 65535 + 64 */

	RTMP_CHUNK_OFFSET     = 64,
};


static int mbuf_write_u24_hton(struct mbuf *mb, uint32_t u24)
{
	int err = 0;

	err |= mbuf_write_u8(mb, u24 >> 16);
	err |= mbuf_write_u8(mb, u24 >> 8);
	err |= mbuf_write_u8(mb, u24 >> 0);

	return err;
}


static uint32_t mbuf_read_u24_ntoh(struct mbuf *mb)
{
	uint32_t u24;

	u24  = (uint32_t)mbuf_read_u8(mb) << 16;
	u24 |= (uint32_t)mbuf_read_u8(mb) << 8;
	u24 |= (uint32_t)mbuf_read_u8(mb) << 0;

	return u24;
}


static int encode_basic_hdr(struct mbuf *mb, unsigned fmt,
			    uint32_t chunk_id)
{
	uint8_t v;
	int err = 0;

	if (chunk_id >= 320) {

		const uint16_t cs_id = chunk_id - RTMP_CHUNK_OFFSET;

		v = fmt<<6 | 1;

		err |= mbuf_write_u8(mb, v);
		err |= mbuf_write_u16(mb, htons(cs_id));
	}
	else if (chunk_id >= RTMP_CHUNK_OFFSET) {

		const uint8_t cs_id = chunk_id - RTMP_CHUNK_OFFSET;

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
		err |= mbuf_write_u32(mb, sys_htoll(hdr->stream_id));
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


static int decode_basic_hdr(struct rtmp_header *hdr, struct mbuf *mb)
{
	uint8_t cs_id;
	uint8_t v;

	if (mbuf_get_left(mb) < 1)
		return ENODATA;

	v = mbuf_read_u8(mb);

	hdr->format = v>>6;

	cs_id = v & 0x3f;

	switch (cs_id) {

	case 0:
		if (mbuf_get_left(mb) < 1)
			return ENODATA;

		hdr->chunk_id = mbuf_read_u8(mb) + RTMP_CHUNK_OFFSET;
		break;

	case 1:
		if (mbuf_get_left(mb) < 2)
			return ENODATA;

		hdr->chunk_id = ntohs(mbuf_read_u16(mb)) + RTMP_CHUNK_OFFSET;
		break;

	default:
		hdr->chunk_id = cs_id;
		break;
	}

	return 0;
}


int rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb)
{
	int err;

	if (!hdr || !mb)
		return EINVAL;

	err = decode_basic_hdr(hdr, mb);
	if (err)
		return err;

	switch (hdr->format) {

	case 0:
		if (mbuf_get_left(mb) < 11)
			return ENODATA;

		hdr->timestamp = mbuf_read_u24_ntoh(mb);
		hdr->length    = mbuf_read_u24_ntoh(mb);
		hdr->type_id   = mbuf_read_u8(mb);
		hdr->stream_id = sys_ltohl(mbuf_read_u32(mb));
		break;

	case 1:
		if (mbuf_get_left(mb) < 7)
			return ENODATA;

		hdr->timestamp_delta = mbuf_read_u24_ntoh(mb);
		hdr->length          = mbuf_read_u24_ntoh(mb);
		hdr->type_id         = mbuf_read_u8(mb);

		if (hdr->length > MESSAGE_LEN_MAX) {
			re_fprintf(stderr, "rtmp: header decode:"
				   " message length too large"
				   " (%u > %u)\n",
				   hdr->length, MESSAGE_LEN_MAX);
		}
		break;

	case 2:
		if (mbuf_get_left(mb) < 3)
			return ENODATA;

		hdr->timestamp_delta = mbuf_read_u24_ntoh(mb);
		break;

	case 3:
		/* no payload */
		break;
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
		err |= re_hprintf(pf, "msg_type:   %u (%s)\n",
				  hdr->type_id,
				  rtmp_packet_type_name(hdr->type_id));
		err |= re_hprintf(pf, "stream_id:  %u\n", hdr->stream_id);
		break;

	case 1:
		err |= re_hprintf(pf, "timestamp_delta:  %u\n",
				  hdr->timestamp_delta);
		err |= re_hprintf(pf, "msg_length:       %u\n",
				  hdr->length);
		err |= re_hprintf(pf, "msg_type:         %u (%s)\n",
				  hdr->type_id,
				  rtmp_packet_type_name(hdr->type_id));
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


const char *rtmp_packet_type_name(enum rtmp_packet_type type)
{
	switch (type) {

	case RTMP_TYPE_SET_CHUNK_SIZE:    return "Set Chunk Size";
	case RTMP_TYPE_USER_CONTROL_MSG:  return "User Control Message";
	case RTMP_TYPE_WINDOW_ACK_SIZE:   return "Window Acknowledgement Size";
	case RTMP_TYPE_SET_PEER_BANDWIDTH:return "Set Peer Bandwidth";
	case RTMP_TYPE_AUDIO:             return "Audio Message";
	case RTMP_TYPE_AMF0:              return "AMF";
	default: return "?";
	}
}
