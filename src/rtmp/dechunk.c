/**
 * @file rtmp/dechunk.c  Real Time Messaging Protocol (RTMP) -- Dechunking
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_rtmp.h>
#include "rtmp.h"


enum {
	MAX_PENDING = 16,
	MAX_CHUNK_ID = 64
};


struct chunk_cache {

	size_t msg_len;
	bool   msg_len_set;

	uint32_t stream_id;
	bool     stream_id_set;
};

struct rtmp_dechunker {
	struct list msgl;  /* struct rtmp_message */
	struct chunk_cache chunkv[MAX_CHUNK_ID];  /* chunk_id is index */
	size_t chunk_sz;
	rtmp_msg_h *msgh;
	void *arg;
};


static void destructor(void *data)
{
	struct rtmp_dechunker *rd = data;

#if 0
	size_t i;

	re_printf("*** Dechunker cache:\n");

	for (i=0; i<ARRAY_SIZE(rd->chunkv); i++) {
		struct chunk_cache *cache = &rd->chunkv[i];

		if (cache->stream_id_set || cache->msg_len_set) {
			re_printf(".... chunk_id=%u    len=%zu"
				  "    stream_id=%u\n",
				  i,
				  cache->msg_len,
				  cache->stream_id);
		}
	}
#endif

	list_flush(&rd->msgl);
}


static void chunk_destructor(void *data)
{
	struct rtmp_message *msg = data;

	list_unlink(&msg->le);
	mem_deref(msg->buf);
}


static struct rtmp_message *create_message(struct list *msgl,
					   uint32_t chunk_id, size_t length,
					   uint8_t type)
{
	struct rtmp_message *msg;

	msg = mem_zalloc(sizeof(*msg), chunk_destructor);
	if (!msg)
		return NULL;

	msg->chunk_id = chunk_id;
	msg->length   = length;
	msg->type     = type;

	msg->buf = mem_alloc(length, NULL);
	if (!msg->buf)
		return mem_deref(msg);

	list_append(msgl, &msg->le, msg);

	return msg;
}


static struct rtmp_message *find_message(const struct list *msgl,
					 uint32_t chunk_id)
{
	struct le *le;

	for (le = list_head(msgl); le; le = le->next) {

		struct rtmp_message *msg = le->data;

		if (chunk_id == msg->chunk_id)
			return msg;
	}

	return NULL;
}


/*
 * Stateful RTMP de-chunker for receiving complete messages
 */
int rtmp_dechunker_alloc(struct rtmp_dechunker **rdp,
			 rtmp_msg_h *msgh, void *arg)
{
	struct rtmp_dechunker *rd;

	if (!rdp || !msgh)
		return EINVAL;

	rd = mem_zalloc(sizeof(*rd), destructor);
	if (!rd)
		return ENOMEM;

	rd->chunk_sz = RTMP_DEFAULT_CHUNKSIZE;

	rd->msgh = msgh;
	rd->arg  = arg;

	*rdp = rd;

	return 0;
}


int rtmp_dechunker_receive(struct rtmp_dechunker *rd, struct mbuf *mb)
{
	struct rtmp_header hdr;
	struct rtmp_message *msg;
	struct chunk_cache *cache;
	size_t chunk_sz, left, msg_len;
	bool complete;
	int err;

	if (!rd)
		return EINVAL;

	err = rtmp_header_decode(&hdr, mb);
	if (err)
		return err;

	switch (hdr.format) {

		/* only types 0-2 can create a new chunk */
	case 0:
	case 1:
	case 2:
		if (hdr.chunk_id >= MAX_CHUNK_ID) {
			re_printf("chunk id out of range (%u > %u)\n",
				  hdr.chunk_id, MAX_CHUNK_ID);
			return ERANGE;
		}

		cache = &rd->chunkv[hdr.chunk_id];

		msg = find_message(&rd->msgl, hdr.chunk_id);
		if (msg) {
			re_printf("rtmp: dechunker: unexpected"
				  " message found (chunk_id=%u)\n",
				  hdr.chunk_id);
			return EPROTO;
		}

		/* limits */
		if (list_count(&rd->msgl) > MAX_PENDING)
			return EOVERFLOW;

		/* Type 2 -- this chunk has the same stream ID and
		   message length as the preceding chunk. */
		if (hdr.format == 2) {
			if (!cache->msg_len_set)
				return EPROTO;

			msg_len = cache->msg_len;
		}
		else {
			cache->msg_len = hdr.length;
			cache->msg_len_set = true;

			msg_len = hdr.length;
		}

		if (msg_len > MESSAGE_LEN_MAX)
			return EOVERFLOW;

		chunk_sz = min(msg_len, rd->chunk_sz);

		if (mbuf_get_left(mb) < chunk_sz)
			return ENODATA;

		msg = create_message(&rd->msgl, hdr.chunk_id,
				     msg_len, hdr.type_id);
		if (!msg)
			return ENOMEM;

		/* type 1 and 2 does not contain stream id */
		if (hdr.format == 0) {

			msg->stream_id = hdr.stream_id;

			cache->stream_id     = hdr.stream_id;
			cache->stream_id_set = true;
		}
		else {
			if (!cache->stream_id_set)
				return EPROTO;
			msg->stream_id = cache->stream_id;
		}

		err = mbuf_read_mem(mb, msg->buf, chunk_sz);
		if (err)
			return err;

		msg->pos = chunk_sz;

		msg->format = hdr.format;
		msg->timestamp = hdr.timestamp;
		msg->timestamp_delta = hdr.timestamp_delta;
		break;

	case 3:
		msg = find_message(&rd->msgl, hdr.chunk_id);
		if (!msg) {
			re_printf("rtmp: dechunker: no chunk found\n");
			return EPROTO;
		}

		left = msg->length - msg->pos;

		chunk_sz = min(left, rd->chunk_sz);

		if (mbuf_get_left(mb) < chunk_sz)
			return ENODATA;

		err = mbuf_read_mem(mb, &msg->buf[msg->pos], chunk_sz);
		if (err)
			return err;

		msg->pos += chunk_sz;
		break;
	}

	complete = (msg->pos >= msg->length);

	if (complete) {

		rd->msgh(msg, rd->arg);

		mem_deref(msg);
	}

	return err;
}


void rtmp_dechunker_set_chunksize(struct rtmp_dechunker *rd, size_t chunk_sz)
{
	if (!rd)
		return;

	rd->chunk_sz = chunk_sz;
}
