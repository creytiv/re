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
};


struct rtmp_chunk {
	struct le le;
	struct rtmp_header hdr;
	struct mbuf *mb;
};

struct rtmp_dechunker {
	struct list msgl;      /* struct rtmp_chunk */
	size_t chunk_sz;
	rtmp_dechunk_h *chunkh;
	void *arg;
};


static void destructor(void *data)
{
	struct rtmp_dechunker *rd = data;

	list_flush(&rd->msgl);
}


static void chunk_destructor(void *data)
{
	struct rtmp_chunk *msg = data;

	list_unlink(&msg->le);
	mem_deref(msg->mb);
}


static struct rtmp_chunk *create_chunk(struct list *msgl,
					 const struct rtmp_header *hdr)
{
	struct rtmp_chunk *msg;

	msg = mem_zalloc(sizeof(*msg), chunk_destructor);
	if (!msg)
		return NULL;

	msg->hdr = *hdr;

	list_append(msgl, &msg->le, msg);

	return msg;
}


static struct rtmp_chunk *find_chunk(const struct list *msgl,
					 uint32_t chunk_id)
{
	struct le *le;

	for (le = list_head(msgl); le; le = le->next) {

		struct rtmp_chunk *msg = le->data;

		if (chunk_id == msg->hdr.chunk_id)
			return msg;
	}

	return NULL;
}


/*
 * Stateful RTMP de-chunker for receiving complete messages
 */
int  rtmp_dechunker_alloc(struct rtmp_dechunker **rdp, size_t chunk_sz,
			  rtmp_dechunk_h *chunkh, void *arg)
{
	struct rtmp_dechunker *rd;

	if (!rdp || !chunkh)
		return EINVAL;

	rd = mem_zalloc(sizeof(*rd), destructor);
	if (!rd)
		return ENOMEM;

	rd->chunk_sz = chunk_sz;

	rd->chunkh = chunkh;
	rd->arg    = arg;

	*rdp = rd;

	return 0;
}


int rtmp_dechunker_receive(struct rtmp_dechunker *rd, struct mbuf *mb)
{
	struct rtmp_header hdr;
	struct rtmp_chunk *msg;
	size_t chunk_sz, left, msg_len;
	bool complete;
	int err;

	if (!rd)
		return EINVAL;

	err = rtmp_header_decode(&hdr, mb);
	if (err)
		return err;

	/* find preceding chunk, from chunk id */
	msg = find_chunk(&rd->msgl, hdr.chunk_id);

#if 0
	re_printf("dechunk: packet: format=%u  chunk_id=%u  length=%u"
		  "  type=%d"
		  " -- msg_find: %p\n",
		  hdr.format, hdr.chunk_id, hdr.length,
		  msg ? msg->hdr.type_id : -1,
		  msg);
#endif

	if (!msg) {

		/* only type 0 can create a new chunk stream */
		if (hdr.format == 0) {
			msg = create_chunk(&rd->msgl, &hdr);
			if (!msg)
				return ENOMEM;
		}
		else {
			re_printf("no chunk stream found for id=%u\n",
				  hdr.chunk_id);
			return ENOENT;
		}
	}

	/* only types 0-2 can create a new buffer */

	switch (hdr.format) {

	case 0:
	case 1:
	case 2:
		if (hdr.format == 0) {

			/* copy the whole header */
			msg->hdr = hdr;
		}
		else if (hdr.format == 1) {

			msg->hdr.timestamp_delta = hdr.timestamp_delta;
			msg->hdr.length          = hdr.length;
			msg->hdr.type_id         = hdr.type_id;

			msg->hdr.timestamp      += hdr.timestamp_delta;
		}
		else if (hdr.format == 2) {

			msg->hdr.timestamp_delta = hdr.timestamp_delta;
			msg->hdr.timestamp      += hdr.timestamp_delta;
		}

		msg_len = msg->hdr.length;

		chunk_sz = min(msg_len, rd->chunk_sz);

		if (mbuf_get_left(mb) < chunk_sz)
			return ENODATA;

		mem_deref(msg->mb);
		msg->mb = mbuf_alloc(msg_len);
		if (!msg->mb)
			return ENOMEM;

		err = mbuf_read_mem(mb, msg->mb->buf, chunk_sz);
		if (err)
			return err;

		msg->mb->pos = chunk_sz;
		msg->mb->end = chunk_sz;

		msg->hdr.format = hdr.format;
		break;

	case 3:
		if (!msg->mb)
			return EPROTO;

		left = msg->hdr.length - msg->mb->pos;

		chunk_sz = min(left, rd->chunk_sz);

		if (mbuf_get_left(mb) < chunk_sz)
			return ENODATA;

		err = mbuf_read_mem(mb, mbuf_buf(msg->mb), chunk_sz);
		if (err)
			return err;

		msg->mb->pos += chunk_sz;
		msg->mb->end += chunk_sz;
		break;
	}

	complete = (msg->mb->pos >= msg->hdr.length);

	if (complete) {

		msg->mb->pos = 0;

		err = rd->chunkh(&msg->hdr, msg->mb, rd->arg);

		msg->mb = mem_deref(msg->mb);
	}

	return err;
}


void rtmp_dechunker_set_chunksize(struct rtmp_dechunker *rd, size_t chunk_sz)
{
	if (!rd)
		return;

	rd->chunk_sz = chunk_sz;
}


int rtmp_dechunker_debug(struct re_printf *pf, const struct rtmp_dechunker *rd)
{
	struct le *le;
	int err;

	if (!rd)
		return 0;

	err  = re_hprintf(pf, "Dechunker Debug:\n");

	err |= re_hprintf(pf, "chunk list:  %u\n", list_count(&rd->msgl));

	for (le = rd->msgl.head; le; le = le->next) {

		const struct rtmp_chunk *msg = le->data;

		err |= re_hprintf(pf, "..... %H [ buf = %p ]\n",
				  rtmp_header_print, &msg->hdr, msg->mb);

	}

	err |= re_hprintf(pf, "\n");

	return err;
}
