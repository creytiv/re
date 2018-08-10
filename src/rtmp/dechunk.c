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


struct rtmp_dechunker {
	struct list msgl;  /* struct rtmp_message */
	rtmp_msg_h *msgh;
	void *arg;
};


static void destructor(void *data)
{
	struct rtmp_dechunker *rd = data;

	list_flush(&rd->msgl);
}


static void chunk_destructor(void *data)
{
	struct rtmp_message *msg = data;

	list_unlink(&msg->le);
	mem_deref(msg->buf);
}


static struct rtmp_message *create_message(struct list *msgl,
					   uint32_t chunk_id, uint32_t length,
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


/**
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

	rd->msgh = msgh;
	rd->arg  = arg;

	*rdp = rd;

	return 0;
}


int rtmp_dechunker_receive(struct rtmp_dechunker *rd, struct mbuf *mb)
{
	struct rtmp_header hdr;
	struct rtmp_message *msg;
	size_t chunk_sz, left;
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

		if (hdr.length > MESSAGE_LEN_MAX)
			return EOVERFLOW;

		chunk_sz = min(hdr.length, RTMP_DEFAULT_CHUNKSIZE);

		if (mbuf_get_left(mb) < chunk_sz)
			return ENODATA;

		msg = create_message(&rd->msgl, hdr.chunk_id,
				     hdr.length, hdr.type_id);
		if (!msg)
			return ENOMEM;

		err = mbuf_read_mem(mb, msg->buf, chunk_sz);
		if (err)
			return err;

		msg->pos = chunk_sz;
		break;

	case 3:
		msg = find_message(&rd->msgl, hdr.chunk_id);
		if (!msg) {
			re_printf("rtmp: dechunker: no chunk found\n");
			return EPROTO;
		}

		left = msg->length - msg->pos;

		chunk_sz = min(left, RTMP_DEFAULT_CHUNKSIZE);

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
