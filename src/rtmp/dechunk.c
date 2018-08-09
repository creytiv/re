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


/*
 * XXX: add limit for max chunks
 * XXX: add max message length
 */
enum {
	MAX_PENDING = 16,
	MESSAGE_LEN_MAX = 524288,
};


struct rtmp_message {
	struct le le;
	uint32_t chunk_id;
	uint32_t message_length;
	uint8_t *buf;
	size_t len;             /* how many bytes received so far */
	uint8_t type;
};


struct rtmp_dechunker {
	struct list chunkl;
	rtmp_msg_h *msgh;
	void *arg;
};


static void destructor(void *data)
{
	struct rtmp_dechunker *rd = data;

	list_flush(&rd->chunkl);
}


static void chunk_destructor(void *data)
{
	struct rtmp_message *msg = data;

	list_unlink(&msg->le);
	mem_deref(msg->buf);
}


static struct rtmp_message *create_chunk(struct list *chunkl, uint32_t id,
				       uint32_t message_length, uint8_t type)
{
	struct rtmp_message *msg;

	msg = mem_zalloc(sizeof(*msg), chunk_destructor);
	if (!msg)
		return NULL;

	msg->chunk_id    = id;
	msg->message_length = message_length;
	msg->type      = type;

	msg->buf = mem_alloc(message_length, NULL);
	if (!msg->buf)
		goto error;

	list_append(chunkl, &msg->le, msg);

	return msg;

 error:
	return mem_deref(msg);
}


static struct rtmp_message *find_chunk(const struct list *chunkl, uint32_t id)
{
	struct le *le;

	for (le = list_head(chunkl); le; le = le->next) {

		struct rtmp_message *msg = le->data;

		if (id == msg->chunk_id)
			return msg;
	}

	return NULL;
}


/**
 * Stateful RTMP de-chunker for receiving
 */
int rtmp_dechunker_alloc(struct rtmp_dechunker **rdp,
			 rtmp_msg_h *msgh, void *arg)
{
	struct rtmp_dechunker *rd;

	if (!rdp)
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

		/* only type 0 and 1 can create a new chunk */
	case 0:
	case 1:
		/* XXX: add case 2 */

		msg = find_chunk(&rd->chunkl, hdr.chunk_id);
		if (msg) {
			re_printf("rtmp: dechunker: unexpected"
				  " message found (chunk_id=%u)\n",
				  hdr.chunk_id);
			return EPROTO;
		}

		/* limits */
		if (list_count(&rd->chunkl) > MAX_PENDING)
			return EOVERFLOW;

		if (hdr.length > MESSAGE_LEN_MAX)
			return EOVERFLOW;

		msg = create_chunk(&rd->chunkl, hdr.chunk_id,
				     hdr.length, hdr.type_id);
		if (!msg)
			return ENOMEM;

		chunk_sz = min(hdr.length, RTMP_DEFAULT_CHUNKSIZE);

		if (mbuf_get_left(mb) < chunk_sz) {
			re_printf("more data..\n");

			/* rollback */
			mem_deref(msg);
			return ENODATA;
		}

		err = mbuf_read_mem(mb, msg->buf, chunk_sz);
		if (err)
			return err;

		msg->len += chunk_sz;
		break;

	case 3:
		msg = find_chunk(&rd->chunkl, hdr.chunk_id);
		if (!msg) {
			re_printf("rtmp: dechunker: no chunk found\n");
			return EPROTO;
		}

		left = msg->message_length - msg->len;

		chunk_sz = min(left, RTMP_DEFAULT_CHUNKSIZE);

		if (mbuf_get_left(mb) < chunk_sz) {
			re_printf("more data..\n");
			return ENODATA;
		}

		err = mbuf_read_mem(mb, &msg->buf[msg->len], chunk_sz);
		if (err)
			return err;

		msg->len += chunk_sz;
		break;

	default:
		re_printf("rtmp: dechunker: format type %d not handled\n",
			  hdr.format);
		return EPROTO;
	}

	complete = (msg->len >= msg->message_length);

	if (complete) {

		if (rd->msgh) {

			/* XXX: send struct rtmp_msg  */
			rd->msgh(msg->type, msg->buf,
				 msg->message_length, rd->arg);
		}

		mem_deref(msg);
	}

	return err;
}
