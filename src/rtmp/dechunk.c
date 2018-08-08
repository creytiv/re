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


/*
 * XXX: add limit for max chunks
 * XXX: add max message length
 */


/* XXX rename to rtmp_msg */
struct rtmp_chunk {
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
	struct rtmp_chunk *chunk = data;

	list_unlink(&chunk->le);
	mem_deref(chunk->buf);
}


static struct rtmp_chunk *create_chunk(struct list *chunkl, uint32_t id,
				       uint32_t message_length, uint8_t type)
{
	struct rtmp_chunk *chunk;

	chunk = mem_zalloc(sizeof(*chunk), chunk_destructor);
	if (!chunk)
		return NULL;

	chunk->chunk_id = id;
	chunk->message_length = message_length;
	chunk->type = type;

	chunk->buf = mem_alloc(message_length, NULL);
	if (!chunk->buf)
		goto error;

	list_append(chunkl, &chunk->le, chunk);

	return chunk;

 error:
	return mem_deref(chunk);
}


static struct rtmp_chunk *find_chunk(const struct list *chunkl, uint32_t id)
{
	struct le *le;

	for (le = list_head(chunkl); le; le = le->next) {

		struct rtmp_chunk *chunk = le->data;

		if (id == chunk->chunk_id)
			return chunk;
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
	struct rtmp_chunk *chunk;
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

		chunk = find_chunk(&rd->chunkl, hdr.chunk_id);
		if (chunk) {
			re_printf("rtmp: dechunker: unexpected"
				  " chunk found (id=%u)\n", hdr.chunk_id);
			return EPROTO;
		}

		chunk = create_chunk(&rd->chunkl, hdr.chunk_id,
				     hdr.message_length, hdr.message_type_id);
		if (!chunk)
			return ENOMEM;

		chunk_sz = min(hdr.message_length, RTMP_DEFAULT_CHUNKSIZE);

		if (mbuf_get_left(mb) < chunk_sz) {
			re_printf("more data..\n");

			/* rollback */
			mem_deref(chunk);
			return ENODATA;
		}

		err = mbuf_read_mem(mb, chunk->buf, chunk_sz);
		if (err)
			return err;

		chunk->len += chunk_sz;
		break;

	case 3:
		chunk = find_chunk(&rd->chunkl, hdr.chunk_id);
		if (!chunk) {
			re_printf("rtmp: dechunker: no chunk found\n");
			return EPROTO;
		}

		left = chunk->message_length - chunk->len;

		chunk_sz = min(left, RTMP_DEFAULT_CHUNKSIZE);

		if (mbuf_get_left(mb) < chunk_sz) {
			re_printf("more data..\n");
			return ENODATA;
		}

		err = mbuf_read_mem(mb, &chunk->buf[chunk->len], chunk_sz);
		if (err)
			return err;

		chunk->len += chunk_sz;
		break;

	default:
		re_printf("rtmp: dechunker: format type %d not handled\n",
			  hdr.format);
		return EPROTO;
	}

	complete = (chunk->len >= chunk->message_length);

	if (complete) {

		if (rd->msgh) {

			/* XXX: send struct rtmp_msg  */
			rd->msgh(chunk->type, chunk->buf,
				 chunk->message_length, rd->arg);
		}

		mem_deref(chunk);
	}

	return err;
}
