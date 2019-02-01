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
#include <re_sa.h>
#include <re_rtmp.h>
#include "rtmp.h"


enum {
	MAX_CHUNKS = 64,
};


struct rtmp_chunk {
	struct le le;
	struct rtmp_header hdr;
	struct mbuf *mb;
};

/** Defines the RTMP Dechunker */
struct rtmp_dechunker {
	struct list chunkl;      /* struct rtmp_chunk */
	size_t chunk_sz;
	rtmp_dechunk_h *chunkh;
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
	mem_deref(chunk->mb);
}


static struct rtmp_chunk *create_chunk(struct list *chunkl,
				       const struct rtmp_header *hdr)
{
	struct rtmp_chunk *chunk;

	chunk = mem_zalloc(sizeof(*chunk), chunk_destructor);
	if (!chunk)
		return NULL;

	chunk->hdr = *hdr;

	list_append(chunkl, &chunk->le, chunk);

	return chunk;
}


static struct rtmp_chunk *find_chunk(const struct list *chunkl,
				     uint32_t chunk_id)
{
	struct le *le;

	for (le = list_head(chunkl); le; le = le->next) {

		struct rtmp_chunk *chunk = le->data;

		if (chunk_id == chunk->hdr.chunk_id)
			return chunk;
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

	if (!rdp || !chunk_sz || !chunkh)
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
	struct rtmp_chunk *chunk;
	size_t chunk_sz, left, msg_len;
	int err;

	if (!rd || !mb)
		return EINVAL;

	err = rtmp_header_decode(&hdr, mb);
	if (err)
		return err;

	/* find preceding chunk, from chunk id */
	chunk = find_chunk(&rd->chunkl, hdr.chunk_id);
	if (!chunk) {

		/* only type 0 can create a new chunk stream */
		if (hdr.format == 0) {
			if (list_count(&rd->chunkl) > MAX_CHUNKS)
				return EOVERFLOW;

			chunk = create_chunk(&rd->chunkl, &hdr);
			if (!chunk)
				return ENOMEM;
		}
		else
			return ENOENT;
	}

	switch (hdr.format) {

	case 0:
	case 1:
	case 2:
		if (hdr.format == 0) {

			/* copy the whole header */
			chunk->hdr = hdr;
		}
		else if (hdr.format == 1) {

			chunk->hdr.timestamp_delta = hdr.timestamp_delta;
			chunk->hdr.length          = hdr.length;
			chunk->hdr.type_id         = hdr.type_id;
		}
		else if (hdr.format == 2) {

			chunk->hdr.timestamp_delta = hdr.timestamp_delta;
		}

		msg_len = chunk->hdr.length;

		chunk_sz = min(msg_len, rd->chunk_sz);

		if (mbuf_get_left(mb) < chunk_sz)
			return ENODATA;

		mem_deref(chunk->mb);
		chunk->mb = mbuf_alloc(msg_len);
		if (!chunk->mb)
			return ENOMEM;

		err = mbuf_read_mem(mb, chunk->mb->buf, chunk_sz);
		if (err)
			return err;

		chunk->mb->pos = chunk_sz;
		chunk->mb->end = chunk_sz;

		chunk->hdr.format = hdr.format;
		chunk->hdr.ext_ts = hdr.ext_ts;

		if (hdr.format == 1 || hdr.format == 2)
			chunk->hdr.timestamp += hdr.timestamp_delta;
		break;

	case 3:
		if (chunk->hdr.ext_ts) {

			uint32_t ext_ts;

			if (mbuf_get_left(mb) < 4)
				return ENODATA;

			ext_ts = ntohl(mbuf_read_u32(mb));

			if (chunk->hdr.format == 0)
				chunk->hdr.timestamp = ext_ts;
			else
				chunk->hdr.timestamp_delta = ext_ts;
		}

		if (!chunk->mb) {

			chunk->mb = mbuf_alloc(chunk->hdr.length);
			if (!chunk->mb)
				return ENOMEM;

			if (chunk->hdr.format == 0) {
				chunk->hdr.timestamp_delta =
					chunk->hdr.timestamp;
			}

			chunk->hdr.timestamp += chunk->hdr.timestamp_delta;
		}

		left = mbuf_get_space(chunk->mb);

		chunk_sz = min(left, rd->chunk_sz);

		if (mbuf_get_left(mb) < chunk_sz)
			return ENODATA;

		err = mbuf_read_mem(mb, mbuf_buf(chunk->mb), chunk_sz);
		if (err)
			return err;

		chunk->mb->pos += chunk_sz;
		chunk->mb->end += chunk_sz;
		break;

	default:
		return EPROTO;
	}

	if (chunk->mb->pos >= chunk->mb->size) {

		struct mbuf *buf;

		chunk->mb->pos = 0;

		buf = chunk->mb;
		chunk->mb = NULL;

		err = rd->chunkh(&chunk->hdr, buf, rd->arg);

		mem_deref(buf);
	}

	return err;
}


void rtmp_dechunker_set_chunksize(struct rtmp_dechunker *rd, size_t chunk_sz)
{
	if (!rd || !chunk_sz)
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

	err |= re_hprintf(pf, "chunk list: (%u)\n", list_count(&rd->chunkl));

	for (le = rd->chunkl.head; le; le = le->next) {

		const struct rtmp_chunk *msg = le->data;

		err |= re_hprintf(pf, ".. %H\n",
				  rtmp_header_print, &msg->hdr);
	}

	err |= re_hprintf(pf, "\n");

	return err;
}
