/**
 * @file rtmp/chunk.c  Real Time Messaging Protocol (RTMP) -- Chunking
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


/**
 * Stateless RTMP chunker
 */
int rtmp_chunker(uint32_t chunk_id, uint32_t timestamp,
		 uint8_t msg_type_id, uint32_t msg_stream_id,
		 const uint8_t *payload, size_t payload_len,
		 rtmp_chunk_h *chunkh, void *arg)
{
	const uint32_t msg_length = (uint32_t)payload_len;
	const uint8_t *p    = payload;
	const uint8_t *pend = payload + payload_len;
	struct mbuf *mb;
	size_t chunk_sz;
	int err;

	if (!payload || !payload_len || !chunkh)
		return EINVAL;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = rtmp_header_encode_type0(mb, chunk_id, timestamp, msg_length,
				       msg_type_id, msg_stream_id);
	if (err)
		goto out;

	chunk_sz = min(payload_len, RTMP_DEFAULT_CHUNKSIZE);

	chunkh(mb->buf, mb->end, p, chunk_sz, arg);

	p += chunk_sz;

	while (p < pend) {

		const size_t len = pend - p;

		chunk_sz = min(len, RTMP_DEFAULT_CHUNKSIZE);

		mb->pos = 0;
		mb->end = 0;

		err = rtmp_header_encode_type3(mb, chunk_id);
		if (err)
			goto out;

		p += chunk_sz;

		chunkh(mb->buf, mb->end, p, chunk_sz, arg);
	}

 out:
	mem_deref(mb);

	return err;
}
