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
#include <re_sa.h>
#include <re_tcp.h>
#include <re_list.h>
#include <re_rtmp.h>
#include "rtmp.h"


/*
 * Stateless RTMP chunker
 */
int rtmp_chunker(unsigned format, uint32_t chunk_id,
		 uint32_t timestamp, uint32_t timestamp_delta,
		 uint8_t msg_type_id, uint32_t msg_stream_id,
		 const uint8_t *payload, size_t payload_len,
		 size_t max_chunk_sz, struct tcp_conn *tc)
{
	const uint8_t *pend = payload + payload_len;
	struct rtmp_header hdr;
	struct mbuf *mb;
	size_t chunk_sz;
	int err;

	if (!payload || !payload_len || !max_chunk_sz || !tc)
		return EINVAL;

	mb = mbuf_alloc(payload_len + 256);
	if (!mb)
		return ENOMEM;

	memset(&hdr, 0, sizeof(hdr));

	hdr.format = format;
	hdr.chunk_id = chunk_id;

	hdr.timestamp       = timestamp;
	hdr.timestamp_delta = timestamp_delta;
	hdr.length          = (uint32_t)payload_len;
	hdr.type_id         = msg_type_id;
	hdr.stream_id       = msg_stream_id;

	chunk_sz = min(payload_len, max_chunk_sz);

	err  = rtmp_header_encode(mb, &hdr);
	err |= mbuf_write_mem(mb, payload, chunk_sz);
	if (err)
		goto out;

	payload += chunk_sz;

	hdr.format = 3;

	while (payload < pend) {

		const size_t len = pend - payload;

		chunk_sz = min(len, max_chunk_sz);

		err  = rtmp_header_encode(mb, &hdr);
		err |= mbuf_write_mem(mb, payload, chunk_sz);
		if (err)
			goto out;

		payload += chunk_sz;
	}

	mb->pos = 0;

	err = tcp_send(tc, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}
