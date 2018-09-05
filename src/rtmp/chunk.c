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
		 size_t max_chunk_sz, rtmp_chunk_h *chunkh, void *arg)
{
	const uint8_t *pend = payload + payload_len;
	struct rtmp_header hdr;
	size_t chunk_sz;
	int err;

	if (!payload || !payload_len || !chunkh)
		return EINVAL;

	memset(&hdr, 0, sizeof(hdr));

	hdr.format = format;
	hdr.chunk_id = chunk_id;

	hdr.timestamp       = timestamp;
	hdr.timestamp_delta = timestamp_delta;
	hdr.length          = (uint32_t)payload_len;
	hdr.type_id         = msg_type_id;
	hdr.stream_id       = msg_stream_id;

	chunk_sz = min(payload_len, max_chunk_sz);

	err = chunkh(&hdr, payload, chunk_sz, arg);
	if (err)
		goto out;

	payload += chunk_sz;

	hdr.format = 3;

	while (payload < pend) {

		const size_t len = pend - payload;

		chunk_sz = min(len, max_chunk_sz);

		err = chunkh(&hdr, payload, chunk_sz, arg);
		if (err)
			break;

		payload += chunk_sz;
	}

 out:
	return err;
}
