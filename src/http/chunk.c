/**
 * @file http/chunk.c Chunked Transfer Encoding
 *
 * Copyright (C) 2011 Creytiv.com
 */

#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include "http.h"


static int decode_chunk_size(struct http_chunk *chunk, struct mbuf *mb)
{
	while (mbuf_get_left(mb)) {

		char ch = (char)mbuf_read_u8(mb);
		uint8_t c;

		if (ch == '\n') {
			if (chunk->digit) {
				chunk->digit = false;
				chunk->param = false;

				return 0;
			}
			else
				continue;
		}

		if (chunk->param)
			continue;

		if ('0' <= ch && ch <= '9')
			c = ch - '0';
		else if ('A' <= ch && ch <= 'F')
			c = ch - 'A' + 10;
		else if ('a' <= ch && ch <= 'f')
			c = ch - 'a' + 10;
		else if (ch == '\r' || ch == ' ' || ch == '\t')
			continue;
		else if (ch == ';' && chunk->digit) {
			chunk->param = true;
			continue;
		}
		else
			return EPROTO;

		chunk->digit = true;

		chunk->size <<= 4;
		chunk->size += c;
	}

	return ENODATA;
}


static int decode_trailer(struct http_chunk *chunk, struct mbuf *mb)
{
	while (mbuf_get_left(mb)) {

		char ch = (char)mbuf_read_u8(mb);

		if (ch == '\n') {
			if (++chunk->lf >= 2)
				return 0;
		}
		else if (ch != '\r')
			chunk->lf = 0;
	}

	return ENODATA;
}


int http_chunk_decode(struct http_chunk *chunk, struct mbuf *mb, size_t *size)
{
	int err;

	if (!chunk || !mb || !size)
		return EINVAL;

	if (chunk->trailer) {
		err = decode_trailer(chunk, mb);
		if (err)
			return err;

		*size = 0;

		return 0;
	}

	err = decode_chunk_size(chunk, mb);
	if (err)
		return err;

	if (chunk->size == 0) {
		chunk->trailer = true;
		chunk->lf = 1;

		err = decode_trailer(chunk, mb);
		if (err)
			return err;
	}

	*size = chunk->size;
	chunk->size = 0;

	return 0;
}
