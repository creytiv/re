/**
 * @file http.h  HTTP Private Interface
 *
 * Copyright (C) 2010 Creytiv.com
 */


struct http_chunk {
	size_t size;
	unsigned lf;
	bool trailer;
	bool digit;
	bool param;
};


int http_chunk_decode(struct http_chunk *chunk, struct mbuf *mb, size_t *size);
