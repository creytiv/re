/**
 * @file re_hmac.h  Interface to HMAC functions
 *
 * Copyright (C) 2010 Creytiv.com
 */


void hmac_sha1(const uint8_t *k,   /* secret key */
	       size_t         lk,  /* length of the key in bytes */
	       const uint8_t *d,   /* data */
	       size_t         ld,  /* length of data in bytes */
	       uint8_t*       out, /* output buffer, at least "t" bytes */
	       size_t         t);
