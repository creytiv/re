/**
 * @file rtmp.h  Real Time Messaging Protocol (RTMP) -- Internal API
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_DEFAULT_CHUNKSIZE = 128,
	MESSAGE_LEN_MAX = 524288,
};


/* Command */

struct command_header {
	char name[64];
	uint64_t transaction_id;
};

int rtmp_command_header_encode(struct mbuf *mb,
			       const char *name, uint64_t tid);
int rtmp_command_header_decode(struct command_header *hdr,
			       const struct odict *dict);
int rtmp_command_header_print(struct re_printf *pf,
			      const struct command_header *hdr);
