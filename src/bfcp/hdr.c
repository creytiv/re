/**
 * @file bfcp/hdr.c BFCP Message header
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_bfcp.h>
#include "bfcp.h"


int bfcp_hdr_encode(struct mbuf *mb, enum bfcp_prim prim, uint16_t len,
		    uint32_t confid, uint16_t tid, uint16_t userid)
{
	int err;

	err  = mbuf_write_u8(mb, BFCP_VERSION << 5);
	err |= mbuf_write_u8(mb, prim);
	err |= mbuf_write_u16(mb, htons(len));
	err |= mbuf_write_u32(mb, htonl(confid));
	err |= mbuf_write_u16(mb, htons(tid));
	err |= mbuf_write_u16(mb, htons(userid));

	return err;
}


int bfcp_hdr_decode(struct mbuf *mb, struct bfcp_hdr *hdr)
{
	uint8_t b;

	if (mbuf_get_left(mb) < BFCP_HDR_SIZE)
		return EBADMSG;

	b = mbuf_read_u8(mb);
	hdr->ver    = b >> 5;
	hdr->i      = (b >> 4) & 1;
	hdr->prim   = mbuf_read_u8(mb);
	hdr->len    = ntohs(mbuf_read_u16(mb));
	hdr->confid = ntohl(mbuf_read_u32(mb));
	hdr->tid    = ntohs(mbuf_read_u16(mb));
	hdr->userid = ntohs(mbuf_read_u16(mb));

	if (hdr->ver != BFCP_VERSION)
		return EBADMSG;

	if (mbuf_get_left(mb) < (size_t)(hdr->len*4)) {

		return ENODATA;
	}

	return 0;
}
