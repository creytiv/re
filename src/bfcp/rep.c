/**
 * @file bfcp/rep.c BFCP Reply
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_bfcp.h>
#include "bfcp.h"


int bfcp_reply(struct bfcp_sock *sock, const struct bfcp_msg *req,
	       enum bfcp_prim prim, uint32_t attrc, ...)
{
	struct mbuf *mb;
	va_list ap;
	int err;

	if (!sock || !req)
		return EINVAL;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	va_start(ap, attrc);
	err = bfcp_msg_vencode(mb, prim, bfcp_msg_confid(req),
			       bfcp_msg_tid(req), bfcp_msg_userid(req),
			       attrc, ap);
	va_end(ap);

	if (err)
		goto out;

	mb->pos = 0;

	err = bfcp_send(sock, bfcp_msg_src(req), mb);

 out:
	mem_deref(mb);

	return err;
}


int bfcp_ereply(struct bfcp_sock *sock, const struct bfcp_msg *req,
		enum bfcp_err code, ...)
{
	struct bfcp_errcode ec;
	va_list ap;

	va_start(ap, code);

	memset(&ec, 0, sizeof(ec));
	ec.code = code;

	if (code == BFCP_ERR_UNKNOWN_MAND_ATTR) {
		ec.details = va_arg(ap, uint8_t *);
		ec.len     = va_arg(ap, size_t);
	}

	va_end(ap);

	return bfcp_reply(sock, req, BFCP_ERROR, 1, BFCP_ERROR_CODE, &ec);
}
