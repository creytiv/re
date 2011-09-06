/**
 * @file bfcp/req.c BFCP Client request
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_bfcp.h>
#include "bfcp.h"


struct bfcp_ctrans {
	struct le le;
	struct tmr tmr;
	struct bfcp_ctrans **ctp;
	uint16_t tid;
	bfcp_resp_h *resph;
	void *arg;
};


static void destructor(void *arg)
{
	struct bfcp_ctrans *ct = arg;

	list_unlink(&ct->le);
	tmr_cancel(&ct->tmr);
}


static void timeout(void *arg)
{
	struct bfcp_ctrans *ct = arg;

	bfcp_ctrans_completed(ct, ETIMEDOUT, NULL);
}


static struct bfcp_ctrans *ctrans_new(struct bfcp_sock *sock,
				      bfcp_resp_h *resph, void *arg)
{
	struct bfcp_ctrans *ct;

	ct = mem_zalloc(sizeof(*ct), destructor);
	if (!ct)
		return NULL;

	list_append(&sock->transl, &ct->le, ct);

	sock->tidc++;

	if (sock->tidc == 0)
		sock->tidc++;

	ct->tid = sock->tidc;
	ct->resph = resph;
	ct->arg = arg;

	tmr_start(&ct->tmr, 10000, timeout, ct);

	return ct;
}


void bfcp_ctrans_completed(struct bfcp_ctrans *ct, int err,
			   const struct bfcp_msg *msg)
{
	bfcp_resp_h *resph = ct->resph;
	void *arg = ct->arg;

	list_unlink(&ct->le);
	tmr_cancel(&ct->tmr);

	if (ct->ctp) {
		*ct->ctp = NULL;
		ct->ctp = NULL;
	}

	ct->resph = NULL;

	mem_deref(ct);

	if (resph)
		resph(err, msg, arg);
}


struct bfcp_ctrans *bfcp_ctrans_find(struct bfcp_sock *sock, uint16_t tid)
{
	struct le *le;

	for (le = sock->transl.head; le; le = le->next) {

		struct bfcp_ctrans *ct = le->data;

		if (ct->tid == tid)
			return ct;
	}

	return NULL;
}


int bfcp_request(struct bfcp_ctrans **ctp, struct bfcp_sock *sock,
		 const struct sa *dst,
		 enum bfcp_prim prim, uint32_t confid, uint16_t userid,
		 bfcp_resp_h *resph, void *arg, uint32_t attrc, ...)
{
	struct bfcp_ctrans *ct;
	struct mbuf *mb;
	va_list ap;
	int err;

	if (!sock || !dst || !confid || !userid)
		return EINVAL;

	ct = ctrans_new(sock, resph, arg);
	if (!ct)
		return ENOMEM;

	mb = mbuf_alloc(512);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	va_start(ap, attrc);
	err = bfcp_msg_vencode(mb, prim, confid, ct->tid, userid,
			       attrc, ap);
	va_end(ap);
	if (err)
		goto out;

	mb->pos = 0;

	err = bfcp_send(sock, dst, mb);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(ct);
	else if (ctp) {
		ct->ctp = ctp;
		*ctp = ct;
	}

	mem_deref(mb);
	return err;
}
