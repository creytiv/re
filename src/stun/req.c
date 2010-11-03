/**
 * @file stun/req.c  STUN request
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_sys.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_stun.h>
#include "stun.h"


int stun_request(struct stun_ctrans **ctp, struct stun *stun, int proto,
		 void *sock, const struct sa *dst, size_t presz,
		 uint16_t method, const uint8_t *key, size_t keylen, bool fp,
		 stun_resp_h *resph, void *arg, uint32_t attrc, ...)
{
	uint8_t tid[STUN_TID_SIZE];
	struct mbuf *mb;
	uint32_t i;
	va_list ap;
	int err;

	if (!stun)
		return EINVAL;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	for (i=0; i<STUN_TID_SIZE; i++)
		tid[i] = rand_u32();

	va_start(ap, attrc);
	mb->pos = presz;
	err = stun_msg_vencode(mb, method, STUN_CLASS_REQUEST,
			       tid, NULL, key, keylen, fp, 0x00, attrc, ap);
	va_end(ap);
	if (err)
		goto out;

	mb->pos = presz;
	err = stun_ctrans_request(ctp, stun, proto, sock, dst, mb, tid, method,
				  key, keylen, resph, arg);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}
