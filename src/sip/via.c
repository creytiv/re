/**
 * @file via.c  SIP Via decode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_uri.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_sip.h>


int sip_via_decode(struct sip_via *via, const struct pl *pl)
{
	struct pl received, rport, ip;
	int err;

	if (!via || !pl)
		return EINVAL;

	err = re_regex(pl->p, pl->l,
		       "SIP[  \t\r\n]*/[ \t\r\n]*2.0[ \t\r\n]*/[ \t\r\n]*"
		       "[A-Z]+[ \t\r\n]*[^; \t\r\n]+[ \t\r\b]*[^]*",
		       NULL, NULL, NULL, NULL, &via->transp,
		       NULL, &via->sentby, NULL, &via->params);
	if (err)
		return err;

	if (!sip_param_decode(&via->params, "received", &received)) {
		(void)sa_set(&via->addr, &received, 0);

		if (!sip_param_decode(&via->params, "rport", &rport))
			sa_set_port(&via->addr, pl_u32(&rport));
	}
	else if (sa_decode(&via->addr, via->sentby.p, via->sentby.l)) {

		ip = via->sentby;

		if (ip.l > 1 && ip.p[0] == '[' && ip.p[ip.l-1] == ']') {
			ip.p += 1;
			ip.l -= 2;
		}

		(void)sa_set(&via->addr, &ip, 0);
	}

	via->val = *pl;

	return sip_param_decode(&via->params, "branch", &via->branch);
}
