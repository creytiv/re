/**
 * @file stun.c  STUN stack
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_udp.h>
#include <re_tcp.h>
#include <re_sys.h>
#include <re_list.h>
#include <re_stun.h>
#include "stun.h"


const char *stun_software = "libre v" VERSION " (" ARCH "/" OS ")";


static const struct stun_conf conf_default = {
	STUN_DEFAULT_RTO,
	STUN_DEFAULT_RC,
	STUN_DEFAULT_RM,
	STUN_DEFAULT_TI,
	0x00
};


static void destructor(void *arg)
{
	struct stun *stun = arg;

	stun_ctrans_close(stun);
}


int stun_alloc(struct stun **stunp, const struct stun_conf *conf,
	       stun_ind_h *indh, void *arg)
{
	struct stun *stun;

	if (!stunp)
		return EINVAL;

	stun = mem_zalloc(sizeof(*stun), destructor);
	if (!stun)
		return ENOMEM;

	stun->conf = conf ? *conf : conf_default;
	stun->indh = indh;
	stun->arg  = arg;

	*stunp = stun;

	return 0;
}


struct stun_conf *stun_conf(struct stun *stun)
{
	return stun ? &stun->conf : NULL;
}


int stun_send(int proto, void *sock, const struct sa *dst, struct mbuf *mb)
{
	int err;

	if (!sock || !mb)
		return EINVAL;

	switch (proto) {

	case IPPROTO_UDP:
		err = udp_send(sock, dst, mb);
		break;

	case IPPROTO_TCP:
		err = tcp_send(sock, mb);
		break;

	default:
		err = EPROTONOSUPPORT;
		break;
	}

	return err;
}


int stun_recv(struct stun *stun, struct mbuf *mb)
{
	struct stun_unknown_attr ua;
	struct stun_msg *msg;
	int err;

	if (!stun || !mb)
		return EINVAL;

	err = stun_msg_decode(&msg, mb, &ua);
	if (err)
		return err;

	switch (stun_msg_class(msg)) {

	case STUN_CLASS_INDICATION:
		if (ua.typec > 0)
			break;

		if (stun->indh)
			stun->indh(msg, stun->arg);
		break;

	case STUN_CLASS_ERROR_RESP:
	case STUN_CLASS_SUCCESS_RESP:
		err = stun_ctrans_recv(stun, msg, &ua);
		break;

	default:
		break;
	}

	mem_deref(msg);

	return err;
}


int stun_debug(struct re_printf *pf, const struct stun *stun)
{
	if (!stun)
		return 0;

	return re_hprintf(pf, "STUN debug:\n%H", stun_ctrans_debug, stun);
}
