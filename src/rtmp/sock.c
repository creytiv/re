/**
 * @file rtmp/sock.c  Real Time Messaging Protocol (RTMP) -- Server socket
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_tcp.h>
#include <re_sys.h>
#include <re_odict.h>
#include <re_rtmp.h>
#include "rtmp.h"


struct rtmp_sock {
	struct tcp_sock *ts;
	rtmp_conn_h *connh;
	void *arg;
};


static void destructor(void *data)
{
	struct rtmp_sock *sock = data;

	mem_deref(sock->ts);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct rtmp_sock *sock = arg;

	if (sock->connh)
		sock->connh(sock->ts, sock->arg);
}


int rtmp_listen(struct rtmp_sock **sockp, const struct sa *laddr,
		rtmp_conn_h *connh, void *arg)
{
	struct rtmp_sock *sock;
	int err;

	if (!sockp || !laddr)
		return EINVAL;

	sock = mem_zalloc(sizeof(*sock), destructor);
	if (!sock)
		return ENOMEM;

	sock->connh = connh;
	sock->arg = arg;

	err = tcp_listen(&sock->ts, laddr, tcp_conn_handler, sock);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(sock);
	else
		*sockp = sock;

	return err;
}
