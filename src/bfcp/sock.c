/**
 * @file bfcp/sock.c BFCP Socket
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_tcp.h>
#include <re_tls.h>
#include <re_bfcp.h>
#include "bfcp.h"


struct bfcp_conn {
	struct le le;
	struct sa paddr;
	struct mbuf *mbtx;
	struct mbuf *mbrx;
	struct tcp_conn *tc;
	struct tls_conn *sc;
	struct bfcp_sock *bs;
	bool established;
};


static void destructor(void *arg)
{
	struct bfcp_sock *sock = arg;

	list_flush(&sock->transl);
	list_flush(&sock->connl);
	mem_deref(sock->tls);
	mem_deref(sock->ts);
}


static void conn_destructor(void *arg)
{
	struct bfcp_conn *conn = arg;

	list_unlink(&conn->le);
	mem_deref(conn->mbtx);
	mem_deref(conn->mbrx);
	mem_deref(conn->sc);
	mem_deref(conn->tc);
}


static struct bfcp_conn *conn_add(struct bfcp_sock *bs,
				  const struct sa *paddr)
{
	struct bfcp_conn *bc = mem_zalloc(sizeof(*bc), conn_destructor);
	if (!bc)
		return NULL;

	list_append(&bs->connl, &bc->le, bc);

	bc->bs    = bs;
	bc->paddr = *paddr;

	return bc;
}


static void tcp_estab_handler(void *arg)
{
	struct bfcp_conn *conn = arg;

#ifdef USE_TLS
	if (conn->sc) {
		char cn[256];
		int err;

		err = tls_verify_cert(conn->sc, cn, sizeof(cn));

		(void)re_printf("CN: '%s' (%sverified)\n",
				cn, err ? "not " : "");
	}
#endif

	conn->established = true;

	/* flush transmit buffer */
	if (conn->mbtx) {

		conn->mbtx->pos = 0;
		if (tcp_send(conn->tc, conn->mbtx))
			return;

		conn->mbtx = mem_deref(conn->mbtx);
	}
}


static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
	struct bfcp_conn *conn = arg;
	size_t pos;
	int err = 0;

	if (conn->mbrx) {
		pos = conn->mbrx->pos;

		conn->mbrx->pos = conn->mbrx->end;

		err = mbuf_write_mem(conn->mbrx,
				     mbuf_buf(mb), mbuf_get_left(mb));
		if (err)
			goto out;

		conn->mbrx->pos = pos;
	}
	else {
		conn->mbrx = mem_ref(mb);
	}

	for (;;) {
		struct bfcp_msg *msg;
		struct bfcp_ctrans *ct;

		pos = conn->mbrx->pos;

		err = bfcp_msg_decode(&msg, conn->mbrx, &conn->paddr);
		if (err) {
			if (err == ENODATA) {
				conn->mbrx->pos = pos;
				err = 0;
			}
			break;
		}

		ct = bfcp_ctrans_find(conn->bs, bfcp_msg_tid(msg));
		if (ct) {
			bfcp_ctrans_completed(ct, 0, msg);
		}
		else {
			if (conn->bs->msgh)
				conn->bs->msgh(msg, conn->bs->arg);
		}

		mem_deref(msg);

		if (0 == mbuf_get_left(conn->mbrx)) {
			conn->mbrx = mem_deref(conn->mbrx);
			break;
		}
	}

 out:
	if (err)
		mem_deref(conn);
}


static void tcp_close_handler(int err, void *arg)
{
	struct bfcp_conn *conn = arg;

	(void)re_printf("BFCP connection closed: %m\n", err);

	mem_deref(conn);
}


static void tcp_conn_handler(const struct sa *addr, void *arg)
{
	struct bfcp_sock *bs = arg;
	struct bfcp_conn *conn;

	(void)re_printf("bfcpd: Connection from %J via %s\n", addr,
			bs->transp == BFCP_TRANSP_TLS ? "TLS" : "TCP");

	conn = conn_add(bs, addr);
	if (conn) {
		if (tcp_accept(&conn->tc, bs->ts, tcp_estab_handler,
				tcp_recv_handler, tcp_close_handler, conn))
			goto error;

#ifdef USE_TLS
		if (bs->transp == BFCP_TRANSP_TLS) {
			if (tls_start_tcp(&conn->sc, bs->tls, conn->tc, 0))
				goto error;
		}
#endif

		return;
	}

 error:
	tcp_reject(bs->ts);
	mem_deref(conn);
}


static struct bfcp_conn *findconn(const struct bfcp_sock *bs,
				  const struct sa *peer)
{
	struct le *le;

	for (le = bs->connl.head; le; le = le->next) {

		struct bfcp_conn *bc = le->data;

		if (sa_cmp(&bc->paddr, peer, SA_ALL))
			return bc;
	}

	return NULL;
}


/**
 * Listen on a BFCP socket
 *
 * @param sockp   Pointer to allocated BFCP socket object
 * @param transp  BFCP transport
 * @param tls     TLS context, used for secure transport (optional)
 * @param laddr   Local network address (optional)
 * @param msgh    BFCP message handler (optional)
 * @param arg     Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int bfcp_listen(struct bfcp_sock **sockp, enum bfcp_transp transp,
		struct tls *tls, const struct sa *laddr,
		bfcp_msg_h *msgh, void *arg)
{
	struct bfcp_sock *sock;
	int err = 0;

	if (!sockp)
		return EINVAL;

	sock = mem_zalloc(sizeof(*sock), destructor);
	if (!sock)
		return ENOMEM;

	sock->transp = transp;
	sock->tls = mem_ref(tls);
	sock->msgh = msgh;
	sock->arg = arg;

	/* Server */
	if (laddr) {
		switch (transp) {

		case BFCP_TRANSP_TLS:
			if (!tls) {
				err = EINVAL;
				goto out;
			}
			/*@fallthrough@*/

		case BFCP_TRANSP_TCP:
			sock->active = false;
			err = tcp_listen(&sock->ts, laddr, tcp_conn_handler,
					 sock);
			break;

		default:
			err = EPROTONOSUPPORT;
			break;
		}
	}
	else {
		sock->active = true;
	}

 out:
	if (err)
		mem_deref(sock);
	else if (sockp)
		*sockp = sock;

	return err;
}


int bfcp_send(struct bfcp_sock *sock, const struct sa *dst, struct mbuf *mb)
{
	struct bfcp_conn *conn = NULL;
	int err = 0;

	if (!sock || !dst || !mb)
		return EINVAL;

	switch (sock->transp) {

	case BFCP_TRANSP_TCP:
	case BFCP_TRANSP_TLS:

		conn = findconn(sock, dst);

		if (!conn) {

			if (!sock->active)
				return ENOTCONN;

			conn = conn_add(sock, dst);
			if (!conn) {
				err = ENOMEM;
				goto out;
			}

			err = tcp_connect(&conn->tc, dst, tcp_estab_handler,
					  tcp_recv_handler,
					  tcp_close_handler, conn);
			if (err)
				goto out;

#ifdef USE_TLS
			if (sock->transp == BFCP_TRANSP_TLS) {

				err = tls_start_tcp(&conn->sc, sock->tls,
						    conn->tc, 0);
				if (err)
					goto out;
			}
#endif
		}

		if (conn->established) {
			err = tcp_send(conn->tc, mb);
		}
		else {
			if (!conn->mbtx) {
				conn->mbtx = mem_ref(mb);
			}
			else {
				conn->mbtx->pos = conn->mbtx->end;
				err = mbuf_write_mem(conn->mbtx, mbuf_buf(mb),
						     mbuf_get_left(mb));
			}
		}
		break;

	default:
		err = EPROTONOSUPPORT;
		break;
	}

 out:
	if (err)
		mem_deref(conn);

	return err;
}
