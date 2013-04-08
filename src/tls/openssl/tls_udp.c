/**
 * @file openssl/tls_udp.c DTLS/UDP backend using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */
#define OPENSSL_NO_KRB5 1
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_udp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls_udp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct tls_sock {
	struct udp_helper *uh;
	struct udp_sock *us;
	struct hash *ht_conn;
	struct tls *tls;
};

/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	SSL *ssl;             /* inheritance */
	BIO *sbio_out;
	BIO *sbio_in;
	struct le he;
	struct sa peer;
	struct tmr tmr;
	struct tls_sock *ts;
};


static void check_timer(struct tls_conn *conn);


static int bio_create(BIO *b)
{
	b->init  = 1;
	b->num   = 0;
	b->ptr   = NULL;
	b->flags = 0;

	return 1;
}


static int bio_destroy(BIO *b)
{
	if (!b)
		return 0;

	b->ptr   = NULL;
	b->init  = 0;
	b->flags = 0;

	return 1;
}


static int bio_write(BIO *b, const char *buf, int len)
{
	struct tls_conn *tc = b->ptr;
	struct mbuf mb;
	int err;

	mb.buf = (void *)buf;
	mb.pos = 0;
	mb.end = mb.size = len;

	err = udp_send_helper(tc->ts->us, &tc->peer, &mb, tc->ts->uh);
	if (err)
		return -1;

	return len;
}


static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	(void)b;
	(void)num;
	(void)ptr;

	if (cmd == BIO_CTRL_FLUSH) {
		/* The OpenSSL library needs this */
		return 1;
	}

	return 0;
}


static struct bio_method_st bio_udp_send = {
	BIO_TYPE_SOURCE_SINK,
	"udp_send",
	bio_write,
	0,
	0,
	0,
	bio_ctrl,
	bio_create,
	bio_destroy,
	0
};


#if defined (DTLS_CTRL_HANDLE_TIMEOUT) && defined(DTLS_CTRL_GET_TIMEOUT)
static void timeout(void *arg)
{
	struct tls_conn *tc = arg;

	DTLSv1_handle_timeout(tc->ssl);
	check_timer(tc);
}
#endif


static void check_timer(struct tls_conn *tc)
{
#if defined (DTLS_CTRL_HANDLE_TIMEOUT) && defined (DTLS_CTRL_GET_TIMEOUT)
	struct timeval tv = {0, 0};

	if (DTLSv1_get_timeout(tc->ssl, &tv)) {
		tmr_start(&tc->tmr, tv.tv_sec * 1000 + tv.tv_usec / 1000,
			  timeout, tc);
	}
#else
	(void)tc;
#endif
}


static void destructor(void *arg)
{
	struct tls_sock *ts = arg;

	hash_flush(ts->ht_conn);
	mem_deref(ts->ht_conn);
	mem_deref(ts->uh);
	mem_deref(ts->us);
	mem_deref(ts->tls);
}


static void conn_destructor(void *arg)
{
	struct tls_conn *tc = arg;

	hash_unlink(&tc->he);
	tmr_cancel(&tc->tmr);

	if (tc->ssl) {
		(void)SSL_shutdown(tc->ssl);
		SSL_free(tc->ssl);
	}
}


static bool hash_cmp_handler(struct le *le, void *arg)
{
	const struct tls_conn *tc = le->data;

	return sa_cmp(&tc->peer, arg, SA_ALL);
}


static struct tls_conn *conn_alloc(struct tls_sock *ts, const struct sa *peer)
{
	struct tls_conn *tc;

	tc = mem_zalloc(sizeof(*tc), conn_destructor);
	if (!tc)
		return NULL;

	tc->ssl = SSL_new(ts->tls->ctx);
	if (!tc->ssl)
		goto error;

	tc->sbio_in = BIO_new(BIO_s_mem());
	if (!tc->sbio_in)
		goto error;

	tc->sbio_out = BIO_new(&bio_udp_send);
	if (!tc->sbio_out) {
		BIO_free(tc->sbio_in);
		goto error;
	}
	tc->sbio_out->ptr = tc;

	SSL_set_bio(tc->ssl, tc->sbio_in, tc->sbio_out);

	tmr_init(&tc->tmr);

	tc->peer = *peer;
	tc->ts   = ts;

	hash_append(ts->ht_conn, sa_hash(peer, SA_ALL), &tc->he, tc);

	return tc;

 error:
	return mem_deref(tc);
}


static bool send_handler(int *err, struct sa *dst, struct mbuf *mb, void *arg)
{
	struct tls_sock *ts = arg;
	struct tls_conn *tc;
	int r;

	tc = tls_udp_conn(ts, dst);
	if (!tc) {

		/* No connection found, assuming Client role */

		tc = conn_alloc(ts, dst);
		if (!tc) {
			*err = ENOMEM;
			return true;
		}

		SSL_set_connect_state(tc->ssl);

		check_timer(tc);
	}

	r = SSL_write(tc->ssl, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r < 0) {

		switch (SSL_get_error(tc->ssl, r)) {

		case SSL_ERROR_WANT_READ:
			break;

		default:
			DEBUG_WARNING("SSL_write: %d\n",
				      SSL_get_error(tc->ssl, r));
			*err = EPROTO;
			return true;
		}
	}

	return true;
}


static bool recv_handler(struct sa *src, struct mbuf *mb, void *arg)
{
	struct tls_sock *ts = arg;
	struct tls_conn *tc;
	int r;

	tc = tls_udp_conn(ts, src);
	if (!tc) {

		/* No connection found, assuming Server role */

		tc = conn_alloc(ts, src);
		if (!tc)
			return true;

		SSL_set_verify(tc->ssl, 0, 0);
		SSL_set_accept_state(tc->ssl);
	}

	/* feed SSL data to the BIO */
	r = BIO_write(tc->sbio_in, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r <= 0)
		return true;

	check_timer(tc);

	mbuf_set_pos(mb, 0);

	for (;;) {
		int n;

		if (mbuf_get_space(mb) < 4096) {
			if (mbuf_resize(mb, mb->size + 8192))
				return true;
		}

		n = SSL_read(tc->ssl, mbuf_buf(mb), (int)mbuf_get_space(mb));
		if (n < 0) {
			const int ssl_err = SSL_get_error(tc->ssl, n);

			switch (ssl_err) {

			case SSL_ERROR_WANT_READ:
				break;

			default:
				return true;
			}

			break;
		}
		else if (n == 0)
			break;

		mb->pos += n;
	}

	if (!mb->pos)
		return true;

	mbuf_set_end(mb, mb->pos);
	mbuf_set_pos(mb, 0);

	return false;
}


/**
 * Start TLS on a UDP socket (aka DTLS). The UDP socket can act as a
 * client or a server, and multiple DTLS connections can be established to
 * multiple peers, all from the same UDP socket.
 *
 * @param tsp    Pointer to allocated TLS socket
 * @param tls    TLS context
 * @param us     UDP socket
 * @param layer  Protocol stack layer
 * @param bsize  Bucket size for hash table (0 for default)
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_start_udp(struct tls_sock **tsp, struct tls *tls, struct udp_sock *us,
		  int layer, uint32_t bsize)
{
	struct tls_sock *ts;
	int err;

	if (!tsp || !tls || !us)
		return EINVAL;

	ts = mem_zalloc(sizeof(*ts), destructor);
	if (!ts)
		return ENOMEM;

	err = hash_alloc(&ts->ht_conn, bsize ? bsize : 4);
	if (err)
		goto out;

	err = udp_register_helper(&ts->uh, us, layer, send_handler,
				  recv_handler, ts);
	if (err)
		goto out;

	ts->us = mem_ref(us);
	ts->tls = mem_ref(tls);

 out:
	if (err)
		mem_deref(ts);
	else
		*tsp = ts;

	return err;
}


/**
 * Get the TLS Connection for a given peer
 *
 * @param ts   TLS Socket
 * @param peer Network address of peer
 *
 * @return TLS Connection if found, NULL if not found
 */
struct tls_conn *tls_udp_conn(const struct tls_sock *ts, const struct sa *peer)
{
	if (!ts)
		return NULL;

	return list_ledata(hash_lookup(ts->ht_conn, sa_hash(peer, SA_ALL),
				       hash_cmp_handler, (void *)peer));
}
