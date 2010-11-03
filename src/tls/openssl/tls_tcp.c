/**
 * @file openssl/tls_tcp.c TLS/TCP backend using OpenSSL
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
#include <re_main.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_tcp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct tls_conn {
	SSL *ssl;
	BIO *sbio_out;
	BIO *sbio_in;
	struct tcp_helper *th;
	struct tcpconn *tcp;
	bool active;
	bool up;
};


static void destructor(void *arg)
{
	struct tls_conn *tc = arg;

	if (tc->ssl) {
		(void)SSL_shutdown(tc->ssl);
		SSL_free(tc->ssl);
	}
	mem_deref(tc->th);
	mem_deref(tc->tcp);
}


static int tls_connect(struct tls_conn *tc)
{
	int err = 0, r;

	r = SSL_connect(tc->ssl);
	if (r <= 0) {
		const int ssl_err = SSL_get_error(tc->ssl, r);

		switch (ssl_err) {
		case SSL_ERROR_WANT_READ:
			break;

		default:
			DEBUG_WARNING("connect: error (r=%d, ssl_err=%d)\n",
				      r, ssl_err);
			err = EPROTO;
			break;
		}
	}

	return err;
}


static int tls_accept(struct tls_conn *tc)
{
	int err = 0, r;

	r = SSL_accept(tc->ssl);
	if (r <= 0) {
		const int ssl_err = SSL_get_error(tc->ssl, r);

		switch (ssl_err) {
		case SSL_ERROR_WANT_READ:
			break;

		default:
			DEBUG_WARNING("accept error: (r=%d, ssl_err=%d)\n",
				      r, ssl_err);
			err = EPROTO;
			break;
		}
	}

	return err;
}


static bool estab_handler(int *err, bool active, void *arg)
{
	struct tls_conn *tc = arg;

	DEBUG_INFO("tcp established (active=%u)\n", active);

	if (!active)
		return true;

	tc->active = true;
	*err = tls_connect(tc);

	return true;
}


static bool recv_handler(int *err, struct mbuf *mb, bool *estab, void *arg)
{
	struct tls_conn *tc = arg;
	int r;

	/* feed SSL data to the BIO */
	r = BIO_write(tc->sbio_in, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r <= 0) {
		DEBUG_WARNING("recv: BIO_write %d\n", r);
		*err = ENOMEM;
		return true;
	}

	if (SSL_state(tc->ssl) != SSL_ST_OK) {

		if (tc->up) {
			*err = EPROTO;
			return true;
		}

		if (tc->active) {
			*err = tls_connect(tc);
		}
		else {
			*err = tls_accept(tc);
		}

		DEBUG_INFO("state=0x%04x\n", SSL_state(tc->ssl));

		/* TLS connection is established */
		if (SSL_state(tc->ssl) == SSL_ST_OK) {
			*estab = true;
			tc->up = true;
			return false;
		}

		return true;
	}

	mbuf_set_pos(mb, 0);

	for (;;) {
		int n;

		if (mbuf_get_space(mb) < 4096) {
			*err = mbuf_resize(mb, mb->size + 8192);
			if (*err)
				return true;
		}

		n = SSL_read(tc->ssl, mbuf_buf(mb), (int)mbuf_get_space(mb));
		if (n < 0) {
			const int ssl_err = SSL_get_error(tc->ssl, n);

			switch (ssl_err) {
			case SSL_ERROR_WANT_READ:
				break;

			default:
				*err = EPROTO;
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


static bool send_handler(int *err, struct mbuf *mb, void *arg)
{
	struct tls_conn *tc = arg;
	int r;

	r = SSL_write(tc->ssl, mbuf_buf(mb), (int)mbuf_get_left(mb));
	if (r <= 0) {
		DEBUG_WARNING("SSL_write: %d\n", SSL_get_error(tc->ssl, r));
		*err = EPROTO;
	}

	return true;
}


int tls_start_tcp(struct tls_conn **ptc, struct tls *tls, struct tcp_conn *tcp)
{
	int err, fd;
	struct tls_conn *tc;

	if (!ptc || !tls || !tcp)
		return EINVAL;

	tc = mem_zalloc(sizeof(*tc), destructor);
	if (!tc)
		return ENOMEM;

	err = tcp_register_helper(&tc->th, tcp, &fd, estab_handler,
				  send_handler, recv_handler, tc);
	if (err)
		goto out;

	tc->tcp = mem_ref(tcp);

	err = ENOMEM;

	/* Connect the SSL socket */
	tc->ssl = SSL_new(tls->ctx);
	if (!tc->ssl) {
		DEBUG_WARNING("alloc: SSL_new() failed (ctx=%p)\n", tls->ctx);
		goto out;
	}

	tc->sbio_in = BIO_new(BIO_s_mem());
	if (!tc->sbio_in) {
		DEBUG_WARNING("alloc: BIO_new() failed\n");
		goto out;
	}

	tc->sbio_out = BIO_new_socket(fd, BIO_NOCLOSE);
	if (!tc->sbio_out) {
		DEBUG_WARNING("alloc: BIO_new_socket() failed\n");
		goto out;
	}

	SSL_set_bio(tc->ssl, tc->sbio_in, tc->sbio_out);

	err = 0;

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}
