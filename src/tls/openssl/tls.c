/**
 * @file openssl/tls.c TLS backend using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <signal.h>
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
};


static struct {
	uint32_t tlsc;
	bool up;
} tlsg;


#ifdef SIGPIPE
static void sigpipe_handle(int x)
{
	(void)x;
	(void)signal(SIGPIPE, sigpipe_handle);
}
#endif


static void destructor(void *data)
{
	struct tls *tls = data;

	SSL_CTX_free(tls->ctx);

	if (--tlsg.tlsc == 0) {
		DEBUG_INFO("error strings freed\n");
		ERR_free_strings();
	}
}


/*The password code is not thread safe*/
static int password_cb(char *buf, int size, int rwflag, void *userdata)
{
	struct tls *tls = userdata;

	(void)rwflag;

	DEBUG_NOTICE("password callback\n");

	if (size < (int)strlen(tls->pass)+1)
		return 0;

	strncpy(buf, tls->pass, size);

	return (int)strlen(tls->pass);
}


int tls_alloc(struct tls **tlsp, const char *keyfile, const char *pwd)
{
	int r, err = ENOMEM;
	struct tls *tls;

	if (!tlsp)
		return EINVAL;

	tls = mem_zalloc(sizeof(*tls), destructor);
	if (!tls)
		return ENOMEM;

	if (!tlsg.up) {
#ifdef SIGPIPE
		/* Set up a SIGPIPE handler */
		(void)signal(SIGPIPE, sigpipe_handle);
#endif

		SSL_library_init();
		tlsg.up = true;
	}

	if (tlsg.tlsc++ == 0) {
		DEBUG_INFO("error strings loaded\n");
		SSL_load_error_strings();
	}

	tls->ctx = SSL_CTX_new(SSLv23_method());
	if (!tls->ctx)
		goto out;

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	SSL_CTX_set_verify_depth(tls->ctx, 1);
#endif

	/* Load our keys and certificates */
	if (keyfile) {
		err = EINVAL;

		tls->pass = pwd;
		SSL_CTX_set_default_passwd_cb(tls->ctx, password_cb);
		SSL_CTX_set_default_passwd_cb_userdata(tls->ctx, tls);

		r = SSL_CTX_use_certificate_chain_file(tls->ctx, keyfile);
		if (r <= 0) {
			DEBUG_WARNING("Can't read certificate file: %s (%d)\n",
				      keyfile, r);
			goto out;
		}

		r = SSL_CTX_use_PrivateKey_file(tls->ctx, keyfile,
						SSL_FILETYPE_PEM);
		if (r <= 0) {
			DEBUG_WARNING("Can't read key file: %s (%d)\n",
				      keyfile, r);
			goto out;
		}
	}

	err = 0;
 out:
	if (err)
		mem_deref(tls);
	else
		*tlsp = tls;

	return err;
}


int tls_add_ca(struct tls *tls, const char *capath)
{
	if (!tls || !capath)
		return EINVAL;

	/* Load the CAs we trust */
	if (!(SSL_CTX_load_verify_locations(tls->ctx, capath, 0))) {
		DEBUG_WARNING("Can't read CA list: %s\n", capath);
		return EINVAL;
	}

	return 0;
}


int tls_verify_cert(struct tls_conn *tc, char *cn, size_t cn_size)
{
	X509 *peer;

	if (!tc)
		return EINVAL;

	/* Check the cert chain. The chain length
	   is automatically checked by OpenSSL when
	   we set the verify depth in the ctx */

	/* Get the common name */
	peer = SSL_get_peer_certificate(tc->ssl);
	/* todo: check return value */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
				  NID_commonName, cn, (int)cn_size);

	/* todo get valid start/end date */


	if (SSL_get_verify_result(tc->ssl) != X509_V_OK) {
		DEBUG_WARNING("Certificate doesn't verify\n");
		return EPROTO;
	}

	return 0;
}
