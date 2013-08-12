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


/* NOTE: shadow struct defined in tls_*.c */
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

	if (tls->ctx)
		SSL_CTX_free(tls->ctx);

	mem_deref(tls->pass);

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


/**
 * Allocate a new TLS context
 *
 * @param tlsp    Pointer to allocated TLS context
 * @param method  TLS method
 * @param keyfile Optional private key file
 * @param pwd     Optional password
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_alloc(struct tls **tlsp, enum tls_method method, const char *keyfile,
	      const char *pwd)
{
	struct tls *tls;
	int r, err;

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

	switch (method) {

	case TLS_METHOD_SSLV23:
		tls->ctx = SSL_CTX_new(SSLv23_method());
		break;

#ifdef USE_OPENSSL_DTLS
	case TLS_METHOD_DTLSV1:
		tls->ctx = SSL_CTX_new(DTLSv1_method());
		break;
#endif

	default:
		DEBUG_WARNING("tls method %d not supported\n", method);
		err = ENOSYS;
		goto out;
	}

	if (!tls->ctx) {
		err = ENOMEM;
		goto out;
	}

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	SSL_CTX_set_verify_depth(tls->ctx, 1);
#endif

	if (method == TLS_METHOD_DTLSV1) {
		SSL_CTX_set_read_ahead(tls->ctx, 1);
	}

	/* Load our keys and certificates */
	if (keyfile) {
		if (pwd) {
			err = str_dup(&tls->pass, pwd);
			if (err)
				goto out;

			SSL_CTX_set_default_passwd_cb(tls->ctx, password_cb);
			SSL_CTX_set_default_passwd_cb_userdata(tls->ctx, tls);
		}

		r = SSL_CTX_use_certificate_chain_file(tls->ctx, keyfile);
		if (r <= 0) {
			DEBUG_WARNING("Can't read certificate file: %s (%d)\n",
				      keyfile, r);
			err = EINVAL;
			goto out;
		}

		r = SSL_CTX_use_PrivateKey_file(tls->ctx, keyfile,
						SSL_FILETYPE_PEM);
		if (r <= 0) {
			DEBUG_WARNING("Can't read key file: %s (%d)\n",
				      keyfile, r);
			err = EINVAL;
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


/**
 * Set default locations for trusted CA certificates
 *
 * @param tls    TLS Context
 * @param capath Path to CA certificates
 *
 * @return 0 if success, otherwise errorcode
 */
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


/**
 * Verify peer certificate of a TLS connection
 *
 * @param tc      TLS Connection
 * @param cn      Returned common name
 * @param cn_size Size of cn string
 *
 * @return 0 if success, otherwise errorcode
 */
int tls_verify_cert(struct tls_conn *tc, char *cn, size_t cn_size)
{
	X509 *peer;

	if (!tc || !cn || !cn_size)
		return EINVAL;

	/* Check the cert chain. The chain length
	   is automatically checked by OpenSSL when
	   we set the verify depth in the ctx */

	peer = SSL_get_peer_certificate(tc->ssl);
	if (!peer) {
		DEBUG_WARNING("Unable to get peer certificate\n");
		return EPROTO;
	}

	/* Get the common name */
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
				  NID_commonName, cn, (int)cn_size);

	/* todo get valid start/end date */


	if (SSL_get_verify_result(tc->ssl) != X509_V_OK) {
		DEBUG_WARNING("Certificate doesn't verify\n");
		return EPROTO;
	}

	return 0;
}


static const EVP_MD *type2evp(const char *type)
{
	if (0 == str_casecmp(type, "SHA-1"))
		return EVP_sha1();
	else if (0 == str_casecmp(type, "SHA-256"))
		return EVP_sha256();
	else
		return NULL;
}


int tls_get_remote_fingerprint(const struct tls_conn *tc, const char *type,
			       struct tls_fingerprint *fp)
{
	X509 *x;

	if (!tc || !fp)
		return EINVAL;

	x = SSL_get_peer_certificate(tc->ssl);
	if (!x)
		return EPROTO;

	fp->len = sizeof(fp->md);
	if (1 != X509_digest(x, type2evp(type), fp->md, &fp->len))
		return ENOENT;

	return 0;
}
