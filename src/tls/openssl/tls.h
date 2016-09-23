/**
 * @file openssl/tls.h TLS backend using OpenSSL (Internal API)
 *
 * Copyright (C) 2010 Creytiv.com
 */


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define SSL_state SSL_get_state
#define SSL_ST_OK TLS_ST_OK
#endif


struct tls {
	SSL_CTX *ctx;
	X509 *cert;
	char *pass;  /* password for private key */
};


void tls_flush_error(void);
