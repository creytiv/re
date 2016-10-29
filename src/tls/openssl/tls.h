/**
 * @file openssl/tls.h TLS backend using OpenSSL (Internal API)
 *
 * Copyright (C) 2010 Creytiv.com
 */


/*
 * Mapping of feature macros
 */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define TLS_BIO_OPAQUE 1
#endif

#if defined (LIBRESSL_VERSION_NUMBER)
#undef  TLS_BIO_OPAQUE
#endif


#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	!defined(LIBRESSL_VERSION_NUMBER)
#define SSL_state SSL_get_state
#define SSL_ST_OK TLS_ST_OK
#endif


struct tls {
	SSL_CTX *ctx;
	X509 *cert;
	char *pass;  /* password for private key */
#ifdef TLS_BIO_OPAQUE
	BIO_METHOD *method_tcp;
	BIO_METHOD *method_udp;
#endif
};


#ifdef TLS_BIO_OPAQUE
BIO_METHOD *tls_method_tcp(void);
BIO_METHOD *tls_method_udp(void);
#endif


void tls_flush_error(void);
