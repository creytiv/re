/**
 * @file openssl/tls.h TLS backend using OpenSSL (Internal API)
 *
 * Copyright (C) 2010 Creytiv.com
 */


#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	!defined(LIBRESSL_VERSION_NUMBER)
#define SSL_state SSL_get_state
#define SSL_ST_OK TLS_ST_OK
#endif


struct tls {
	SSL_CTX *ctx;
	X509 *cert;
	char *pass;  /* password for private key */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	!defined(LIBRESSL_VERSION_NUMBER)
	BIO_METHOD *method_tcp;
	BIO_METHOD *method_udp;
#endif
};


#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
	!defined(LIBRESSL_VERSION_NUMBER)
BIO_METHOD *tls_method_tcp(void);
BIO_METHOD *tls_method_udp(void);
#endif


void tls_flush_error(void);
