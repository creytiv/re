/**
 * @file openssl/tls.h TLS backend using OpenSSL (Internal API)
 *
 * Copyright (C) 2010 Creytiv.com
 */


struct tls {
	SSL_CTX *ctx;
	const char *pass;  /* password for private key */
};
