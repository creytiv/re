/**
 * @file re_tls.h  Interface to Transport Layer Security
 *
 * Copyright (C) 2010 Creytiv.com
 */


struct tls;
struct tls_conn;


int tls_alloc(struct tls **tlsp, const char *keyfile, const char *pwd);
int tls_add_ca(struct tls *tls, const char *capath);
int tls_verify_cert(struct tls_conn *tc, char *cn, size_t cn_size);

int tls_start_tcp(struct tls_conn **ptc, struct tls *tls,
		  struct tcp_conn *tcp);
