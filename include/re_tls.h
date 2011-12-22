/**
 * @file re_tls.h  Interface to Transport Layer Security
 *
 * Copyright (C) 2010 Creytiv.com
 */


struct tls;
struct tls_conn;
struct tls_sock;
struct tcp_conn;
struct udp_sock;


/** Defines the TLS method */
enum tls_method {
	TLS_METHOD_SSLV23,
	TLS_METHOD_DTLSV1,
};


int tls_alloc(struct tls **tlsp, enum tls_method method, const char *keyfile,
	      const char *pwd);
int tls_add_ca(struct tls *tls, const char *capath);
int tls_verify_cert(struct tls_conn *tc, char *cn, size_t cn_size);

int tls_start_tcp(struct tls_conn **ptc, struct tls *tls,
		  struct tcp_conn *tcp, int layer);
int tls_start_udp(struct tls_sock **tsp, struct tls *tls,
		  struct udp_sock *us, int layer, uint32_t bsize);
struct tls_conn *tls_udp_conn(const struct tls_sock *ts,
			      const struct sa *peer);
