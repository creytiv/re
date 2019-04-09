/**
 * @file re_httpauth.h  Interface to HTTP Authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */


/** HTTP Digest Challenge */
struct httpauth_digest_chall {
	struct pl realm;
	struct pl nonce;

	/* optional */
	struct pl opaque;
	struct pl stale;
	struct pl algorithm;
	struct pl qop;
};

/** HTTP Digest response */
struct httpauth_digest_resp {
	struct pl realm;
	struct pl nonce;
	struct pl response;
	struct pl username;
	struct pl uri;

	/* optional */
	struct pl nc;
	struct pl cnonce;
	struct pl qop;

	struct mbuf *mb;
};


/** HTTP Basic */
struct httpauth_basic {
	struct mbuf *mb;
	struct pl realm;
	struct pl auth;
};


int httpauth_digest_challenge_decode(struct httpauth_digest_chall *chall,
				     const struct pl *hval);
int httpauth_digest_response_decode(struct httpauth_digest_resp *resp,
				    const struct pl *hval);
int httpauth_digest_response_auth(const struct httpauth_digest_resp *resp,
				  const struct pl *method, const uint8_t *ha1);
int httpauth_digest_make_response(struct httpauth_digest_resp **resp,
		const struct httpauth_digest_chall *chall,
		const char *path, const char *method, const char *user,
		const char *pwd, const char *body);
int httpauth_digest_response_encode(const struct httpauth_digest_resp *resp,
				  struct mbuf *mb);

struct httpauth_basic *httpauth_basic_alloc(void);
int httpauth_basic_decode(struct httpauth_basic *basic,
		const struct pl *hval);
int httpauth_basic_make_response(struct httpauth_basic *basic,
		const char *user, const char *pwd);
int httpauth_basic_encode(const struct httpauth_basic *basic, struct mbuf *mb);
