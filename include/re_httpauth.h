/**
 * @file re_httpauth.h  Interface to HTTP Authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */


/** Authentication type */
enum httpauth_hdr {
	HTTPAUTH_WWW,
	HTTPAUTH_PROXY
};


/* Client code */
struct httpauth_digest_chall {
	enum httpauth_hdr hdr;
	struct pl realm;
	struct pl nonce;

	/* optional */
	struct pl opaque;
	struct pl stale;
	struct pl algorithm;
	struct pl qop;
};

int httpauth_digest_challenge_decode(struct httpauth_digest_chall *chall,
				     const struct pl *hval);
int httpauth_digest_response_encode(struct mbuf *mb, const struct pl *hname,
				    const struct httpauth_digest_chall *chall,
				    const struct pl *username,
				    const struct pl *uri,
				    const struct pl *cnonce,
				    const struct pl *qop,
				    const struct pl *nc,
				    const uint8_t *digest);


/* Server code */
struct httpauth_digest_resp {
	struct pl realm;
	struct pl nonce;
	struct pl response;
	struct pl nc;
	struct pl cnonce;
	struct pl qop;
	struct pl username;
	struct pl uri;
};

int httpauth_digest_authenticate(struct httpauth_digest_resp *resp,
				 bool *auth, const struct pl *method,
				 const char *ha1);
int httpauth_digest_decode_response(struct httpauth_digest_resp *resp,
				    const struct pl *hval);
int httpauth_digest_encode_challenge(struct mbuf *mb, const struct pl *hname,
				     const struct pl *realm);
