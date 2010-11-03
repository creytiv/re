/**
 * @file digest.c  HTTP Digest authentication (RFC 2617)
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_md5.h>
#include <re_sys.h>
#include <re_httpauth.h>


static const struct pl str_digest = PL("Digest");

static const struct pl param_algo     = PL("algorithm");
static const struct pl param_cnonce   = PL("cnonce");
static const struct pl param_nc       = PL("nc");
static const struct pl param_nonce    = PL("nonce");
static const struct pl param_opaque   = PL("opaque");
static const struct pl param_qop      = PL("qop");
static const struct pl param_realm    = PL("realm");
static const struct pl param_response = PL("response");
static const struct pl param_uri      = PL("uri");
static const struct pl param_username = PL("username");
static const struct pl param_stale    = PL("stale");


static int param_get(const struct pl *pl, const struct pl *name,
		     struct pl *val)
{
	char expr[32];
	int err;

	if (re_snprintf(expr, sizeof(expr), "[ ]*%r=[^, ]+", name) < 0)
		return EINVAL;

	err = re_regex(pl->p, pl->l, expr, NULL, val);
	if (err)
		return err;

	/* Optionally strip off quotes */
	(void)re_regex(val->p, val->l, "\"[^\"]+\"", val);

	return 0;
}


/* Client code */


int httpauth_digest_challenge_decode(struct httpauth_digest_chall *chall,
				     const struct pl *hval)
{
	struct pl scheme;
	int err;

	if (!chall || !hval)
		return EINVAL;

	err = re_regex(hval->p, hval->l, "[^ \t]+[ \t]+", &scheme, NULL);
	if (err)
		return err;

	err = pl_casecmp(&scheme, &str_digest);
	if (err)
		return err;

	/* Mandatory */
	if (param_get(hval, &param_realm,    &chall->realm)  ||
	    param_get(hval, &param_nonce,    &chall->nonce))
		return EINVAL;

	/* Optional */
	(void)param_get(hval, &param_opaque, &chall->opaque);
	(void)param_get(hval, &param_stale,  &chall->stale);
	(void)param_get(hval, &param_algo,   &chall->algorithm);
	(void)param_get(hval, &param_qop,    &chall->qop);

	return 0;
}


int httpauth_digest_response_encode(struct mbuf *mb, const struct pl *hname,
				    const struct httpauth_digest_chall *chall,
				    const struct pl *username,
				    const struct pl *uri,
				    const struct pl *cnonce,
				    const struct pl *qop,
				    const struct pl *nc,
				    const uint8_t *digest)
{
	int err = 0;

	if (!mb || !hname || !chall)
		return EINVAL;

	err |= mbuf_printf(mb, "%r: Digest ", hname);

	err |= mbuf_printf(mb, "username=\"%r\",realm=\"%r\",nonce=\"%r\""
			   ",uri=\"%r\"",
			   username, &chall->realm, &chall->nonce, uri);

	err |= mbuf_printf(mb, ",response=\"%w\"", digest, MD5_SIZE);

	if (chall->opaque.p)
		err |= mbuf_printf(mb, ",opaque=\"%r\"", &chall->opaque);

	if (chall->qop.p) {
		err |= mbuf_printf(mb, ",cnonce=\"%r\",qop=%r,nc=%r",
				   cnonce, qop, nc);
	}

	err |= mbuf_write_str(mb, "\r\n");

	return err;
}


/* Server code */

int httpauth_digest_authenticate(struct httpauth_digest_resp *resp,
				 bool *auth, const struct pl *method,
				 const char *ha1)
{
	uint8_t a2[MD5_SIZE], d[MD5_SIZE];
	char hd[MD5_STR_SIZE];
	int err;

	if (!resp || !auth || !method)
		return EINVAL;

	err = md5_printf(a2, "%r:%r", method, &resp->uri);
	if (err)
		return err;

	err = md5_printf(d, "%s:%r:%r:%r:%r:%w", ha1, &resp->nonce, &resp->nc,
			 &resp->cnonce, &resp->qop, a2, MD5_SIZE);
	if (err)
		return err;

	if (re_snprintf(hd, sizeof(hd), "%w", d, sizeof(d)) < 0)
		return EINVAL;

	*auth = (pl_strcasecmp(&resp->response, hd) == 0);

	return 0;
}


int httpauth_digest_decode_response(struct httpauth_digest_resp *resp,
				    const struct pl *hval)
{
	struct pl scheme;

	if (!resp || !hval)
		return EINVAL;

	if (re_regex(hval->p, hval->l, "[^ \t]+[ \t]+", &scheme, NULL) ||
	    pl_casecmp(&scheme, &str_digest))
		return EINVAL;

	if (param_get(hval, &param_realm,    &resp->realm)    ||
	    param_get(hval, &param_nonce,    &resp->nonce)    ||
	    param_get(hval, &param_response, &resp->response) ||
	    param_get(hval, &param_nc,       &resp->nc)       ||
	    param_get(hval, &param_cnonce,   &resp->cnonce)   ||
	    param_get(hval, &param_qop,      &resp->qop)      ||
	    param_get(hval, &param_username, &resp->username) ||
	    param_get(hval, &param_uri,      &resp->uri))
		return EINVAL;

	return 0;
}


int httpauth_digest_encode_challenge(struct mbuf *mb, const struct pl *hname,
				     const struct pl *realm)
{
	if (!mb || !hname || !realm)
		return EINVAL;

	return mbuf_printf(mb,
			   "%r: Digest realm=\"%r\", "
			   "nonce=\"%08lx%08lx%08lx%08lx\", "
			   "qop=\"auth\"\r\n",
			   hname, realm,
			   rand_u32(), rand_u32(), rand_u32(), rand_u32());
}
