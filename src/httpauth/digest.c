/**
 * @file digest.c  HTTP Digest authentication (RFC 2617)
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_mem.h>
#include <re_md5.h>
#include <re_sys.h>
#include <re_httpauth.h>


typedef void (digest_decode_h)(const struct pl *name, const struct pl *val,
			       void *arg);


static const struct pl param_algorithm = PL("algorithm");
static const struct pl param_cnonce    = PL("cnonce");
static const struct pl param_nc        = PL("nc");
static const struct pl param_nonce     = PL("nonce");
static const struct pl param_opaque    = PL("opaque");
static const struct pl param_qop       = PL("qop");
static const struct pl param_realm     = PL("realm");
static const struct pl param_response  = PL("response");
static const struct pl param_uri       = PL("uri");
static const struct pl param_username  = PL("username");
static const struct pl param_stale     = PL("stale");


static void challenge_decode(const struct pl *name, const struct pl *val,
			     void *arg)
{
	struct httpauth_digest_chall *chall = arg;

	if (!pl_casecmp(name, &param_realm))
		chall->realm = *val;
	else if (!pl_casecmp(name, &param_nonce))
		chall->nonce = *val;
	else if (!pl_casecmp(name, &param_opaque))
		chall->opaque= *val;
	else if (!pl_casecmp(name, &param_stale))
		chall->stale = *val;
	else if (!pl_casecmp(name, &param_algorithm))
		chall->algorithm = *val;
	else if (!pl_casecmp(name, &param_qop))
		chall->qop = *val;
}


static void response_decode(const struct pl *name, const struct pl *val,
			    void *arg)
{
	struct httpauth_digest_resp *resp = arg;

	if (!pl_casecmp(name, &param_realm))
		resp->realm = *val;
	else if (!pl_casecmp(name, &param_nonce))
		resp->nonce = *val;
	else if (!pl_casecmp(name, &param_response))
		resp->response = *val;
	else if (!pl_casecmp(name, &param_username))
		resp->username = *val;
	else if (!pl_casecmp(name, &param_uri))
		resp->uri = *val;
	else if (!pl_casecmp(name, &param_nc))
		resp->nc = *val;
	else if (!pl_casecmp(name, &param_cnonce))
		resp->cnonce = *val;
	else if (!pl_casecmp(name, &param_qop))
		resp->qop = *val;
}


static int digest_decode(const struct pl *hval, digest_decode_h *dech,
			 void *arg)
{
	struct pl r = *hval, start, end, name, val;

	if (re_regex(r.p, r.l, "[ \t\r\n]*Digest[ \t\r\n]+", &start, &end) ||
	    start.p != r.p)
		return EBADMSG;

	pl_advance(&r, end.p - r.p);

	while (!re_regex(r.p, r.l,
			 "[ \t\r\n,]+[a-z]+[ \t\r\n]*=[ \t\r\n]*[~ \t\r\n,]*",
			 NULL, &name, NULL, NULL, &val)) {

		pl_advance(&r, val.p + val.l - r.p);

		dech(&name, &val, arg);
	}

	return 0;
}


static void response_destructor(void *data)
{
	struct httpauth_digest_resp *resp = data;

	mem_deref(resp->mb);
}


/**
 * Decode a Digest challenge
 *
 * @param chall Digest challenge object to decode into
 * @param hval  Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_digest_challenge_decode(struct httpauth_digest_chall *chall,
				     const struct pl *hval)
{
	int err;

	if (!chall || !hval)
		return EINVAL;

	memset(chall, 0, sizeof(*chall));

	err = digest_decode(hval, challenge_decode, chall);
	if (err)
		return err;

	if (!chall->realm.p || !chall->nonce.p)
		return EBADMSG;

	return 0;
}


/**
 * Decode a Digest response
 *
 * @param resp Digest response object to decode into
 * @param hval Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_digest_response_decode(struct httpauth_digest_resp *resp,
				    const struct pl *hval)
{
	int err;

	if (!resp || !hval)
		return EINVAL;

	memset(resp, 0, sizeof(*resp));

	err = digest_decode(hval, response_decode, resp);
	if (err)
		return err;

	if (!resp->realm.p    ||
	    !resp->nonce.p    ||
	    !resp->response.p ||
	    !resp->username.p ||
	    !resp->uri.p)
		return EBADMSG;

	return 0;
}


/**
 * Authenticate a digest response
 *
 * @param resp   Digest response
 * @param method Request method
 * @param ha1    HA1 value from MD5(username:realm:password)
 *
 * @return 0 if successfully authenticated, otherwise errorcode
 */
int httpauth_digest_response_auth(const struct httpauth_digest_resp *resp,
				  const struct pl *method, const uint8_t *ha1)
{
	uint8_t ha2[MD5_SIZE], digest[MD5_SIZE], response[MD5_SIZE];
	const char *p;
	uint32_t i;
	int err;

	if (!resp || !method || !ha1)
		return EINVAL;

	if (resp->response.l != 32)
		return EAUTH;

	err = md5_printf(ha2, "%r:%r", method, &resp->uri);
	if (err)
		return err;

	if (pl_isset(&resp->qop))
		err = md5_printf(digest, "%w:%r:%r:%r:%r:%w",
				 ha1, (size_t)MD5_SIZE,
				 &resp->nonce,
				 &resp->nc,
				 &resp->cnonce,
				 &resp->qop,
				 ha2, sizeof(ha2));
	else
		err = md5_printf(digest, "%w:%r:%w",
				 ha1, (size_t)MD5_SIZE,
				 &resp->nonce,
				 ha2, sizeof(ha2));
	if (err)
		return err;

	for (i=0, p=resp->response.p; i<sizeof(response); i++) {
		response[i]  = ch_hex(*p++) << 4;
		response[i] += ch_hex(*p++);
	}

	if (memcmp(digest, response, MD5_SIZE))
		return EAUTH;

	return 0;
}


static uint32_t nc = 1;

int httpauth_digest_make_response(struct httpauth_digest_resp **presp,
		const struct httpauth_digest_chall *chall,
		const char *path, const char *method, const char *user,
		const char *pwd, const char *body)
{
	struct httpauth_digest_resp *resp;
	size_t p1, p2;
	uint8_t ha1[MD5_SIZE], ha2[MD5_SIZE], response[MD5_SIZE];
	uint32_t cnonce;
	struct mbuf *mb = NULL;
	int err;

	if (!presp || !chall || !method || !user || !path || !pwd)
		return EINVAL;

	resp = mem_zalloc(sizeof(*resp), response_destructor);
	if (!resp) {
		err = ENOMEM;
		goto out;
	}

	mb = mbuf_alloc(256);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	resp->realm = chall->realm;
	resp->nonce = chall->nonce;
	pl_set_str(&resp->username, user);
	pl_set_str(&resp->uri, path);
	resp->qop = chall->qop;

	err = mbuf_printf(mb, "%x", nc);
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	/* Client nonce should change, so we use random value. */
	cnonce = rand_u32();
	p1 = mb->pos;
	err = mbuf_printf(mb, "%x", cnonce);
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	/* compute response */
	/* HA1 = MD5(username:realm:password) */
	p2 = mb->pos;
	err = mbuf_printf(mb, "%r:%r:%s", &resp->username, &resp->realm,
			pwd);
	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), ha1);
	mbuf_skip_to_end(mb);
	if (0 == pl_strcmp(&chall->algorithm, "MD5-sess")) {
		/* HA1 = MD5(HA1:nonce:cnonce) */
		p2 = mb->pos;
		err = mbuf_printf(mb, "%w:%r:%x", ha1, sizeof(ha1),
				&resp->nonce, cnonce);
		if (err)
			goto out;

		mbuf_set_pos(mb, p2);
		md5(mbuf_buf(mb), mbuf_get_left(mb), ha1);
		mbuf_skip_to_end(mb);
	}

	/* HA2 */
	p2 = mb->pos;
	if (0 == pl_strcmp(&resp->qop, "auth-int") && str_isset(body)) {
		/* HA2 = MD5(method:digestURI:MD5(entityBody)) */
		err = mbuf_printf(mb, "%s", body);
		if (err)
			goto out;

		mbuf_set_pos(mb, p2);
		md5(mbuf_buf(mb), mbuf_get_left(mb), ha2);
		mbuf_skip_to_end(mb);
		p2 = mb->pos;
		err = mbuf_printf(mb, "%s:%r:%w", method, &resp->uri,
				ha2, sizeof(ha2));
	}
	else {
		/* HA2 = MD5(method:digestURI) */
		err = mbuf_printf(mb, "%s:%r", method, &resp->uri);

	}

	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), ha2);
	mbuf_skip_to_end(mb);

	/* repsonse */
	p2 = mb->pos;
	if (0 == pl_strcmp(&resp->qop, "auth-int") ||
			0 == pl_strcmp(&resp->qop, "auth")) {
	/* response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2) */
		err = mbuf_printf(mb, "%w:%r:%x:%x:%r:%w",
				ha1, sizeof(ha1), &resp->nonce, nc, cnonce,
				&resp->qop, ha2, sizeof(ha2));
	}
	else {
	/* response = MD5(HA1:nonce:HA2) */
		err = mbuf_printf(mb, "%w:%r:%w", ha1, sizeof(ha1),
				&resp->nonce, ha2, sizeof(ha2));
	}

	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), response);
	mbuf_skip_to_end(mb);

	p2 = mb->pos;
	err = mbuf_printf(mb, "%w", response, sizeof(response));
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	++nc;
	mbuf_set_pos(mb, 0);
	pl_set_str(&resp->nc, (const char*) mbuf_buf(mb));
	mbuf_set_pos(mb, p1);
	pl_set_str(&resp->cnonce, (const char*) mbuf_buf(mb));
	mbuf_set_pos(mb, p2);
	pl_set_str(&resp->response, (const char*) mbuf_buf(mb));
out:
	resp->mb = mb;
	if (err)
		mem_deref(resp);
	else
		*presp = resp;

	return err;
}


int httpauth_digest_response_encode(const struct httpauth_digest_resp *resp,
				  struct mbuf *mb)
{
	int err;
	size_t s;

	if (!resp || !mb)
		return EINVAL;

	/* lenth of string literals */
	s = 93;
	if (pl_isset(&resp->qop))
		s += 26;

	/* length of values */
	s += resp->username.l + resp->realm.l + resp->nonce.l + resp->uri.l;
	s += resp->response.l;
	if (pl_isset(&resp->qop))
		s += resp->qop.l + resp->nc.l + resp->cnonce.l;

	if (s > mb->size)
		mbuf_resize(mb, s);

	err = mbuf_write_str(mb, "Authorization: ");
	err |= mbuf_printf(mb, "Digest username=\"%r\"", &resp->username);
	err |= mbuf_printf(mb, ", realm=\"%r\"", &resp->realm);
	err |= mbuf_printf(mb, ", nonce=\"%r\"", &resp->nonce);
	err |= mbuf_printf(mb, ", uri=\"%r\"", &resp->uri);
	err |= mbuf_printf(mb, ", response=\"%r\"", &resp->response);

	if (pl_isset(&resp->qop)) {
		err |= mbuf_printf(mb, ", qop=%r", &resp->qop);
		err |= mbuf_printf(mb, ", nc=%r", &resp->nc);
		err |= mbuf_printf(mb, ", cnonce=\"%r\"", &resp->cnonce);
	}

	mbuf_set_pos(mb, 0);
	return err;
}
