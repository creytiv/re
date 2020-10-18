/**
 * @file basic.c HTTP Basic authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_mbuf.h>
#include <re_base64.h>
#include <re_mem.h>
#include <re_fmt.h>
#include <re_httpauth.h>


#define DEBUG_MODULE "httpauth_basic"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void httpauth_basic_destr(void *arg)
{
	struct httpauth_basic *basic = arg;

	mem_deref(basic->mb);
}


struct httpauth_basic *httpauth_basic_alloc(void)
{
	struct httpauth_basic *basic = mem_zalloc(sizeof(*basic),
			httpauth_basic_destr);

	if (!basic)
		DEBUG_WARNING("could not allocate httpauth_basic\n");

	return basic;
}


/**
 * Decode a Basic response
 *
 * @param basic Basic response object
 * @param hval Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_basic_decode(struct httpauth_basic *basic,
				    const struct pl *hval)
{
	if (!basic || !hval)
		return EINVAL;

	if (re_regex(hval->p, hval->l,
			"[ \t\r\n]*Basic[ \t\r\n]+realm[ \t\r\n]*=[ \t\r\n]*"
				"[~ \t\r\n,]*",
			NULL, NULL, NULL, NULL, &basic->realm) ||
			!pl_isset(&basic->realm))
		return EBADMSG;

	return 0;
}


int httpauth_basic_make_response(struct httpauth_basic *basic,
		const char *user, const char *pwd)
{
	uint8_t *in;
	char *out;
	size_t si, so;
	size_t poso;
	int err;

	if (!basic || !user || !pwd)
		return EINVAL;

	si = strlen(user) + strlen(pwd) + 1;
	so = 4 * (si + 2) / 3;
	basic->mb = mbuf_alloc(si + so + 1);
	if (!basic->mb)
		return ENOMEM;

	err = mbuf_printf(basic->mb, "%s:%s", user, pwd);
	poso = basic->mb->pos;

	err |= mbuf_fill(basic->mb, 0, so + 1);
	if (err)
		goto fault;

	mbuf_set_pos(basic->mb, 0);
	in = mbuf_buf(basic->mb);
	mbuf_set_pos(basic->mb, poso);
	out = (char*) mbuf_buf(basic->mb);
	err = base64_encode(in, si, out, &so);
	if (err)
		goto fault;

	pl_set_str(&basic->auth, out);

	return 0;

fault:
	mem_deref(basic->mb);
	return err;
}

int httpauth_basic_encode(const struct httpauth_basic *basic, struct mbuf *mb)
{
	int err;

	if (!basic || !mb || !pl_isset(&basic->auth))
		return EINVAL;

	err = mbuf_resize(mb, basic->auth.l + 21);
	if (err)
		return err;

	err = mbuf_write_str(mb, "Authorization: Basic ");
	err |= mbuf_write_pl(mb, &basic->auth);
	if (err)
		return err;

	mbuf_set_pos(mb, 0);
	return 0;
}
