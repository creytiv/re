/**
 * @file prm.c Generic parameter decoding
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>


bool fmt_param_get(const struct pl *pl, const char *pname, struct pl *val)
{
	char expr[128];

	if (!pl)
		return false;

	(void)re_snprintf(expr, sizeof(expr), "%s[=]*[^;]*", pname);

	return 0 == re_regex(pl->p, pl->l, expr, NULL, val);
}


void fmt_param_apply(const struct pl *pl, fmt_param_h *ph, void *arg)
{
	size_t i;

	if (!pl || !ph)
		return;

	for (i=0; i<pl->l; ) {
		struct pl lws, name, eq, val, s;

		lws.l = eq.l = s.l = val.l = 0;
		if (re_regex(&pl->p[i], pl->l - i, "[ ]*[^;=]+[=]*[^;]*[;]*",
			     &lws, &name, &eq, &val, &s))
			break;

		ph(&name, &val, arg);

		i += (lws.l + name.l + eq.l + val.l + s.l);
	}
}
