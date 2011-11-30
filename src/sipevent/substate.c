/**
 * @file substate.c  SIP Subscription-State header
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_uri.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_sip.h>
#include <re_sipevent.h>


int sipevent_substate_decode(struct sipevent_substate *ss, const struct pl *pl)
{
	struct pl state, expires;
	int err;

	if (!ss || !pl)
		return EINVAL;

	err = re_regex(pl->p, pl->l, "[a-z]+[ \t\r\n]*[^]*",
		       &state, NULL, &ss->params);
	if (err)
		return EBADMSG;

	// todo: check case-sensitiveness
	if (!pl_strcasecmp(&state, "active"))
		ss->state = SIPEVENT_ACTIVE;
	else if (!pl_strcasecmp(&state, "terminated"))
		ss->state = SIPEVENT_TERMINATED;
	else
		ss->state = -1;

	if (!sip_param_decode(&ss->params, "expires", &expires))
		ss->expires = pl_u32(&expires);
	else
		ss->expires = 0;

	return 0;
}


const char *sipevent_substate_name(enum sipevent_subst state)
{
	switch (state) {

	case SIPEVENT_ACTIVE:     return "active";
	case SIPEVENT_TERMINATED: return "terminated";
	default:                  return "???";
	}
}
