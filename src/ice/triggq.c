/**
 * @file triggq.c  ICE Triggered Check Queue
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_stun.h>
#include <re_turn.h>
#include <re_ice.h>
#include "ice.h"


void icem_triggq_push(struct icem *icem, struct candpair *cp)
{
	if (!icem || !cp)
		return;

	if (!list_contains(&icem->triggl, &cp->le_tq))
		list_append(&icem->triggl, &cp->le_tq, cp);
}


struct candpair *icem_triggq_pop(struct icem *icem)
{
	struct candpair *cp;

	if (!icem)
		return NULL;

	cp = list_ledata(icem->triggl.head);
	if (!cp)
		return NULL;

	list_unlink(&cp->le_tq);

	return cp;
}
