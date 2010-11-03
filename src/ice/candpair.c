/**
 * @file candpair.c  ICE Candidate Pairs
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
#include <re_ice.h>
#include "ice.h"


#define DEBUG_MODULE "candpair"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void candpair_destructor(void *data)
{
	struct candpair *cp = data;

	list_unlink(&cp->le);

	mem_deref(cp->ct_conn);

	mem_deref(cp->lcand);
	mem_deref(cp->rcand);
}


static void candpair_set_pprio(struct candpair *cp)
{
	uint32_t g, d;

	if (ROLE_CONTROLLING == cp->icem->ice->lrole) {
		g = cp->lcand->prio;
		d = cp->rcand->prio;
	}
	else {
		g = cp->rcand->prio;
		d = cp->lcand->prio;
	}

	cp->pprio = ice_calc_pair_prio(g, d);
}


int icem_candpair_alloc(struct candpair **cpp, struct icem *icem,
			struct cand *lcand, struct cand *rcand)
{
	struct candpair *cp;

	if (!icem || !lcand || !rcand)
		return EINVAL;

	cp = mem_zalloc(sizeof(*cp), candpair_destructor);
	if (!cp)
		return ENOMEM;

	list_append(&icem->checkl, &cp->le, cp);

	cp->icem  = icem;
	cp->lcand = mem_ref(lcand);
	cp->rcand = mem_ref(rcand);
	cp->state = CANDPAIR_FROZEN;
	cp->rtt   = -1;

	candpair_set_pprio(cp);

	if (cpp)
		*cpp = cp;

	return 0;
}


static bool sort_handler(struct le *le1, struct le *le2, void *arg)
{
	const struct candpair *cp1 = le1->data;
	const struct candpair *cp2 = le2->data;

	(void)arg;

	return cp1->pprio >= cp2->pprio;
}


/** Computing Pair Priority and Ordering Pairs */
void icem_candpair_prio_order(struct list *lst)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {
		struct candpair *cp = le->data;

		candpair_set_pprio(cp);
	}

	list_sort(lst, sort_handler, NULL);
}


void icem_candpair_move(struct candpair *cp, struct list *list)
{
	list_unlink(&cp->le);
	list_append(list, &cp->le, cp);
}


/* cancel transaction */
void icem_candpair_cancel(struct candpair *cp)
{
	if (!cp)
		return;

	cp->ct_conn = mem_deref(cp->ct_conn);
}


/**
 * Compare local and remote candidates of two candidate pairs
 *
 * @return true if match
 */
bool icem_candpair_cmp(const struct candpair *cp1, const struct candpair *cp2)
{
	if (!sa_cmp(&cp1->lcand->addr, &cp2->lcand->addr, SA_ALL))
		return false;

	return sa_cmp(&cp1->rcand->addr, &cp2->rcand->addr, SA_ALL);
}


/**
 * Find the highest-priority candidate-pair in a given list, with
 * optional match parameters
 *
 * note: assume list is sorted by priority
 */
struct candpair *icem_candpair_find(const struct list *lst,
				    const struct cand *lcand,
				    const struct cand *rcand)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {

		struct candpair *cp = le->data;

		if (!cp->lcand || !cp->rcand) {
			DEBUG_WARNING("corrupt candpair %p\n", cp);
			continue;
		}

		if (lcand && cp->lcand != lcand)
			continue;

		if (rcand && cp->rcand != rcand)
			continue;

		return cp;
	}

	return NULL;
}


struct candpair *icem_candpair_find_st(const struct list *lst, uint8_t compid,
				       enum candpair_state state)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {

		struct candpair *cp = le->data;

		if (compid && cp->lcand->compid != compid)
			continue;

		if (cp->state != state)
			continue;

		return cp;
	}

	return NULL;
}


bool icem_candpair_cmp_fnd(const struct candpair *cp1,
			   const struct candpair *cp2)
{
	if (!cp1 || !cp2)
		return false;

	return 0 == strcmp(cp1->lcand->foundation, cp2->lcand->foundation) &&
		0 == strcmp(cp1->rcand->foundation, cp2->rcand->foundation);
}


int icem_candpair_debug(struct re_printf *pf, const struct candpair *cp)
{
	int err;

	if (!cp)
		return 0;

	err = re_hprintf(pf, "{%u} %10s {%c%c%c%c}  %28H --> %28H",
			 cp->lcand->compid,
			 ice_candpair_state2name(cp->state),
			 cp->def ? 'D' : ' ',
			 cp->valid ? 'V' : ' ',
			 cp->nominated ? 'N' : ' ',
			 cp->use_cand ? 'U' : ' ',
			 icem_cand_print, cp->lcand,
			 icem_cand_print, cp->rcand);

	if (cp->rtt != -1) {
		err |= re_hprintf(pf, " RTT=%dms", cp->rtt);
	}

	return err;
}


int icem_candpairs_debug(struct re_printf *pf, const struct list *list)
{
	struct le *le;
	int err;

	if (!list)
		return 0;

	err = re_hprintf(pf, " (%u)\n", list_count(list));

	for (le = list->head; le && !err; le = le->next) {

		const struct candpair *cp = le->data;

		err = re_hprintf(pf, "  %H\n", icem_candpair_debug, cp);
	}

	return err;
}
