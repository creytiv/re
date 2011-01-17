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


#define DEBUG_MODULE "cndpair"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void candpair_destructor(void *data)
{
	struct candpair *cp = data;

	list_unlink(&cp->le);
	list_unlink(&cp->le_tq);

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
	struct icem_comp *comp;

	if (!icem || !lcand || !rcand)
		return EINVAL;

	comp = icem_comp_find(icem, lcand->compid);
	if (!comp)
		return ENOENT;

	cp = mem_zalloc(sizeof(*cp), candpair_destructor);
	if (!cp)
		return ENOMEM;

	list_append(&icem->checkl, &cp->le, cp);

	cp->icem  = icem;
	cp->comp  = comp;
	cp->lcand = mem_ref(lcand);
	cp->rcand = mem_ref(rcand);
	cp->state = CANDPAIR_FROZEN;
	cp->rtt   = -1;
	cp->def   = comp->def_lcand == lcand && comp->def_rcand == rcand;

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

	icem_conncheck_continue(cp->icem);
}


void icem_candpair_make_valid(struct candpair *cp)
{
	if (!cp)
		return;

	cp->err = 0;
	cp->scode = 0;
	cp->valid = true;

	if (cp->tick_sent)
		cp->rtt = (int)(tmr_jiffies() - cp->tick_sent);

	icem_candpair_set_state(cp, CANDPAIR_SUCCEEDED);
	icem_candpair_move(cp, &cp->icem->validl);
}


void icem_candpair_failed(struct candpair *cp, int err, uint16_t scode)
{
	if (!cp)
		return;

	cp->err = err;
	cp->scode = scode;

	icem_candpair_set_state(cp, CANDPAIR_FAILED);
}


void icem_candpair_set_state(struct candpair *cp, enum candpair_state state)
{
	if (!cp)
		return;

	if (cp->state != state) {
		icecomp_printf(cp->comp, "FSM: %10s ===> %-10s\n",
			       ice_candpair_state2name(cp->state),
			       ice_candpair_state2name(state));
	}

	cp->state = state;
}


/**
 * Delete all Candidate-Pairs where the Local candidate is of a given type
 */
void icem_candpairs_flush(struct list *lst, enum cand_type type, uint8_t id)
{
	struct le *le = list_head(lst);

	while (le) {

		struct candpair *cp = le->data;

		le = le->next;

		if (cp->lcand->compid != id)
			continue;

		if (cp->lcand->type != type)
			continue;

		/* also remove the local candidate */
		mem_deref(cp->lcand);

		mem_deref(cp);
	}
}


bool icem_candpair_iscompleted(const struct candpair *cp)
{
	if (!cp)
		return false;

	return cp->state == CANDPAIR_FAILED || cp->state == CANDPAIR_SUCCEEDED;
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


struct candpair *icem_candpair_find_compid(const struct list *lst,
					   uint8_t compid)
{
	struct le *le;

	for (le = list_head(lst); le; le = le->next) {

		struct candpair *cp = le->data;

		if (cp->lcand->compid != compid)
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

	err = re_hprintf(pf, "{%u} %10s {%c%c%c%c}  %28H <---> %28H",
			 cp->lcand->compid,
			 ice_candpair_state2name(cp->state),
			 cp->def ? 'D' : ' ',
			 cp->valid ? 'V' : ' ',
			 cp->nominated ? 'N' : ' ',
			 cp->use_cand ? 'U' : ' ',
			 icem_cand_print, cp->lcand,
			 icem_cand_print, cp->rcand);

	if (cp->rtt != -1)
		err |= re_hprintf(pf, " RTT=%dms", cp->rtt);

	if (cp->err)
		err |= re_hprintf(pf, " (%s)", strerror(cp->err));

	if (cp->scode)
		err |= re_hprintf(pf, " [%u]", cp->scode);

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
