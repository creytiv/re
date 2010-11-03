/**
 * @file connchk.c  ICE Connectivity Checks
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


#define DEBUG_MODULE "connchk"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void pace_next(struct icem *icem);


/** Constructing a Valid Pair */
static void construct_valid_pair(struct icem *icem, struct candpair *cp,
				 const struct sa *mapped,
				 const struct sa *dest)
{
	struct cand *lcand, *rcand;
	struct candpair *cp2;
	int err;

	lcand = icem_cand_find(&icem->lcandl, cp->lcand->compid, mapped);
	rcand = icem_cand_find(&icem->rcandl, cp->lcand->compid, dest);
	if (!lcand) {
		DEBUG_WARNING("no such local candidate: %J\n", mapped);
		return;
	}
	if (!rcand) {
		DEBUG_WARNING("no such remote candidate: %J\n", dest);
		return;
	}

	/* New candidate? */
	if (lcand != cp->lcand || rcand != cp->rcand) {

		/* note:  could be optimized */
		cp->state = CANDPAIR_FAILED;

		if (icem_candpair_find(&icem->validl, lcand, rcand))
			return;

		err = icem_candpair_alloc(&cp2, icem, lcand, rcand);
		if (err)
			return;

		cp2->valid = true;
		cp2->rtt = (int)(tmr_jiffies() - cp->tick_sent);
		cp2->state = CANDPAIR_SUCCEEDED;

		/* Add to VALID LIST */
		icem_candpair_move(cp2, &icem->validl);
	}
	else {
		/* Add to VALID LIST, the pair that generated the check */
		cp->valid = true;
		cp->rtt = (int)(tmr_jiffies() - cp->tick_sent);
		cp->state = CANDPAIR_SUCCEEDED;
		icem_candpair_move(cp, &icem->validl);
	}
}


static void handle_success(struct icem *icem, struct candpair *cp,
			   const struct sa *addr)
{
	if (!icem_cand_find(&icem->lcandl, cp->lcand->compid, addr)) {

		int err;

		DEBUG_NOTICE("adding PRFLX Candidate: %J\n", addr);

		err = icem_lcand_add(icem, cp->lcand->base,
				     CAND_TYPE_PRFLX, addr);
		if (err) {
			DEBUG_WARNING("failed to add PRFLX: %s\n",
				      strerror(err));
		}
	}

	construct_valid_pair(icem, cp, addr, &cp->rcand->addr);

	if (icem->ice->lrole == ROLE_CONTROLLING && cp->use_cand)
		cp->nominated = true;
}


static void stunc_resp_handler(int err, uint16_t scode, const char *reason,
			       const struct stun_msg *msg, void *arg)
{
	struct candpair *cp = arg;
	struct icem *icem = cp->icem;
	struct stun_attr *attr;

	(void)reason;

#if ICE_TRACE
	DEBUG_NOTICE("{id=%u} rx %H <--- %H '%u %s' (%s)\n", cp->lcand->compid,
		     icem_cand_print, cp->lcand, icem_cand_print, cp->rcand,
		     scode, reason, err ? strerror(err) : "");
#endif

	if (err) {
		cp->state = CANDPAIR_FAILED;
		goto out;
	}

	switch (scode) {

	case 0: /* Success case */
		attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
		if (!attr) {
			cp->state = CANDPAIR_FAILED;
			break;
		}

		handle_success(icem, cp, &attr->v.sa);
		break;

	case 487: /* Role Conflict */
		ice_switch_local_role(icem->ice);
		cp->state = CANDPAIR_WAITING;
		icem_triggq_push(icem, cp);
		break;

	default:
		cp->state = CANDPAIR_FAILED;
		break;
	}

 out:
	pace_next(icem);
}


static int send_req(struct candpair *cp)
{
	struct cand *lcand = cp->lcand;
	struct icem *icem = cp->icem;
	struct ice *ice = icem->ice;
	struct icem_comp *comp;
	char username_buf[64];
	size_t presz = 0;
	int use_cand = 0;
	uint32_t prio_prflx;
	uint16_t ctrl_attr;
	int err = 0;

	comp = icem_comp_find(icem, lcand->compid);
	if (!comp)
		return ENOENT;

#if ICE_TRACE
	DEBUG_NOTICE("{id=%u} tx %H ---> %H (%s) %s\n", lcand->compid,
		     icem_cand_print, cp->lcand, icem_cand_print, cp->rcand,
		     ice_candpair_state2name(cp->state),
		     cp->use_cand ? "[USE]" : "");
#endif

	(void)re_snprintf(username_buf, sizeof(username_buf),
			  "%s:%s", icem->rufrag, ice->lufrag);

	/* PRIORITY and USE-CANDIDATE */
	prio_prflx = ice_calc_prio(CAND_TYPE_PRFLX, 0, lcand->compid);

	switch (ice->lrole) {

	case ROLE_CONTROLLING:
		ctrl_attr = STUN_ATTR_CONTROLLING;

		if (cp->use_cand)
			use_cand = 1;
		break;

	case ROLE_CONTROLLED:
		ctrl_attr = STUN_ATTR_CONTROLLED;
		break;

	default:
		return EINVAL;
	}

	/* A connectivity check MUST utilize the STUN short term credential
	   mechanism. */

	/* The password is equal to the password provided by the peer */
	if (!icem->rpwd) {
		DEBUG_WARNING("no remote password!\n");
	}

	cp->tick_sent = tmr_jiffies();

	switch (lcand->type) {

	case CAND_TYPE_RELAY:
		/* Creating Permissions for Relayed Candidates */
		err = turnc_add_chan(comp->turnc, &cp->rcand->addr,
				     NULL, NULL);
		if (err) {
			DEBUG_WARNING("add channel: %s\n", strerror(err));
			break;
		}
		presz = 4;
		/*@fallthrough@*/

	case CAND_TYPE_HOST:
	case CAND_TYPE_SRFLX:
		cp->ct_conn = mem_deref(cp->ct_conn);
		err = stun_request(&cp->ct_conn, icem->stun, icem->proto,
				   comp->sock, &cp->rcand->addr, presz,
				   STUN_METHOD_BINDING,
				   (uint8_t *)icem->rpwd, str_len(icem->rpwd),
				   true, stunc_resp_handler, cp,
				   4,
				   STUN_ATTR_USERNAME, username_buf,
				   STUN_ATTR_PRIORITY, &prio_prflx,
				   ctrl_attr, &ice->tiebrk,
				   STUN_ATTR_USE_CAND, use_cand);
		break;

	case CAND_TYPE_PRFLX:
		DEBUG_WARNING("cannot send conncheck from Peer Reflexive\n");
		err = EINVAL;
		break;
	}

	return err;
}


static void do_check(struct candpair *cp)
{
	int err;

	err = send_req(cp);
	if (err) {
		cp->state = CANDPAIR_FAILED;
		return;
	}

	cp->state = CANDPAIR_INPROGRESS;
}


/**
 * 5.8.  Scheduling Checks
 */
void icem_conncheck_schedule_check(struct icem *icem)
{
	struct candpair *cp;

	/* search in triggered check queue first */
	cp = icem_triggq_pop(icem);
	if (cp) {
		do_check(cp);
		return;
	}

	/* Find the highest priority pair in that check list that is in the
	   Waiting state. */
	cp = icem_candpair_find_st(&icem->checkl, 0, CANDPAIR_WAITING);
	if (cp) {
		do_check(cp);
		return;
	}

	/* If there is no such pair: */

	/* Find the highest priority pair in that check list that is in
	   the Frozen state. */
	cp = icem_candpair_find_st(&icem->checkl, 0, CANDPAIR_FROZEN);
	if (cp) { /* If there is such a pair: */

		/* Unfreeze the pair.
		   Perform a check for that pair, causing its state to
		   transition to In-Progress. */
		do_check(cp);
		return;
	}

	/* If there is no such pair: */

	/* Terminate the timer for that check list. */

	icem->state = CHECKLIST_COMPLETED;
}


static void timeout(void *arg)
{
	struct icem *icem = arg;

	if (icem->state == CHECKLIST_RUNNING) {
		tmr_start(&icem->tmr_pace, 100, timeout, icem);
	}

	pace_next(icem);
}


static void pace_next(struct icem *icem)
{
	icem_conncheck_schedule_check(icem);

	icem_checklist_update(icem);
}


/**
 * Scheduling Checks
 */
int icem_conncheck_start(struct icem *icem)
{
	int err;

	if (!icem)
		return EINVAL;

	if (ICE_MODE_FULL != icem->ice->lmode) {
		DEBUG_WARNING("connchk: invalid mode %s\n",
			      ice_mode2name(icem->ice->lmode));
		return EINVAL;
	}

	err = icem_checklist_form(icem);
	if (err)
		return err;

	icem->state = CHECKLIST_RUNNING;

	tmr_start(&icem->tmr_pace, 1, timeout, icem);

	return 0;
}
