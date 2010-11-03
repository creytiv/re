/**
 * @file stunsrv.c  Basic STUN Server for Connectivity checks
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
#include <re_sys.h>
#include "ice.h"


#define DEBUG_MODULE "stunsrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static const char *sw = "ice stunsrv v" VERSION " (" ARCH "/" OS ")";


/** Learning Peer Reflexive Candidates */
static int learn_peer_reflexive(struct icem_comp *comp, const struct sa *src,
				uint32_t prio)
{
	struct icem *icem = comp->icem;
	char foundation[8];
	struct pl fnd;

	/*
	  If the source transport address of the request does not match any
	  existing remote candidates, it represents a new peer reflexive remote
	  candidate.  This candidate is constructed as follows:
	*/
	if (icem_cand_find(&icem->rcandl, comp->id, src))
		return 0;

	DEBUG_NOTICE("**** Adding Peer-Reflexive candidate: %J\n", src);

	/*
	  The foundation of the candidate is set to an arbitrary value,
	  different from the foundation for all other remote candidates.  If
	  any subsequent offer/answer exchanges contain this peer reflexive
	  candidate in the SDP, it will signal the actual foundation for the
	  candidate.
	 */
	rand_str(foundation, sizeof(foundation));
	pl_set_str(&fnd, foundation);

	return icem_rcand_add(icem, CAND_TYPE_PRFLX, comp->id, prio,
			      src, NULL, &fnd);
}


static void triggered_check(struct icem *icem, struct cand *lcand,
			    struct cand *rcand)
{
	struct candpair *cp;

	if (!lcand || !rcand)
		return;

	cp = icem_candpair_find(&icem->checkl, lcand, rcand);
	if (cp) {

		switch (cp->state) {

		case CANDPAIR_INPROGRESS:
			icem_candpair_cancel(cp);
			/*@fallthrough@*/

		case CANDPAIR_FAILED:
			cp->state = CANDPAIR_WAITING;
			/*@fallthrough@*/

		case CANDPAIR_FROZEN:
		case CANDPAIR_WAITING:
			icem_triggq_push(icem, cp);
			break;

		case CANDPAIR_SUCCEEDED:
			break;
		}
	}
}


static struct candpair *lookup_candpair(struct icem *icem,
					const struct cand *rcand)
{
	struct candpair *cp;

	cp = icem_candpair_find(&icem->checkl, NULL, rcand);
	if (cp)
		return cp;

	cp = icem_candpair_find(&icem->validl, NULL, rcand);
	if (cp)
		return cp;

	cp = icem_candpair_find(&icem->triggl, NULL, rcand);
	if (cp)
		return cp;

	return NULL;
}


static void handle_stun(struct ice *ice, struct icem *icem,
			struct icem_comp *comp, const struct sa *src,
			uint32_t prio, bool use_cand)
{
	struct cand *lcand = NULL;
	struct cand *rcand = NULL;
	struct candpair *cp = NULL;
	int err;

	rcand = icem_cand_find(&icem->rcandl, comp->id, src);
	if (rcand) {
		cp = lookup_candpair(icem, rcand);
		if (cp)
			lcand = cp->lcand;
	}
	if (!cp) {
		DEBUG_NOTICE("candidate pair not found: remote=%J\n", src);
		/* This can happen for Peer-Reflexive candidates */
	}

#if ICE_TRACE
	DEBUG_NOTICE("{id=%u} Binding Request from %J (candpair=%s)\n",
		     comp->id, src,
		     cp ? ice_candpair_state2name(cp->state) : "n/a");
#endif

	if (use_cand) {
		if (ice->lrole == ROLE_CONTROLLED) {
			if (cp && cp->state == CANDPAIR_SUCCEEDED) {
				DEBUG_NOTICE("setting NOMINATED flag\n");
				cp->nominated = true;
			}
		}

		/* Cancel conncheck. Choose Selected Pair */
		if (cp) {
			icem_candpair_cancel(cp);
			icem_comp_set_selected(comp, cp);
		}
	}

	/* Send TRIGGERED CHECK to peer if mode=full */
	if (ICE_MODE_FULL == ice->lmode)
		triggered_check(icem, lcand, rcand);

	err = learn_peer_reflexive(comp, src, prio);

	/* 7.2.1.5.  Updating the Nominated Flag */
}


int icem_stund_recv(struct icem_comp *comp, const struct sa *src,
		    struct stun_msg *req, size_t presz)
{
	struct icem *icem = comp->icem;
	struct ice *ice = icem->ice;
	struct stun_attr *attr;
	struct pl lu, ru;
	enum role rrole = ROLE_UNKNOWN;
	uint64_t tiebrk = 0;
	uint32_t prio_prflx;
	bool use_cand = false;
	int err;

	/* RFC 5389: Fingerprint errors are silently discarded */
	err = stun_msg_chk_fingerprint(req);
	if (err)
		return err;

	err = stun_msg_chk_mi(req, (uint8_t *)ice->lpwd, strlen(ice->lpwd));
	if (err) {
		if (err == EBADMSG)
			goto unauth;
		else
			goto badmsg;
	}

	attr = stun_msg_attr(req, STUN_ATTR_USERNAME);
	if (!attr)
		goto badmsg;

	err = re_regex(attr->v.username, strlen(attr->v.username),
		       "[^:]+:[^]+", &lu, &ru);
	if (err || pl_strcmp(&lu, ice->lufrag) || pl_strcmp(&ru, icem->rufrag))
		goto unauth;

	attr = stun_msg_attr(req, STUN_ATTR_CONTROLLED);
	if (attr) {
		rrole = ROLE_CONTROLLED;
		tiebrk = attr->v.uint64;
	}

	attr = stun_msg_attr(req, STUN_ATTR_CONTROLLING);
	if (attr) {
		rrole = ROLE_CONTROLLING;
		tiebrk = attr->v.uint64;
	}

	if (rrole == ice->lrole) {
		if (ice->tiebrk >= tiebrk)
			ice_switch_local_role(ice);
		else
			goto conflict;
	}

	attr = stun_msg_attr(req, STUN_ATTR_PRIORITY);
	if (attr)
		prio_prflx = attr->v.uint32;
	else
		goto badmsg;

	attr = stun_msg_attr(req, STUN_ATTR_USE_CAND);
	if (attr)
		use_cand = true;

	handle_stun(ice, icem, comp, src, prio_prflx, use_cand);

	return stun_reply(icem->proto, comp->sock, src, presz, req,
			  (uint8_t *)ice->lpwd, strlen(ice->lpwd), true, 2,
			  STUN_ATTR_XOR_MAPPED_ADDR, src,
			  STUN_ATTR_SOFTWARE, sw);

 badmsg:
	return stun_ereply(icem->proto, comp->sock, src, presz, req,
			   400, "Bad Request",
			   (uint8_t *)ice->lpwd, strlen(ice->lpwd), true, 1,
			   STUN_ATTR_SOFTWARE, sw);

 unauth:
	return stun_ereply(icem->proto, comp->sock, src, presz, req,
			   401, "Unauthorized",
			   (uint8_t *)ice->lpwd, strlen(ice->lpwd), true, 1,
			   STUN_ATTR_SOFTWARE, sw);

 conflict:
	return stun_ereply(icem->proto, comp->sock, src, presz, req,
			   487, "Role Conflict",
			   (uint8_t *)ice->lpwd, strlen(ice->lpwd), true, 1,
			   STUN_ATTR_SOFTWARE, sw);
}
