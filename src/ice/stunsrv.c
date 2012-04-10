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


static void triggered_check(struct icem *icem, struct cand *lcand,
			    struct cand *rcand)
{
	struct candpair *cp = NULL;
	int err;

	if (lcand && rcand)
		cp = icem_candpair_find(&icem->checkl, lcand, rcand);

	if (cp) {
		DEBUG_NOTICE("{%s.%u} triggered_check: found CANDPAIR on"
			     " checklist in state: %s [%H]\n",
			     icem->name, cp->comp->id,
			     ice_candpair_state2name(cp->state),
			     icem_candpair_debug, cp);

		switch (cp->state) {

#if 0
			/* TODO: I am not sure why we should cancel the
			 *       pending Connectivity check here. this
			 *       can lead to a deadlock situation where
			 *       both agents are stuck on sending
			 *       triggered checks on the same candidate pair
			 */
		case CANDPAIR_INPROGRESS:
			icem_candpair_cancel(cp);
			/*@fallthrough@*/
#endif

		case CANDPAIR_FAILED:
			icem_candpair_set_state(cp, CANDPAIR_WAITING);
			/*@fallthrough@*/

		case CANDPAIR_FROZEN:
		case CANDPAIR_WAITING:
			err = icem_conncheck_send(cp, false, true);
			if (err) {
				DEBUG_WARNING("triggered check failed\n");
			}
			break;

		case CANDPAIR_SUCCEEDED:
		default:
			break;
		}
	}
	else {
		err = icem_candpair_alloc(&cp, icem, lcand, rcand);
		if (err) {
			DEBUG_WARNING("failed to allocate candpair:"
				      " lcand=%p rcand=%p (%s)\n",
				      lcand, rcand, strerror(err));
			return;
		}

		icem_candpair_prio_order(&icem->checkl);

		icem_candpair_set_state(cp, CANDPAIR_WAITING);

		(void)icem_conncheck_send(cp, false, true);
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

	return NULL;
}


/**
 * Find the highest priority LCAND on the check-list of type HOST/RELAY
 */
static struct cand *lookup_lcand(struct icem *icem, uint8_t compid)
{
	struct le *le;

	for (le = icem->checkl.head; le; le = le->next) {
		struct candpair *cp = le->data;

		if (cp->lcand->compid != compid)
			continue;

		switch (cp->lcand->type) {

		case CAND_TYPE_HOST:
		case CAND_TYPE_RELAY:
			return cp->lcand;

		default:
			break;
		}
	}

	return NULL;
}


static void handle_stun(struct ice *ice, struct icem *icem,
			struct icem_comp *comp, const struct sa *src,
			uint32_t prio, bool use_cand, bool tunnel)
{
	struct cand *lcand = NULL, *rcand = NULL;
	struct candpair *cp = NULL;
	int err;

	if (icem->state != CHECKLIST_RUNNING) {
		DEBUG_WARNING("{%s.%u} src=%J Checklist is not running (%s)\n",
			      icem->name, comp->id, src,
			      ice_checkl_state2name(icem->state));
		return;
	}

	/* 7.2.1.3.  Learning Peer Reflexive Candidates */
	rcand = icem_cand_find(&icem->rcandl, comp->id, src);
	if (!rcand) {

		icecomp_printf(comp, "Adding PRFLX remote candidate: %J\n",
			       src);

		err = icem_rcand_add_prflx(&rcand, icem, comp->id, prio, src);
		if (err) {
			DEBUG_WARNING("icem_rcand_add_prflx: %s\n",
				      strerror(err));
			return;
		}
	}

	cp = lookup_candpair(icem, rcand);
	if (cp)
		lcand = cp->lcand;
	else {
		lcand = lookup_lcand(icem, comp->id);
	}

	if (!lcand) {
		DEBUG_WARNING("{%s.%u} no local candidate (checkl=%u)\n",
			      icem->name, comp->id,
			      list_count(&icem->checkl));
	}

	/* 7.2.1.4.  Triggered Checks */
	if (ICE_MODE_FULL == ice->lmode)
		triggered_check(icem, lcand, rcand);

	if (!cp) {
		cp = lookup_candpair(icem, rcand);

		if (!cp) {
			DEBUG_WARNING("{%s.%u} candidate pair not found:"
				      " source=%J\n",
				      icem->name, comp->id, src);
		}
	}

#if ICE_TRACE
	icecomp_printf(comp, "Rx Binding Request from %J via %s"
		       " (candpair=%s) %s\n",
		       src, tunnel ? "Tunnel" : "Socket",
		       cp ? ice_candpair_state2name(cp->state) : "n/a",
		       use_cand ? "[USE]" : "");
#else
	(void)tunnel;
#endif

	/* 7.2.1.5.  Updating the Nominated Flag */
	if (use_cand) {
		if (ice->lrole == ROLE_CONTROLLED) {
			if (cp && cp->state == CANDPAIR_SUCCEEDED) {
				DEBUG_NOTICE("{%s.%u} setting NOMINATED"
					     " flag on candpair [%H]\n",
					     icem->name, comp->id,
					     icem_candpair_debug, cp);
				cp->nominated = true;
			}
		}

		/* Cancel conncheck. Choose Selected Pair */
		if (cp) {
			icem_candpair_make_valid(cp);

			if (ice->conf.nom == ICE_NOMINATION_REGULAR) {
				icem_candpair_cancel(cp);
				icem_comp_set_selected(comp, cp);
			}
		}
	}
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
	if (err) {
		DEBUG_WARNING("could not parse USERNAME attribute (%s)\n",
			      attr->v.username);
		goto unauth;
	}
	if (pl_strcmp(&lu, ice->lufrag))
		goto unauth;
	if (str_isset(icem->rufrag) && pl_strcmp(&ru, icem->rufrag))
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

	handle_stun(ice, icem, comp, src, prio_prflx, use_cand, presz > 0);

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
