/**
 * @file icem.c  ICE Media stream
 *
 * Copyright (C) 2010 Creytiv.com
 */
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


#define DEBUG_MODULE "icem"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void icem_destructor(void *data)
{
	struct icem *icem = data;

	list_unlink(&icem->le);
	tmr_cancel(&icem->tmr_pace);

	list_flush(&icem->compl);
	list_flush(&icem->validl);
	list_flush(&icem->checkl);
	list_flush(&icem->lcandl);
	list_flush(&icem->rcandl);

	mem_deref(icem->stun);
	mem_deref(icem->rufrag);
	mem_deref(icem->rpwd);
}


int icem_alloc(struct icem **icemp, struct ice *ice, int proto, int layer,
	       ice_gather_h *gh, ice_connchk_h *chkh, void *arg)
{
	struct icem *icem;
	int err = 0;

	if (!ice)
		return EINVAL;

	if (proto != IPPROTO_UDP)
		return EPROTONOSUPPORT;

	icem = mem_zalloc(sizeof(*icem), icem_destructor);
	if (!icem)
		return ENOMEM;

	tmr_init(&icem->tmr_pace);
	list_init(&icem->lcandl);
	list_init(&icem->rcandl);
	list_init(&icem->checkl);
	list_init(&icem->validl);

	icem->ice   = ice;
	icem->layer = layer;
	icem->proto = proto;
	icem->state = CHECKLIST_NULL;
	icem->nstun = 0;
	icem->gh    = gh;
	icem->chkh  = chkh;
	icem->arg   = arg;

	if (ICE_MODE_FULL == ice->lmode) {

		err = stun_alloc(&icem->stun, NULL, NULL, NULL);
		if (err)
			goto out;

		/* Update STUN Transport */
		stun_conf(icem->stun)->rto = ice->conf.rto;
		stun_conf(icem->stun)->rc = ice->conf.rc;
	}

	if (err)
		goto out;

	list_append(&ice->ml, &icem->le, icem);

 out:
	if (err)
		mem_deref(icem);
	else if (icemp)
		*icemp = icem;

	return err;
}


void icem_set_name(struct icem *icem, const char *name)
{
	if (!icem)
		return;

	str_ncpy(icem->name, name, sizeof(icem->name));
}


int icem_comp_add(struct icem *icem, uint8_t compid, void *sock)
{
	struct icem_comp *comp;
	int err;

	if (!icem)
		return EINVAL;

	if (icem_comp_find(icem, compid))
		return EALREADY;

	err = icem_comp_alloc(&comp, icem, compid, sock);
	if (err)
		return err;

	list_append(&icem->compl, &comp->le, comp);

	return 0;
}


int icem_cand_add(struct icem *icem, uint8_t compid, uint16_t lprio,
		  const char *ifname, const struct sa *addr)
{
	if (!icem_comp_find(icem, compid))
		return ENOENT;

	return icem_lcand_add_base(icem, compid, lprio, ifname,
				   ICE_TRANSP_UDP, addr);
}


static void *unique_handler(struct le *le1, struct le *le2)
{
	struct cand *c1 = le1->data, *c2 = le2->data;

	if (c1->base != c2->base || !sa_cmp(&c1->addr, &c2->addr, SA_ALL))
		return NULL;

	/* remove candidate with lower priority */
	return c1->prio < c2->prio ? c1 : c2;
}


/** Eliminating Redundant Candidates */
void icem_cand_redund_elim(struct icem *icem)
{
	uint32_t n = ice_list_unique(&icem->lcandl, unique_handler);
	if (n > 0) {
		DEBUG_NOTICE("redundant candidates eliminated: %u\n", n);
	}
}


const struct sa *icem_cand_default(struct icem *icem, uint8_t compid)
{
	const struct icem_comp *comp = icem_comp_find(icem, compid);
	if (!comp || !comp->def_lcand)
		return NULL;

	return &comp->def_lcand->addr;
}


/**
 * Verifying ICE Support and set default remote candidate
 *
 * @param icem   ICE Media
 * @param compid Component ID
 * @param raddr  Address of default remote candidate
 *
 * @return True if ICE is supported, otherwise false
 */
bool icem_verify_support(struct icem *icem, uint8_t compid,
			 const struct sa *raddr)
{
	struct cand *rcand;
	bool match;

	if (!icem)
		return false;

	rcand = icem_cand_find(&icem->rcandl, compid, raddr);
	match = rcand != NULL;

	if (!match)
		icem->mismatch = true;

	if (rcand) {
		icem_comp_set_default_rcand(icem_comp_find(icem, compid),
					    rcand);
	}

	return match;
}


int icem_add_chan(struct icem *icem, uint8_t compid, const struct sa *raddr)
{
	struct icem_comp *comp;

	if (!icem)
		return EINVAL;

	comp = icem_comp_find(icem, compid);
	if (!comp)
		return ENOENT;

	if (comp->turnc)
		return turnc_add_chan(comp->turnc, raddr, NULL, NULL);

	return 0;
}


static void purge_relayed(struct icem *icem, struct icem_comp *comp)
{
	icecomp_printf(comp, "purge local RELAY candidates\n");

	/*
	 * Purge all Candidate-Pairs where the Local candidate
	 * is of type "Relay"
	 */
	icem_candpairs_flush(&icem->checkl, CAND_TYPE_RELAY, comp->id);
	icem_candpairs_flush(&icem->validl, CAND_TYPE_RELAY, comp->id);

	comp->turnc = mem_deref(comp->turnc);
}


void icem_update(struct icem *icem)
{
	struct le *le;

	if (!icem)
		return;

	for (le = icem->compl.head; le; le = le->next) {

		struct icem_comp *comp = le->data;

		/* remove TURN client if not used by local "Selected" */
		if (comp->cp_sel) {
			if (comp->cp_sel->lcand->type != CAND_TYPE_RELAY)
				purge_relayed(icem, comp);
		}
	}
}


bool icem_mismatch(const struct icem *icem)
{
	return icem ? icem->mismatch : true;
}


int icem_debug(struct re_printf *pf, const struct icem *icem)
{
	struct le *le;
	int err = 0;

	if (!icem)
		return 0;

	err |= re_hprintf(pf, "----- ICE Media <%s> -----\n", icem->name);

	err |= re_hprintf(pf, " Local Candidates: %H",
			  icem_cands_debug, &icem->lcandl);
	err |= re_hprintf(pf, " Remote Candidates: %H",
			  icem_cands_debug, &icem->rcandl);
	err |= re_hprintf(pf, " Check list: [%s]%H",
			  ice_checkl_state2name(icem->state),
			  icem_candpairs_debug, &icem->checkl);
	err |= re_hprintf(pf, " Valid list: %H",
			  icem_candpairs_debug, &icem->validl);

	for (le = icem->compl.head; le; le = le->next) {

		const struct icem_comp *comp = le->data;

		if (comp->cp_sel) {
			err |= re_hprintf(pf, " Selected id=%u:  %H\n",
					  comp->id,
					  icem_candpair_debug, comp->cp_sel);
		}
	}

	err |= stun_debug(pf, icem->stun);

	return err;
}


struct list *icem_lcandl(const struct icem *icem)
{
	return icem ? (struct list *)&icem->lcandl : NULL;
}
