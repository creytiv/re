/**
 * @file listen.c  SIP Event Listen
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_fmt.h>
#include <re_uri.h>
#include <re_tmr.h>
#include <re_sip.h>
#include <re_sipevent.h>
#include "sipevent.h"


static void destructor(void *arg)
{
	struct sipevent_sock *sock = arg;

	mem_deref(sock->lsnr);
	hash_flush(sock->ht_not);
	hash_flush(sock->ht_sub);
	mem_deref(sock->ht_not);
	mem_deref(sock->ht_sub);
}


static bool not_cmp_handler(struct le *le, void *arg)
{
	const struct sip_msg *msg = arg;
	struct sipnot *not = le->data;

	return sip_dialog_cmp(not->dlg, msg);
}


static bool sub_cmp_handler(struct le *le, void *arg)
{
	const struct sip_msg *msg = arg;
	struct sipsub *sub = le->data;

	return sip_dialog_cmp(sub->dlg, msg);
}


static bool sub_cmp_half_handler(struct le *le, void *arg)
{
	const struct sip_msg *msg = arg;
	struct sipsub *sub = le->data;

	return sip_dialog_cmp_half(sub->dlg, msg);
}


static struct sipnot *sipnot_find(struct sipevent_sock *sock,
				   const struct sip_msg *msg)
{
	return list_ledata(hash_lookup(sock->ht_not,
				       hash_joaat_pl(&msg->callid),
				       not_cmp_handler, (void *)msg));
}


static struct sipsub *sipsub_find(struct sipevent_sock *sock,
				  const struct sip_msg *msg, bool full)
{
	return list_ledata(hash_lookup(sock->ht_sub,
				       hash_joaat_pl(&msg->callid), full ?
				       sub_cmp_handler : sub_cmp_half_handler,
				       (void *)msg));
}


static void notify_handler(struct sipevent_sock *sock,
			   const struct sip_msg *msg)
{
	struct sipevent_substate state;
	struct sipevent_event event;
	struct sip *sip = sock->sip;
	const struct sip_hdr *hdr;
	struct sipsub *sub;
	uint32_t nrefs;
	bool indialog;

	hdr = sip_msg_hdr(msg, SIP_HDR_EVENT);
	if (!hdr || sipevent_event_decode(&event, &hdr->val)) {
		(void)sip_reply(sip, msg, 400, "Bad Event Header");
		return;
	}

	hdr = sip_msg_hdr(msg, SIP_HDR_SUBSCRIPTION_STATE);
	if (!hdr || sipevent_substate_decode(&state, &hdr->val)) {
		(void)sip_reply(sip, msg, 400,"Bad Subscription-State Header");
		return;
	}

	sub = sipsub_find(sock, msg, true);
	if (!sub) {

		/* hack: while we are waiting for proper fork handling */

		sub = sipsub_find(sock, msg, false);
		if (!sub || sip_dialog_established(sub->dlg)) {
			(void)sip_reply(sip, msg,
					481, "Subscription Does Not Exist");
			return;
		}

		indialog = false;
	}
	else {
		if (!sip_dialog_rseq_valid(sub->dlg, msg)) {
			(void)sip_reply(sip, msg, 500, "Bad Sequence");
			return;
		}

		(void)sip_dialog_update(sub->dlg, msg);

		indialog = true;
	}

	if (pl_strcasecmp(&event.event, sub->event)) {
		(void)sip_reply(sip, msg, 489, "Bad Event");
		return;
	}

	/* hack: while we are waiting for proper fork handling */
	if (!indialog) {
		sub->notifyh(sip, msg, sub->arg);
		return;
	}

	re_printf("notify: %s (%r)\n", sipevent_substate_name(state.state),
		  &state.params);

	switch (state.state) {

	case SIPEVENT_ACTIVE:
	case SIPEVENT_PENDING:
		sub->subscribed = true;

		if (!sub->terminated && pl_isset(&state.expires))
			sipsub_reschedule(sub, pl_u32(&state.expires) * 900);
		break;

	case SIPEVENT_TERMINATED:
		sub->subscribed = false;
		break;
	}

	mem_ref(sub);
	sub->notifyh(sip, msg, sub->arg);
	nrefs = mem_nrefs(sub);
	mem_deref(sub);

	/* check if subscription was deref'd from notify handler */
	if (nrefs == 1)
		return;

	if (!sub->terminated && state.state == SIPEVENT_TERMINATED)
		sipsub_terminate(sub, 0, msg);
}


static void subscribe_handler(struct sipevent_sock *sock,
			      const struct sip_msg *msg)
{
	struct sip *sip = sock->sip;
	struct sipnot *not;

	not = sipnot_find(sock, msg);
	if (!not || not->terminated) {
		(void)sip_reply(sip, msg, 481, "Subscription Does Not Exist");
		return;
	}

	if (!sip_dialog_rseq_valid(not->dlg, msg)) {
		(void)sip_reply(sip, msg, 500, "Bad Sequence");
		return;
	}

	(void)sip_dialog_update(not->dlg, msg);

	/* todo: implement notifier */
}


static bool request_handler(const struct sip_msg *msg, void *arg)
{
	struct sipevent_sock *sock = arg;

	if (!pl_strcmp(&msg->met, "SUBSCRIBE")) {

		if (pl_isset(&msg->to.tag)) {
			subscribe_handler(sock, msg);
			return true;
		}

		return sock->subh ? sock->subh(msg, arg) : false;
	}
	else if (!pl_strcmp(&msg->met, "NOTIFY")) {

		notify_handler(sock, msg);
		return true;
	}
	else {
		return false;
	}
}


int sipevent_listen(struct sipevent_sock **sockp, struct sip *sip,
		    uint32_t htsize_not, uint32_t htsize_sub,
		    sip_msg_h *subh, void *arg)
{
	struct sipevent_sock *sock;
	int err;

	if (!sockp || !sip || !htsize_not || !htsize_sub)
		return EINVAL;

	sock = mem_zalloc(sizeof(*sock), destructor);
	if (!sock)
		return ENOMEM;

	err = sip_listen(&sock->lsnr, sip, true, request_handler, sock);
	if (err)
		goto out;

	err = hash_alloc(&sock->ht_not, htsize_not);
	if (err)
		goto out;

	err = hash_alloc(&sock->ht_sub, htsize_sub);
	if (err)
		goto out;

	sock->sip  = sip;
	sock->subh = subh;
	sock->arg  = arg;

 out:
	if (err)
		mem_deref(sock);
	else
		*sockp = sock;

	return err;
}
