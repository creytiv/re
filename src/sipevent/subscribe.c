/**
 * @file sub.c  SIP Event Subscribe
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_fmt.h>
#include <re_uri.h>
#include <re_sys.h>
#include <re_tmr.h>
#include <re_sip.h>
#include <re_sipevent.h>
#include "sipevent.h"


enum {
	DEFAULT_EXPIRES = 3600,
};


static int request(struct sipsub *sub, bool reset_ls);


static void internal_response_handler(int err, const struct sip_msg *msg,
				      void *arg)
{
	(void)err;
	(void)msg;
	(void)arg;
}


static bool internal_notify_handler(const struct sip_msg *msg, void *arg)
{
	(void)msg;
	(void)arg;

	return false;
}


static void destructor(void *arg)
{
	struct sipsub *sub = arg;

	tmr_cancel(&sub->tmr);

	if (!sub->terminated) {

		sub->resph = internal_response_handler;
		sub->noth  = internal_notify_handler;
		sub->terminated = true;

		if (sub->req) {
			mem_ref(sub);
			return;
		}

		if (sub->subscribed && !request(sub, true)) {
			mem_ref(sub);
			return;
		}
	}

	if (sub->routev) {

		uint32_t i;

		for (i=0; i<sub->routec; i++)
			mem_deref(sub->routev[i]);

		mem_deref(sub->routev);
	}

	hash_unlink(&sub->he);
	mem_deref(sub->dlg);
	mem_deref(sub->auth);
	mem_deref(sub->uri);
	mem_deref(sub->from_name);
	mem_deref(sub->from_uri);
	mem_deref(sub->event);
	mem_deref(sub->cuser);
	mem_deref(sub->hdrs);
	mem_deref(sub->sock);
	mem_deref(sub->sip);
}


static uint64_t failwait(uint32_t failc)
{
	return min(1800, (30 * (1<<min(failc, 6)))) * (500 + rand_u16() % 501);
}


static void tmr_handler(void *arg)
{
	struct sipsub *sub = arg;
	int err;

	if (sub->req)
		return;

	if (!sub->dlg) {

		err = sip_dialog_alloc(&sub->dlg, sub->uri, sub->uri,
				       sub->from_name, sub->from_uri,
				       (const char **)sub->routev,
				       sub->routec);
		if (err)
			goto out;

		hash_append(sub->sock->ht_sub,
			    hash_joaat_str(sip_dialog_callid(sub->dlg)),
			    &sub->he, sub);
	}

	err = request(sub, true);
	if (err)
		goto out;

 out:
	if (err) {
		tmr_start(&sub->tmr, failwait(++sub->failc), tmr_handler, sub);
		sub->resph(err, NULL, sub->arg);
	}
}


void sipevent_resubscribe(struct sipsub *sub, uint64_t wait)
{
	if (!wait)
		wait = failwait(++sub->failc);

	re_printf("will re-subscribe in %llu ms\n", wait);

	tmr_start(&sub->tmr, wait, tmr_handler, sub);
}


static void response_handler(int err, const struct sip_msg *msg, void *arg)
{
	const struct sip_hdr *minexp;
	struct sipsub *sub = arg;
	uint64_t wait;

	wait = failwait(sub->failc + 1);

	if (err || sip_request_loops(&sub->ls, msg->scode)) {

		if (err == ETIMEDOUT) {
			sub->subscribed = false;
			sub->dlg = mem_deref(sub->dlg);
			hash_unlink(&sub->he);
		}

		sub->failc++;
		goto out;
	}

	if (msg->scode < 200) {
		return;
	}
	else if (msg->scode < 300) {

		if (!sip_dialog_established(sub->dlg)) {

			err = sip_dialog_create(sub->dlg, msg);
			if (err) {
				sub->dlg = mem_deref(sub->dlg);
				hash_unlink(&sub->he);
				sub->failc++;
				goto out;
			}
		}
		else {
			(void)sip_dialog_update(sub->dlg, msg);
		}

		if (sub->refer && tmr_isrunning(&sub->tmr))
			wait = tmr_get_expire(&sub->tmr);
		else if (pl_isset(&msg->expires))
			wait = pl_u32(&msg->expires) * 900;
		else
			wait = sub->expires * 900;

		sub->subscribed = true;
		sub->refer = false;
		sub->failc = 0;
	}
	else {
		if (sub->terminated && !sub->subscribed)
			goto out;

		switch (msg->scode) {

		case 401:
		case 407:
			err = sip_auth_authenticate(sub->auth, msg);
			if (err) {
				err = (err == EAUTH) ? 0 : err;
				break;
			}

			err = request(sub, false);
			if (err)
				break;

			return;

		case 403:
			sip_auth_reset(sub->auth);
			break;

		case 408:
		case 481:
			sub->subscribed = false;
			sub->dlg = mem_deref(sub->dlg);
			hash_unlink(&sub->he);
			break;

		case 423:
			minexp = sip_msg_hdr(msg, SIP_HDR_MIN_EXPIRES);
			if (!minexp || !pl_u32(&minexp->val) || !sub->expires)
				break;

			sub->expires = pl_u32(&minexp->val);

			err = request(sub, false);
			if (err)
				break;

			return;
		}

		++sub->failc;
	}

 out:
	if (!sub->expires) {
		mem_deref(sub);
	}
	else if (sub->terminated) {
		if (!sub->subscribed || request(sub, true))
			mem_deref(sub);
	}
	else {
		if (sub->retry || sub->subscribed) {
			re_printf("will re-subscribe in %llu ms...\n", wait);
			tmr_start(&sub->tmr, wait, tmr_handler, sub);
		}
		else {
			tmr_cancel(&sub->tmr);
		}

		sub->resph(err, msg, sub->arg);
	}
}


static int send_handler(enum sip_transp tp, const struct sa *src,
			const struct sa *dst, struct mbuf *mb, void *arg)
{
	struct sipsub *sub = arg;
	(void)dst;

	return mbuf_printf(mb, "Contact: <sip:%s@%J%s>\r\n",
                           sub->cuser, src, sip_transp_param(tp));
}


static int request(struct sipsub *sub, bool reset_ls)
{
	if (sub->terminated)
		sub->expires = 0;

	if (reset_ls)
		sip_loopstate_reset(&sub->ls);

	if (sub->refer) {

		return sip_drequestf(&sub->req, sub->sip, true, "REFER",
				     sub->dlg, 0, sub->auth,
				     send_handler, response_handler, sub,
				     "%s"
				     "Content-Length: 0\r\n"
				     "\r\n",
				     sub->hdrs);
	}
	else {
		return sip_drequestf(&sub->req, sub->sip, true, "SUBSCRIBE",
				     sub->dlg, 0, sub->auth,
				     send_handler, response_handler, sub,
				     "Event: %s\r\n"
				     "Expires: %u\r\n"
				     "%s"
				     "Content-Length: 0\r\n"
				     "\r\n",
				     sub->event,
				     sub->expires,
				     sub->hdrs);
	}
}


static int sipsub_alloc(struct sipsub **subp, struct sipevent_sock *sock,
			bool refer, bool retry, const char *uri,
			const char *from_name, const char *from_uri,
			const char *event, uint32_t expires, const char *cuser,
			const char *routev[], uint32_t routec,
			sip_auth_h *authh, void *aarg, bool aref,
			sip_resp_h *resph, sip_msg_h *noth, void *arg,
			const char *fmt, va_list ap)
{
	struct sipsub *sub;
	int err;

	if (!subp || !sock || !uri || !from_uri || !event || !expires ||!cuser)
		return EINVAL;

	sub = mem_zalloc(sizeof(*sub), destructor);
	if (!sub)
		return ENOMEM;

	err = sip_dialog_alloc(&sub->dlg, uri, uri, from_name, from_uri,
			       routev, routec);
	if (err)
		goto out;

	hash_append(sock->ht_sub,
		    hash_joaat_str(sip_dialog_callid(sub->dlg)),
		    &sub->he, sub);

	err = sip_auth_alloc(&sub->auth, authh, aarg, aref);
	if (err)
		goto out;

	err = str_dup(&sub->uri, uri);
	if (err)
		goto out;

	err = str_dup(&sub->from_uri, from_uri);
	if (err)
		goto out;

	if (from_name) {

		err = str_dup(&sub->from_name, from_name);
		if (err)
			goto out;
	}

	sub->routec = routec;

	if (routec > 0) {

		uint32_t i;

		sub->routev = mem_zalloc(sizeof(*sub->routev) * routec, NULL);
		if (!sub->routev) {
			err = ENOMEM;
			goto out;
		}

		for (i=0; i<routec; i++) {

			err = str_dup(&sub->routev[i], routev[i]);
			if (err)
				goto out;
		}
	}

	err = str_dup(&sub->event, event);
	if (err)
		goto out;

	err = str_dup(&sub->cuser, cuser);
	if (err)
		goto out;

	/* Custom SIP headers */
	if (fmt) {
		err = re_vsdprintf(&sub->hdrs, fmt, ap);
		if (err)
			goto out;
	}

	sub->refer   = refer;
	sub->retry   = retry;
	sub->sock    = mem_ref(sock);
	sub->sip     = mem_ref(sock->sip);
	sub->expires = expires;
	sub->resph   = resph ? resph : internal_response_handler;
	sub->noth    = noth  ? noth  : internal_notify_handler;
	sub->arg     = arg;

	err = request(sub, true);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(sub);
	else
		*subp = sub;

	return err;
}


/**
 * Allocate a SIP subscriber client
 *
 * @param subp      Pointer to allocated SIP subscriber client
 * @param sock      SIP Event socket
 * @param retry     Re-subscribe if subscription terminates
 * @param uri       SIP Request URI
 * @param from_name SIP From-header Name (optional)
 * @param from_uri  SIP From-header URI
 * @param event     SIP Event to subscribe to
 * @param expires   Subscription expires value
 * @param cuser     Contact username
 * @param routev    Optional route vector
 * @param routec    Number of routes
 * @param authh     Authentication handler
 * @param aarg      Authentication handler argument
 * @param aref      True to ref argument
 * @param resph     SUBSCRIBE response handler
 * @param noth      Notify handler
 * @param arg       Response handler argument
 * @param fmt       Formatted strings with extra SIP Headers
 *
 * @return 0 if success, otherwise errorcode
 */
int sipevent_subscribe(struct sipsub **subp, struct sipevent_sock *sock,
		       bool retry, const char *uri, const char *from_name,
		       const char *from_uri, const char *event,
		       uint32_t expires, const char *cuser,
		       const char *routev[], uint32_t routec,
		       sip_auth_h *authh, void *aarg, bool aref,
		       sip_resp_h *resph, sip_msg_h *noth, void *arg,
		       const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = sipsub_alloc(subp, sock, false, retry, uri, from_name, from_uri,
			   event, expires, cuser, routev, routec, authh, aarg,
			   aref, resph, noth, arg, fmt, ap);
	va_end(ap);

	return err;
}


/**
 * Allocate a SIP refer client
 *
 * @param subp      Pointer to allocated SIP subscriber client
 * @param sock      SIP Event socket
 * @param uri       SIP Request URI
 * @param from_name SIP From-header Name (optional)
 * @param from_uri  SIP From-header URI
 * @param cuser     Contact username
 * @param routev    Optional route vector
 * @param routec    Number of routes
 * @param authh     Authentication handler
 * @param aarg      Authentication handler argument
 * @param aref      True to ref argument
 * @param resph     SUBSCRIBE response handler
 * @param noth      Notify handler
 * @param arg       Response handler argument
 * @param fmt       Formatted strings with extra SIP Headers
 *
 * @return 0 if success, otherwise errorcode
 */
int sipevent_refer(struct sipsub **subp, struct sipevent_sock *sock,
		   const char *uri, const char *from_name,
		   const char *from_uri, const char *cuser,
		   const char *routev[], uint32_t routec,
		   sip_auth_h *authh, void *aarg, bool aref,
		   sip_resp_h *resph, sip_msg_h *noth, void *arg,
		   const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = sipsub_alloc(subp, sock, true, false, uri, from_name, from_uri,
			   "refer", DEFAULT_EXPIRES, cuser, routev, routec,
			   authh, aarg, aref, resph, noth, arg, fmt, ap);
	va_end(ap);

	return err;
}
