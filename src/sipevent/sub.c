/**
 * @file sub.c  SIP Subscription
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


enum {
	DEFAULT_EXPIRES = 3600,
};


/** Defines a SIP subscriber client */
struct sipsub {
	struct sip_loopstate ls;
	struct tmr tmr;
	struct sip *sip;
	struct sip_request *req;
	struct sip_dialog *dlg;
	struct sip_auth *auth;
	char *event;
	char *cuser;
	char *hdrs;
	sip_resp_h *resph;
	void *arg;
	uint32_t expires;
	uint32_t failc;
	bool subscribed;
	bool terminated;
};


static int request(struct sipsub *sub, bool reset_ls);


static void dummy_handler(int err, const struct sip_msg *msg, void *arg)
{
	(void)err;
	(void)msg;
	(void)arg;
}


static void destructor(void *arg)
{
	struct sipsub *sub = arg;

	tmr_cancel(&sub->tmr);

	if (!sub->terminated) {

		sub->resph = dummy_handler;
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

	mem_deref(sub->dlg);
	mem_deref(sub->auth);
	mem_deref(sub->event);
	mem_deref(sub->cuser);
	mem_deref(sub->sip);
	mem_deref(sub->hdrs);
}


static uint32_t failwait(uint32_t failc)
{
	return min(1800, (30 * (1<<min(failc, 6)))) * (500 + rand_u16() % 501);
}


static void tmr_handler(void *arg)
{
	struct sipsub *sub = arg;
	int err;

	err = request(sub, true);
	if (err) {
		tmr_start(&sub->tmr, failwait(++sub->failc), tmr_handler, sub);
		sub->resph(err, NULL, sub->arg);
	}
}


static void response_handler(int err, const struct sip_msg *msg, void *arg)
{
	const struct sip_hdr *minexp;
	struct sipsub *sub = arg;
	uint32_t wait;

	wait = failwait(sub->failc + 1);

	if (err || sip_request_loops(&sub->ls, msg->scode)) {
		sub->failc++;
		goto out;
	}

	if (msg->scode < 200) {
		return;
	}
	else if (msg->scode < 300) {

		sub->subscribed = true;
		sub->failc      = 0;

		if (pl_isset(&msg->expires))
			wait = pl_u32(&msg->expires);
		else
			wait = DEFAULT_EXPIRES;

		wait *= 900;
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
		tmr_start(&sub->tmr, wait, tmr_handler, sub);
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

	return sip_drequestf(&sub->req, sub->sip, true, "SUBSCRIBE", sub->dlg,
			     0, sub->auth, send_handler, response_handler, sub,
			     "Event: %s\r\n"
			     "Expires: %u\r\n"
			     "%s"
			     "Content-Length: 0\r\n"
			     "\r\n",
			     sub->event,
			     sub->expires,
			     sub->hdrs);
}


/**
 * Allocate a SIP subscriber client
 *
 * @param subp      Pointer to allocated SIP subscriber client
 * @param sip       SIP Stack instance
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
 * @param resph     Response handler
 * @param arg       Response handler argument
 * @param fmt       Formatted strings with extra SIP Headers
 *
 * @return 0 if success, otherwise errorcode
 */
int sipevent_subscribe(struct sipsub **subp, struct sip *sip, const char *uri,
		       const char *from_name, const char *from_uri,
		       const char *event, uint32_t expires, const char *cuser,
		       const char *routev[], uint32_t routec,
		       sip_auth_h *authh, void *aarg, bool aref,
		       sip_resp_h *resph, void *arg,
		       const char *fmt, ...)
{
	struct sipsub *sub;
	int err;

	if (!subp || !sip || !uri || !from_uri || !event || !expires || !cuser)
		return EINVAL;

	sub = mem_zalloc(sizeof(*sub), destructor);
	if (!sub)
		return ENOMEM;

	err = sip_dialog_alloc(&sub->dlg, uri, uri, from_name, from_uri,
			       routev, routec);
	if (err)
		goto out;

	err = sip_auth_alloc(&sub->auth, authh, aarg, aref);
	if (err)
		goto out;

	err = str_dup(&sub->event, event);
	if (err)
		goto out;

	err = str_dup(&sub->cuser, cuser);
	if (err)
		goto out;

	/* Custom SIP headers */
	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		err = re_vsdprintf(&sub->hdrs, fmt, ap);
		va_end(ap);

		if (err)
			goto out;
	}

	sub->sip     = mem_ref(sip);
	sub->expires = expires;
	sub->resph   = resph ? resph : dummy_handler;
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
