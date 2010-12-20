/**
 * @file accept.c  SIP Session Accept
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
#include <re_tmr.h>
#include <re_sip.h>
#include <re_sipsess.h>
#include "sipsess.h"


static void cancel_handler(void *arg)
{
	struct sipsess *sess = arg;

	(void)sip_treply(&sess->st, sess->sip, sess->msg,
			 487, "Request Terminated");

	sess->peerterm = true;

	if (sess->terminated)
		return;

	sipsess_terminate(sess, ECONNRESET, NULL);
}


int sipsess_accept(struct sipsess **sessp, struct sipsess_sock *sock,
		   const struct sip_msg *msg, uint16_t scode,
		   const char *reason, const char *cuser, const char *ctype,
		   struct mbuf *desc,
		   sip_auth_h *authh, void *aarg, bool aref,
		   sipsess_offer_h *offerh, sipsess_answer_h *answerh,
		   sipsess_estab_h *estabh, sipsess_info_h *infoh,
		   sipsess_refer_h *referh, sipsess_close_h *closeh,
		   void *arg, const char *fmt, ...)
{
	struct sipsess *sess;
	va_list ap;
	int err;

	if (!sessp || !sock || !msg || scode < 101 || scode > 299 ||
	    !cuser || !ctype)
		return EINVAL;

	err = sipsess_alloc(&sess, sock, cuser, ctype, NULL, authh, aarg, aref,
			    offerh, answerh, NULL, estabh, infoh, referh,
			    closeh, arg);
	if (err)
		return err;

	err = sip_dialog_accept(&sess->dlg, msg);
	if (err)
		goto out;

	hash_append(sock->ht_sess,
		    hash_joaat_str(sip_dialog_callid(sess->dlg)),
		    &sess->he, sess);

	sess->msg = mem_ref((void *)msg);

	err = sip_strans_alloc(&sess->st, sess->sip, msg, cancel_handler,
			       sess);
	if (err)
		goto out;

	va_start(ap, fmt);

	if (scode >= 200)
		err = sipsess_reply_2xx(sess, msg, scode, reason, desc,
					fmt, &ap);
	else
		err = sip_treplyf(&sess->st, NULL, sess->sip,
				  msg, true, scode, reason,
				  "Contact: <sip:%s@%J%s>\r\n"
				  "%v"
				  "%s%s%s"
				  "Content-Length: %u\r\n"
				  "\r\n"
				  "%b",
				  sess->cuser, &msg->dst,
				  sip_transp_param(msg->tp),
				  fmt, &ap,
				  desc ? "Content-Type: " : "",
				  desc ? sess->ctype : "",
				  desc ? "\r\n" : "",
				  desc ? mbuf_get_left(desc) : 0,
				  desc ? mbuf_buf(desc) : NULL,
				  desc ? mbuf_get_left(desc) : 0);

	va_end(ap);

	if (err)
		goto out;

 out:
	if (err)
		mem_deref(sess);
	else
		*sessp = sess;

	return err;
}


int sipsess_progress(struct sipsess *sess, uint16_t scode, const char *reason,
		     struct mbuf *desc, const char *fmt, ...)
{
	va_list ap;
	int err;

	if (!sess || !sess->st || !sess->msg || scode < 101 || scode > 199)
		return EINVAL;

	va_start(ap, fmt);

	err = sip_treplyf(&sess->st, NULL, sess->sip, sess->msg, true,
			  scode, reason,
			  "Contact: <sip:%s@%J%s>\r\n"
			  "%v"
			  "%s%s%s"
			  "Content-Length: %u\r\n"
			  "\r\n"
			  "%b",
			  sess->cuser, &sess->msg->dst,
			  sip_transp_param(sess->msg->tp),
			  fmt, &ap,
			  desc ? "Content-Type: " : "",
			  desc ? sess->ctype : "",
			  desc ? "\r\n" : "",
			  desc ? mbuf_get_left(desc) : 0,
			  desc ? mbuf_buf(desc) : NULL,
			  desc ? mbuf_get_left(desc) : 0);

	va_end(ap);

	return err;
}


int sipsess_answer(struct sipsess *sess, uint16_t scode, const char *reason,
		   struct mbuf *desc, const char *fmt, ...)
{
	va_list ap;
	int err;

	if (!sess || !sess->st || !sess->msg || scode < 200 || scode > 299)
		return EINVAL;

	va_start(ap, fmt);
	err = sipsess_reply_2xx(sess, sess->msg, scode, reason, desc,
				fmt, &ap);
	va_end(ap);

	return err;
}


int sipsess_reject(struct sipsess *sess, uint16_t scode, const char *reason,
		   const char *fmt, ...)
{
	va_list ap;
	int err;

	if (!sess || !sess->st || !sess->msg || scode < 300)
		return EINVAL;

	va_start(ap, fmt);
	err = sip_treplyf(&sess->st, NULL, sess->sip, sess->msg, false,
			  scode, reason, fmt ? "%v" : NULL, fmt, &ap);
	va_end(ap);

	return err;
}
