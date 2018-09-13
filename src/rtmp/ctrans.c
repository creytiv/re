/**
 * @file rtmp/ctrans.c  Real Time Messaging Protocol -- AMF Client Transactions
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_tcp.h>
#include <re_sys.h>
#include <re_odict.h>
#include <re_rtmp.h>
#include "rtmp.h"


#define DEBUG_MODULE "rtmp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void ctrans_destructor(void *data)
{
	struct rtmp_ctrans *ct = data;

	list_unlink(&ct->le);
	mem_deref(ct->command);
}


int rtmp_ctrans_send(struct rtmp_conn *conn, uint32_t stream_id,
		     const char *command, rtmp_resp_h *resph, void *arg,
		     unsigned body_propc, ...)
{
	struct rtmp_ctrans *ct = NULL;
	struct mbuf *mb = mbuf_alloc(512);
	va_list ap;
	uint64_t tid;
	int err;

	if (!conn || !command)
		return EINVAL;
	if (!mb)
		return ENOMEM;

	if (resph) {
		tid = ++conn->tid_counter;

		ct = mem_zalloc(sizeof(*ct), ctrans_destructor);
		if (!ct)
			return ENOMEM;

		ct->tid   = tid;
		ct->resph = resph;
		ct->arg   = arg;

		err = str_dup(&ct->command, command);
		if (err)
			goto out;

		list_append(&conn->ctransl, &ct->le, ct);
	}
	else {
		tid = 0;  /* no response expected */
	}

	err = rtmp_command_header_encode(mb, command, tid);
	if (err)
		goto out;

	if (body_propc) {
		va_start(ap, body_propc);
		err = rtmp_amf_vencode_object(mb, AMF_TYPE_ROOT,
					      body_propc, &ap);
		va_end(ap);
		if (err)
			goto out;
	}

	err = rtmp_send_amf_command(conn, 0, RTMP_CONN_CHUNK_ID,
				    stream_id, mb->buf, mb->end);
	if (err)
		goto out;

#if 1
	DEBUG_NOTICE("### new ctrans (command=\"%s\", tid=%llu)"
		  " stream_id=%u, propc=%u\n",
		  command, tid, stream_id, body_propc);
#endif

 out:
	mem_deref(mb);
	if (err)
		mem_deref(ct);

	return err;
}


struct rtmp_ctrans *rtmp_ctrans_find(const struct list *ctransl, uint64_t tid)
{
	struct le *le;

	for (le = list_head(ctransl); le; le = le->next) {
		struct rtmp_ctrans *ct = le->data;

		if (tid == ct->tid)
			return ct;
	}

	return NULL;
}


int rtmp_ctrans_response(const struct list *ctransl, bool success,
			 const struct rtmp_amf_message *msg)
{
	struct rtmp_ctrans *ct;
	uint64_t tid;
	rtmp_resp_h *resph;
	void *arg;

	if (!ctransl || !msg)
		return EINVAL;

	tid = rtmp_amf_message_tid(msg);
	if (!tid) {
		re_printf("ctrans: transaction id is zero.\n");
		return EINVAL;
	}

	ct = rtmp_ctrans_find(ctransl, tid);
	if (!ct) {
		DEBUG_WARNING("ctrans: no matching transaction"
			      " for response '%s' (tid=%llu)\n",
			      msg->name, tid);
		return ENOENT;
	}

	if (success)
		++ct->replies;
	else
		++ct->errors;

	resph = ct->resph;
	arg = ct->arg;

	/* destroy transaction */
	ct = mem_deref(ct);

	if (resph) {
		resph(success ? 0 : ENOENT, msg, arg);
	}

	return 0;
}
