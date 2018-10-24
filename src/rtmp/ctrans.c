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


struct rtmp_ctrans {
	struct le le;
	uint64_t tid;
	rtmp_resp_h *resph;
	void *arg;
};


static void ctrans_destructor(void *data)
{
	struct rtmp_ctrans *ct = data;

	list_unlink(&ct->le);
}


static struct rtmp_ctrans *rtmp_ctrans_find(const struct list *ctransl,
					    uint64_t tid)
{
	struct le *le;

	for (le = list_head(ctransl); le; le = le->next) {
		struct rtmp_ctrans *ct = le->data;

		if (tid == ct->tid)
			return ct;
	}

	return NULL;
}


int rtmp_amf_request(struct rtmp_conn *conn, uint32_t stream_id,
		     const char *command,
		     rtmp_resp_h *resph, void *arg, unsigned body_propc, ...)
{
	struct rtmp_ctrans *ct = NULL;
	struct mbuf *mb;
	va_list ap;
	int err;

	if (!conn || !command || !resph)
		return EINVAL;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	ct = mem_zalloc(sizeof(*ct), ctrans_destructor);
	if (!ct) {
		err = ENOMEM;
		goto out;
	}

	ct->tid   = rtmp_conn_assign_tid(conn);
	ct->resph = resph;
	ct->arg   = arg;

	err = rtmp_command_header_encode(mb, command, ct->tid);
	if (err)
		goto out;

	if (body_propc) {
		va_start(ap, body_propc);
		err = rtmp_amf_vencode_object(mb, RTMP_AMF_TYPE_ROOT,
					      body_propc, &ap);
		va_end(ap);
		if (err)
			goto out;
	}

	err = rtmp_send_amf_command(conn, 0, RTMP_CHUNK_ID_CONN,
				    RTMP_TYPE_AMF0,
				    stream_id, mb->buf, mb->end);
	if (err)
		goto out;

	list_append(&conn->ctransl, &ct->le, ct);

 out:
	mem_deref(mb);
	if (err)
		mem_deref(ct);

	return err;
}


int rtmp_ctrans_response(const struct list *ctransl,
			 const struct odict *msg)
{
	struct rtmp_ctrans *ct;
	uint64_t tid;
	bool success;
	rtmp_resp_h *resph;
	void *arg;

	if (!ctransl || !msg)
		return EINVAL;

	success = (0 == str_casecmp(odict_string(msg, "0"), "_result"));

	if (!odict_get_number(msg, &tid, "1"))
		return EPROTO;

	ct = rtmp_ctrans_find(ctransl, tid);
	if (!ct)
		return ENOENT;

	resph = ct->resph;
	arg = ct->arg;

	mem_deref(ct);

	resph(success, msg, arg);

	return 0;
}
