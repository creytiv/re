/**
 * @file rtmp/reply.c  Real Time Messaging Protocol (RTMP) -- Command Reply
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


int rtmp_server_reply(struct rtmp_conn *conn, const struct command_header *req,
		      unsigned body_propc, ...)
{
	struct mbuf *mb = mbuf_alloc(512);
	va_list ap;
	uint64_t tid;
	int err;

	if (!conn || !req)
		return EINVAL;
	if (!mb)
		return ENOMEM;

	tid = req->transaction_id;

	err = rtmp_command_header_encode(mb, "_result", tid);
	if (err)
		goto out;

	if (body_propc) {
		va_start(ap, body_propc);
		err = rtmp_amf_vencode_object(mb, CLASS_ROOT, body_propc, &ap);
		va_end(ap);
		if (err)
			goto out;
	}

	err = rtmp_send_amf_command(conn, 0, RTMP_CONN_CHUNK_ID,
				    RTMP_CONTROL_STREAM_ID, mb->buf, mb->end);

	if (err)
		goto out;

#if 1
	DEBUG_NOTICE("### amf reply (request=\"%s\" tid=%llu)"
		     " propc=%u\n",
		     req->name, tid, body_propc);
#endif

 out:
	mem_deref(mb);

	return err;
}