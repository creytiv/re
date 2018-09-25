/**
 * @file rtmp/amf.c  Real Time Messaging Protocol (RTMP) -- AMF Commands
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


int rtmp_amf_command(struct rtmp_conn *conn, uint32_t stream_id,
		     const char *command, unsigned body_propc, ...)
{


	struct mbuf *mb;
	va_list ap;
	int err;

	if (!conn || !command)
		return EINVAL;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err  = rtmp_amf_encode_string(mb, command);
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

	err = rtmp_send_amf_command(conn, 0, RTMP_CONN_CHUNK_ID,
				    stream_id, mb->buf, mb->end);

	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;


}


int rtmp_amf_reply(struct rtmp_conn *conn, uint32_t stream_id, bool success,
		   const struct rtmp_amf_message *req,
		   unsigned body_propc, ...)
{
	struct mbuf *mb;
	va_list ap;
	uint64_t tid;
	int err;

	if (!conn || !req)
		return EINVAL;

	if (!rtmp_amf_message_get_number(req, &tid, 1))
		return EPROTO;
	if (tid == 0)
		return EPROTO;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = rtmp_command_header_encode(mb,
					 success ? "_result" : "_result", tid);
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

	err = rtmp_send_amf_command(conn, 0, RTMP_CONN_CHUNK_ID,
				    stream_id, mb->buf, mb->end);

	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}
