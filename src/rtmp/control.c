/**
 * @file rtmp/control.c  Real Time Messaging Protocol (RTMP) -- Control
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_rtmp.h>
#include "rtmp.h"


/* XXX: event_data type fits most event types */
int rtmp_control_send_user_control_msg(struct rtmp_conn *conn,
				       uint16_t event_type,
				       uint32_t event_data)
{
	struct mbuf *mb = mbuf_alloc(6);
	int err;

#if 0
	re_printf("send User Control Msg:  type=%u, data=%u\n",
		  event_type, event_data);
#endif

	if (!mb)
		return ENOMEM;

	(void)mbuf_write_u16(mb, htons(event_type));
	(void)mbuf_write_u32(mb, htonl(event_data));

	err = rtmp_conn_send_msg(conn, 0, RTMP_CHUNK_ID_CONTROL, 0, 0,
				 RTMP_TYPE_USER_CONTROL_MSG,
				 RTMP_CONTROL_STREAM_ID,
				 mb->buf, mb->end);

	mem_deref(mb);

	return err;
}


int rtmp_control_send_was(struct rtmp_conn *conn, uint32_t was)
{
	struct mbuf *mb = mbuf_alloc(4);
	int err;

	if (!mb)
		return ENOMEM;

	(void)mbuf_write_u32(mb, htonl(was));

	err = rtmp_conn_send_msg(conn, 0, RTMP_CHUNK_ID_CONTROL, 0, 0,
				 RTMP_TYPE_WINDOW_ACK_SIZE,
				 RTMP_CONTROL_STREAM_ID,
				 mb->buf, mb->end);

	mem_deref(mb);

	return err;
}


int rtmp_control_send_set_peer_bw(struct rtmp_conn *conn,
				    size_t was, uint8_t limit_type)
{
	struct mbuf *mb = mbuf_alloc(5);
	int err;

	if (!mb)
		return ENOMEM;

	(void)mbuf_write_u32(mb, htonl(was));
	(void)mbuf_write_u8(mb, limit_type);

	err = rtmp_conn_send_msg(conn, 0, RTMP_CHUNK_ID_CONTROL, 0, 0,
				 RTMP_TYPE_SET_PEER_BANDWIDTH,
				 RTMP_CONTROL_STREAM_ID,
				 mb->buf, mb->end);

	mem_deref(mb);

	return err;
}
