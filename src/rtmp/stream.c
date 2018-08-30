/**
 * @file rtmp/stream.c  Real Time Messaging Protocol (RTMP) -- NetStream
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


#define STREAM_CHUNK_ID  (8)


static int send_amf_play(struct rtmp_conn *conn, const char *stream_name,
			 uint32_t stream_id)
{
	struct mbuf *mb = mbuf_alloc(512);
	int err;

	err = rtmp_command_header_encode(mb, "play", 4);

	err |= rtmp_amf_encode_null(mb);
	err |= rtmp_amf_encode_string(mb, stream_name);
	err |= rtmp_amf_encode_number(mb, -2000);
	if (err)
		goto out;

	err = rtmp_send_amf_command(conn, 0, STREAM_CHUNK_ID, stream_id,
				    mb->buf, mb->end);
	if (err) {
		re_printf("rtmp: play amf command error %m\n", err);
		goto out;
	}

 out:
	mem_deref(mb);

	return err;
}


static int send_amf_publish(struct rtmp_conn *conn, const char *stream_name,
			    uint32_t stream_id)
{
	struct mbuf *mb = mbuf_alloc(512);
	int err;

	/* XXX: select transaction ID from TID counter */

	err = rtmp_command_header_encode(mb, "publish", 5);

	err |= rtmp_amf_encode_null(mb);
	err |= rtmp_amf_encode_string(mb, stream_name);
	err |= rtmp_amf_encode_string(mb, "live");
	if (err)
		goto out;

	err = rtmp_send_amf_command(conn, 0, STREAM_CHUNK_ID, stream_id,
				    mb->buf, mb->end);
	if (err) {
		re_printf("rtmp: play amf command error %m\n", err);
		goto out;
	}

 out:
	mem_deref(mb);

	return err;
}


static void destructor(void *data)
{
	struct rtmp_stream *strm = data;

	list_unlink(&strm->le);
	mem_deref(strm->name);
}


static struct rtmp_stream *rtmp_stream_alloc(struct rtmp_conn *conn,
					     const char *name,
					     uint32_t stream_id)
{
	struct rtmp_stream *strm;
	int err;

	strm = mem_zalloc(sizeof(*strm), destructor);
	if (!strm)
		return NULL;

	strm->conn      = conn;
	strm->stream_id = stream_id;

	err = str_dup(&strm->name, name);
	if (err)
		goto out;

	list_append(&conn->streaml, &strm->le, strm);

 out:
	if (err)
		return mem_deref(strm);

	return strm;
}


int rtmp_play(struct rtmp_stream **streamp, struct rtmp_conn *conn,
	      const char *name, uint32_t stream_id,
	      rtmp_audio_h *auh, rtmp_video_h *vidh, void *arg)
{
	struct rtmp_stream *strm;
	int err;

	if (!conn || !name)
		return EINVAL;

	re_printf("rtmp: stream: play '%s'\n", name);

	strm = rtmp_stream_alloc(conn, name, stream_id);
	if (!strm)
		return ENOMEM;

	strm->auh       = auh;
	strm->vidh      = vidh;
	strm->arg       = arg;

	err = send_amf_play(conn, name, stream_id);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(strm);
	else if (streamp)
		*streamp = strm;

	return err;
}


int rtmp_publish(struct rtmp_stream **streamp, struct rtmp_conn *conn,
		 const char *name, uint32_t stream_id)
{
	struct rtmp_stream *strm;
	int err;

	if (!conn || !name)
		return EINVAL;

	re_printf("rtmp: stream: publish '%s'\n", name);

	strm = rtmp_stream_alloc(conn, name, stream_id);
	if (!strm)
		return ENOMEM;

	err = send_amf_publish(conn, name, stream_id);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(strm);
	else if (streamp)
		*streamp = strm;

	return err;
}


int rtmp_send_video(struct rtmp_stream *strm, const uint8_t *pld, size_t len)
{
	unsigned format = 0;           /* XXX: format 0 or 1 */
	uint32_t chunk_id = 6;         /* XXX: how to choose? */
	uint32_t timestamp = 0;        /* XXX: move to API */
	uint32_t timestamp_delta = 0;  /* XXX: move to API */
	int err;

	if (!strm || !pld || !len)
		return EINVAL;

	re_printf("send_video:  %zu bytes\n", len);

	err = rtmp_conn_send_msg(strm->conn, format, chunk_id, timestamp,
				 timestamp_delta, RTMP_TYPE_VIDEO,
				 strm->stream_id, pld, len);

	return err;
}


struct rtmp_stream *rtmp_stream_find(const struct list *streaml,
				     uint32_t stream_id)
{
	struct le *le;

	for (le = list_head(streaml); le; le = le->next) {

		struct rtmp_stream *strm = le->data;

		if (stream_id == strm->stream_id)
			return strm;
	}

	return NULL;
}
