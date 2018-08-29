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


static void destructor(void *data)
{
	struct rtmp_stream *strm = data;

	list_unlink(&strm->le);
	mem_deref(strm->name);
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

	strm = mem_zalloc(sizeof(*strm), destructor);
	if (!strm)
		return ENOMEM;

	err = str_dup(&strm->name, name);
	if (err)
		goto out;

	strm->conn      = conn;
	strm->stream_id = stream_id;
	strm->auh       = auh;
	strm->vidh      = vidh;
	strm->arg       = arg;

	list_append(&conn->streaml, &strm->le, strm);

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
