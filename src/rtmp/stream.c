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


static void destructor(void *data)
{
	struct rtmp_stream *strm = data;

	list_unlink(&strm->le);
	mem_deref(strm->name);
}


struct rtmp_stream *rtmp_stream_alloc(struct rtmp_conn *conn,
				      const char *name,
				      uint32_t stream_id,
				      rtmp_ready_h *readyh,
				      rtmp_audio_h *auh,
				      rtmp_video_h *vidh,
				      void *arg)
{
	struct rtmp_stream *strm;
	int err;

	strm = mem_zalloc(sizeof(*strm), destructor);
	if (!strm)
		return NULL;

	strm->conn      = conn;
	strm->stream_id = stream_id;  /* unknown */

	err = str_dup(&strm->name, name);
	if (err)
		goto out;

	strm->readyh = readyh;
	strm->auh    = auh;
	strm->vidh   = vidh;
	strm->arg    = arg;

	list_append(&conn->streaml, &strm->le, strm);

 out:
	if (err)
		return mem_deref(strm);

	return strm;
}


static void createstream_handler(int err, const struct rtmp_amf_message *msg,
				 void *arg)
{
	struct rtmp_stream *strm = arg;
	const struct odict_entry *entry;

	if (err) {
		re_printf("### createStream failed (%m)\n", err);
		return;
	}

	/* use stream_id from response, pass to struct rtmp_stream */
	entry = odict_lookup_index(msg->dict, 3, ODICT_DOUBLE);
	if (!entry) {
		re_printf("missing entry\n");
		return;
	}

	strm->stream_id = (uint32_t)entry->u.dbl;
	if (strm->stream_id == 0) {
		re_printf("invalid stream id\n");
		return;
	}

	switch (strm->operation) {

	case OP_PLAY:
		/* NOTE: the play command does not have a response */
		err = rtmp_ctrans_send(strm->conn, strm->stream_id, "play",
				       NULL, NULL,
				       3,
				       AMF_TYPE_NULL, NULL,
				       AMF_TYPE_STRING, strm->name,
				       AMF_TYPE_NUMBER, -2000.0);
		if (err) {
			re_printf("rtmp: play: ctrans failed (%m)\n", err);
			goto out;
		}
		break;

	case OP_PUBLISH:
		/* NOTE: the publish command does not have a response */
		err = rtmp_ctrans_send(strm->conn, strm->stream_id, "publish",
				       NULL, NULL,
				       3,
				       AMF_TYPE_NULL, NULL,
				       AMF_TYPE_STRING, strm->name,
				       AMF_TYPE_STRING, "live");
		if (err) {
			re_printf("rtmp: publish: ctrans failed (%m)\n", err);
			goto out;
		}

		break;
	}

	if (strm->readyh)
		strm->readyh(strm->arg);
 out:
	return;
}


int rtmp_play(struct rtmp_stream **streamp, struct rtmp_conn *conn,
	      const char *name, rtmp_ready_h *readyh,
	      rtmp_audio_h *auh, rtmp_video_h *vidh, void *arg)
{
	struct rtmp_stream *strm;
	int err;

	if (!conn || !name)
		return EINVAL;

	re_printf("rtmp: stream: play '%s'\n", name);

	strm = rtmp_stream_alloc(conn, name, (uint32_t)-1,
				 readyh, auh, vidh, arg);
	if (!strm)
		return ENOMEM;

	strm->command   = "play";
	strm->operation = OP_PLAY;

	err = rtmp_ctrans_send(conn, RTMP_CONTROL_STREAM_ID, "createStream",
			       createstream_handler, strm,
			       1,
			         AMF_TYPE_NULL, NULL
			       );
	if (err) {
		re_printf("rtmp: create_stream: ctrans failed (%m)\n", err);
		goto out;
	}

 out:
	if (err)
		mem_deref(strm);
	else if (streamp)
		*streamp = strm;

	return err;
}


int rtmp_publish(struct rtmp_stream **streamp, struct rtmp_conn *conn,
		 const char *name, rtmp_ready_h *readyh, void *arg)
{
	struct rtmp_stream *strm;
	int err;

	if (!conn || !name)
		return EINVAL;

	re_printf("rtmp: stream: publish '%s'\n", name);

	strm = rtmp_stream_alloc(conn, name, (uint32_t)-1,
				 readyh, NULL, NULL, arg);
	if (!strm)
		return ENOMEM;

	strm->command   = "publish";
	strm->operation = OP_PUBLISH;

	err = rtmp_ctrans_send(conn, RTMP_CONTROL_STREAM_ID, "createStream",
			       createstream_handler, strm,
			       1,
			         AMF_TYPE_NULL, NULL
			       );
	if (err) {
		re_printf("rtmp: create_stream: ctrans failed (%m)\n", err);
		goto out;
	}

 out:
	if (err)
		mem_deref(strm);
	else if (streamp)
		*streamp = strm;

	return err;
}


int rtmp_send_audio(struct rtmp_stream *strm, uint32_t timestamp,
		    const uint8_t *pld, size_t len)
{
	unsigned format = 0;
	uint32_t chunk_id = 6;         /* XXX: how to choose? */
	int err;

	if (!strm || !pld || !len)
		return EINVAL;

	++strm->n_send;

	err = rtmp_conn_send_msg(strm->conn, format, chunk_id, timestamp,
				 0, RTMP_TYPE_AUDIO,
				 strm->stream_id, pld, len);

	return err;
}


int rtmp_send_video(struct rtmp_stream *strm, uint32_t timestamp,
		    const uint8_t *pld, size_t len)
{
	unsigned format = 0;
	uint32_t chunk_id = 7;         /* XXX: how to choose? */
	int err;

	if (!strm || !pld || !len)
		return EINVAL;

	++strm->n_send;

	err = rtmp_conn_send_msg(strm->conn, format, chunk_id, timestamp,
				 0, RTMP_TYPE_VIDEO,
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


bool rtmp_stream_isready(const struct rtmp_stream *strm)
{
	if (!strm)
		return false;

	return strm->begin && !strm->eof;
}


int rtmp_stream_debug(struct re_printf *pf, const struct rtmp_stream *strm)
{
	if (!strm)
		return 0;

	return re_hprintf(pf,
			  "stream_id=%u  begin=%d  eof=%d  %s   name=%12s"
			  "  send=%zu  recv=%zu",
			  strm->stream_id, strm->begin, strm->eof,
			  strm->command, strm->name,
			  strm->n_send, strm->n_recv);
}
