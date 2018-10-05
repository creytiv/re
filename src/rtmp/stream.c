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

	if (strm->created) {

		rtmp_amf_command(strm->conn, 0, "deleteStream",
				 3,
				RTMP_AMF_TYPE_NUMBER, 0.0,
				RTMP_AMF_TYPE_NULL,
				RTMP_AMF_TYPE_NUMBER, (double)strm->stream_id);
	}
}


int rtmp_stream_alloc(struct rtmp_stream **strmp, struct rtmp_conn *conn,
		      uint32_t stream_id, rtmp_command_h *cmdh,
		      rtmp_control_h *ctrlh, rtmp_audio_h *auh,
		      rtmp_video_h *vidh, rtmp_command_h *datah,
		      void *arg)
{
	struct rtmp_stream *strm;
	int err = 0;

	if (!strmp || !conn)
		return EINVAL;

	strm = mem_zalloc(sizeof(*strm), destructor);
	if (!strm)
		return ENOMEM;

	strm->conn      = conn;
	strm->stream_id = stream_id;

	strm->cmdh   = cmdh;
	strm->ctrlh  = ctrlh;
	strm->auh    = auh;
	strm->vidh   = vidh;
	strm->datah  = datah;
	strm->arg    = arg;

	strm->chunk_id_audio = rtmp_conn_assign_chunkid(conn);
	strm->chunk_id_video = rtmp_conn_assign_chunkid(conn);
	strm->chunk_id_data  = rtmp_conn_assign_chunkid(conn);

	list_append(&conn->streaml, &strm->le, strm);

	if (err)
		mem_deref(strm);
	else
		*strmp = strm;

	return err;
}


static void createstream_handler(int err, const struct rtmp_amf_message *msg,
				 void *arg)
{
	struct rtmp_stream *strm = arg;
	uint64_t num;

	if (err) {
		re_printf("### createStream failed (%m)\n", err);
		return;
	}

	if (!rtmp_amf_message_get_number(msg, &num, 3)) {
		re_printf("missing stream id\n");
		return;
	}

	strm->stream_id = (uint32_t)num;
	if (strm->stream_id == 0) {
		re_printf("rtmp: stream: invalid stream id 0\n");
		return;
	}

	re_printf("using stream id %u\n", strm->stream_id);

	strm->created = true;

	if (strm->resph)
		strm->resph(msg, strm->arg);
}


int rtmp_stream_create(struct rtmp_stream **strmp, struct rtmp_conn *conn,
		       rtmp_command_h *resph, rtmp_command_h *cmdh,
		       rtmp_control_h *ctrlh, rtmp_audio_h *auh,
		       rtmp_video_h *vidh, rtmp_command_h *datah,
		       void *arg)
{
	struct rtmp_stream *strm;
	int err;

	if (!strmp)
		return EINVAL;

	err = rtmp_stream_alloc(&strm, conn, (uint32_t)-1,
				cmdh, ctrlh, auh, vidh, datah, arg);
	if (err)
		return err;

	strm->resph = resph;

	err = rtmp_amf_request(conn, 0,
			       "createStream", createstream_handler, strm,
			       1,
			       RTMP_AMF_TYPE_NULL);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(strm);
	else
		*strmp = strm;

	return err;
}


int rtmp_play(struct rtmp_stream *strm, const char *name)
{
	if (!strm || !name)
		return EINVAL;

	return rtmp_amf_command(strm->conn, strm->stream_id, "play",
				4,
				RTMP_AMF_TYPE_NUMBER, 0.0,
				RTMP_AMF_TYPE_NULL,
				RTMP_AMF_TYPE_STRING, name,
				RTMP_AMF_TYPE_NUMBER, -2000.0);
}


int rtmp_publish(struct rtmp_stream *strm, const char *name)
{
	if (!strm || !name)
		return EINVAL;

	re_printf("publish:  name=%s\n", name);

	return rtmp_amf_command(strm->conn, strm->stream_id, "publish",
				4,
				RTMP_AMF_TYPE_NUMBER, 0.0,
				RTMP_AMF_TYPE_NULL,
				RTMP_AMF_TYPE_STRING, name,
				RTMP_AMF_TYPE_STRING, "live");
}


int rtmp_send_audio(struct rtmp_stream *strm, uint32_t timestamp,
		    const uint8_t *pld, size_t len)
{
	uint32_t chunk_id;

	if (!strm || !pld || !len)
		return EINVAL;

	chunk_id = strm->chunk_id_audio;

	return rtmp_conn_send_msg(strm->conn, 0, chunk_id, timestamp, 0,
				  RTMP_TYPE_AUDIO, strm->stream_id, pld, len);
}


int rtmp_send_video(struct rtmp_stream *strm, uint32_t timestamp,
		    const uint8_t *pld, size_t len)
{
	uint32_t chunk_id;

	if (!strm || !pld || !len)
		return EINVAL;

	chunk_id = strm->chunk_id_video;

	return rtmp_conn_send_msg(strm->conn, 0, chunk_id, timestamp, 0,
				  RTMP_TYPE_VIDEO, strm->stream_id, pld, len);
}


struct rtmp_stream *rtmp_stream_find(const struct rtmp_conn *conn,
				     uint32_t stream_id)
{
	struct le *le;

	for (le = list_head(&conn->streaml); le; le = le->next) {

		struct rtmp_stream *strm = le->data;

		if (stream_id == strm->stream_id)
			return strm;
	}

	return NULL;
}


int rtmp_stream_debug(struct re_printf *pf, const struct rtmp_stream *strm)
{
	if (!strm)
		return 0;

	return re_hprintf(pf,
			  "stream_id=%u  "
			  "  ",
			  strm->stream_id);
}
