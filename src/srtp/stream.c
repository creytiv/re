/**
 * @file srtp/stream.c  Secure Real-time Transport Protocol (SRTP) -- stream
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_srtp.h>
#include "srtp.h"


enum {
	MAX_STREAMS  = 8,  /**< Maximum number of SRTP streams */
};


static void stream_destructor(void *arg)
{
	struct srtp_stream *strm = arg;

	list_unlink(&strm->le);
}


static struct srtp_stream *stream_find(struct srtp *srtp, uint32_t ssrc)
{
	struct le *le;

	for (le = srtp->streaml.head; le; le = le->next) {

		struct srtp_stream *strm = le->data;

		if (strm->ssrc == ssrc)
			return strm;
	}

	return NULL;
}


static struct srtp_stream *stream_new(struct srtp *srtp, uint32_t ssrc)
{
	struct srtp_stream *strm;

	if (list_count(&srtp->streaml) >= MAX_STREAMS)
		return NULL;

	strm = mem_zalloc(sizeof(*strm), stream_destructor);
	if (!strm)
		return NULL;

	strm->ssrc = ssrc;
	srtp_replay_init(&strm->replay_rtp);
	srtp_replay_init(&strm->replay_rtcp);

	list_append(&srtp->streaml, &strm->le, strm);

	return strm;
}


struct srtp_stream *stream_get(struct srtp *srtp, uint32_t ssrc)
{
	struct srtp_stream *strm;

	if (!srtp)
		return NULL;

	strm = stream_find(srtp, ssrc);
	if (strm)
		return strm;

	return stream_new(srtp, ssrc);
}


struct srtp_stream *stream_get_seq(struct srtp *srtp, uint32_t ssrc,
				   uint16_t seq)
{
	struct srtp_stream *strm;

	strm = stream_get(srtp, ssrc);
	if (!strm)
		return NULL;

	/* Set the initial sequence number once only */
	if (!strm->s_l_set) {
		strm->s_l = seq;
		strm->s_l_set = true;
	}

	return strm;
}
