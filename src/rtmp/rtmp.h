/**
 * @file rtmp.h  Real Time Messaging Protocol (RTMP) -- Internal API
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_DEFAULT_CHUNKSIZE = 128,
	MESSAGE_LEN_MAX = 524288,
};


struct rtmp_conn {
	struct list streaml;
	struct rtmp_dechunker *dechunk;
	struct tcp_conn *tc;
	struct mbuf *mb;                  /* TCP reassembly buffer */
	enum rtmp_handshake_state state;
	uint8_t x1[RTMP_SIG_SIZE];        /* C1 or S1 */
	uint32_t window_ack_size;
	bool is_client;
	bool estab;
	bool term;
	rtmp_estab_h *estabh;
	rtmp_status_h *statush;
	rtmp_close_h *closeh;
	void *arg;

	bool createstream;
	bool stream_begin;  /* XXX: move to stream */

	/* client specific: */
	char *app;
	char *uri;
};

struct rtmp_stream {
	struct le le;
	struct rtmp_conn *conn;    /* pointer */
	char *name;
	uint32_t stream_id;
	rtmp_audio_h *auh;
	rtmp_video_h *vidh;
	void *arg;
};


/* Command */

struct command_header {
	char name[64];
	uint64_t transaction_id;
};

int rtmp_command_header_encode(struct mbuf *mb,
			       const char *name, uint64_t tid);
int rtmp_command_header_decode(struct command_header *hdr,
			       const struct odict *dict);
int rtmp_command_header_print(struct re_printf *pf,
			      const struct command_header *hdr);


/* Stream */

struct rtmp_stream *rtmp_stream_find(const struct list *streaml,
				     uint32_t stream_id);

/* Connection */

int rtmp_conn_send_msg(struct rtmp_conn *conn,
		       unsigned format, uint32_t chunk_id,
		       uint32_t timestamp, uint32_t timestamp_delta,
		       uint8_t msg_type_id, uint32_t msg_stream_id,
		       const uint8_t *payload, size_t payload_len);
