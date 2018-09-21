/**
 * @file rtmp.h  Real Time Messaging Protocol (RTMP) -- Internal API
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_PROTOCOL_VERSION  = 3,
	RTMP_CONN_CHUNK_ID     = 3,
	RTMP_DEFAULT_CHUNKSIZE = 128,
	RTMP_HANDSHAKE_SIZE    = 1536,
	RTMP_MESSAGE_LEN_MAX   = 524288,
};

/* Chunk IDs */
enum {
	RTMP_CHUNK_ID_CONTROL = 2,
};

enum rtmp_handshake_state {
	RTMP_STATE_UNINITIALIZED = 0,
	RTMP_STATE_VERSION_SENT,
	RTMP_STATE_ACK_SENT,
	RTMP_STATE_HANDSHAKE_DONE
};

struct rtmp_conn {
	struct list streaml;
	struct rtmp_dechunker *dechunk;
	struct tcp_conn *tc;
	struct mbuf *mb;                  /* TCP reassembly buffer */
	enum rtmp_handshake_state state;
	uint8_t x1[RTMP_HANDSHAKE_SIZE];        /* C1 or S1 */
	uint32_t window_ack_size;
	bool is_client;
	bool connected;
	rtmp_estab_h *estabh;
	rtmp_status_h *statush;
	rtmp_close_h *closeh;
	void *arg;

	struct {
		size_t ping;
		size_t ack;
	} stats;

	/* client specific: */
	struct list ctransl;
	uint64_t tid_counter;
	char *app;
	char *uri;

	/* server specific: */
	rtmp_command_h *cmdh;

	uint32_t send_chunk_size;

	unsigned chunk_id_counter;
};

enum stream_op {
	OP_PLAY,
	OP_PUBLISH,
};

struct rtmp_stream {
	struct le le;
	struct rtmp_conn *conn;    /* pointer */
	char *name;
	uint32_t stream_id;
	enum stream_op operation;
	const char *command;
	bool begin;
	bool eof;
	unsigned chunk_id_audio;
	unsigned chunk_id_video;
	rtmp_ready_h *readyh;
	rtmp_audio_h *auh;
	rtmp_video_h *vidh;
	void *arg;
};

struct rtmp_amf_message {
	struct odict *dict;
};


/* Command */

int rtmp_command_header_encode(struct mbuf *mb, const char *name,
			       uint64_t tid);


/* Stream */

struct rtmp_stream *rtmp_stream_find(const struct list *streaml,
				     uint32_t stream_id);


/* Connection */

int rtmp_conn_send_msg(struct rtmp_conn *conn, unsigned format,
		       uint32_t chunk_id, uint32_t timestamp,
		       uint32_t timestamp_delta, uint8_t msg_type_id,
		       uint32_t msg_stream_id,
		       const uint8_t *payload, size_t payload_len);
int rtmp_send_amf_command(struct rtmp_conn *conn, unsigned format,
			  uint32_t chunk_id, uint32_t msg_stream_id,
			  const uint8_t *cmd, size_t len);


/* Client Transaction */

typedef void (rtmp_resp_h)(int err, const struct rtmp_amf_message *msg,
			   void *arg);

struct rtmp_ctrans;

int  rtmp_ctrans_send(struct rtmp_conn *conn, uint32_t stream_id,
		      const char *command, rtmp_resp_h *resph, void *arg,
		      unsigned body_propc, ...);
int  rtmp_ctrans_response(const struct list *ctransl, bool success,
			  const struct rtmp_amf_message *msg);


/* AMF Encode/Decode */

int rtmp_amf_vencode_object(struct mbuf *mb, enum rtmp_amf_type container,
			    unsigned propc, va_list *ap);


/* RTMP Handshake */

const char *rtmp_handshake_name(enum rtmp_handshake_state state);


/*
 * RTMP Chunk
 */

typedef int (rtmp_chunk_h)(const struct rtmp_header *hdr,
			   const uint8_t *pld, size_t pld_len, void *arg);

int rtmp_chunker(unsigned format, uint32_t chunk_id,
		 uint32_t timestamp, uint32_t timestamp_delta,
		 uint8_t msg_type_id, uint32_t msg_stream_id,
		 const uint8_t *payload, size_t payload_len,
		 size_t max_chunk_sz, rtmp_chunk_h *chunkh, void *arg);


/*
 * RTMP Header
 */

int  rtmp_header_encode(struct mbuf *mb, const struct rtmp_header *hdr);
int  rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb);
int  rtmp_header_print(struct re_printf *pf, const struct rtmp_header *hdr);
const char *rtmp_packet_type_name(enum rtmp_packet_type type);
