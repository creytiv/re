/**
 * @file rtmp.h  Real Time Messaging Protocol (RTMP) -- Internal API
 *
 * Copyright (C) 2010 Creytiv.com
 */


#define RTMP_CONN_CHUNK_ID  (3)  /* XXX: dynamic selection */


enum {
	MESSAGE_LEN_MAX = 524288,
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
	uint8_t x1[RTMP_SIG_SIZE];        /* C1 or S1 */
	uint32_t window_ack_size;
	bool is_client;
	bool connected;
	bool term;
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
	rtmp_ready_h *readyh;
	rtmp_audio_h *auh;
	rtmp_video_h *vidh;
	void *arg;

	uint32_t recv_timestamp;

	size_t n_send;
	size_t n_recv;
};


/* Command */

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
int rtmp_send_amf_command(struct rtmp_conn *conn,
			  unsigned format, uint32_t chunk_id,
			  uint32_t msg_stream_id,
			  const uint8_t *cmd, size_t len);


/* Control */

int rtmp_control_send_was(struct rtmp_conn *conn, uint32_t was);
int rtmp_control_send_set_peer_bw(struct rtmp_conn *conn,
				  size_t was, uint8_t limit_type);
int rtmp_control_send_user_control_msg(struct rtmp_conn *conn,
				       uint16_t event_type,
				       uint32_t event_data);
int rtmp_control_send_set_chunk_size(struct rtmp_conn *conn,
				     uint32_t chunk_size);


/* Client Transaction */

typedef void (rtmp_resp_h)(int err, const struct command_header *cmd_hdr,
			   struct odict *dict, void *arg);

struct rtmp_ctrans {
	struct le le;
	char *command;
	uint64_t tid;
	unsigned replies;
	unsigned errors;
	rtmp_resp_h *resph;
	void *arg;
};

int  rtmp_ctrans_send(struct rtmp_conn *conn, uint32_t stream_id,
		      const char *command, rtmp_resp_h *resph, void *arg,
		      unsigned body_propc, ...);
int  rtmp_ctrans_response(const struct list *ctransl, bool success,
			  const struct command_header *cmd_hdr,
			  struct odict *dict);
struct rtmp_ctrans *rtmp_ctrans_find(const struct list *ctransl, uint64_t tid);


/* AMF Encode/Decode */

int rtmp_amf_vencode_object(struct mbuf *mb, enum class class,
			    unsigned propc, va_list *ap);


const struct odict_entry *odict_lookup_index(const struct odict *o,
					     unsigned ix,
					     int type);


/*
 * RTMP Handshake
 */

const char *rtmp_handshake_name(enum rtmp_handshake_state state);
