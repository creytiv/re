/**
 * @file rtmp.h  Real Time Messaging Protocol (RTMP) -- Internal API
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_PROTOCOL_VERSION  = 3,
	RTMP_DEFAULT_CHUNKSIZE = 128,
	RTMP_HANDSHAKE_SIZE    = 1536,
	RTMP_MESSAGE_LEN_MAX   = 524288,
};

/* Chunk IDs */
enum {
	RTMP_CHUNK_ID_CONTROL  = 2,
	RTMP_CHUNK_ID_CONN     = 3,
};

/** Defines the RTMP Handshake State */
enum rtmp_handshake_state {
	RTMP_STATE_UNINITIALIZED = 0,
	RTMP_STATE_VERSION_SENT,
	RTMP_STATE_ACK_SENT,
	RTMP_STATE_HANDSHAKE_DONE
};

/**
 * Defines an RTMP Connection
 */
struct rtmp_conn {
	struct list streaml;
	struct rtmp_dechunker *dechunk;
	struct tcp_conn *tc;
	struct tls_conn *sc;
	struct mbuf *mb;                        /* TCP reassembly buffer */
	enum rtmp_handshake_state state;
	size_t total_bytes;
	size_t last_ack;
	uint32_t window_ack_size;
	uint32_t send_chunk_size;
	unsigned chunk_id_counter;
	bool is_client;
	bool connected;
	rtmp_estab_h *estabh;
	rtmp_command_h *cmdh;
	rtmp_close_h *closeh;
	void *arg;

	/* client specific: */
	struct dnsc *dnsc;
	struct dns_query *dnsq4;
	struct dns_query *dnsq6;
	struct list ctransl;
	struct sa srvv[16];
	struct tls *tls;
	unsigned srvc;
	uint64_t tid_counter;
	uint16_t port;
	char *app;
	char *uri;
	char *stream;
	char *host;
};

/**
 * Defines an RTMP Stream
 */
struct rtmp_stream {
	struct le le;
	const struct rtmp_conn *conn;    /**< Pointer to parent connection */
	bool created;
	uint32_t stream_id;
	unsigned chunk_id_audio;
	unsigned chunk_id_video;
	unsigned chunk_id_data;
	rtmp_audio_h *auh;
	rtmp_video_h *vidh;
	rtmp_command_h *datah;
	rtmp_command_h *cmdh;
	rtmp_resp_h *resph;
	rtmp_control_h *ctrlh;
	void *arg;
};

struct rtmp_header {
	unsigned format:2;           /* type 0-3 */
	uint32_t chunk_id;           /* from 3-65599 */

	uint32_t timestamp;          /* 24-bit or 32-bit */
	uint32_t timestamp_delta;    /* 24-bit */
	uint32_t timestamp_ext;
	uint32_t length;             /* 24-bit */
	uint8_t type_id;             /* enum rtmp_packet_type */
	uint32_t stream_id;
	bool ext_ts;
};


/* Command */

int rtmp_command_header_encode(struct mbuf *mb, const char *name,
			       uint64_t tid);

/* Connection */

int rtmp_conn_send_msg(const struct rtmp_conn *conn, unsigned format,
		       uint32_t chunk_id, uint32_t timestamp,
		       uint32_t timestamp_delta, uint8_t msg_type_id,
		       uint32_t msg_stream_id,
		       const uint8_t *payload, size_t payload_len);
int rtmp_send_amf_command(const struct rtmp_conn *conn,
			  unsigned format, uint32_t chunk_id,
			  uint8_t type_id,
			  uint32_t msg_stream_id,
			  const uint8_t *cmd, size_t len);
unsigned rtmp_conn_assign_chunkid(struct rtmp_conn *conn);
uint64_t rtmp_conn_assign_tid(struct rtmp_conn *conn);


/* Client Transaction */


struct rtmp_ctrans;

int  rtmp_ctrans_response(const struct list *ctransl,
			  const struct odict *msg);


/*
 * RTMP Chunk
 */

int rtmp_chunker(unsigned format, uint32_t chunk_id,
		 uint32_t timestamp, uint32_t timestamp_delta,
		 uint8_t msg_type_id, uint32_t msg_stream_id,
		 const uint8_t *payload, size_t payload_len,
		 size_t max_chunk_sz, struct tcp_conn *tc);


/*
 * RTMP Header
 */

int  rtmp_header_encode(struct mbuf *mb, struct rtmp_header *hdr);
int  rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb);
int  rtmp_header_print(struct re_printf *pf, const struct rtmp_header *hdr);
const char *rtmp_packet_type_name(enum rtmp_packet_type type);


/*
 * RTMP De-chunker
 */

struct rtmp_dechunker;

typedef int (rtmp_dechunk_h)(const struct rtmp_header *hdr,
			     struct mbuf *mb, void *arg);

int  rtmp_dechunker_alloc(struct rtmp_dechunker **rdp, size_t chunk_sz,
			  rtmp_dechunk_h *chunkh, void *arg);
int  rtmp_dechunker_receive(struct rtmp_dechunker *rd, struct mbuf *mb);
void rtmp_dechunker_set_chunksize(struct rtmp_dechunker *rd, size_t chunk_sz);
int  rtmp_dechunker_debug(struct re_printf *pf,
			  const struct rtmp_dechunker *rd);


/*
 * AMF (Action Message Format)
 */

int rtmp_amf_encode_number(struct mbuf *mb, double val);
int rtmp_amf_encode_boolean(struct mbuf *mb, bool boolean);
int rtmp_amf_encode_string(struct mbuf *mb, const char *str);
int rtmp_amf_encode_null(struct mbuf *mb);
int rtmp_amf_vencode_object(struct mbuf *mb, enum rtmp_amf_type container,
			    unsigned propc, va_list *ap);

int rtmp_amf_decode(struct odict **msgp, struct mbuf *mb);
