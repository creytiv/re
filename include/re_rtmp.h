/**
 * @file re_rtmp.h  Interface to Real Time Messaging Protocol (RTMP)
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_PORT              = 1935,
};


/* Stream IDs */
enum {

	/* User Control messages SHOULD use message stream ID 0
	   (known as the control stream) */
	RTMP_CONTROL_STREAM_ID = 0
};


enum rtmp_packet_type {
	RTMP_TYPE_SET_CHUNK_SIZE     = 1,   /* Set Chunk Size               */
	RTMP_TYPE_ACKNOWLEDGEMENT    = 3,   /* Acknowledgement              */
	RTMP_TYPE_USER_CONTROL_MSG   = 4,   /* User Control Messages        */
	RTMP_TYPE_WINDOW_ACK_SIZE    = 5,   /* Window Acknowledgement Size  */
	RTMP_TYPE_SET_PEER_BANDWIDTH = 6,   /* Set Peer Bandwidth           */
	RTMP_TYPE_AUDIO              = 8,   /* Audio Message                */
	RTMP_TYPE_VIDEO              = 9,   /* Video Message                */
	RTMP_TYPE_DATA               = 18,  /* Data Message                 */
	RTMP_TYPE_AMF0               = 20,  /* Action Message Format (AMF)  */
};


/* forward declarations */
struct sa;
struct tcp_sock;


struct rtmp_header {
	unsigned format:2;           /* type 0-3 */
	uint32_t chunk_id;           /* from 3-65599 */

	uint32_t timestamp;          /* 24-bit */
	uint32_t timestamp_delta;    /* 24-bit */
	uint32_t length;             /* 24-bit */
	uint8_t type_id;             /* enum rtmp_packet_type */
	uint32_t stream_id;
};

struct rtmp_amf_message {
	struct odict *dict;
};

/*
 * RTMP Header
 */

int  rtmp_header_encode(struct mbuf *mb, const struct rtmp_header *hdr);
int  rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb);
int  rtmp_header_print(struct re_printf *pf, const struct rtmp_header *hdr);
const char *rtmp_packet_type_name(enum rtmp_packet_type type);


/*
 * RTMP De-chunker XXX make private
 */

// rename to rtmp_chunk, make opaque
struct rtmp_message {
	struct le le;
	uint32_t chunk_id;
	size_t length;
	uint8_t *buf;
	size_t pos;             /* how many bytes received so far */
	uint8_t type;
	uint32_t stream_id;

	unsigned format;
	uint32_t timestamp;
	uint32_t timestamp_delta;
};

struct rtmp_dechunker;

// XXX: use rtmp_chunk_h instead
typedef int (rtmp_msg_h)(struct rtmp_message *msg, void *arg);

int  rtmp_dechunker_alloc(struct rtmp_dechunker **rdp,
			  rtmp_msg_h *msgh, void *arg);
int  rtmp_dechunker_receive(struct rtmp_dechunker *rd, struct mbuf *mb);
void rtmp_dechunker_set_chunksize(struct rtmp_dechunker *rd, size_t chunk_sz);


/*
 * AMF (Action Message Format)
 */

enum rtmp_amf_type {
	RTMP_AMF_TYPE_ROOT         = -1,   /* special */
	RTMP_AMF_TYPE_NUMBER       = 0x00,
	RTMP_AMF_TYPE_BOOLEAN      = 0x01,
	RTMP_AMF_TYPE_STRING       = 0x02,
	RTMP_AMF_TYPE_OBJECT       = 0x03,
	RTMP_AMF_TYPE_NULL         = 0x05,
	RTMP_AMF_TYPE_ECMA_ARRAY   = 0x08,  /* 'associative' Array */
	RTMP_AMF_TYPE_OBJECT_END   = 0x09,
	RTMP_AMF_TYPE_STRICT_ARRAY = 0x0a,  /* ordinal indices */
};

struct odict;

int rtmp_amf_encode_number(struct mbuf *mb, double val);
int rtmp_amf_encode_boolean(struct mbuf *mb, bool boolean);
int rtmp_amf_encode_string(struct mbuf *mb, const char *str);
int rtmp_amf_encode_null(struct mbuf *mb);
int rtmp_amf_encode_object(struct mbuf *mb, enum rtmp_amf_type container,
			   unsigned propc, ...);

int rtmp_amf_decode(struct rtmp_amf_message **msgp, struct mbuf *mb);

/* AMF Message */

uint64_t rtmp_amf_message_tid(const struct rtmp_amf_message *msg);
bool     rtmp_amf_message_get_number(const struct rtmp_amf_message *msg,
				     uint64_t *num, unsigned ix);
const char *rtmp_amf_message_string(const struct rtmp_amf_message *msg,
				    unsigned ix);


/*
 * RTMP High-level API (socket, connection, stream)
 */


struct rtmp_conn;

typedef void (rtmp_estab_h)(void *arg);
typedef void (rtmp_command_h)(struct rtmp_amf_message *msg, void *arg);
typedef void (rtmp_status_h)(const struct rtmp_amf_message *msg, void *arg);
typedef void (rtmp_close_h)(int err, void *arg);


int rtmp_connect(struct rtmp_conn **connp, const char *uri,
		 rtmp_estab_h *estabh, rtmp_status_h *statush,
		 rtmp_close_h *closeh, void *arg);
int rtmp_accept(struct rtmp_conn **connp, struct tcp_sock *ts,
		rtmp_estab_h *estabh, rtmp_command_h *cmdh,
		rtmp_status_h *statush, rtmp_close_h *closeh, void *arg);
uint32_t rtmp_window_ack_size(const struct rtmp_conn *conn);
struct tcp_conn *rtmp_conn_tcpconn(const struct rtmp_conn *conn);
int rtmp_conn_debug(struct re_printf *pf, const struct rtmp_conn *conn);


struct rtmp_stream;

typedef void (rtmp_ready_h)(void *arg);
typedef void (rtmp_audio_h)(uint32_t timestamp,
			    const uint8_t *pld, size_t len, void *arg);
typedef void (rtmp_video_h)(uint32_t timestamp,
			    const uint8_t *pld, size_t len, void *arg);

int  rtmp_play(struct rtmp_stream **streamp, struct rtmp_conn *conn,
	       const char *name, rtmp_ready_h *readyh,
	       rtmp_audio_h *auh, rtmp_video_h *vidh, void *arg);
int  rtmp_publish(struct rtmp_stream **streamp, struct rtmp_conn *conn,
		  const char *name, rtmp_ready_h *ready, void *arg);
int  rtmp_send_audio(struct rtmp_stream *strm, uint32_t timestamp,
		     const uint8_t *pld, size_t len);
int  rtmp_send_video(struct rtmp_stream *strm, uint32_t timestamp,
		     const uint8_t *pld, size_t len);
bool rtmp_stream_isready(const struct rtmp_stream *strm);
int  rtmp_stream_debug(struct re_printf *pf, const struct rtmp_stream *strm);
struct rtmp_stream *rtmp_stream_alloc(struct rtmp_conn *conn,
				      const char *name,
				      uint32_t stream_id,
				      rtmp_ready_h *readyh,
				      rtmp_audio_h *auh,
				      rtmp_video_h *vidh,
				      void *arg);


/*
 * Server
 */

int rtmp_amf_reply(struct rtmp_conn *conn, const struct rtmp_amf_message *req,
		   unsigned body_propc, ...);


/*
 * Control
 */


/* XXX: make private ? */

enum event_type {
	RTMP_EVENT_STREAM_BEGIN       = 0,
	RTMP_EVENT_STREAM_EOF         = 1,
	RTMP_EVENT_STREAM_IS_RECORDED = 4,
	RTMP_EVENT_PING_REQUEST       = 6,
	RTMP_EVENT_PING_RESPONSE      = 7,
};


int rtmp_control(struct rtmp_conn *conn, enum rtmp_packet_type type, ...);
