/**
 * @file re_rtmp.h  Interface to Real Time Messaging Protocol (RTMP)
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_PROTOCOL_VERSION = 3,
	RTMP_SIG_SIZE         = 1536,
	RTMP_PORT             = 1935,
	RTMP_DEFAULT_CHUNKSIZE = 128,
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

enum rtmp_packet_type {
	RTMP_TYPE_SET_CHUNK_SIZE     = 1,   /* Set Chunk Size               */
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


/*
 * RTMP Header
 */

void rtmp_header_init(struct rtmp_header *hdr,
		      unsigned fmt, uint32_t chunk_id);
int  rtmp_header_encode(struct mbuf *mb, const struct rtmp_header *hdr);
int  rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb);
int  rtmp_header_print(struct re_printf *pf, const struct rtmp_header *hdr);
const char *rtmp_packet_type_name(enum rtmp_packet_type type);


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
 * RTMP De-chunker
 */

struct rtmp_message {
	struct le le;
	uint32_t chunk_id;
	size_t length;
	uint8_t *buf;
	size_t pos;             /* how many bytes received so far */
	uint8_t type;
	uint32_t stream_id;
};

struct rtmp_dechunker;

typedef void (rtmp_msg_h)(struct rtmp_message *msg, void *arg);

int  rtmp_dechunker_alloc(struct rtmp_dechunker **rdp,
			  rtmp_msg_h *msgh, void *arg);
int  rtmp_dechunker_receive(struct rtmp_dechunker *rd, struct mbuf *mb);
void rtmp_dechunker_set_chunksize(struct rtmp_dechunker *rd, size_t chunk_sz);


/*
 * AMF (Action Message Format)
 */

enum amf_type {
	AMF_TYPE_NUMBER     = 0x00,
	AMF_TYPE_BOOLEAN    = 0x01,
	AMF_TYPE_STRING     = 0x02,
	AMF_TYPE_OBJECT     = 0x03,
	AMF_TYPE_NULL       = 0x05,
	AMF_TYPE_ARRAY      = 0x08,
	AMF_TYPE_OBJECT_END = 0x09,
};

/* XXX: find a better name */
enum class {
	CLASS_OBJECT = 0,
	CLASS_ARRAY  = 1,
	CLASS_ROOT   = 2
};

struct odict;

int rtmp_amf_encode_number(struct mbuf *mb, double val);
int rtmp_amf_encode_boolean(struct mbuf *mb, bool boolean);
int rtmp_amf_encode_string(struct mbuf *mb, const char *str);
int rtmp_amf_encode_null(struct mbuf *mb);
int rtmp_amf_encode_object(struct mbuf *mb, enum class class,
			   unsigned propc, ...);

int rtmp_amf_decode(struct odict *dict, struct mbuf *mb);


/*
 * RTMP Handshake
 */

const char *rtmp_handshake_name(enum rtmp_handshake_state state);


/*
 * RTMP High-level API (socket, connection, stream)
 */


typedef void (rtmp_conn_h)(struct tcp_sock *ts, void *arg);

struct rtmp_sock;

int rtmp_listen(struct rtmp_sock **sockp, const struct sa *laddr,
		rtmp_conn_h *connh, void *arg);


struct rtmp_conn;

typedef void (rtmp_estab_h)(void *arg);
typedef void (rtmp_status_h)(struct odict *dict, void *arg);
typedef void (rtmp_close_h)(int err, void *arg);


int rtmp_connect(struct rtmp_conn **connp, const char *uri,
		 rtmp_estab_h *estabh, rtmp_status_h *statush,
		 rtmp_close_h *closeh, void *arg);
int rtmp_accept(struct rtmp_conn **connp, struct tcp_sock *ts,
		rtmp_estab_h *estabh, rtmp_status_h *statush,
		rtmp_close_h *closeh, void *arg);
int rtmp_createstream(struct rtmp_conn *conn);
int rtmp_send_amf_command(struct rtmp_conn *conn,
			  unsigned format, uint32_t chunk_id,
			  uint32_t msg_stream_id,
			  const uint8_t *cmd, size_t len);
uint32_t rtmp_window_ack_size(const struct rtmp_conn *conn);
int rtmp_conn_debug(struct re_printf *pf, const struct rtmp_conn *conn);


struct rtmp_stream;

typedef void (rtmp_audio_h)(const uint8_t *pld, size_t len, void *arg);
typedef void (rtmp_video_h)(const uint8_t *pld, size_t len, void *arg);

int rtmp_play(struct rtmp_stream **streamp, struct rtmp_conn *conn,
	      const char *name, uint32_t stream_id,
	      rtmp_audio_h *auh, rtmp_video_h *vidh, void *arg);
int rtmp_publish(struct rtmp_stream **streamp, struct rtmp_conn *conn,
		 const char *name, uint32_t stream_id);
int rtmp_send_audio(struct rtmp_stream *stream, ...);
int rtmp_send_video(struct rtmp_stream *strm, const uint8_t *pld, size_t len);
