/**
 * @file re_rtmp.h  Interface to Real Time Messaging Protocol (RTMP)
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_PROTOCOL_VERSION = 3,
	RTMP_SIG_SIZE         = 1536,
	RTMP_PORT             = 1935
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

int rtmp_header_encode(struct mbuf *mb, const struct rtmp_header *hdr);
int rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb);
int rtmp_header_print(struct re_printf *pf, const struct rtmp_header *hdr);
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
		 rtmp_chunk_h *chunkh, void *arg);


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

struct odict;

int rtmp_amf_encode_number(struct mbuf *mb, double val);
int rtmp_amf_encode_boolean(struct mbuf *mb, bool boolean);
int rtmp_amf_encode_string(struct mbuf *mb, const char *str);
int rtmp_amf_encode_object(struct mbuf *mb, const struct odict *dict);
int rtmp_amf_encode_null(struct mbuf *mb);

int rtmp_amf_decode(struct odict *dict, struct mbuf *mb);


/*
 * RTMP Handshake
 */

const char *rtmp_handshake_name(enum rtmp_handshake_state state);
