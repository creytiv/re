/**
 * @file re_rtmp.h  Interface to Real Time Messaging Protocol (RTMP)
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_PROTOCOL_VERSION  =    3,
	RTMP_DEFAULT_CHUNKSIZE =  128,
	RTMP_SIG_SIZE          = 1536,
	RTMP_PORT              = 1935,
};


enum rtmp_handshake_state {
	RTMP_STATE_UNINITIALIZED = 0,
	RTMP_STATE_VERSION_SENT,
	RTMP_STATE_ACK_SENT,
	RTMP_STATE_HANDSHAKE_DONE
};

enum rtmp_packet_type {
	RTMP_TYPE_WINDOW_ACK_SIZE =  5,  /* Window Acknowledgement Size  */
	RTMP_TYPE_AUDIO           =  8,  /* Audio Message                */
	RTMP_TYPE_AMF0            = 20,  /* Action Message Format (AMF)  */
};


struct rtmp_header {
	unsigned format:2;           /* type 0-3 */
	uint32_t chunk_id;           /* from 3-65599 */

	uint32_t timestamp;          /* 24-bit */
	uint32_t timestamp_delta;    /* 24-bit */
	uint32_t message_length;     /* 24-bit */
	uint8_t message_type_id;     /* enum rtmp_packet_type */
	uint32_t message_stream_id;
};


/*
 * RTMP Header
 */

int rtmp_header_encode_type0(struct mbuf *mb, uint32_t chunk_id,
			     uint32_t timestamp, uint32_t msg_length,
			     uint8_t msg_type_id, uint32_t msg_stream_id);
int rtmp_header_encode_type1(struct mbuf *mb, uint32_t chunk_id,
			     uint32_t timestamp_delta, uint32_t msg_length,
			     uint8_t msg_type_id);
int rtmp_header_encode_type2(struct mbuf *mb, uint32_t chunk_id,
			     uint32_t timestamp_delta);
int rtmp_header_encode_type3(struct mbuf *mb, uint32_t chunk_id);

int rtmp_header_decode(struct rtmp_header *hdr, struct mbuf *mb);
int rtmp_header_print(struct re_printf *pf, const struct rtmp_header *hdr);


/*
 * RTMP Chunk
 */

typedef int (rtmp_chunk_h)(const uint8_t *hdr, size_t hdr_len,
			    const uint8_t *pld, size_t pld_len, void *arg);

int rtmp_chunker(uint32_t chunk_id, uint32_t timestamp,
		 uint8_t msg_type_id, uint32_t msg_stream_id,
		 const uint8_t *payload, size_t payload_len,
		 rtmp_chunk_h *chunkh, void *arg);


/*
 * RTMP De-chunker
 */

struct rtmp_dechunker;

typedef void (rtmp_msg_h)(enum rtmp_packet_type type,
			  const uint8_t *msg, size_t len, void *arg);

int rtmp_dechunker_alloc(struct rtmp_dechunker **rdp,
			 rtmp_msg_h *msgh, void *arg);
int rtmp_dechunker_receive(struct rtmp_dechunker *rd, struct mbuf *mb);
