/**
 * @file re_rtmp.h  Interface to Real Time Messaging Protocol (RTMP)
 *
 * Copyright (C) 2010 Creytiv.com
 */


/** RTMP Protocol values */
enum {
	RTMP_PORT = 1935,
};

/** RTMP Stream IDs */
enum {

	/* User Control messages SHOULD use message stream ID 0
	   (known as the control stream) */
	RTMP_CONTROL_STREAM_ID = 0
};

/** RTMP Packet types */
enum rtmp_packet_type {
	RTMP_TYPE_SET_CHUNK_SIZE     = 1,  /**< Set Chunk Size               */
	RTMP_TYPE_ACKNOWLEDGEMENT    = 3,  /**< Acknowledgement              */
	RTMP_TYPE_USER_CONTROL_MSG   = 4,  /**< User Control Messages        */
	RTMP_TYPE_WINDOW_ACK_SIZE    = 5,  /**< Window Acknowledgement Size  */
	RTMP_TYPE_SET_PEER_BANDWIDTH = 6,  /**< Set Peer Bandwidth           */
	RTMP_TYPE_AUDIO              = 8,  /**< Audio Message                */
	RTMP_TYPE_VIDEO              = 9,  /**< Video Message                */
	RTMP_TYPE_DATA               = 18, /**< Data Message                 */
	RTMP_TYPE_AMF0               = 20, /**< Action Message Format (AMF)  */
};

/** RTMP AMF types */
enum rtmp_amf_type {
	RTMP_AMF_TYPE_ROOT         = -1,    /**< Special internal type      */
	RTMP_AMF_TYPE_NUMBER       = 0x00,  /**< Number Type                */
	RTMP_AMF_TYPE_BOOLEAN      = 0x01,  /**< Boolean Type               */
	RTMP_AMF_TYPE_STRING       = 0x02,  /**< String Type                */
	RTMP_AMF_TYPE_OBJECT       = 0x03,  /**< Object Type                */
	RTMP_AMF_TYPE_NULL         = 0x05,  /**< Null type                  */
	RTMP_AMF_TYPE_ECMA_ARRAY   = 0x08,  /**< ECMA 'associative' Array   */
	RTMP_AMF_TYPE_OBJECT_END   = 0x09,  /**< Object End Type            */
	RTMP_AMF_TYPE_STRICT_ARRAY = 0x0a,  /**< Array with ordinal indices */
};

/** RTMP Event types */
enum rtmp_event_type {
	RTMP_EVENT_STREAM_BEGIN       = 0,  /**< Stream begin               */
	RTMP_EVENT_STREAM_EOF         = 1,  /**< Stream End-Of-File         */
	RTMP_EVENT_STREAM_DRY         = 2,  /**< No more data on the stream */
	RTMP_EVENT_SET_BUFFER_LENGTH  = 3,  /**< Set buffer size in [ms]    */
	RTMP_EVENT_STREAM_IS_RECORDED = 4,  /**< Stream is recorded         */
	RTMP_EVENT_PING_REQUEST       = 6,  /**< Ping Request from server   */
	RTMP_EVENT_PING_RESPONSE      = 7,  /**< Ping Response to server    */
};


/* forward declarations */
struct tls;
struct dnsc;
struct odict;
struct tcp_sock;


/*
 * RTMP High-level API (connection, stream)
 */


/* conn */
struct rtmp_conn;

typedef void (rtmp_estab_h)(void *arg);
typedef void (rtmp_command_h)(const struct odict *msg, void *arg);
typedef void (rtmp_close_h)(int err, void *arg);

int rtmp_connect(struct rtmp_conn **connp, struct dnsc *dnsc, const char *uri,
		 struct tls *tls,
		 rtmp_estab_h *estabh, rtmp_command_h *cmdh,
		 rtmp_close_h *closeh, void *arg);
int rtmp_accept(struct rtmp_conn **connp, struct tcp_sock *ts,
		struct tls *tls,
		rtmp_command_h *cmdh, rtmp_close_h *closeh, void *arg);
int rtmp_control(const struct rtmp_conn *conn,
		 enum rtmp_packet_type type, ...);
void rtmp_set_handlers(struct rtmp_conn *conn, rtmp_command_h *cmdh,
		       rtmp_close_h *closeh, void *arg);
struct tcp_conn *rtmp_conn_tcpconn(const struct rtmp_conn *conn);
const char *rtmp_conn_stream(const struct rtmp_conn *conn);
int  rtmp_conn_debug(struct re_printf *pf, const struct rtmp_conn *conn);


typedef void (rtmp_resp_h)(bool success, const struct odict *msg,
			   void *arg);

/* amf */
int rtmp_amf_command(const struct rtmp_conn *conn, uint32_t stream_id,
		     const char *command,
		     unsigned body_propc, ...);
int rtmp_amf_request(struct rtmp_conn *conn, uint32_t stream_id,
		     const char *command,
		     rtmp_resp_h *resph, void *arg, unsigned body_propc, ...);
int rtmp_amf_reply(struct rtmp_conn *conn, uint32_t stream_id, bool success,
		   const struct odict *req,
		   unsigned body_propc, ...);
int rtmp_amf_data(const struct rtmp_conn *conn, uint32_t stream_id,
		  const char *command, unsigned body_propc, ...);


/* stream */
struct rtmp_stream;

typedef void (rtmp_control_h)(enum rtmp_event_type event, struct mbuf *mb,
			      void *arg);
typedef void (rtmp_audio_h)(uint32_t timestamp,
			    const uint8_t *pld, size_t len, void *arg);
typedef void (rtmp_video_h)(uint32_t timestamp,
			    const uint8_t *pld, size_t len, void *arg);

int rtmp_stream_alloc(struct rtmp_stream **strmp, struct rtmp_conn *conn,
		      uint32_t stream_id, rtmp_command_h *cmdh,
		      rtmp_control_h *ctrlh, rtmp_audio_h *auh,
		      rtmp_video_h *vidh, rtmp_command_h *datah,
		      void *arg);
int rtmp_stream_create(struct rtmp_stream **strmp, struct rtmp_conn *conn,
		       rtmp_resp_h *resph, rtmp_command_h *cmdh,
		       rtmp_control_h *ctrlh, rtmp_audio_h *auh,
		       rtmp_video_h *vidh, rtmp_command_h *datah,
		       void *arg);
int rtmp_play(struct rtmp_stream *strm, const char *name);
int rtmp_publish(struct rtmp_stream *strm, const char *name);
int rtmp_meta(struct rtmp_stream *strm);
int rtmp_send_audio(struct rtmp_stream *strm, uint32_t timestamp,
		    const uint8_t *pld, size_t len);
int rtmp_send_video(struct rtmp_stream *strm, uint32_t timestamp,
		    const uint8_t *pld, size_t len);
struct rtmp_stream *rtmp_stream_find(const struct rtmp_conn *conn,
				     uint32_t stream_id);


const char *rtmp_event_name(enum rtmp_event_type event);
