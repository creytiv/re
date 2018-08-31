/**
 * @file rtmp/conn.c  Real Time Messaging Protocol (RTMP) -- NetConnection
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_tcp.h>
#include <re_sys.h>
#include <re_odict.h>
#include <re_rtmp.h>
#include "rtmp.h"


#define CONN_CHUNK_ID  (3)
#define CONN_STREAM_ID (0)  /* always zero for netconn */


/* User Control messages SHOULD use message stream ID 0
   (known as the control stream)*/
#define RTMP_CONTROL_STREAM_ID (0)


#define WINDOW_ACK_SIZE 2500000


enum event_type {
	EVENT_STREAM_BEGIN       = 0,
	EVENT_STREAM_IS_RECORDED = 4,
	EVENT_PING_REQUEST       = 6,
	EVENT_PING_RESPONSE      = 7,
};


static void conn_close(struct rtmp_conn *conn, int err);
static int rtmp_chunk_handler(const struct rtmp_header *hdr,
			      const uint8_t *pld, size_t pld_len, void *arg);


static int build_connect(struct mbuf *mb, const char *app, const char *url)
{
	double transaction_id = 1.0;
	int err;
	const int aucodecs  = 0x0400;  /* AAC  */
	const int vidcodecs = 0x0080;  /* H264 */

	err = rtmp_command_header_encode(mb, "connect", transaction_id);

	err |= rtmp_amf_encode_object(mb, false, 8,
		     AMF_TYPE_STRING, "app", app,
		     AMF_TYPE_STRING, "flashVer", "LNX 9,0,124,2",
		     AMF_TYPE_STRING, "tcUrl", url,
		     AMF_TYPE_BOOLEAN, "fpad", false,
		     AMF_TYPE_NUMBER, "capabilities", 15.0,
		     AMF_TYPE_NUMBER, "audioCodecs", (double)aucodecs,
		     AMF_TYPE_NUMBER, "videoCodecs", (double)vidcodecs,
		     AMF_TYPE_NUMBER, "videoFunction", 1.0);

	return err;
}


static void conn_destructor(void *data)
{
	struct rtmp_conn *conn = data;

	re_printf("%H\n", rtmp_conn_debug, conn);

	list_flush(&conn->streaml);

	mem_deref(conn->tc);
	mem_deref(conn->mb);
	mem_deref(conn->dechunk);
	mem_deref(conn->uri);
	mem_deref(conn->app);
}


/* Server */
static int send_reply(struct rtmp_conn *conn, uint64_t transaction_id)
{
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(256);
	if (!mb)
		return ENOMEM;

	re_printf("[%s] reply: tid=%llu\n",
		  conn->is_client ? "Client" : "Server",
		  transaction_id);

	err  = rtmp_command_header_encode(mb, "_result", transaction_id);

	err |= rtmp_amf_encode_object(mb, false, 3,
		     AMF_TYPE_STRING, "fmsVer",       "FMS/3,5,7,7009",
		     AMF_TYPE_NUMBER, "capabilities", 31.0,
		     AMF_TYPE_NUMBER, "mode",         1.0);

	err |= rtmp_amf_encode_object(mb, false, 6,
	      AMF_TYPE_STRING, "level",        "status",
	      AMF_TYPE_STRING, "code",         "NetConnection.Connect.Success",
	      AMF_TYPE_STRING, "description",  "Connection succeeded.",
	      AMF_TYPE_ARRAY,  "data",         1,
	      AMF_TYPE_STRING, "version",      "3,5,7,7009",
	      AMF_TYPE_NUMBER, "clientid",     734806661.0,
	      AMF_TYPE_NUMBER, "objectEncoding", 0.0);
	if (err)
		goto out;

	err = rtmp_send_amf_command(conn, 0, CONN_CHUNK_ID, CONN_STREAM_ID,
			       mb->buf, mb->end);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}


static int control_send_was(struct rtmp_conn *conn, uint32_t was)
{
	struct mbuf *mb = mbuf_alloc(4);
	int err;

	if (!mb)
		return ENOMEM;

	(void)mbuf_write_u32(mb, htonl(was));

	err = rtmp_conn_send_msg(conn, 0, RTMP_CHUNK_ID_CONTROL, 0, 0,
				 RTMP_TYPE_WINDOW_ACK_SIZE, CONN_STREAM_ID,
				 mb->buf, mb->end);

	mem_deref(mb);

	return err;
}


static int control_send_set_peer_bw(struct rtmp_conn *conn,
				    size_t was, uint8_t limit_type)
{
	struct mbuf *mb = mbuf_alloc(5);
	uint32_t chunk_id = RTMP_CHUNK_ID_CONTROL;
	uint32_t timestamp = 0;
	uint32_t timestamp_delta = 0;
	int err;

	if (!mb)
		return ENOMEM;

	(void)mbuf_write_u32(mb, htonl(was));
	(void)mbuf_write_u8(mb, limit_type);

	err = rtmp_chunker(0, chunk_id, timestamp, timestamp_delta,
			   RTMP_TYPE_SET_PEER_BANDWIDTH, CONN_STREAM_ID,
			   mb->buf, mb->end, rtmp_chunk_handler, conn);

	mem_deref(mb);

	return err;
}


/* Stream Begin */
static int control_send_user_control_msg(struct rtmp_conn *conn,
					 uint32_t stream_id)
{
	struct mbuf *mb = mbuf_alloc(6);
	uint32_t chunk_id = RTMP_CHUNK_ID_CONTROL;
	uint32_t timestamp = 0;
	uint32_t timestamp_delta = 0;
	int err;

	if (!mb)
		return ENOMEM;

	(void)mbuf_write_u16(mb, htons(EVENT_STREAM_BEGIN));
	(void)mbuf_write_u32(mb, htonl(stream_id));

	err = rtmp_chunker(0, chunk_id, timestamp, timestamp_delta,
			   RTMP_TYPE_USER_CONTROL_MSG, CONN_STREAM_ID,
			   mb->buf, mb->end, rtmp_chunk_handler, conn);

	mem_deref(mb);

	return err;
}


static bool is_established(const struct rtmp_conn *conn)
{
	return conn->estab && conn->window_ack_size;
}


static void check_established(struct rtmp_conn *conn)
{
	rtmp_estab_h *estabh;

	if (!is_established(conn))
		return;

	estabh = conn->estabh;
	if (estabh) {
		conn->estabh = NULL;
		estabh(conn->arg);
	}
}


static void client_handle_amf_command(struct rtmp_conn *conn,
				      const struct command_header *cmd_hdr,
				      struct odict *dict)
{
	(void)dict;

	if (0 == str_casecmp(cmd_hdr->name, "_result")) {

		if (conn->estab)
			return;

		re_printf("client: Established\n");

		conn->estab = true;

		check_established(conn);
	}
	else if (0 == str_casecmp(cmd_hdr->name, "onStatus")) {

		re_printf("rtmp: client: recv onStatus\n");

		if (conn->statush)
			conn->statush(dict, conn->arg);
	}
	else {
		re_printf("rtmp: client: command not handled (%s)\n",
			  cmd_hdr->name);
	}
}


static void server_handle_amf_command(struct rtmp_conn *conn,
				      const struct command_header *cmd_hdr,
				      struct odict *dict)
{
	int err = 0;

	(void)dict;

	if (0 == str_casecmp(cmd_hdr->name, "connect")) {

		if (conn->estab)
			return;

		err = control_send_was(conn, WINDOW_ACK_SIZE);
		if (err)
			goto error;

		err = control_send_set_peer_bw(conn, WINDOW_ACK_SIZE, 2);
		if (err)
			goto error;

		err = control_send_user_control_msg(conn,
						    RTMP_CONTROL_STREAM_ID);
		if (err)
			goto error;

		err = send_reply(conn, cmd_hdr->transaction_id);
		if (err) {
			re_printf("rtmp: reply failed (%m)\n", err);
			goto error;
		}

		conn->estab = true;

		check_established(conn);
	}
	else if (0 == str_casecmp(cmd_hdr->name, "createStream")) {

		re_printf("got createStream\n");
		conn->createstream = true;

		/* XXX send_reply();*/
	}
	else {
		re_printf("rtmp: server: command not handled (%s)\n",
			  cmd_hdr->name);
	}

	return;

 error:
	if (err)
		conn_close(conn, err);
}


static void handle_amf_command(struct rtmp_conn *conn,
			       const uint8_t *cmd, size_t len)
{
	struct mbuf mb = {
		.buf = (uint8_t *)cmd,
		.end = len,
		.size = len,
	};
	struct command_header cmd_hdr;
	struct odict *dict;
	int err;

	err = odict_alloc(&dict, 32);
	if (err)
		return;

	err = rtmp_amf_decode(dict, &mb);
	if (err) {
		re_printf("rtmp: amf decode error (%m)\n", err);
		goto out;
	}

	err = rtmp_command_header_decode(&cmd_hdr, dict);
	if (err) {
		re_printf("could not decode command header (%m)\n", err);
		goto out;
	}

#if 1
	re_printf("[%s] Command: %H\n",
		  conn->is_client ? "Client" : "Server",
		  rtmp_command_header_print, &cmd_hdr);
	re_printf("     %H\n", odict_debug, dict);
#endif

	if (conn->is_client) {
		client_handle_amf_command(conn, &cmd_hdr, dict);
	}
	else {
		server_handle_amf_command(conn, &cmd_hdr, dict);
	}

 out:
	mem_deref(dict);
}


static int handle_user_control_msg(struct rtmp_conn *conn, struct mbuf *mb)
{
	struct rtmp_stream *strm;
	enum event_type event;
	uint32_t stream_id;

	event = ntohs(mbuf_read_u16(mb));

	re_printf("[%s] got User Control Message:"
		  " event_type=%u event_data=%zu bytes\n",
		  conn->is_client ? "Client" : "Server",
		  event, mbuf_get_left(mb));

	switch (event) {

	case EVENT_STREAM_BEGIN:
		stream_id = ntohl(mbuf_read_u32(mb));

		re_printf("rtmp: Stream Begin (stream_id=%u)\n", stream_id);

		if (stream_id == RTMP_CONTROL_STREAM_ID) {
			conn->stream_begin = true;
		}
		else {
			strm = rtmp_stream_find(&conn->streaml, stream_id);
			if (!strm) {
				re_printf("rtmp: stream_begin:"
					  " stream %u not found\n", stream_id);
				return ENOSTR;
			}
		}
		break;

	case EVENT_STREAM_IS_RECORDED:
		stream_id = ntohl(mbuf_read_u32(mb));
		re_printf("rtmp: StreamIsRecorded (stream_id=%u)\n",
			  stream_id);
		break;

	default:
		re_printf("rtmp: user_control:"
			  " unhandled event %u\n", event);
		return EPROTO;  /* XXX: for development */
	}

	return 0;
}


static void rtmp_msg_handler(struct rtmp_message *msg, void *arg)
{
	struct rtmp_conn *conn = arg;
	struct rtmp_stream *strm;
	void *p;
	uint32_t val;
	struct mbuf mb = {
		.pos = 0,
		.end = msg->length,
		.size = msg->length,
		.buf = msg->buf
	};
	uint32_t was;
	uint8_t limit;
	int err = 0;

	if (conn->term)
		return;

	re_printf("[%s] ### recv message: type 0x%02x (%s) (%zu bytes)\n",
		  conn->is_client ? "Client" : "Server",
		  msg->type, rtmp_packet_type_name(msg->type), msg->length);

	switch (msg->type) {

	case RTMP_TYPE_SET_CHUNK_SIZE:
		p = msg->buf;
		val = *(uint32_t *)p;

		val = ntohl(val) & 0x7fffffff;

		re_printf("set chunk size:  %u bytes\n", val);

		rtmp_dechunker_set_chunksize(conn->dechunk, val);
		break;

	case RTMP_TYPE_AMF0:
		handle_amf_command(conn, msg->buf, msg->length);
		break;

	case RTMP_TYPE_WINDOW_ACK_SIZE:
		was = ntohl(mbuf_read_u32(&mb));
		re_printf("[%s] got Window Ack Size from peer: %u\n",
			  conn->is_client ? "Client" : "Server", was);
		conn->window_ack_size = was;

		check_established(conn);
		break;

	case RTMP_TYPE_SET_PEER_BANDWIDTH:
		was = ntohl(mbuf_read_u32(&mb));
		limit = mbuf_read_u8(&mb);
		re_printf("[%s] got Set Peer Bandwidth from peer:"
			  " was=%u, limit_type=%u\n",
			  conn->is_client ? "Client" : "Server",
			  was, limit);

		err = control_send_was(conn, WINDOW_ACK_SIZE);
		if (err)
			goto error;
		break;

	case RTMP_TYPE_USER_CONTROL_MSG:
		err = handle_user_control_msg(conn, &mb);
		if (err)
			goto error;
		break;

	case RTMP_TYPE_AUDIO:
		strm = rtmp_stream_find(&conn->streaml, msg->stream_id);
		if (strm) {
			if (strm->auh)
				strm->auh(msg->buf, msg->length, strm->arg);
		}
		else {
			re_printf("rtmp: audio: stream not found (%u)\n",
				  msg->stream_id);
		}
		break;

	case RTMP_TYPE_VIDEO:
		strm = rtmp_stream_find(&conn->streaml, msg->stream_id);
		if (strm) {
			if (strm->vidh)
				strm->vidh(msg->buf, msg->length, strm->arg);
		}
		else {
			re_printf("rtmp: video: stream not found (%u)\n",
				  msg->stream_id);
		}
		break;

	case RTMP_TYPE_DATA:
		/* XXX: pass to app */
		break;

	default:
		re_printf("rtmp: conn: unhandled message:"
			  " type=%d (%s)\n",
			  msg->type, rtmp_packet_type_name(msg->type));
		break;
	}

	return;

 error:
	if (err)
		conn_close(conn, err);
}


static struct rtmp_conn *rtmp_conn_alloc(bool is_client,
					 rtmp_estab_h *estabh,
					 rtmp_status_h *statush,
					 rtmp_close_h *closeh,
					 void *arg)
{
	struct rtmp_conn *conn;
	int err;

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn)
		return NULL;

	conn->is_client = is_client;
	conn->state = RTMP_STATE_UNINITIALIZED;

	rand_bytes(conn->x1, sizeof(conn->x1));

	err = rtmp_dechunker_alloc(&conn->dechunk, rtmp_msg_handler, conn);
	if (err)
		goto out;

	conn->estabh = estabh;
	conn->statush = statush;
	conn->closeh = closeh;
	conn->arg = arg;

 out:
	if (err)
		return mem_deref(conn);

	return conn;
}


static void set_state(struct rtmp_conn *conn, enum rtmp_handshake_state state)
{
	if (!conn)
		return;

	re_printf("[%s] set state: %d (%s)\n",
		  conn->is_client ? "Client" : "Server",
		  state, rtmp_handshake_name(state));

	conn->state = state;
}


static int send_packet(struct rtmp_conn *conn,
		       const uint8_t *pkt, size_t len)
{
	struct mbuf *mb = mbuf_alloc(len);
	int err;

	if (!conn || !pkt || !len)
		return EINVAL;

	err = mbuf_write_mem(mb, pkt, len);
	if (err)
		goto out;

	mb->pos = 0;

	re_printf("[%s] send packet (%zu bytes)\n",
		  conn->is_client ? "Client" : "Server", mb->end);

	err = tcp_send(conn->tc, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}


static int handshake_start(struct rtmp_conn *conn)
{
	const uint8_t x0 = RTMP_PROTOCOL_VERSION;
	int err;

	err = send_packet(conn, &x0, sizeof(x0));
	if (err)
		return err;

	err = send_packet(conn, conn->x1, sizeof(conn->x1));
	if (err)
		return err;

	set_state(conn, RTMP_STATE_VERSION_SENT);

	return 0;
}


static void conn_close(struct rtmp_conn *conn, int err)
{
	re_printf("rtmp: connection closed (%m)\n", err);

	conn->tc = mem_deref(conn->tc);

	conn->term = true;

	if (conn->closeh)
		conn->closeh(err, conn->arg);
}


static void tcp_estab_handler(void *arg)
{
	struct rtmp_conn *conn = arg;
	int err = 0;

	re_printf("[%s] TCP established\n",
		  conn->is_client ? "Client" : "Server");

	if (conn->is_client) {

		err = handshake_start(conn);
		if (err)
			goto out;
	}

 out:
	if (err) {
		conn_close(conn, err);
	}
}


static int rtmp_chunk_handler(const struct rtmp_header *hdr,
			      const uint8_t *pld, size_t pld_len, void *arg)
{
	struct rtmp_conn *conn = arg;
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err  = rtmp_header_encode(mb, hdr);
	err |= mbuf_write_mem(mb, pld, pld_len);
	if (err)
		goto out;

	mb->pos = 0;

	err = tcp_send(conn->tc, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}


int rtmp_send_amf_command(struct rtmp_conn *conn,
			    unsigned format, uint32_t chunk_id,
			    uint32_t msg_stream_id,
			    const uint8_t *cmd, size_t len)
{
	uint32_t timestamp = 0;
	int err;

	if (!conn || !cmd || !len)
		return EINVAL;

	re_printf("[%s] send AMF command: [fmt=%u, chunk=%u, stream=%u]"
		  " %zu bytes\n",
		  conn->is_client ? "Client" : "Server",
		  format, chunk_id, msg_stream_id, len);

	err = rtmp_chunker(format, chunk_id,
			   timestamp, 0,
			   RTMP_TYPE_AMF0, msg_stream_id,
			   cmd, len,
			   rtmp_chunk_handler, conn);
	if (err)
		return err;

	return 0;
}


static int send_connect(struct rtmp_conn *conn)
{
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(512);

	err = build_connect(mb, conn->app, conn->uri);
	if (err)
		goto out;

	err = rtmp_send_amf_command(conn, 0, CONN_CHUNK_ID, CONN_STREAM_ID,
				    mb->buf, mb->end);
	if (err) {
		re_printf("rtmp: failed to send AMF command (%m)\n", err);
		goto out;
	}

 out:
	mem_deref(mb);

	return err;
}


static int handshake_done(struct rtmp_conn *conn)
{
	int err;

	re_printf("[%s] ** handshake done **\n",
		  conn->is_client ? "Client" : "Server");

	if (conn->is_client) {

		err = send_connect(conn);
		if (err)
			return err;
	}

	return 0;
}


static int client_handle_packet(struct rtmp_conn *conn, struct mbuf *mb)
{
	uint8_t s0;
	uint8_t s1[RTMP_SIG_SIZE];
	uint8_t s2[RTMP_SIG_SIZE];
	uint8_t c2[RTMP_SIG_SIZE];
	int err = 0;

	switch (conn->state) {

	case RTMP_STATE_VERSION_SENT:
		if (mbuf_get_left(mb) < (1+RTMP_SIG_SIZE))
			return ENODATA;

		s0 = mbuf_read_u8(mb);
		if (s0 != RTMP_PROTOCOL_VERSION) {
			re_printf("rtmp: handshake: illegal version %u\n", s0);
			return EPROTO;
		}

		err = mbuf_read_mem(mb, s1, sizeof(s1));
		if (err)
			return err;

		memcpy(c2, s1, sizeof(c2));

		err = send_packet(conn, c2, sizeof(c2));
		if (err)
			return err;

		set_state(conn, RTMP_STATE_ACK_SENT);
		break;

	case RTMP_STATE_ACK_SENT:
		if (mbuf_get_left(mb) < RTMP_SIG_SIZE)
			return ENODATA;

		err = mbuf_read_mem(mb, s2, sizeof(s2));
		if (err)
			return err;

		/* XXX: compare */

		set_state(conn, RTMP_STATE_HANDSHAKE_DONE);

		handshake_done(conn);
		break;

	case RTMP_STATE_HANDSHAKE_DONE:
		err = rtmp_dechunker_receive(conn->dechunk, mb);
		if (err)
			return err;
		break;

	default:
		re_printf("[%s] unhandled state %d\n",
			  conn->is_client ? "Client" : "Server",
			  conn->state);
		return EPROTO;
	}

	return 0;
}


static int server_handle_packet(struct rtmp_conn *conn, struct mbuf *mb)
{
	uint8_t c0;
	uint8_t s2[RTMP_SIG_SIZE];
	uint8_t c1[RTMP_SIG_SIZE];
	uint8_t c2[RTMP_SIG_SIZE];
	int err = 0;

	switch (conn->state) {

	case RTMP_STATE_UNINITIALIZED:
		if (mbuf_get_left(mb) < (1+RTMP_SIG_SIZE))
			return ENODATA;

		c0 = mbuf_read_u8(mb);
		if (c0 != RTMP_PROTOCOL_VERSION) {
			re_printf("rtmp: handshake: illegal version %u\n", c0);
			return EPROTO;
		}

		err = mbuf_read_mem(mb, c1, sizeof(c1));
		if (err)
			return err;

		err = handshake_start(conn);
		break;

	case RTMP_STATE_VERSION_SENT:
		if (mbuf_get_left(mb) < (RTMP_SIG_SIZE))
			return ENODATA;

		err = mbuf_read_mem(mb, c2, sizeof(c2));
		if (err)
			return err;

		/* XXX memcpy(c2, s1, sizeof(c2)); */
		memset(s2, 0, sizeof(s2));

		err = send_packet(conn, s2, sizeof(s2));
		if (err)
			return err;

		set_state(conn, RTMP_STATE_ACK_SENT);
		set_state(conn, RTMP_STATE_HANDSHAKE_DONE);

		handshake_done(conn);
		break;

	case RTMP_STATE_HANDSHAKE_DONE:
		err = rtmp_dechunker_receive(conn->dechunk, mb);
		if (err)
			return err;
		break;

	default:
		re_printf("[%s] unhandled state %d\n",
			  conn->is_client ? "Client" : "Server",
			  conn->state);
		return EPROTO;
	}

	return 0;
}


static void tcp_recv_handler(struct mbuf *mb_pkt, void *arg)
{
	struct rtmp_conn *conn = arg;
	int err;

#if 0
	re_printf("[%s] tcp recv %zu bytes\n",
		  conn->is_client ? "Client" : "Server",
		  mbuf_get_left(mb_pkt));
#endif

	/* re-assembly of fragments */
	if (conn->mb) {
		size_t pos;

		pos = conn->mb->pos;

		conn->mb->pos = conn->mb->end;

		err = mbuf_write_mem(conn->mb,
				     mbuf_buf(mb_pkt), mbuf_get_left(mb_pkt));
		if (err)
			goto out;

		conn->mb->pos = pos;
	}
	else {
		conn->mb = mem_ref(mb_pkt);
	}

	while (mbuf_get_left(conn->mb) > 0) {

		size_t pos;

		pos = conn->mb->pos;

		if (conn->is_client)
			err = client_handle_packet(conn, conn->mb);
		else
			err = server_handle_packet(conn, conn->mb);
		if (err) {

			/* rewind */
			conn->mb->pos = pos;

			if (err == ENODATA) {
#if 0
				re_printf("rtmp: conn: wait for more data"
					  " (%zu bytes in buffer)\n",
					  conn->mb->end - conn->mb->pos);
#endif
				err = 0;
			}
			break;
		}

		if (conn->mb->pos >= conn->mb->end) {
			conn->mb = mem_deref(conn->mb);
			break;
		}
	}

 out:
	if (err)
		conn_close(conn, err);
}


static void tcp_close_handler(int err, void *arg)
{
	struct rtmp_conn *conn = arg;

	re_printf("TCP connection closed (%m)\n", err);

	conn_close(conn, err);
}


int rtmp_connect(struct rtmp_conn **connp, const char *uri,
		 rtmp_estab_h *estabh, rtmp_status_h *statush,
		 rtmp_close_h *closeh, void *arg)
{
	struct rtmp_conn *conn;
	struct pl pl_addr;
	struct pl pl_port = pl_null;
	struct pl pl_app;
	struct sa addr;
	uint16_t port;
	int err = 0;

	if (!connp || !uri)
		return EINVAL;

	if (re_regex(uri, strlen(uri), "rtmp://[^:/]+[:]*[0-9]*/[^/]+/[^]+",
		     &pl_addr, NULL, &pl_port, &pl_app, NULL)) {
		re_printf("rtmp: invalid uri '%s'\n", uri);
		return EINVAL;
	}

	port = pl_isset(&pl_port) ? pl_u32(&pl_port) : RTMP_PORT;

	err = sa_set(&addr, &pl_addr, port);
	if (err)
		return err;

	conn = rtmp_conn_alloc(true, estabh, statush, closeh, arg);
	if (!conn)
		return ENOMEM;

	err |= pl_strdup(&conn->app, &pl_app);
	err |= str_dup(&conn->uri, uri);
	if (err)
		goto out;

	err = tcp_connect(&conn->tc, &addr, tcp_estab_handler,
			  tcp_recv_handler, tcp_close_handler, conn);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(conn);
	else
		*connp = conn;

	return err;
}


int rtmp_accept(struct rtmp_conn **connp, struct tcp_sock *ts,
		rtmp_estab_h *estabh, rtmp_status_h *statush,
		rtmp_close_h *closeh, void *arg)
{
	struct rtmp_conn *conn;
	int err;

	if (!connp || !ts)
		return EINVAL;

	conn = rtmp_conn_alloc(false, estabh, statush, closeh, arg);
	if (!conn)
		return ENOMEM;

	err = tcp_accept(&conn->tc, ts, tcp_estab_handler,
			 tcp_recv_handler, tcp_close_handler, conn);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(conn);
	else
		*connp = conn;

	return err;
}


uint32_t rtmp_window_ack_size(const struct rtmp_conn *conn)
{
	if (!conn)
		return 0;

	return conn->window_ack_size;
}


int rtmp_createstream(struct rtmp_conn *conn)
{
	struct mbuf *mb;
	int err;

	if (!conn)
		return EINVAL;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err  = rtmp_command_header_encode(mb, "createStream", 2);
	err |= rtmp_amf_encode_null(mb);
	if (err)
		goto out;

	err = rtmp_send_amf_command(conn, 1, CONN_CHUNK_ID, CONN_STREAM_ID,
				    mb->buf, mb->end);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}


int rtmp_conn_send_msg(struct rtmp_conn *conn,
		       unsigned format, uint32_t chunk_id,
		       uint32_t timestamp, uint32_t timestamp_delta,
		       uint8_t msg_type_id, uint32_t msg_stream_id,
		       const uint8_t *payload, size_t payload_len)
{
	int err;

	if (!conn)
		return EINVAL;

	err = rtmp_chunker(format, chunk_id, timestamp, timestamp_delta,
			   msg_type_id, msg_stream_id, payload, payload_len,
			   rtmp_chunk_handler, conn);
	if (err)
		return err;

	return 0;
}


int rtmp_conn_debug(struct re_printf *pf, const struct rtmp_conn *conn)
{
	int err = 0;

	if (!conn)
		return 0;

	err |= re_hprintf(pf, "role:          %s\n",
			  conn->is_client ? "Client" : "Server");
	err |= re_hprintf(pf, "state:         %s\n",
			  rtmp_handshake_name(conn->state));
	err |= re_hprintf(pf, "estab:         %d\n", conn->estab);

	err |= re_hprintf(pf, "createstream:  %d\n", conn->createstream);
	err |= re_hprintf(pf, "stream_begin:  %d\n", conn->stream_begin);

	return err;
}
