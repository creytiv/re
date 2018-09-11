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


#define WINDOW_ACK_SIZE 2500000


enum {
	RTMP_BUFSIZE_MAX  = 524288,
};


static void conn_close(struct rtmp_conn *conn, int err);


static void get_version(uint8_t version[4])
{
	const char *ver_str = sys_libre_version_get();
	struct pl plv[3];
	int i;

	memset(version, 0, 4);

	if (0 == re_regex(ver_str, str_len(ver_str),
			  "[0-9]+.[0-9]+.[0-9]+",
			  &plv[0], &plv[1], &plv[2])) {

		for (i=0; i<3; i++) {

			version[i] = pl_u32(&plv[i]);
		}
	}
}


static void conn_destructor(void *data)
{
	struct rtmp_conn *conn = data;

	list_flush(&conn->ctransl);
	list_flush(&conn->streaml);

	mem_deref(conn->tc);
	mem_deref(conn->mb);
	mem_deref(conn->dechunk);
	mem_deref(conn->uri);
	mem_deref(conn->app);
}


static bool is_established(const struct rtmp_conn *conn)
{
	return conn->connected && conn->window_ack_size;
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
	int err;

	(void)dict;

	if (0 == str_casecmp(cmd_hdr->name, "_result") ||
	    0 == str_casecmp(cmd_hdr->name, "_error")) {

		bool success = (0 == str_casecmp(cmd_hdr->name, "_result"));

		/* forward response to transaction layer */
		err = rtmp_ctrans_response(&conn->ctransl, success,
					   cmd_hdr, dict);
		if (err)
			goto error;
	}
	else if (0 == str_casecmp(cmd_hdr->name, "onStatus")) {

		re_printf("rtmp: client: recv onStatus\n");

		/* XXX: lookup stream_id, pass to struct rtmp_stream ? */

		if (conn->statush)
			conn->statush(dict, conn->arg);
	}
	else {
		re_printf("rtmp: client: command not handled (%s)\n",
			  cmd_hdr->name);

		/* XXX: for development */
		conn_close(conn, EPROTO);
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

#if 0
	re_printf("[%s] Command: %H\n",
		  conn->is_client ? "Client" : "Server",
		  rtmp_command_header_print, &cmd_hdr);
	re_printf("     %H\n", odict_debug, dict);
#endif

	if (conn->is_client) {
		client_handle_amf_command(conn, &cmd_hdr, dict);
	}
	else {
		if (conn->cmdh)
			conn->cmdh(&cmd_hdr, dict, conn->arg);
	}

 out:
	mem_deref(dict);
}


static int handle_user_control_msg(struct rtmp_conn *conn, struct mbuf *mb)
{
	struct rtmp_stream *strm;
	enum event_type event;
	uint32_t stream_id;
	uint32_t value;
	int err;

	if (mbuf_get_left(mb) < 2)
		return EBADMSG;

	event = ntohs(mbuf_read_u16(mb));

#if 0
	re_printf("[%s] got User Control Message:"
		  " event_type=%u event_data=%zu bytes\n",
		  conn->is_client ? "Client" : "Server",
		  event, mbuf_get_left(mb));
#endif

	switch (event) {

	case RTMP_EVENT_STREAM_BEGIN:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;
		stream_id = ntohl(mbuf_read_u32(mb));

		if (stream_id != RTMP_CONTROL_STREAM_ID) {

			strm = rtmp_stream_find(&conn->streaml, stream_id);
			if (!strm) {
				re_printf("rtmp: stream_begin:"
					  " stream %u not found\n", stream_id);
				return ENOSTR;
			}
			strm->begin = true;
		}
		break;

	case RTMP_EVENT_STREAM_EOF:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;
		stream_id = ntohl(mbuf_read_u32(mb));

		if (stream_id != RTMP_CONTROL_STREAM_ID) {

			strm = rtmp_stream_find(&conn->streaml, stream_id);
			if (!strm) {
				re_printf("rtmp: stream_eof:"
					  " stream %u not found\n", stream_id);
				return ENOSTR;
			}
			strm->eof = true;
		}
		break;

	case RTMP_EVENT_STREAM_IS_RECORDED:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;
		stream_id = ntohl(mbuf_read_u32(mb));
		re_printf("rtmp: StreamIsRecorded (stream_id=%u)\n",
			  stream_id);
		break;

	case RTMP_EVENT_PING_REQUEST:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		value = ntohl(mbuf_read_u32(mb));

		re_printf("got Ping request (value=%u)\n", value);

		++conn->stats.ping;

		err = rtmp_control_send_user_control_msg(conn,
						 RTMP_EVENT_PING_RESPONSE,
						 value);
		if (err)
			return err;
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
	struct mbuf mb = {
		.pos  = 0,
		.end  = msg->length,
		.size = msg->length,
		.buf  = msg->buf
	};
	uint32_t val;
	uint32_t was;
	uint8_t limit;
	int err = 0;

	if (conn->term)
		return;

#if 0
	re_printf("[%s] ### recv message: type 0x%02x (%s) (%zu bytes)\n",
		  conn->is_client ? "Client" : "Server",
		  msg->type, rtmp_packet_type_name(msg->type), msg->length);
#endif

	switch (msg->type) {

	case RTMP_TYPE_SET_CHUNK_SIZE:
		if (mbuf_get_left(&mb) < 4)
			return;

		val = ntohl(mbuf_read_u32(&mb));

		val = val & 0x7fffffff;

		re_printf("rtmp: set chunk size:  %u bytes\n", val);

		rtmp_dechunker_set_chunksize(conn->dechunk, val);
		break;

	case RTMP_TYPE_ACKNOWLEDGEMENT:
		if (mbuf_get_left(&mb) < 4)
			return;

		val = ntohl(mbuf_read_u32(&mb));

		re_printf("got Acknowledgement:  sequence=%u\n", val);

		++conn->stats.ack;
		break;

	case RTMP_TYPE_AMF0:
		handle_amf_command(conn, msg->buf, msg->length);
		break;

	case RTMP_TYPE_WINDOW_ACK_SIZE:
		if (mbuf_get_left(&mb) < 4)
			return;

		was = ntohl(mbuf_read_u32(&mb));
#if 0
		re_printf("[%s] got Window Ack Size from peer: %u\n",
			  conn->is_client ? "Client" : "Server", was);
#endif
		conn->window_ack_size = was;

		check_established(conn);
		break;

	case RTMP_TYPE_SET_PEER_BANDWIDTH:
		if (mbuf_get_left(&mb) < 5)
			return;

		was = ntohl(mbuf_read_u32(&mb));
		limit = mbuf_read_u8(&mb);

		(void)was;
		(void)limit;

#if 0
		re_printf("[%s] got Set Peer Bandwidth from peer:"
			  " was=%u, limit_type=%u\n",
			  conn->is_client ? "Client" : "Server",
			  was, limit);
#endif

		err = rtmp_control_send_was(conn, WINDOW_ACK_SIZE);
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
			if (msg->format == 0) {
				strm->recv_timestamp = msg->timestamp;
			}
			else {
				strm->recv_timestamp += msg->timestamp_delta;
			}

			++strm->n_recv;

			if (strm->auh) {
				strm->auh(strm->recv_timestamp,
					  msg->buf, msg->length, strm->arg);
			}
		}
		else {
			re_printf("rtmp: audio: stream not found (%u)\n",
				  msg->stream_id);
		}
		break;

	case RTMP_TYPE_VIDEO:
		strm = rtmp_stream_find(&conn->streaml, msg->stream_id);
		if (strm) {
			if (msg->format == 0) {
				strm->recv_timestamp = msg->timestamp;
			}
			else {
				strm->recv_timestamp += msg->timestamp_delta;
			}

			++strm->n_recv;

			if (strm->vidh) {
				strm->vidh(strm->recv_timestamp,
					   msg->buf, msg->length, strm->arg);
			}
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

		/* XXX: for development */
		err = EPROTO;
		goto error;

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
	uint32_t uptime;
	int err;

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn)
		return NULL;

	conn->is_client = is_client;
	conn->state = RTMP_STATE_UNINITIALIZED;

	conn->send_chunk_size = RTMP_DEFAULT_CHUNKSIZE;

	/* XXX check this */
	uptime = 0;
	memcpy(conn->x1, &uptime, 4);
	get_version(&conn->x1[4]);
	rand_bytes(conn->x1 + 8, sizeof(conn->x1) - 8);

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

#if 0
	re_printf("[%s] set state: %d (%s)\n",
		  conn->is_client ? "Client" : "Server",
		  state, rtmp_handshake_name(state));
#endif

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

#if 0
	re_printf("[%s] send packet (%zu bytes)\n",
		  conn->is_client ? "Client" : "Server", mb->end);
#endif

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

#if 0
	re_printf("[%s] TCP established\n",
		  conn->is_client ? "Client" : "Server");
#endif

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

#if 0
	re_printf("[%s] send AMF command: [fmt=%u, chunk=%u, stream=%u]"
		  " %zu bytes\n",
		  conn->is_client ? "Client" : "Server",
		  format, chunk_id, msg_stream_id, len);
#endif

	err = rtmp_chunker(format, chunk_id,
			   timestamp, 0,
			   RTMP_TYPE_AMF0, msg_stream_id,
			   cmd, len, conn->send_chunk_size,
			   rtmp_chunk_handler, conn);
	if (err)
		return err;

	return 0;
}


static void connect_resp_handler(int err, const struct command_header *cmd_hdr,
				 struct odict *dict, void *arg)
{
	struct rtmp_conn *conn = arg;
	(void)conn;

	if (err) {
		re_printf("### connect failed (%m)\n", err);
		conn_close(conn, err);
		return;
	}

	if (conn->connected)
		return;

	conn->connected = true;

	conn->send_chunk_size = 4096;
	err = rtmp_control_send_set_chunk_size(conn, conn->send_chunk_size);
	if (err)
		goto error;

	check_established(conn);
	return;

 error:
	if (err)
		conn_close(conn, err);
}


static int send_connect(struct rtmp_conn *conn)
{
	const int aucodecs  = 0x0400;  /* AAC  */
	const int vidcodecs = 0x0080;  /* H264 */
	int err;

	err = rtmp_ctrans_send(conn, RTMP_CONTROL_STREAM_ID, "connect",
			       connect_resp_handler, conn,
			       1,
		       AMF_TYPE_OBJECT, 8,
		         AMF_TYPE_STRING, "app", conn->app,
		         AMF_TYPE_STRING, "flashVer", "LNX 9,0,124,2",
		         AMF_TYPE_STRING, "tcUrl", conn->uri,
		         AMF_TYPE_BOOLEAN, "fpad", false,
		         AMF_TYPE_NUMBER, "capabilities", 15.0,
		         AMF_TYPE_NUMBER, "audioCodecs", (double)aucodecs,
		         AMF_TYPE_NUMBER, "videoCodecs", (double)vidcodecs,
		         AMF_TYPE_NUMBER, "videoFunction", 1.0

			       );
	if (err) {
		re_printf("rtmp: ctrans failed (%m)\n", err);
		return err;
	}

	return 0;
}


static int handshake_done(struct rtmp_conn *conn)
{
	int err;

#if 0
	re_printf("[%s] ** handshake done **\n",
		  conn->is_client ? "Client" : "Server");
#endif

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

#if 0
		re_printf("server version: %u.%u.%u.%u\n",
			  s1[4], s1[5], s1[6], s1[7]);
#endif

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

		/* XXX: compare C1 and S2 */

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
	uint8_t c1[RTMP_SIG_SIZE];
	uint8_t c2[RTMP_SIG_SIZE];
	uint8_t s2[RTMP_SIG_SIZE];
	int err = 0;

	switch (conn->state) {

	case RTMP_STATE_UNINITIALIZED:
		if (mbuf_get_left(mb) < 1)
			return ENODATA;

		c0 = mbuf_read_u8(mb);
		if (c0 != RTMP_PROTOCOL_VERSION) {
			re_printf("rtmp: handshake: illegal version %u\n", c0);
			return EPROTO;
		}

		/* Send S0 + S1 */
		err = handshake_start(conn);
		if (err)
			return err;
		break;

	case RTMP_STATE_VERSION_SENT:
		if (mbuf_get_left(mb) < (RTMP_SIG_SIZE))
			return ENODATA;

		err = mbuf_read_mem(mb, c1, sizeof(c1));
		if (err)
			return err;

#if 0
		re_printf("        client version: %u.%u.%u.%u\n",
			  c1[4], c1[5], c1[6], c1[7]);
#endif

		/* Send S2 */

		/* Copy C1 to S2 */
		memcpy(s2, c1, sizeof(s2));

		err = send_packet(conn, s2, sizeof(s2));
		if (err)
			return err;

		set_state(conn, RTMP_STATE_ACK_SENT);
		break;

	case RTMP_STATE_ACK_SENT:
		if (mbuf_get_left(mb) < (RTMP_SIG_SIZE))
			return ENODATA;

		err = mbuf_read_mem(mb, c2, sizeof(c2));
		if (err)
			return err;

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
		const size_t len = mbuf_get_left(mb_pkt), pos = conn->mb->pos;

		if ((mbuf_get_left(conn->mb) + len) > RTMP_BUFSIZE_MAX) {
			err = EOVERFLOW;
			goto out;
		}

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
		rtmp_estab_h *estabh, rtmp_command_h *cmdh,
		rtmp_status_h *statush,
		rtmp_close_h *closeh, void *arg)
{
	struct rtmp_conn *conn;
	int err;

	if (!connp || !ts)
		return EINVAL;

	conn = rtmp_conn_alloc(false, estabh, statush, closeh, arg);
	if (!conn)
		return ENOMEM;

	conn->cmdh = cmdh;

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
			   conn->send_chunk_size, rtmp_chunk_handler, conn);
	if (err)
		return err;

	return 0;
}


struct tcp_conn *rtmp_conn_tcpconn(const struct rtmp_conn *conn)
{
	return conn ? conn->tc : NULL;
}


int rtmp_conn_debug(struct re_printf *pf, const struct rtmp_conn *conn)
{
	struct le *le;
	int err = 0;

	if (!conn)
		return 0;

	err |= re_hprintf(pf, "role:          %s\n",
			  conn->is_client ? "Client" : "Server");
	err |= re_hprintf(pf, "state:         %s\n",
			  rtmp_handshake_name(conn->state));
	err |= re_hprintf(pf, "connected:     %d\n", conn->connected);

	if (conn->is_client) {
		err |= re_hprintf(pf, "app:           %s\n", conn->app);
		err |= re_hprintf(pf, "uri:           %s\n", conn->uri);
	}

	/* Stats */
	err |= re_hprintf(pf, "ack:           %zu\n", conn->stats.ack);
	err |= re_hprintf(pf, "ping:          %zu\n", conn->stats.ping);

	err |= re_hprintf(pf, "streams:\n");
	for (le = conn->streaml.head; le; le = le->next) {
		struct rtmp_stream *strm = le->data;

		err |= re_hprintf(pf, ".... %H\n", rtmp_stream_debug, strm);
	}

	return err;
}