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
#include <re_dns.h>
#include <re_rtmp.h>
#include "rtmp.h"


#define WINDOW_ACK_SIZE 2500000


static void conn_destructor(void *data)
{
	struct rtmp_conn *conn = data;

	list_flush(&conn->ctransl);
	list_flush(&conn->streaml);

	mem_deref(conn->dnsq);
	mem_deref(conn->dnsc);
	mem_deref(conn->tc);
	mem_deref(conn->mb);
	mem_deref(conn->dechunk);
	mem_deref(conn->uri);
	mem_deref(conn->app);
}


static int client_handle_amf_command(struct rtmp_conn *conn,
				     uint32_t stream_id,
				     const struct odict *msg)
{
	const char *name;

	name = odict_string(msg, "0");

	if (0 == str_casecmp(name, "_result") ||
	    0 == str_casecmp(name, "_error")) {

		/* forward response to transaction layer */
		rtmp_ctrans_response(&conn->ctransl, msg);
	}
	else if (0 == str_casecmp(name, "onStatus")) {

		struct rtmp_stream *strm;

		if (stream_id == 0) {
			if (conn->cmdh)
				conn->cmdh(msg, conn->arg);
		}
		else {
			strm = rtmp_stream_find(conn, stream_id);
			if (strm) {
				if (strm->cmdh)
					strm->cmdh(msg, strm->arg);
			}
		}
	}
	else {
		if (conn->cmdh)
			conn->cmdh(msg, conn->arg);
	}

	return 0;
}


static int handle_amf_command(struct rtmp_conn *conn, uint32_t stream_id,
			      struct mbuf *mb)
{
	struct odict *msg = NULL;
	int err;

	err = rtmp_amf_decode(&msg, mb);
	if (err)
		return err;

	if (conn->is_client) {
		err = client_handle_amf_command(conn, stream_id, msg);
	}
	else {
		if (stream_id == 0) {
			if (conn->cmdh)
				conn->cmdh(msg, conn->arg);
		}
		else {
			struct rtmp_stream *strm;

			strm = rtmp_stream_find(conn, stream_id);
			if (strm) {
				if (strm->cmdh)
					strm->cmdh(msg, strm->arg);
			}
		}
	}

	mem_deref(msg);

	return err;
}


static int handle_user_control_msg(struct rtmp_conn *conn, struct mbuf *mb)
{
	struct rtmp_stream *strm;
	enum rtmp_event_type event;
	uint32_t stream_id;
	uint32_t value = 0;
	int err;

	if (mbuf_get_left(mb) < 2)
		return EBADMSG;

	event = ntohs(mbuf_read_u16(mb));

	switch (event) {

	case RTMP_EVENT_STREAM_BEGIN:
	case RTMP_EVENT_STREAM_EOF:
	case RTMP_EVENT_STREAM_IS_RECORDED:
	case RTMP_EVENT_SET_BUFFER_LENGTH:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		stream_id = ntohl(mbuf_read_u32(mb));

		if (event == RTMP_EVENT_SET_BUFFER_LENGTH) {
			if (mbuf_get_left(mb) < 4)
				return EBADMSG;
			value = ntohl(mbuf_read_u32(mb));
		}

		if (stream_id != RTMP_CONTROL_STREAM_ID) {

			strm = rtmp_stream_find(conn, stream_id);
			if (!strm)
				return ENOSTR;

			if (strm->ctrlh)
				strm->ctrlh(event, value, strm->arg);
		}
		break;

	case RTMP_EVENT_PING_REQUEST:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		value = ntohl(mbuf_read_u32(mb));

		++conn->stats.ping;

		err = rtmp_control(conn, RTMP_TYPE_USER_CONTROL_MSG,
				   RTMP_EVENT_PING_RESPONSE,
				   value);
		if (err)
			return err;
		break;

	default:
		break;
	}

	return 0;
}


static int handle_data_message(struct rtmp_conn *conn, uint32_t stream_id,
			       struct mbuf *mb)
{
	struct odict *msg;
	struct rtmp_stream *strm;
	int err;

	err = rtmp_amf_decode(&msg, mb);
	if (err)
		return err;

	if (stream_id != 0) {
		strm = rtmp_stream_find(conn, stream_id);
		if (strm) {
			if (strm->datah)
				strm->datah(msg, strm->arg);
		}
	}

	mem_deref(msg);

	return err;
}


static int rtmp_dechunk_handler(const struct rtmp_header *hdr,
				struct mbuf *mb, void *arg)
{
	struct rtmp_conn *conn = arg;
	struct rtmp_stream *strm;
	uint32_t val;
	uint32_t was;
	uint8_t limit;
	int err = 0;

	switch (hdr->type_id) {

	case RTMP_TYPE_SET_CHUNK_SIZE:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		val = ntohl(mbuf_read_u32(mb));

		val = val & 0x7fffffff;

		conn->recv_chunk_size = val;
		rtmp_dechunker_set_chunksize(conn->dechunk, val);
		break;

	case RTMP_TYPE_ACKNOWLEDGEMENT:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		val = ntohl(mbuf_read_u32(mb));

		++conn->stats.ack;
		break;

	case RTMP_TYPE_AMF0:
		err = handle_amf_command(conn, hdr->stream_id, mb);
		break;

	case RTMP_TYPE_WINDOW_ACK_SIZE:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		was = ntohl(mbuf_read_u32(mb));

		conn->window_ack_size = was;
		break;

	case RTMP_TYPE_SET_PEER_BANDWIDTH:
		if (mbuf_get_left(mb) < 5)
			return EBADMSG;

		was = ntohl(mbuf_read_u32(mb));
		limit = mbuf_read_u8(mb);

		(void)was;
		(void)limit;

		err = rtmp_control(conn, RTMP_TYPE_WINDOW_ACK_SIZE,
				   (uint32_t)WINDOW_ACK_SIZE);
		break;

	case RTMP_TYPE_USER_CONTROL_MSG:
		err = handle_user_control_msg(conn, mb);
		break;

		/* XXX: common code for audio+video */
	case RTMP_TYPE_AUDIO:
		strm = rtmp_stream_find(conn, hdr->stream_id);
		if (strm) {
			if (strm->auh) {
				strm->auh(hdr->timestamp,
					  mb->buf, mb->end,
					  strm->arg);
			}
		}
		break;

	case RTMP_TYPE_VIDEO:
		strm = rtmp_stream_find(conn, hdr->stream_id);
		if (strm) {
			if (strm->vidh) {
				strm->vidh(hdr->timestamp,
					   mb->buf, mb->end,
					   strm->arg);
			}
		}
		break;

	case RTMP_TYPE_DATA:
		err = handle_data_message(conn, hdr->stream_id, mb);
		break;

	default:
		break;
	}

	return err;
}


static struct rtmp_conn *rtmp_conn_alloc(bool is_client,
					 rtmp_estab_h *estabh,
					 rtmp_command_h *cmdh,
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

	conn->send_chunk_size = RTMP_DEFAULT_CHUNKSIZE;

	/* version signature */
	conn->x1[4] = VER_MAJOR;
	conn->x1[5] = VER_MINOR;
	conn->x1[6] = VER_PATCH;
	rand_bytes(conn->x1 + 8, sizeof(conn->x1) - 8);

	err = rtmp_dechunker_alloc(&conn->dechunk, RTMP_DEFAULT_CHUNKSIZE,
				   rtmp_dechunk_handler, conn);
	if (err)
		goto out;

	/* must be above 2 */
	conn->chunk_id_counter = RTMP_CHUNK_ID_CONN + 1;

	conn->estabh = estabh;
	conn->cmdh   = cmdh;
	conn->closeh = closeh;
	conn->arg    = arg;

 out:
	if (err)
		return mem_deref(conn);

	return conn;
}


static inline void set_state(struct rtmp_conn *conn,
			     enum rtmp_handshake_state state)
{
	conn->state = state;
}


static int send_packet(struct rtmp_conn *conn,
		       const uint8_t *pkt, size_t len)
{
	struct mbuf *mb;
	int err;

	if (!conn || !pkt || !len)
		return EINVAL;

	mb = mbuf_alloc(len);
	if (!mb)
		return ENOMEM;

	(void)mbuf_write_mem(mb, pkt, len);

	mb->pos = 0;

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
	rtmp_close_h *closeh;

	conn->tc = mem_deref(conn->tc);
	conn->dnsq = mem_deref(conn->dnsq);

	closeh = conn->closeh;
	if (closeh) {
		conn->closeh = NULL;
		closeh(err, conn->arg);
	}
}


static void tcp_estab_handler(void *arg)
{
	struct rtmp_conn *conn = arg;
	int err = 0;

	if (conn->is_client) {

		err = handshake_start(conn);
	}

	if (err)
		conn_close(conn, err);
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


/* Send AMF0 Command or Data */
int rtmp_send_amf_command(const struct rtmp_conn *conn,
			  unsigned format, uint32_t chunk_id,
			  uint8_t type_id,
			  uint32_t msg_stream_id,
			  const uint8_t *cmd, size_t len)
{
	if (!conn || !cmd || !len)
		return EINVAL;

	return rtmp_chunker(format, chunk_id, 0, 0, type_id, msg_stream_id,
			    cmd, len, conn->send_chunk_size,
			    rtmp_chunk_handler, (void *)conn);
}


static void connect_resp_handler(bool success, const struct odict *msg,
				 void *arg)
{
	struct rtmp_conn *conn = arg;
	rtmp_estab_h *estabh;
	int err;
	(void)msg;

	if (!success) {
		err = EPROTO;
		goto error;
	}

	if (conn->connected)
		return;

	conn->connected = true;

	conn->send_chunk_size = 4096;

	err = rtmp_control(conn, RTMP_TYPE_SET_CHUNK_SIZE,
			   conn->send_chunk_size);
	if (err)
		goto error;

	estabh = conn->estabh;
	if (estabh) {
		conn->estabh = NULL;
		estabh(conn->arg);
	}

	return;

 error:
	if (err)
		conn_close(conn, err);
}


static int send_connect(struct rtmp_conn *conn)
{
	const int aucodecs  = 0x0400;  /* AAC  */
	const int vidcodes  = 0x0080;  /* H264 */
	int err;

	err = rtmp_amf_request(conn, RTMP_CONTROL_STREAM_ID, "connect",
			       connect_resp_handler, conn,
			       1,
		       RTMP_AMF_TYPE_OBJECT, 8,
		         RTMP_AMF_TYPE_STRING, "app", conn->app,
		         RTMP_AMF_TYPE_STRING, "flashVer", "LNX 9,0,124,2",
		         RTMP_AMF_TYPE_STRING, "tcUrl", conn->uri,
		         RTMP_AMF_TYPE_BOOLEAN, "fpad", false,
		         RTMP_AMF_TYPE_NUMBER, "capabilities", 15.0,
		         RTMP_AMF_TYPE_NUMBER, "audioCodecs", (double)aucodecs,
		         RTMP_AMF_TYPE_NUMBER, "videoCodecs", (double)vidcodes,
		         RTMP_AMF_TYPE_NUMBER, "videoFunction", 1.0);
	if (err)
		return err;

	return 0;
}


static int client_handle_packet(struct rtmp_conn *conn, struct mbuf *mb)
{
	uint8_t s0;
	uint8_t s1[RTMP_HANDSHAKE_SIZE];
	uint8_t s2[RTMP_HANDSHAKE_SIZE];
	uint8_t c2[RTMP_HANDSHAKE_SIZE];
	int err = 0;

	switch (conn->state) {

	case RTMP_STATE_VERSION_SENT:
		if (mbuf_get_left(mb) < (1+RTMP_HANDSHAKE_SIZE))
			return ENODATA;

		s0 = mbuf_read_u8(mb);
		if (s0 != RTMP_PROTOCOL_VERSION)
			return EPROTO;

		(void)mbuf_read_mem(mb, s1, sizeof(s1));

		memcpy(c2, s1, sizeof(c2));

		err = send_packet(conn, c2, sizeof(c2));
		if (err)
			return err;

		set_state(conn, RTMP_STATE_ACK_SENT);
		break;

	case RTMP_STATE_ACK_SENT:
		if (mbuf_get_left(mb) < RTMP_HANDSHAKE_SIZE)
			return ENODATA;

		(void)mbuf_read_mem(mb, s2, sizeof(s2));

		set_state(conn, RTMP_STATE_HANDSHAKE_DONE);

		err = send_connect(conn);
		if (err)
			return err;
		break;

	case RTMP_STATE_HANDSHAKE_DONE:
		err = rtmp_dechunker_receive(conn->dechunk, mb);
		if (err)
			return err;
		break;

	default:
		return EPROTO;
	}

	return 0;
}


static int server_handle_packet(struct rtmp_conn *conn, struct mbuf *mb)
{
	uint8_t c0;
	uint8_t c1[RTMP_HANDSHAKE_SIZE];
	uint8_t c2[RTMP_HANDSHAKE_SIZE];
	uint8_t s2[RTMP_HANDSHAKE_SIZE];
	int err = 0;

	switch (conn->state) {

	case RTMP_STATE_UNINITIALIZED:
		if (mbuf_get_left(mb) < 1)
			return ENODATA;

		c0 = mbuf_read_u8(mb);
		if (c0 != RTMP_PROTOCOL_VERSION)
			return EPROTO;

		/* Send S0 + S1 */
		err = handshake_start(conn);
		if (err)
			return err;
		break;

	case RTMP_STATE_VERSION_SENT:
		if (mbuf_get_left(mb) < RTMP_HANDSHAKE_SIZE)
			return ENODATA;

		(void)mbuf_read_mem(mb, c1, sizeof(c1));

		/* Send S2 */

		/* Copy C1 to S2 */
		memcpy(s2, c1, sizeof(s2));

		err = send_packet(conn, s2, sizeof(s2));
		if (err)
			return err;

		set_state(conn, RTMP_STATE_ACK_SENT);
		break;

	case RTMP_STATE_ACK_SENT:
		if (mbuf_get_left(mb) < RTMP_HANDSHAKE_SIZE)
			return ENODATA;

		(void)mbuf_read_mem(mb, c2, sizeof(c2));

		set_state(conn, RTMP_STATE_HANDSHAKE_DONE);
		break;

	case RTMP_STATE_HANDSHAKE_DONE:
		err = rtmp_dechunker_receive(conn->dechunk, mb);
		if (err)
			return err;
		break;

	default:
		return EPROTO;
	}

	return 0;
}


static void tcp_recv_handler(struct mbuf *mb_pkt, void *arg)
{
	struct rtmp_conn *conn = arg;
	int err;

	conn->total_bytes += mbuf_get_left(mb_pkt);

	/* re-assembly of fragments */
	if (conn->mb) {
		const size_t len = mbuf_get_left(mb_pkt), pos = conn->mb->pos;

		if ((mbuf_get_left(conn->mb) + len) > RTMP_MESSAGE_LEN_MAX) {
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
		uint32_t nrefs;

		pos = conn->mb->pos;

		mem_ref(conn);

		if (conn->is_client)
			err = client_handle_packet(conn, conn->mb);
		else
			err = server_handle_packet(conn, conn->mb);

		nrefs = mem_nrefs(conn);

		mem_deref(conn);

		if (nrefs == 1)
			return;

		if (err) {

			/* rewind */
			conn->mb->pos = pos;

			if (err == ENODATA)
				err = 0;
			break;
		}

		if (!conn->tc)
			break;

		if (conn->mb->pos >= conn->mb->end) {
			conn->mb = mem_deref(conn->mb);
			break;
		}
	}

	if (conn->total_bytes >= (conn->last_ack + WINDOW_ACK_SIZE)) {

		conn->last_ack = conn->total_bytes;

		err = rtmp_control(conn, RTMP_TYPE_ACKNOWLEDGEMENT,
				   (uint32_t)conn->total_bytes);
		if (err)
			goto out;
	}

 out:
	if (err)
		conn_close(conn, err);
}


static void tcp_close_handler(int err, void *arg)
{
	struct rtmp_conn *conn = arg;

	conn_close(conn, err);
}


static void query_handler(int err, const struct dnshdr *hdr, struct list *ansl,
			  struct list *authl, struct list *addl, void *arg)
{
	struct rtmp_conn *conn = arg;
	struct dnsrr *rr;
	struct sa addr;
	(void)hdr;
	(void)authl;
	(void)addl;

	rr = dns_rrlist_find(ansl, NULL, DNS_TYPE_A, DNS_CLASS_IN, false);
	if (!rr) {
		err = err ? err : EDESTADDRREQ;
		goto out;
	}

	sa_set_in(&addr, rr->rdata.a.addr, conn->port);

	err = tcp_connect(&conn->tc, &addr, tcp_estab_handler,
			  tcp_recv_handler, tcp_close_handler, conn);
	if (err)
		goto out;

	return;

 out:
	conn_close(conn, err);
}


int rtmp_connect(struct rtmp_conn **connp, struct dnsc *dnsc, const char *uri,
		 rtmp_estab_h *estabh, rtmp_command_h *cmdh,
		 rtmp_close_h *closeh, void *arg)
{
	struct rtmp_conn *conn;
	struct pl pl_host;
	struct pl pl_port = pl_null;
	struct pl pl_app;
	struct sa addr;
	char host[256];
	int err = 0;

	if (!connp || !uri)
		return EINVAL;

	if (re_regex(uri, strlen(uri), "rtmp://[^:/]+[:]*[0-9]*/[^/]+/[^]+",
		     &pl_host, NULL, &pl_port, &pl_app, NULL))
		return EINVAL;

	conn = rtmp_conn_alloc(true, estabh, cmdh, closeh, arg);
	if (!conn)
		return ENOMEM;

	conn->port = pl_isset(&pl_port) ? pl_u32(&pl_port) : RTMP_PORT;

	err |= pl_strdup(&conn->app, &pl_app);
	err |= str_dup(&conn->uri, uri);
	if (err)
		goto out;

	if (0 == sa_set(&addr, &pl_host, conn->port)) {

		err = tcp_connect(&conn->tc, &addr, tcp_estab_handler,
				  tcp_recv_handler, tcp_close_handler, conn);
		if (err)
			goto out;
	}
	else {
		pl_strcpy(&pl_host, host, sizeof(host));

		conn->dnsc = mem_ref(dnsc);

		err = dnsc_query(&conn->dnsq, dnsc, host, DNS_TYPE_A,
				 DNS_CLASS_IN, true, query_handler, conn);
		if (err)
			goto out;
	}

 out:
	if (err)
		mem_deref(conn);
	else
		*connp = conn;

	return err;
}


int rtmp_accept(struct rtmp_conn **connp, struct tcp_sock *ts,
		rtmp_estab_h *estabh, rtmp_command_h *cmdh,
		rtmp_close_h *closeh, void *arg)
{
	struct rtmp_conn *conn;
	int err;

	if (!connp || !ts)
		return EINVAL;

	conn = rtmp_conn_alloc(false, estabh, cmdh, closeh, arg);
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


int rtmp_conn_send_msg(const struct rtmp_conn *conn,
		       unsigned format, uint32_t chunk_id,
		       uint32_t timestamp, uint32_t timestamp_delta,
		       uint8_t msg_type_id, uint32_t msg_stream_id,
		       const uint8_t *payload, size_t payload_len)
{
	if (!conn)
		return EINVAL;

	return rtmp_chunker(format, chunk_id, timestamp, timestamp_delta,
			    msg_type_id, msg_stream_id, payload, payload_len,
			    conn->send_chunk_size,
			    rtmp_chunk_handler, (void *)conn);
}


unsigned rtmp_conn_assign_chunkid(struct rtmp_conn *conn)
{
	if (!conn)
		return 0;

	return ++conn->chunk_id_counter;
}


uint64_t rtmp_conn_assign_tid(struct rtmp_conn *conn)
{
	if (!conn)
		return 0;

	return ++conn->tid_counter;
}


struct tcp_conn *rtmp_conn_tcpconn(const struct rtmp_conn *conn)
{
	return conn ? conn->tc : NULL;
}


static const char *rtmp_handshake_name(enum rtmp_handshake_state state)
{
	switch (state) {

	case RTMP_STATE_UNINITIALIZED:  return "UNINITIALIZED";
	case RTMP_STATE_VERSION_SENT:   return "VERSION_SENT";
	case RTMP_STATE_ACK_SENT:       return "ACK_SENT";
	case RTMP_STATE_HANDSHAKE_DONE: return "HANDSHAKE_DONE";
	default: return "?";
	}
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
	err |= re_hprintf(pf, "connected:     %d\n", conn->connected);

	if (conn->is_client) {
		err |= re_hprintf(pf, "app:           %s\n", conn->app);
		err |= re_hprintf(pf, "uri:           %s\n", conn->uri);
	}

	err |= re_hprintf(pf, "chunk_size:    send=%u, recv=%u\n",
			  conn->send_chunk_size, conn->recv_chunk_size);

	/* Stats */
	err |= re_hprintf(pf, "bytes:         %zu\n", conn->total_bytes);
	err |= re_hprintf(pf, "ack:           %zu\n", conn->stats.ack);
	err |= re_hprintf(pf, "ping:          %zu\n", conn->stats.ping);

	err |= re_hprintf(pf, "streams:       %u\n",
			  list_count(&conn->streaml));

	err |= re_hprintf(pf, "%H\n", rtmp_dechunker_debug, conn->dechunk);

	return err;
}
