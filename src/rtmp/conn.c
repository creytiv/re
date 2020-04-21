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
#include <re_srtp.h>
#include <re_tls.h>
#include <re_sys.h>
#include <re_odict.h>
#include <re_dns.h>
#include <re_uri.h>
#include <re_rtmp.h>
#include "rtmp.h"


enum {
	WINDOW_ACK_SIZE = 2500000
};


static int req_connect(struct rtmp_conn *conn);


static void conn_destructor(void *data)
{
	struct rtmp_conn *conn = data;

	list_flush(&conn->ctransl);
	list_flush(&conn->streaml);

	mem_deref(conn->dnsq6);
	mem_deref(conn->dnsq4);
	mem_deref(conn->dnsc);
	mem_deref(conn->sc);
	mem_deref(conn->tc);
	mem_deref(conn->mb);
	mem_deref(conn->dechunk);
	mem_deref(conn->uri);
	mem_deref(conn->app);
	mem_deref(conn->host);
	mem_deref(conn->stream);
}


static int handle_amf_command(struct rtmp_conn *conn, uint32_t stream_id,
			      struct mbuf *mb)
{
	struct odict *msg = NULL;
	const char *name;
	int err;

	err = rtmp_amf_decode(&msg, mb);
	if (err)
		return err;

	name = odict_string(msg, "0");

	if (conn->is_client &&
	    (0 == str_casecmp(name, "_result") ||
	     0 == str_casecmp(name, "_error"))) {

		/* forward response to transaction layer */
		rtmp_ctrans_response(&conn->ctransl, msg);
	}
	else {
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

	mem_deref(msg);

	return 0;
}


static int handle_user_control_msg(struct rtmp_conn *conn, struct mbuf *mb)
{
	struct rtmp_stream *strm;
	enum rtmp_event_type event;
	uint32_t value;
	int err;

	if (mbuf_get_left(mb) < 6)
		return EBADMSG;

	event = ntohs(mbuf_read_u16(mb));
	value = ntohl(mbuf_read_u32(mb));

	switch (event) {

	case RTMP_EVENT_STREAM_BEGIN:
	case RTMP_EVENT_STREAM_EOF:
	case RTMP_EVENT_STREAM_DRY:
	case RTMP_EVENT_STREAM_IS_RECORDED:
	case RTMP_EVENT_SET_BUFFER_LENGTH:

		if (value != RTMP_CONTROL_STREAM_ID) {

			strm = rtmp_stream_find(conn, value);
			if (strm && strm->ctrlh)
				strm->ctrlh(event, mb, strm->arg);
		}
		break;

	case RTMP_EVENT_PING_REQUEST:

		err = rtmp_control(conn, RTMP_TYPE_USER_CONTROL_MSG,
				   RTMP_EVENT_PING_RESPONSE, value);
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
	struct rtmp_stream *strm;
	struct odict *msg;
	int err;

	err = rtmp_amf_decode(&msg, mb);
	if (err)
		return err;

	strm = rtmp_stream_find(conn, stream_id);
	if (strm && strm->datah)
		strm->datah(msg, strm->arg);

	mem_deref(msg);

	return 0;
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

		rtmp_dechunker_set_chunksize(conn->dechunk, val);
		break;

	case RTMP_TYPE_ACKNOWLEDGEMENT:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		val = ntohl(mbuf_read_u32(mb));
		(void)val;
		break;

	case RTMP_TYPE_AMF0:
		err = handle_amf_command(conn, hdr->stream_id, mb);
		break;

	case RTMP_TYPE_WINDOW_ACK_SIZE:
		if (mbuf_get_left(mb) < 4)
			return EBADMSG;

		was = ntohl(mbuf_read_u32(mb));
		if (was != 0)
			conn->window_ack_size = was;
		break;

	case RTMP_TYPE_SET_PEER_BANDWIDTH:
		if (mbuf_get_left(mb) < 5)
			return EBADMSG;

		was = ntohl(mbuf_read_u32(mb));
		limit = mbuf_read_u8(mb);
		(void)limit;

		if (was != 0)
			conn->window_ack_size = was;

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
	conn->window_ack_size = WINDOW_ACK_SIZE;

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


static int send_packet(struct rtmp_conn *conn, const uint8_t *pkt, size_t len)
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
	uint8_t sig[1+RTMP_HANDSHAKE_SIZE];
	int err;

	sig[0] = RTMP_PROTOCOL_VERSION;
	sig[1] = 0;
	sig[2] = 0;
	sig[3] = 0;
	sig[4] = 0;
	sig[5] = VER_MAJOR;
	sig[6] = VER_MINOR;
	sig[7] = VER_PATCH;
	sig[8] = 0;
	rand_bytes(sig + 9, sizeof(sig) - 9);

	err = send_packet(conn, sig, sizeof(sig));
	if (err)
		return err;

	set_state(conn, RTMP_STATE_VERSION_SENT);

	return 0;
}


static void conn_close(struct rtmp_conn *conn, int err)
{
	rtmp_close_h *closeh;

	conn->sc = mem_deref(conn->sc);
	conn->tc = mem_deref(conn->tc);
	conn->dnsq6 = mem_deref(conn->dnsq6);
	conn->dnsq4 = mem_deref(conn->dnsq4);

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
			    conn->tc);
}


static void connect_resp_handler(bool success, const struct odict *msg,
				 void *arg)
{
	struct rtmp_conn *conn = arg;
	rtmp_estab_h *estabh;
	(void)msg;

	if (!success) {
		conn_close(conn, EPROTO);
		return;
	}

	conn->connected = true;

	estabh = conn->estabh;
	if (estabh) {
		conn->estabh = NULL;
		estabh(conn->arg);
	}
}


static int send_connect(struct rtmp_conn *conn)
{
	const int ac  = 0x0400;  /* AAC  */
	const int vc  = 0x0080;  /* H264 */

	return rtmp_amf_request(conn, RTMP_CONTROL_STREAM_ID, "connect",
				connect_resp_handler, conn,
				1,
			RTMP_AMF_TYPE_OBJECT, 8,
		          RTMP_AMF_TYPE_STRING, "app", conn->app,
		          RTMP_AMF_TYPE_STRING, "flashVer", "FMLE/3.0",
		          RTMP_AMF_TYPE_STRING, "tcUrl", conn->uri,
		          RTMP_AMF_TYPE_BOOLEAN, "fpad", false,
		          RTMP_AMF_TYPE_NUMBER, "capabilities", 15.0,
		          RTMP_AMF_TYPE_NUMBER, "audioCodecs", (double)ac,
		          RTMP_AMF_TYPE_NUMBER, "videoCodecs", (double)vc,
		          RTMP_AMF_TYPE_NUMBER, "videoFunction", 1.0);
}


static int client_handle_packet(struct rtmp_conn *conn, struct mbuf *mb)
{
	uint8_t s0;
	uint8_t s1[RTMP_HANDSHAKE_SIZE];
	int err = 0;

	switch (conn->state) {

	case RTMP_STATE_VERSION_SENT:
		if (mbuf_get_left(mb) < (1+RTMP_HANDSHAKE_SIZE))
			return ENODATA;

		s0 = mbuf_read_u8(mb);
		if (s0 != RTMP_PROTOCOL_VERSION)
			return EPROTO;

		(void)mbuf_read_mem(mb, s1, sizeof(s1));

		err = send_packet(conn, s1, sizeof(s1));
		if (err)
			return err;

		set_state(conn, RTMP_STATE_ACK_SENT);
		break;

	case RTMP_STATE_ACK_SENT:
		if (mbuf_get_left(mb) < RTMP_HANDSHAKE_SIZE)
			return ENODATA;

		/* S2 (ignored) */
		mbuf_advance(mb, RTMP_HANDSHAKE_SIZE);

		conn->send_chunk_size = 4096;
		err = rtmp_control(conn, RTMP_TYPE_SET_CHUNK_SIZE,
				   conn->send_chunk_size);
		if (err)
			return err;

		err = send_connect(conn);
		if (err)
			return err;

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


static int server_handle_packet(struct rtmp_conn *conn, struct mbuf *mb)
{
	uint8_t c0;
	uint8_t c1[RTMP_HANDSHAKE_SIZE];
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

		/* Copy C1 to S2 */
		err = send_packet(conn, c1, sizeof(c1));
		if (err)
			return err;

		set_state(conn, RTMP_STATE_ACK_SENT);
		break;

	case RTMP_STATE_ACK_SENT:
		if (mbuf_get_left(mb) < RTMP_HANDSHAKE_SIZE)
			return ENODATA;

		/* C2 (ignored) */
		mbuf_advance(mb, RTMP_HANDSHAKE_SIZE);

		conn->send_chunk_size = 4096;
		err = rtmp_control(conn, RTMP_TYPE_SET_CHUNK_SIZE,
				   conn->send_chunk_size);
		if (err)
			return err;

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

		if (!conn->tc)
			return;

		if (err) {

			/* rewind */
			conn->mb->pos = pos;

			if (err == ENODATA)
				err = 0;
			break;
		}


		if (conn->mb->pos >= conn->mb->end) {
			conn->mb = mem_deref(conn->mb);
			break;
		}
	}

	if (err)
		goto out;

	if (conn->total_bytes >= (conn->last_ack + conn->window_ack_size)) {

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

	if (conn->is_client && !conn->connected && conn->srvc > 0) {
		err = req_connect(conn);
		if (!err)
			return;
	}

	conn_close(conn, err);
}


static int req_connect(struct rtmp_conn *conn)
{
	const struct sa *addr;
	int err = EINVAL;

	while (conn->srvc > 0) {

		--conn->srvc;

		addr = &conn->srvv[conn->srvc];

		conn->send_chunk_size = RTMP_DEFAULT_CHUNKSIZE;
		conn->window_ack_size = WINDOW_ACK_SIZE;
		conn->state = RTMP_STATE_UNINITIALIZED;
		conn->last_ack = 0;
		conn->total_bytes = 0;
		conn->mb = mem_deref(conn->mb);
		conn->sc = mem_deref(conn->sc);
		conn->tc = mem_deref(conn->tc);

		rtmp_dechunker_set_chunksize(conn->dechunk,
					     RTMP_DEFAULT_CHUNKSIZE);

		err = tcp_connect(&conn->tc, addr, tcp_estab_handler,
				  tcp_recv_handler, tcp_close_handler, conn);

#ifdef USE_TLS
		if (conn->tls && !err) {
			err = tls_start_tcp(&conn->sc, conn->tls,
					    conn->tc, 0);
			if (!err)
				err = tls_set_verify_server(conn->sc,
							    conn->host);
		}
#endif

		if (!err)
			break;
	}

	return err;
}


static bool rr_handler(struct dnsrr *rr, void *arg)
{
	struct rtmp_conn *conn = arg;

	if (conn->srvc >= ARRAY_SIZE(conn->srvv))
		return true;

	switch (rr->type) {

	case DNS_TYPE_A:
		sa_set_in(&conn->srvv[conn->srvc++], rr->rdata.a.addr,
                          conn->port);
		break;

	case DNS_TYPE_AAAA:
		sa_set_in6(&conn->srvv[conn->srvc++], rr->rdata.aaaa.addr,
			   conn->port);
		break;
	}

	return false;
}


static void query_handler(int err, const struct dnshdr *hdr, struct list *ansl,
			  struct list *authl, struct list *addl, void *arg)
{
	struct rtmp_conn *conn = arg;
	(void)hdr;
	(void)authl;
	(void)addl;

	dns_rrlist_apply2(ansl, conn->host, DNS_TYPE_A, DNS_TYPE_AAAA,
                          DNS_CLASS_IN, true, rr_handler, conn);

	/* wait for other (A/AAAA) query to complete */
	if (conn->dnsq4 || conn->dnsq6)
		return;

	if (conn->srvc == 0) {
		err = err ? err : EDESTADDRREQ;
		goto out;
	}

	err = req_connect(conn);
	if (err)
		goto out;

	return;

 out:
	conn_close(conn, err);
}


/**
 * Connect to an RTMP server
 *
 * @param connp  Pointer to allocated RTMP connection object
 * @param dnsc   DNS Client for resolving FQDN uris
 * @param uri    RTMP uri to connect to
 * @param tls    TLS Context (optional)
 * @param estabh Established handler
 * @param cmdh   Incoming command handler
 * @param closeh Close handler
 * @param arg    Handler argument
 *
 * @return 0 if success, otherwise errorcode
 *
 * Example URIs:
 *
 *     rtmp://a.rtmp.youtube.com/live2/my-stream
 *     rtmp://[::1]/vod/mp4:sample.mp4
 */
int rtmp_connect(struct rtmp_conn **connp, struct dnsc *dnsc, const char *uri,
		 struct tls *tls,
		 rtmp_estab_h *estabh, rtmp_command_h *cmdh,
		 rtmp_close_h *closeh, void *arg)
{
	struct rtmp_conn *conn;
	struct pl pl_scheme;
	struct pl pl_hostport;
	struct pl pl_host;
	struct pl pl_port;
	struct pl pl_path;
	struct pl pl_app;
	struct pl pl_stream;
	const char *tok;
	uint16_t defport;
	int err;

	if (!connp || !uri)
		return EINVAL;

	if (re_regex(uri, strlen(uri), "[a-z]+://[^/]+/[^]+",
		     &pl_scheme, &pl_hostport, &pl_path))
		return EINVAL;

	tok = pl_strrchr(&pl_path, '/');
	if (!tok)
		return EINVAL;

	pl_app.p = pl_path.p;
	pl_app.l = tok - pl_path.p;

	pl_stream.p = tok + 1;
	pl_stream.l = pl_path.p + pl_path.l - pl_stream.p;

	if (!pl_strcasecmp(&pl_scheme, "rtmp")) {
		tls     = NULL;
		defport = RTMP_PORT;
	}
#ifdef USE_TLS
	else if (!pl_strcasecmp(&pl_scheme, "rtmps")) {

		if (!tls)
			return EINVAL;

		defport = 443;
	}
#endif
	else
		return ENOTSUP;

	if (uri_decode_hostport(&pl_hostport, &pl_host, &pl_port))
		return EINVAL;

	conn = rtmp_conn_alloc(true, estabh, cmdh, closeh, arg);
	if (!conn)
		return ENOMEM;

	conn->port = pl_isset(&pl_port) ? pl_u32(&pl_port) : defport;
	conn->tls = tls;

	err  = pl_strdup(&conn->app, &pl_app);
	err |= pl_strdup(&conn->stream, &pl_stream);
	err |= pl_strdup(&conn->host, &pl_host);
	err |= str_dup(&conn->uri, uri);
	if (err)
		goto out;

	if (0 == sa_set(&conn->srvv[0], &pl_host, conn->port)) {

		conn->srvc = 1;

		err = req_connect(conn);
		if (err)
			goto out;
	}
	else {
#ifdef HAVE_INET6
		struct sa tmp;
#endif

		if (!dnsc) {
			err = EINVAL;
			goto out;
		}

		conn->dnsc = mem_ref(dnsc);

		err = dnsc_query(&conn->dnsq4, dnsc, conn->host, DNS_TYPE_A,
				 DNS_CLASS_IN, true, query_handler, conn);
		if (err)
			goto out;

#ifdef HAVE_INET6
		if (0 == net_default_source_addr_get(AF_INET6, &tmp)) {

			err = dnsc_query(&conn->dnsq6, dnsc, conn->host,
					 DNS_TYPE_AAAA, DNS_CLASS_IN,
					 true, query_handler, conn);
			if (err)
				goto out;
		}
#endif
	}

 out:
	if (err)
		mem_deref(conn);
	else
		*connp = conn;

	return err;
}


/**
 * Accept an incoming TCP connection creating an RTMP Server connection
 *
 * @param connp  Pointer to allocated RTMP connection object
 * @param ts     TCP socket with pending connection
 * @param tls    TLS Context (optional)
 * @param cmdh   Incoming command handler
 * @param closeh Close handler
 * @param arg    Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int rtmp_accept(struct rtmp_conn **connp, struct tcp_sock *ts,
		struct tls *tls,
		rtmp_command_h *cmdh, rtmp_close_h *closeh, void *arg)
{
	struct rtmp_conn *conn;
	int err;

	if (!connp || !ts)
		return EINVAL;

	conn = rtmp_conn_alloc(false, NULL, cmdh, closeh, arg);
	if (!conn)
		return ENOMEM;

	err = tcp_accept(&conn->tc, ts, tcp_estab_handler,
			 tcp_recv_handler, tcp_close_handler, conn);
	if (err)
		goto out;

#ifdef USE_TLS
	if (tls) {
		err = tls_start_tcp(&conn->sc, tls, conn->tc, 0);
		if (err)
			goto out;
	}
#endif

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
	if (!conn || !payload || !payload_len)
		return EINVAL;

	return rtmp_chunker(format, chunk_id, timestamp, timestamp_delta,
			    msg_type_id, msg_stream_id, payload, payload_len,
			    conn->send_chunk_size,
			    conn->tc);
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


/**
 * Get the underlying TCP connection from an RTMP connection
 *
 * @param conn RTMP Connection
 *
 * @return TCP-Connection
 */
struct tcp_conn *rtmp_conn_tcpconn(const struct rtmp_conn *conn)
{
	return conn ? conn->tc : NULL;
}


/**
 * Get the RTMP connection stream name from rtmp_connect
 *
 * @param conn RTMP Connection
 *
 * @return RTMP Stream name or NULL
 */
const char *rtmp_conn_stream(const struct rtmp_conn *conn)
{
	return conn ? conn->stream : NULL;
}


/**
 * Set callback handlers for the RTMP connection
 *
 * @param conn   RTMP connection
 * @param cmdh   Incoming command handler
 * @param closeh Close handler
 * @param arg    Handler argument
 */
void rtmp_set_handlers(struct rtmp_conn *conn, rtmp_command_h *cmdh,
		       rtmp_close_h *closeh, void *arg)
{
	if (!conn)
		return;

	conn->cmdh   = cmdh;
	conn->closeh = closeh;
	conn->arg    = arg;
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
	err |= re_hprintf(pf, "chunk_size:    send=%u\n",
			  conn->send_chunk_size);
	err |= re_hprintf(pf, "bytes:         %zu\n", conn->total_bytes);
	err |= re_hprintf(pf, "streams:       %u\n",
			  list_count(&conn->streaml));

	if (conn->is_client) {
		err |= re_hprintf(pf, "uri:           %s\n", conn->uri);
		err |= re_hprintf(pf, "app:           %s\n", conn->app);
		err |= re_hprintf(pf, "stream:        %s\n", conn->stream);
	}

	err |= re_hprintf(pf, "%H\n", rtmp_dechunker_debug, conn->dechunk);

	return err;
}
