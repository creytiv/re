/**
 * @file rtmp.h  Real Time Messaging Protocol (RTMP) -- Internal API
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {
	RTMP_DEFAULT_CHUNKSIZE = 128,
	MESSAGE_LEN_MAX = 524288,
};


struct rtmp_conn {
	struct list streaml;
	struct rtmp_dechunker *dechunk;
	struct tcp_conn *tc;
	struct mbuf *mb;                  /* TCP reassembly buffer */
	enum rtmp_handshake_state state;
	uint8_t x1[RTMP_SIG_SIZE];        /* C1 or S1 */
	uint32_t window_ack_size;
	bool is_client;
	bool estab;
	bool term;
	rtmp_estab_h *estabh;
	rtmp_close_h *closeh;
	void *arg;

	/* client specific: */
	char *app;
	char *uri;
};

struct rtmp_stream {
	struct le le;
	struct rtmp_conn *conn;    /* pointer */
	char *name;
	uint32_t stream_id;
	rtmp_audio_h *auh;
	rtmp_video_h *vidh;
	void *arg;
};


/* Command */

struct command_header {
	char name[64];
	uint64_t transaction_id;
};

int rtmp_command_header_encode(struct mbuf *mb,
			       const char *name, uint64_t tid);
int rtmp_command_header_decode(struct command_header *hdr,
			       const struct odict *dict);
int rtmp_command_header_print(struct re_printf *pf,
			      const struct command_header *hdr);
