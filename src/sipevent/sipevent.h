/**
 * @file sipevent.h  SIP Event Private Interface
 *
 * Copyright (C) 2010 Creytiv.com
 */


struct sipevent_sock {
	struct sip_lsnr *lsnr;
	struct hash *ht_not;
	struct hash *ht_sub;
	struct sip *sip;
	sip_msg_h *subh;
	void *arg;
};


struct sipnot {
	struct le he;
	struct sip_dialog *dlg;
	bool terminated;
};


struct sipsub {
	struct le he;
	struct sip_loopstate ls;
	struct tmr tmr;
	struct sipevent_sock *sock;
	struct sip_request *req;
	struct sip_dialog *dlg;
	struct sip_auth *auth;
	struct sip *sip;
	char *uri;
	char *from_name;
	char *from_uri;
	char **routev;
	char *event;
	char *cuser;
	char *hdrs;
	sip_resp_h *resph;
	sip_msg_h *noth;
	void *arg;
	uint32_t expires;
	uint32_t failc;
	uint32_t routec;
	bool subscribed;
	bool terminated;
};


void sipevent_resubscribe(struct sipsub *sub, uint32_t wait);
