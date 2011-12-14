/**
 * @file sipevent.h  SIP Event Private Interface
 *
 * Copyright (C) 2010 Creytiv.com
 */

enum {
	DEFAULT_EXPIRES = 3600,
};


/* Listener Socket */

struct sipevent_sock {
	struct sip_lsnr *lsnr;
	struct hash *ht_not;
	struct hash *ht_sub;
	struct sip *sip;
	sip_msg_h *subh;
	void *arg;
};


/* Notifier */

struct sipnot {
	struct le he;
	struct sip_loopstate ls;
	struct tmr tmr;
	struct sipevent_sock *sock;
	struct sip_request *req;
	struct sip_dialog *dlg;
	struct sip_auth *auth;
	struct sip *sip;
	struct mbuf *mb;
	char *event;
	char *id;
	char *cuser;
	char *hdrs;
	char *ctype;
	sipevent_close_h *closeh;
	void *arg;
	uint32_t expires_max;
	enum sipevent_reason reason;
	bool notify_pending;
	bool subscribed;
	bool terminated;
	bool termsent;
};

void sipnot_refresh(struct sipnot *not, uint32_t expires);
int  sipnot_notify(struct sipnot *not);
int  sipnot_reply(struct sipnot *not, const struct sip_msg *msg,
		  uint16_t scode, const char *reason);


/* Subscriber */

struct sipsub {
	struct le he;
	struct sip_loopstate ls;
	struct tmr tmr;
	struct sipevent_sock *sock;
	struct sip_request *req;
	struct sip_dialog *dlg;
	struct sip_auth *auth;
	struct sip *sip;
	char *event;
	char *id;
	char *refer_to;
	char *cuser;
	char *hdrs;
	sipevent_fork_h *forkh;
	sipevent_notify_h *notifyh;
	sipevent_close_h *closeh;
	void *arg;
	int32_t refer_cseq;
	uint32_t expires;
	uint32_t failc;
	bool subscribed;
	bool terminated;
	bool refer;
};

struct sipsub *sipsub_find(struct sipevent_sock *sock,
			   const struct sip_msg *msg,
			   const struct sipevent_event *evt, bool full);
void sipsub_reschedule(struct sipsub *sub, uint64_t wait);
void sipsub_terminate(struct sipsub *sub, int err, const struct sip_msg *msg);
