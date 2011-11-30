/**
 * @file re_sipevent.h  SIP Event Framework
 *
 * Copyright (C) 2010 Creytiv.com
 */

struct sipevent_sock;
struct sipsub;

int sipevent_listen(struct sipevent_sock **sockp, struct sip *sip,
		    uint32_t htsize_not, uint32_t htsize_sub,
		    sip_msg_h *subh, void *arg);

int sipevent_subscribe(struct sipsub **subp, struct sipevent_sock *sock,
		       const char *uri, const char *from_name,
		       const char *from_uri, const char *event,
		       uint32_t expires, const char *cuser,
		       const char *routev[], uint32_t routec,
		       sip_auth_h *authh, void *aarg, bool aref,
		       sip_resp_h *resph, sip_msg_h *noth, void *arg,
		       const char *fmt, ...);


enum sipevent_subst {
	SIPEVENT_ACTIVE = 0,
	SIPEVENT_TERMINATED,
};

struct sipevent_substate {
	enum sipevent_subst state;
	struct pl params;
	uint32_t expires;
};

int sipevent_substate_decode(struct sipevent_substate *ss,
			     const struct pl *pl);
const char *sipevent_substate_name(enum sipevent_subst state);
