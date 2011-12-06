/**
 * @file re_sipevent.h  SIP Event Framework
 *
 * Copyright (C) 2010 Creytiv.com
 */


/* Listener Socket */

struct sipevent_sock;

int sipevent_listen(struct sipevent_sock **sockp, struct sip *sip,
		    uint32_t htsize_not, uint32_t htsize_sub,
		    sip_msg_h *subh, void *arg);


/* Subscriber */

struct sipsub;

typedef int  (sipevent_fork_h)(struct sipsub **subp, struct sipsub *osub,
			       const struct sip_msg *msg, void *arg);
typedef void (sipevent_notify_h)(struct sip *sip, const struct sip_msg *msg,
				 void *arg);
typedef void (sipevent_close_h)(int err, const struct sip_msg *msg, void *arg);


int sipevent_subscribe(struct sipsub **subp, struct sipevent_sock *sock,
		       const char *uri, const char *from_name,
		       const char *from_uri, const char *event,
		       uint32_t expires, const char *cuser,
		       const char *routev[], uint32_t routec,
		       sip_auth_h *authh, void *aarg, bool aref,
		       sipevent_fork_h *forkh, sipevent_notify_h *notifyh,
		       sipevent_close_h *closeh, void *arg,
		       const char *fmt, ...);
int sipevent_refer(struct sipsub **subp, struct sipevent_sock *sock,
		   const char *uri, const char *from_name,
		   const char *from_uri, const char *refer_to,
		   const char *cuser, const char *routev[], uint32_t routec,
		   sip_auth_h *authh, void *aarg, bool aref,
		   sipevent_fork_h *forkh, sipevent_notify_h *notifyh,
		   sipevent_close_h *closeh, void *arg,
		   const char *fmt, ...);
int sipevent_fork(struct sipsub **subp, struct sipsub *osub,
		  const struct sip_msg *msg,
		  sip_auth_h *authh, void *aarg, bool aref,
		  sipevent_notify_h *notifyh, sipevent_close_h *closeh,
		  void *arg);


/* Message Components */

struct sipevent_event {
	struct pl event;
	struct pl params;
};

enum sipevent_subst {
	SIPEVENT_ACTIVE = 0,
	SIPEVENT_PENDING,
	SIPEVENT_TERMINATED,
};

struct sipevent_substate {
	enum sipevent_subst state;
	struct pl params;
	struct pl expires;
	struct pl reason;
};

int sipevent_event_decode(struct sipevent_event *se, const struct pl *pl);
int sipevent_substate_decode(struct sipevent_substate *ss,
			     const struct pl *pl);
const char *sipevent_substate_name(enum sipevent_subst state);
