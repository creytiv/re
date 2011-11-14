/**
 * @file re_sipevent.h  SIP Event Framework
 *
 * Copyright (C) 2010 Creytiv.com
 */

struct sipsub;

int sipevent_subscribe(struct sipsub **subp, struct sip *sip, const char *uri,
		       const char *from_name, const char *from_uri,
		       const char *event, uint32_t expires, const char *cuser,
		       const char *routev[], uint32_t routec,
		       sip_auth_h *authh, void *aarg, bool aref,
		       sip_resp_h *resph, void *arg,
		       const char *fmt, ...);
