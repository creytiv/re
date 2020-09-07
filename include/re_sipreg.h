/**
 * @file re_sipreg.h  SIP Registration
 *
 * Copyright (C) 2010 Creytiv.com
 */

struct sipreg;


int sipreg_register(struct sipreg **regp, struct sip *sip, const char *reg_uri,
		    const char *to_uri, const char *from_name,
		    const char *from_uri, uint32_t expires,
		    const char *cuser, const char *routev[], uint32_t routec,
		    int regid, sip_auth_h *authh, void *aarg, bool aref,
		    sip_resp_h *resph, void *arg,
		    const char *params, const char *fmt, ...);

int sipreg_set_rwait(struct sipreg *reg, uint32_t rwait);

const struct sa *sipreg_laddr(const struct sipreg *reg);

uint32_t sipreg_proxy_expires(const struct sipreg *reg);
bool sipreg_registered(const struct sipreg *reg);
bool sipreg_failed(const struct sipreg *reg);
void sipreg_incfailc(struct sipreg *reg);

int sipreg_set_fbregint(struct sipreg *reg, uint32_t fbregint);
