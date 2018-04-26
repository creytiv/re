/**
 * @file res.c  Get DNS Server IP using resolv
 *
 * Copyright (C) 2010 Creytiv.com
 */

#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_dns.h>
#include "dns.h"

#ifdef __APPLE__
#       include <TargetConditionals.h>
#endif


int get_resolv_dns(char *domain, size_t dsize, struct sa *nsv, uint32_t *n)
{
	struct __res_state state;
	uint32_t i, cnt;
	int ret, err=0;
#if TARGET_OS_IPHONE
	union res_9_sockaddr_union *addrs;
	int k;
#endif


#ifdef OPENBSD
	ret = res_init();
	state = _res;
#else
	memset(&state, 0, sizeof(state));
	ret = res_ninit(&state);
#endif
	if (0 != ret)
		return ENOENT;

	if (!state.nscount) {
		err = ENOENT;
		goto out;
	}

	cnt = min(*n, (uint32_t)state.nscount);

#if TARGET_OS_IPHONE /* IPHONE targets need special treatment */
	addrs = mem_zalloc(cnt * sizeof(*addrs), NULL);
	if (!addrs) {
		err = ENOMEM;
		goto out;
	}

	cnt = res_getservers(&state, addrs, cnt);
	k = 0;
	for (i=0; i<cnt; i++) {
		switch (addrs[i].sin.sin_family) {
		case AF_INET:
			sa_set_in(&nsv[k++],
				  addrs[i].sin.sin_addr.s_addr,
				  addrs[i].sin.sin_port);
			break;

		case AF_INET6:
			sa_set_in6(&nsv[k++],
				   addrs[i].sin6.sin6_addr.s6_addr,
				   addrs[i].sin6.sin6_port);
			break;

		default:
			break;
		}
	}
	mem_deref(addrs);

	*n = k;
#else
	if (state.dnsrch[0])
		str_ncpy(domain, state.dnsrch[0], dsize);
	else if ((char *)state.defdname)
		str_ncpy(domain, state.defdname, dsize);

	err = 0;
	for (i=0; i<cnt && !err; i++) {
		struct sockaddr_in *addr = &state.nsaddr_list[i];
		err |= sa_set_sa(&nsv[i], (struct sockaddr *)addr);
	}
	if (err)
		goto out;

	*n = i;
#endif

 out:
#ifdef OPENBSD
#else
	res_nclose(&state);
#endif

	return err;
}
