/**
 * @file net.c  Networking code.
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#include <string.h>
#if !defined(WIN32) && !defined(CYGWIN)
#define __USE_BSD 1  /**< Use BSD code */
#include <unistd.h>
#include <netdb.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_net.h>


#define DEBUG_MODULE "net"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/**
 * Get the IP address of the host
 *
 * @param af  Address Family
 * @param ip  Returned IP address
 *
 * @return 0 if success, otherwise errorcode
 */
int net_hostaddr(int af, struct sa *ip)
{
	char hostname[256];
	struct in_addr in;
	struct hostent *he;

	if (-1 == gethostname(hostname, sizeof(hostname)))
		return errno;

	he = gethostbyname(hostname);
	if (!he)
		return ENOENT;

	if (af != he->h_addrtype)
		return EAFNOSUPPORT;

	/* Get the first entry */
	memcpy(&in, he->h_addr_list[0], sizeof(in));
	sa_set_in(ip, ntohl(in.s_addr), 0);

	return 0;
}


/**
 * Get the default source IP address
 *
 * @param af  Address Family
 * @param ip  Returned IP address
 *
 * @return 0 if success, otherwise errorcode
 */
int net_default_source_addr_get(int af, struct sa *ip)
{
#if defined(WIN32) || defined(CYGWIN)
	return net_hostaddr(af, ip);
#else
	char ifname[64] = "";

#ifdef HAVE_ROUTE_LIST
	/* Get interface with default route */
	(void)net_rt_default_get(af, ifname, sizeof(ifname));
#endif

	/* First try with default interface */
	if (0 == net_if_getaddr(ifname, af, ip))
		return 0;

	/* Then try first real IP */
	if (0 == net_if_getaddr(NULL, af, ip))
		return 0;

	return net_if_getaddr4(ifname, af, ip);
#endif
}


/**
 * Get a list of all network interfaces including name and IP address.
 * Both IPv4 and IPv6 are supported
 *
 * @param ifh Interface handler, called once per network interface
 * @param arg Handler argument
 *
 * @return 0 if success, otherwise errorcode
 */
int net_if_apply(net_ifaddr_h *ifh, void *arg)
{
#ifdef HAVE_GETIFADDRS
	return net_getifaddrs(ifh, arg);
#else
	return net_if_list(ifh, arg);
#endif
}
