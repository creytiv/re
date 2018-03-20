/**
 * @file net.c  Networking code.
 *
 * Copyright (C) 2010 Creytiv.com
 */
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <stdlib.h>
#include <string.h>
#if !defined(WIN32)
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


#if defined(WIN32)
/**
 * Get the IP address of the host
 *
 * @param af  Address Family
 * @param ip  Returned IP address
 *
 * @return 0 if success, otherwise errorcode
 */
static int net_hostaddr_win32(int af, struct sa *ip)
{
	char hostname[256];

	if (-1 == gethostname(hostname, sizeof(hostname)))
		return errno;

	struct addrinfo *result = NULL;
	struct addrinfo *ptr = NULL;
	bool ip_family_match = false;

	/*gethostbyname is deprecated. It's better to use GetAddrInfo instead*/
	GetAddrInfo(hostname, NULL, NULL, &result);
	if (!result)
		return ENOENT;

	/*Get entry which have similar to af ip family (for example IPv4)*/
	/*Previously net_hostaddr set ip address of the first adapter*/
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		if (ptr->ai_family == af)
		{
			ip_family_match = true;
			struct sockaddr_in * addr_ipv4 = ptr->ai_addr;
			sa_set_in(ip, ntohl(addr_ipv4->sin_addr.s_addr), 0);
		}
	}

	if (!ip_family_match)
		return EAFNOSUPPORT;
	return 0;
}
#endif


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
#if defined(WIN32)
	return net_hostaddr_win32(af, ip);
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


static bool net_rt_handler(const char *ifname, const struct sa *dst,
			   int dstlen, const struct sa *gw, void *arg)
{
	void **argv = arg;
	struct sa *ip = argv[1];
	(void)dst;
	(void)dstlen;

	if (0 == str_cmp(ifname, argv[0])) {
		*ip = *gw;
		return true;
	}

	return false;
}


/**
 * Get the IP-address of the default gateway
 *
 * @param af  Address Family
 * @param gw  Returned Gateway address
 *
 * @return 0 if success, otherwise errorcode
 */
int net_default_gateway_get(int af, struct sa *gw)
{
	char ifname[64];
	void *argv[2];
	int err;

	if (!af || !gw)
		return EINVAL;

	err = net_rt_default_get(af, ifname, sizeof(ifname));
	if (err)
		return err;

	argv[0] = ifname;
	argv[1] = gw;

	err = net_rt_list(net_rt_handler, argv);
	if (err)
		return err;

	return 0;
}
