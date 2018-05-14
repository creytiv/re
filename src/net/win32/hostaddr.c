/**
* @file hostaddr.c Windows networking code.
*
* Copyright (C) 2010 Creytiv.com
*/
#include <stdlib.h>
#include <re_types.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_net.h>

#define DEBUG_MODULE "hostaddr"
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
	struct addrinfo *result = NULL;
	struct addrinfo *ptr = NULL;
	bool ip_family_match = false;
	int err = 0;

	if (-1 == gethostname(hostname, sizeof(hostname)))
		return errno;

	err = GetAddrInfo(hostname, NULL, NULL, &result);
	if (err)
		return err;
	if (!result)
		return ENOENT;

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		if (ptr->ai_family == af)
		{
			ip_family_match = true;
			struct sockaddr * addr = ptr->ai_addr;
			sa_set_sa(ip, addr);
		}
	}

	if (!ip_family_match)
		return EAFNOSUPPORT;
	return 0;
}