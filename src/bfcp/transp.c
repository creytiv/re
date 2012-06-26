/**
 * @file bfcp/transp.c BFCP Transport
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_tcp.h>
#include <re_bfcp.h>
#include "bfcp.h"


/**
 * Check if BFCP transport is reliable
 *
 * @param tp BFCP transport
 *
 * @return True if reliable, false if un-reliable
 */
bool bfcp_transp_reliable(enum bfcp_transp tp)
{
	switch (tp) {

	case BFCP_TRANSP_TCP:  return true;
	case BFCP_TRANSP_TLS:  return true;
	default:               return false;
	}
}


/**
 * Get the BFCP Transport protocol, suitable for SDP
 *
 * @param tp BFCP transport
 *
 * @return String with BFCP transport protocol
 */
const char *bfcp_transp_proto(enum bfcp_transp tp)
{
	switch (tp) {

	case BFCP_TRANSP_TCP:  return "TCP/BFCP";
	case BFCP_TRANSP_TLS:  return "TCP/TLS/BFCP";
	default:               return "???";
	}
}
