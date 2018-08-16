/**
 * @file rtmp/handshake.c  Real Time Messaging Protocol (RTMP) -- Handshake
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_rtmp.h>
#include "rtmp.h"


const char *rtmp_handshake_name(enum rtmp_handshake_state state)
{
	switch (state) {

	case RTMP_STATE_UNINITIALIZED:  return "UNINITIALIZED";
	case RTMP_STATE_VERSION_SENT:   return "VERSION_SENT";
	case RTMP_STATE_ACK_SENT:       return "ACK_SENT";
	case RTMP_STATE_HANDSHAKE_DONE: return "HANDSHAKE_DONE";
	default: return "?";
	}
}
