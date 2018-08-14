/**
 * @file rtmp/amf.c  Real Time Messaging Protocol (RTMP) -- AMF
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_list.h>
#include <re_sys.h>
#include <re_rtmp.h>
#include "rtmp.h"


int amf_encode_number(struct mbuf *mb, double val)
{
	union {
		uint64_t i;
		double f;
	} num;
	int err;

	num.f = val;

	err  = mbuf_write_u8(mb, AMF_TYPE_NUMBER);
	err |= mbuf_write_u64(mb, sys_htonll(num.i));

	return err;
}


int amf_encode_boolean(struct mbuf *mb, bool boolean)
{
	int err;

	err  = mbuf_write_u8(mb, AMF_TYPE_BOOLEAN);
	err |= mbuf_write_u8(mb, !!boolean);

	return err;
}


int amf_encode_string(struct mbuf *mb, const char *str)
{
	size_t len = str_len(str);
	int err;

	err  = mbuf_write_u8(mb, AMF_TYPE_STRING);
	err |= mbuf_write_u16(mb, htons(len));
	err |= mbuf_write_str(mb, str);

	return err;
}


int amf_encode_null(struct mbuf *mb)
{
	return mbuf_write_u8(mb, AMF_TYPE_NULL);
}
