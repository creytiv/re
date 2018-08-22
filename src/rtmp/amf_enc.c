/**
 * @file rtmp/amf_enc.c  Real Time Messaging Protocol (RTMP) -- AMF Encoding
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
#include <re_odict.h>
#include <re_rtmp.h>
#include "rtmp.h"


int rtmp_amf_encode_number(struct mbuf *mb, double val)
{
	const union {
		uint64_t i;
		double f;
	} num = {
		.f = val
	};
	int err;

	if (!mb)
		return EINVAL;

	err  = mbuf_write_u8(mb, AMF_TYPE_NUMBER);
	err |= mbuf_write_u64(mb, sys_htonll(num.i));

	return err;
}


int rtmp_amf_encode_boolean(struct mbuf *mb, bool boolean)
{
	int err;

	if (!mb)
		return EINVAL;

	err  = mbuf_write_u8(mb, AMF_TYPE_BOOLEAN);
	err |= mbuf_write_u8(mb, !!boolean);

	return err;
}


int rtmp_amf_encode_string(struct mbuf *mb, const char *str)
{
	size_t len;
	int err;

	if (!mb || !str)
		return EINVAL;

	len = str_len(str);

	if (len > 65535)
		return EOVERFLOW;

	err  = mbuf_write_u8(mb, AMF_TYPE_STRING);
	err |= mbuf_write_u16(mb, htons((uint16_t)len));
	err |= mbuf_write_str(mb, str);

	return err;
}


int rtmp_amf_encode_null(struct mbuf *mb)
{
	if (!mb)
		return EINVAL;

	return mbuf_write_u8(mb, AMF_TYPE_NULL);
}


int rtmp_amf_encode_key(struct mbuf *mb, const char *key)
{
	size_t len;
	int err;

	len = str_len(key);

	if (len > 65535)
		return EOVERFLOW;

	err  = mbuf_write_u16(mb, htons((uint16_t)len));
	err |= mbuf_write_str(mb, key);

	return err;
}


int rtmp_amf_encode_object_start(struct mbuf *mb)
{
	return mbuf_write_u8(mb, AMF_TYPE_OBJECT);
}


int rtmp_amf_encode_object_end(struct mbuf *mb)
{
	int err;

	err  = mbuf_write_u16(mb, 0);
	err |= mbuf_write_u8(mb, AMF_TYPE_OBJECT_END);

	return err;
}


int rtmp_amf_encode_type(struct mbuf *mb, uint8_t type)
{
	return mbuf_write_u8(mb, type);
}
