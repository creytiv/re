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


static int rtmp_amf_encode_key(struct mbuf *mb, const char *key)
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


static int rtmp_amf_encode_object_start(struct mbuf *mb)
{
	return mbuf_write_u8(mb, AMF_TYPE_OBJECT);
}


static int rtmp_amf_encode_array_start(struct mbuf *mb, uint32_t length)
{
	int err;

	err  = mbuf_write_u8(mb, AMF_TYPE_ARRAY);
	err |= mbuf_write_u32(mb, htonl(length));

	return err;
}


static int rtmp_amf_encode_object_end(struct mbuf *mb)
{
	int err;

	err  = mbuf_write_u16(mb, 0);
	err |= mbuf_write_u8(mb, AMF_TYPE_OBJECT_END);

	return err;
}


/*
 * NUMBER    double
 * BOOLEAN   bool
 * STRING    const char *
 * OBJECT    const char *key    sub-count
 * NULL      NULL
 * ARRAY     const char *key    sub-count
 */
static int rtmp_amf_vencode_object(struct mbuf *mb, bool array,
				   unsigned propc, va_list *ap)
{
	unsigned i;
	int err;

	if (!mb)
		return EINVAL;

	if (array)
		err = rtmp_amf_encode_array_start(mb, propc);
	else
		err = rtmp_amf_encode_object_start(mb);

	for (i=0; i<propc; i++) {

		int type        = va_arg(*ap, int);
		const char *key = va_arg(*ap, const char *);
		const char *str;
		int subcount;
		double dbl;
		bool b;

		if (!key)
			return EINVAL;

		err = rtmp_amf_encode_key(mb, key);
		if (err)
			break;

		switch (type) {

		case AMF_TYPE_NUMBER:
			dbl = va_arg(*ap, double);
			err = rtmp_amf_encode_number(mb, dbl);
			break;

		case AMF_TYPE_BOOLEAN:
			b = va_arg(*ap, int);
			err = rtmp_amf_encode_boolean(mb, b);
			break;

		case AMF_TYPE_STRING:
			str = va_arg(*ap, const char *);
			err = rtmp_amf_encode_string(mb, str);
			break;

		case AMF_TYPE_NULL:
			(void)va_arg(*ap, const void *);
			err = rtmp_amf_encode_null(mb);
			break;

		case AMF_TYPE_ARRAY:  /* recursive */
			subcount = va_arg(*ap, int);
			err = rtmp_amf_vencode_object(mb, true, subcount, ap);
			break;

		default:
			re_printf("type not supported (%d)\n", type);
			return ENOTSUP;
		}

		if (err)
			break;
	}

	err |= rtmp_amf_encode_object_end(mb);

	return err;
}


int rtmp_amf_encode_object(struct mbuf *mb, bool array, unsigned propc, ...)
{
	va_list ap;
	int err;

	va_start(ap, propc);
	err = rtmp_amf_vencode_object(mb, array, propc, &ap);
	va_end(ap);

	return err;
}
