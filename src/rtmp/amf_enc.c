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


#define DEBUG_MODULE "rtmp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define PROPC_MAX 8


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


/*
 * NUMBER    double
 * BOOLEAN   bool
 * STRING    const char *
 * OBJECT    const char *key    sub-count
 * NULL      NULL
 * ARRAY     const char *key    sub-count
 */
int rtmp_amf_vencode_object(struct mbuf *mb, enum amf_type container,
			    unsigned propc, va_list *ap)
{
	bool is_root = false;
	unsigned i;
	int err = 0;

	if (!mb || !propc)
		return EINVAL;

	if (propc > PROPC_MAX) {
		DEBUG_WARNING("amf_enc: too many properties (%u > %u)\n",
			      propc, PROPC_MAX);
		return EOVERFLOW;
	}

	switch (container) {

	case AMF_TYPE_OBJECT:
		err = rtmp_amf_encode_object_start(mb);
		break;

	case AMF_TYPE_ARRAY:
		err = rtmp_amf_encode_array_start(mb, propc);
		break;

	case AMF_TYPE_ROOT:
		is_root = true;
		break;

	default:
		re_printf("amf_enc: not a container (%d)\n", container);
		return ENOTSUP;
	}

	for (i=0; i<propc; i++) {

		int type        = va_arg(*ap, int);
		const char *str;
		int subcount;
		double dbl;
		bool b;

		/* add key if ARRAY or OBJECT container */
		if (!is_root) {
			const char *key;

			key = va_arg(*ap, const char *);

			if (!key)
				return EINVAL;

			err = rtmp_amf_encode_key(mb, key);
			if (err)
				break;
		}

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
			err = rtmp_amf_vencode_object(mb, type, subcount, ap);
			break;

		case AMF_TYPE_OBJECT:  /* recursive */
			subcount = va_arg(*ap, int);
			err = rtmp_amf_vencode_object(mb, type, subcount, ap);
			break;

		default:
			re_printf("rtmp: amf_enc: type not supported"
				  " (i=%u, propc=%u, type=%d)\n",
				  i, propc, type);
			return ENOTSUP;
		}

		if (err)
			break;
	}

	if (!is_root)
		err |= rtmp_amf_encode_object_end(mb);

	return err;
}


/*
 * Encode AMF Object or Array
 */
int rtmp_amf_encode_object(struct mbuf *mb, enum amf_type container,
			   unsigned propc, ...)
{
	va_list ap;
	int err;

	va_start(ap, propc);
	err = rtmp_amf_vencode_object(mb, container, propc, &ap);
	va_end(ap);

	return err;
}
