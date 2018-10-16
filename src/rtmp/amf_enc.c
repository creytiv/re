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
#include <re_sa.h>
#include <re_list.h>
#include <re_sys.h>
#include <re_odict.h>
#include <re_rtmp.h>
#include "rtmp.h"


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
	return mbuf_write_u8(mb, RTMP_AMF_TYPE_OBJECT);
}


static int rtmp_amf_encode_array_start(struct mbuf *mb,
				       uint8_t type, uint32_t length)
{
	int err;

	err  = mbuf_write_u8(mb, type);
	err |= mbuf_write_u32(mb, htonl(length));

	return err;
}


static int rtmp_amf_encode_object_end(struct mbuf *mb)
{
	int err;

	err  = mbuf_write_u16(mb, 0);
	err |= mbuf_write_u8(mb, RTMP_AMF_TYPE_OBJECT_END);

	return err;
}


static bool container_has_key(enum rtmp_amf_type type)
{
	switch (type) {

	case RTMP_AMF_TYPE_OBJECT:       return true;
	case RTMP_AMF_TYPE_ECMA_ARRAY:   return true;
	case RTMP_AMF_TYPE_STRICT_ARRAY: return false;
	default:                         return false;
	}
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

	err  = mbuf_write_u8(mb, RTMP_AMF_TYPE_NUMBER);
	err |= mbuf_write_u64(mb, sys_htonll(num.i));

	return err;
}


int rtmp_amf_encode_boolean(struct mbuf *mb, bool boolean)
{
	int err;

	if (!mb)
		return EINVAL;

	err  = mbuf_write_u8(mb, RTMP_AMF_TYPE_BOOLEAN);
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

	err  = mbuf_write_u8(mb, RTMP_AMF_TYPE_STRING);
	err |= mbuf_write_u16(mb, htons((uint16_t)len));
	err |= mbuf_write_str(mb, str);

	return err;
}


int rtmp_amf_encode_null(struct mbuf *mb)
{
	if (!mb)
		return EINVAL;

	return mbuf_write_u8(mb, RTMP_AMF_TYPE_NULL);
}


/*
 * NUMBER    double
 * BOOLEAN   bool
 * STRING    const char *
 * OBJECT    const char *key    sub-count
 * NULL      NULL
 * ARRAY     const char *key    sub-count
 */
int rtmp_amf_vencode_object(struct mbuf *mb, enum rtmp_amf_type container,
			    unsigned propc, va_list *ap)
{
	bool encode_key;
	unsigned i;
	int err = 0;

	if (!mb || !propc || !ap)
		return EINVAL;

	encode_key = container_has_key(container);

	switch (container) {

	case RTMP_AMF_TYPE_OBJECT:
		err = rtmp_amf_encode_object_start(mb);
		break;

	case RTMP_AMF_TYPE_ECMA_ARRAY:
	case RTMP_AMF_TYPE_STRICT_ARRAY:
		err = rtmp_amf_encode_array_start(mb, container, propc);
		break;

	case RTMP_AMF_TYPE_ROOT:
		break;

	default:
		return ENOTSUP;
	}

	if (err)
		return err;

	for (i=0; i<propc; i++) {

		int type = va_arg(*ap, int);
		const char *str;
		int subcount;
		double dbl;
		bool b;

		/* add key if ARRAY or OBJECT container */
		if (encode_key) {
			const char *key;

			key = va_arg(*ap, const char *);
			if (!key)
				return EINVAL;

			err = rtmp_amf_encode_key(mb, key);
			if (err)
				return err;
		}

		switch (type) {

		case RTMP_AMF_TYPE_NUMBER:
			dbl = va_arg(*ap, double);
			err = rtmp_amf_encode_number(mb, dbl);
			break;

		case RTMP_AMF_TYPE_BOOLEAN:
			b = va_arg(*ap, int);
			err = rtmp_amf_encode_boolean(mb, b);
			break;

		case RTMP_AMF_TYPE_STRING:
			str = va_arg(*ap, const char *);
			err = rtmp_amf_encode_string(mb, str);
			break;

		case RTMP_AMF_TYPE_NULL:
			err = rtmp_amf_encode_null(mb);
			break;

		case RTMP_AMF_TYPE_OBJECT:
		case RTMP_AMF_TYPE_ECMA_ARRAY:
		case RTMP_AMF_TYPE_STRICT_ARRAY:
			/* recursive */
			subcount = va_arg(*ap, int);
			err = rtmp_amf_vencode_object(mb, type, subcount, ap);
			break;

		default:
			return ENOTSUP;
		}

		if (err)
			return err;
	}

	if (encode_key)
		err = rtmp_amf_encode_object_end(mb);

	return err;
}
