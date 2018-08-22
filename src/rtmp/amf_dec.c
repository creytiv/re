/**
 * @file rtmp/amf_dec.c  Real Time Messaging Protocol (RTMP) -- AMF Decoding
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


static int amf_decode_value(struct odict *dict, const char *key,
			    struct mbuf *mb);


static int amf_decode_object(struct odict *dict, struct mbuf *mb)
{
	char *prop_name = NULL;
	uint16_t len;
	int err = 0;

	while (mbuf_get_left(mb) > 0) {

		/* Property name */

		if (mbuf_get_left(mb) < 2)
			return ENODATA;

		len = ntohs(mbuf_read_u16(mb));

		if (len == 0) {
			uint8_t val;

			if (mbuf_get_left(mb) < 1)
				return ENODATA;

			val = mbuf_read_u8(mb);

			if (val == AMF_TYPE_OBJECT_END)
				return 0;
			else
				return EBADMSG;
		}

		if (mbuf_get_left(mb) < len)
			return ENODATA;

		err = mbuf_strdup(mb, &prop_name, len);
		if (err)
			goto out;

		/* Property value */

		err = amf_decode_value(dict, prop_name, mb);

		prop_name = mem_deref(prop_name);

		if (err)
			goto out;
	}

 out:
	mem_deref(prop_name);

	return err;
}


static int amf_decode_value(struct odict *dict, const char *key,
			    struct mbuf *mb)
{
	union {
		uint64_t i;
		double f;
	} num;
	struct odict *object = NULL;
	uint32_t array_len;
	uint8_t type;
	uint16_t len;
	char *str = NULL;
	bool boolean;
	int err = 0;

	if (mbuf_get_left(mb) < 1)
		return ENODATA;

	type = mbuf_read_u8(mb);

	switch (type) {

	case AMF_TYPE_NUMBER:
		if (mbuf_get_left(mb) < 8)
			return ENODATA;

		num.i = sys_ntohll(mbuf_read_u64(mb));

		err = odict_entry_add(dict, key, ODICT_DOUBLE, num.f);
		if (err)
			goto out;
		break;

	case AMF_TYPE_BOOLEAN:
		if (mbuf_get_left(mb) < 1)
			return ENODATA;

		boolean = !!mbuf_read_u8(mb);

		err = odict_entry_add(dict, key, ODICT_BOOL, boolean);
		if (err)
			goto out;
		break;

	case AMF_TYPE_STRING:
		if (mbuf_get_left(mb) < 2)
			return ENODATA;

		len = ntohs(mbuf_read_u16(mb));

		if (mbuf_get_left(mb) < len)
			return ENODATA;

		err = mbuf_strdup(mb, &str, len);
		if (err)
			goto out;

		err = odict_entry_add(dict, key, ODICT_STRING, str);
		if (err)
			goto out;
		break;

	case AMF_TYPE_OBJECT:
		err = odict_alloc(&object, 32);
		if (err)
			goto out;

		err = amf_decode_object(object, mb);
		if (err)
			goto out;

		err = odict_entry_add(dict, key, ODICT_OBJECT, object);
		if (err)
			goto out;

		object = mem_deref(object);
		break;

	case AMF_TYPE_NULL:
		err = odict_entry_add(dict, key, ODICT_NULL);
		if (err)
			goto out;
		break;

	case AMF_TYPE_ARRAY:
		if (mbuf_get_left(mb) < 4) {
			err = ENODATA;
			goto out;
		}

		array_len = ntohl(mbuf_read_u32(mb));

		re_printf("array:  len=%u (ignored)\n", array_len);

		err = odict_alloc(&object, 32);
		if (err)
			goto out;

		err = amf_decode_object(object, mb);
		if (err)
			goto out;

		err = odict_entry_add(dict, key, ODICT_ARRAY, object);
		if (err)
			goto out;

		object = mem_deref(object);
		break;

	default:
		re_printf("rtmp: amf decode: unknown amf type %u"
			  " \n", type);
		err = EPROTO;
		goto out;
	}

 out:
	mem_deref(object);
	mem_deref(str);

	return err;
}


int rtmp_amf_decode(struct odict *dict, struct mbuf *mb)
{
	int err = 0;

	if (!dict || !mb)
		return EINVAL;

	while (mbuf_get_left(mb) > 0) {

		/* note: key is empty */
		err = amf_decode_value(dict, "", mb);
		if (err)
			break;
	}

	return err;
}
