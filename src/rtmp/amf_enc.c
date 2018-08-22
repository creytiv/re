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


static int amf_encode_key(struct mbuf *mb, const char *key)
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


/* TODO: replace with print handlers ? */
int rtmp_amf_encode_object(struct mbuf *mb, const struct odict *dict)
{
	struct le *le;
	size_t key_len;
	int err = 0;

	if (!mb || !dict)
		return EINVAL;

	for (le = list_head(&dict->lst); le; le = le->next) {

		const struct odict_entry *entry = le->data;

		key_len = str_len(entry->key);

		if (key_len)
			err = amf_encode_key(mb, entry->key);

		switch (entry->type) {

		case ODICT_STRING:
			err = rtmp_amf_encode_string(mb, entry->u.str);
			break;

		case ODICT_DOUBLE:
			err = rtmp_amf_encode_number(mb, entry->u.dbl);
			break;

		case ODICT_BOOL:
			err = rtmp_amf_encode_boolean(mb, entry->u.boolean);
			break;

		case ODICT_OBJECT:
			/* NOTE: recursive function */
			err  = mbuf_write_u8(mb, AMF_TYPE_OBJECT);

			err |= rtmp_amf_encode_object(mb, entry->u.odict);

			err |= mbuf_write_u16(mb, 0);
			err |= mbuf_write_u8(mb, AMF_TYPE_OBJECT_END);
			break;

		case ODICT_ARRAY:
			/* NOTE: recursive function */
			err  = mbuf_write_u8(mb, AMF_TYPE_ARRAY);

			err |= mbuf_write_u32(mb, 0x00000000); /* length */

			err |= rtmp_amf_encode_object(mb, entry->u.odict);

			err |= mbuf_write_u16(mb, 0);
			err |= mbuf_write_u8(mb, AMF_TYPE_OBJECT_END);
			break;

		default:
			re_printf("encode: unknown type %d (%s)\n",
				  entry->type,
				  odict_type_name(entry->type));
			return ENOTSUP;
		}

		if (err)
			break;
	}

	return err;
}
