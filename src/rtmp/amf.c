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
#include <re_odict.h>
#include <re_rtmp.h>
#include "rtmp.h"


/*
 * The AMF data types is very similar to JSON or Ordered Dictionary
 *
 * The AMF types are mapped to Ordered Dictionary (odict).
 * The key field is empty/unused for basic types, but used for
 * object properties.
 */


static int amf_decode_value(struct odict *dict, const char *key,
			    struct mbuf *mb);


int amf_encode_number(struct mbuf *mb, double val)
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


int amf_encode_boolean(struct mbuf *mb, bool boolean)
{
	int err;

	if (!mb)
		return EINVAL;

	err  = mbuf_write_u8(mb, AMF_TYPE_BOOLEAN);
	err |= mbuf_write_u8(mb, !!boolean);

	return err;
}


int amf_encode_string(struct mbuf *mb, const char *str)
{
	const size_t len = str_len(str);
	int err = 0;

	if (!mb)
		return EINVAL;

	if (len > 65535)
		return EOVERFLOW;

	err |= mbuf_write_u8(mb, AMF_TYPE_STRING);
	err |= mbuf_write_u16(mb, htons((uint16_t)len));
	err |= mbuf_write_str(mb, str);

	return err;
}


int amf_encode_null(struct mbuf *mb)
{
	if (!mb)
		return EINVAL;

	return mbuf_write_u8(mb, AMF_TYPE_NULL);
}


int amf_encode_object(struct mbuf *mb, struct odict *dict)
{
	struct le *le;
	size_t key_len;
	int err = 0;

	if (!mb || !dict)
		return EINVAL;

	for (le = list_head(&dict->lst); le; le = le->next) {

		struct odict_entry *entry = le->data;

		key_len = str_len(entry->key);

		switch (entry->type) {

		case ODICT_STRING:
			if (key_len) {
				err |= mbuf_write_u16(mb, htons(key_len));
				err |= mbuf_write_str(mb, entry->key);
			}

			err = amf_encode_string(mb, entry->u.str);
			break;

		case ODICT_DOUBLE:
			if (key_len) {
				err |= mbuf_write_u16(mb, htons(key_len));
				err |= mbuf_write_str(mb, entry->key);
			}

			err = amf_encode_number(mb, entry->u.dbl);
			break;

		case ODICT_OBJECT:
			/* NOTE: recursive function */

			if (key_len) {
				err |= mbuf_write_u16(mb, htons(key_len));
				err |= mbuf_write_str(mb, entry->key);
			}

			err  = mbuf_write_u8(mb, AMF_TYPE_OBJECT);

			err |= amf_encode_object(mb, entry->u.odict);

			err |= mbuf_write_u16(mb, 0);
			err |= mbuf_write_u8(mb, 0x09);
			break;

		case ODICT_ARRAY:
			/* NOTE: recursive function */

			if (key_len) {
				err |= mbuf_write_u16(mb, htons(key_len));
				err |= mbuf_write_str(mb, entry->key);
			}

			err  = mbuf_write_u8(mb, AMF_TYPE_ARRAY);

			err |= mbuf_write_u32(mb, 0x00000000); /* length */

			err |= amf_encode_object(mb, entry->u.odict);

			err |= mbuf_write_u16(mb, 0);
			err |= mbuf_write_u8(mb, 0x09);
			break;

		case ODICT_BOOL:
			if (key_len) {
				err |= mbuf_write_u16(mb, htons(key_len));
				err |= mbuf_write_str(mb, entry->key);
			}

			err = amf_encode_boolean(mb, entry->u.boolean);
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


static int amf_decode_object(struct odict *dict, struct mbuf *mb)
{
	char *prop_name = 0;
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

			if (val == 0x09) {
				return 0;
			}
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
	char *str = 0;
	bool boolean;
	int err = 0;

	if (mbuf_get_left(mb) < 1)
		return ENODATA;

	type = mbuf_read_u8(mb);

	switch (type) {

	case AMF_TYPE_NUMBER: /* number */
		if (mbuf_get_left(mb) < 8)
			return ENODATA;

		num.i = sys_ntohll(mbuf_read_u64(mb));

		err = odict_entry_add(dict, key, ODICT_DOUBLE, num.f);
		if (err)
			goto out;
		break;

	case AMF_TYPE_BOOLEAN: /* boolean */
		if (mbuf_get_left(mb) < 1)
			return ENODATA;

		boolean = mbuf_read_u8(mb);

		err = odict_entry_add(dict, key, ODICT_BOOL, boolean);
		if (err)
			goto out;
		break;

	case AMF_TYPE_STRING: /* string */
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
			  " for key='%s'\n", type, key);
		err = EPROTO;
		goto out;
	}

 out:
	mem_deref(object);
	mem_deref(str);

	return err;
}


int amf_decode(struct odict *dict, struct mbuf *mb)
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
