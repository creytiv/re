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


static int amf_decode_value(struct odict *dict, const char *key,
			    struct mbuf *mb);


static int amf_decode_object(struct odict *dict, struct mbuf *mb)
{
	char *prop_name = 0;
	uint16_t len;
	int err = 0;

	while (mbuf_get_left(mb) > 0) {

		/* Property name */

		len = ntohs(mbuf_read_u16(mb));

		if (len == 0) {
			uint8_t val = mbuf_read_u8(mb);

			if (val == 0x09) {
				re_printf("-- object end --\n");
				return 0;
			}
		}

		err = mbuf_strdup(mb, &prop_name, len);
		if (err)
			goto out;

		re_printf("  prop name = '%s'\n", prop_name);

		/* Property value */

		err = amf_decode_value(dict, prop_name, mb);
		if (err)
			goto out;

		prop_name = mem_deref(prop_name);
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
	uint8_t type;
	uint16_t len;
	char *str = 0;
	bool boolean;
	int err = 0;

	type = mbuf_read_u8(mb);

	switch (type) {

	case AMF_TYPE_NUMBER: /* number */
		num.i = sys_ntohll(mbuf_read_u64(mb));

		re_printf("number: %f\n", num.f, num.i);

		err = odict_entry_add(dict, key, ODICT_DOUBLE, num.f);
		if (err)
			goto out;
		break;

	case AMF_TYPE_BOOLEAN: /* boolean */
		boolean = mbuf_read_u8(mb);

		re_printf("boolean: %s\n", boolean ? "true" : "false");

		err = odict_entry_add(dict, key, ODICT_BOOL, boolean);
		if (err)
			goto out;
		break;

	case AMF_TYPE_STRING: /* string */
		len = ntohs(mbuf_read_u16(mb));

		err = mbuf_strdup(mb, &str, len);
		if (err)
			goto out;
		re_printf("string: %u bytes (%s)\n", len, str);

		err = odict_entry_add(dict, key, ODICT_STRING, str);
		if (err)
			goto out;
		break;

	case AMF_TYPE_OBJECT:      /* object */
		re_printf("-- object start --\n");

		struct odict *object;

		err = odict_alloc(&object, 32);

		err = amf_decode_object(object, mb);
		if (err)
			goto out;

		err = odict_entry_add(dict, key, ODICT_OBJECT, object);
		if (err)
			goto out;

		mem_deref(object);
		break;

	case AMF_TYPE_NULL: /* null */
		re_printf("null\n");
		err = odict_entry_add(dict, key, ODICT_NULL);
		if (err)
			goto out;
		break;

	default:
		re_printf("unknown amf type: %u\n", type);
		err = EPROTO;
		goto out;
	}

 out:
	mem_deref(str);

	return err;
}


int amf_decode(struct odict *dict, struct mbuf *mb)
{
	int err = 0;

	while (mbuf_get_left(mb) > 0) {

		/* note: key is empty */
		err = amf_decode_value(dict, "", mb);
		if (err)
			break;
	}

	return err;
}
