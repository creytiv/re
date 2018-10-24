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
#include <re_sa.h>
#include <re_list.h>
#include <re_sys.h>
#include <re_odict.h>
#include <re_rtmp.h>
#include "rtmp.h"


enum {
	AMF_HASH_SIZE = 32
};


static int amf_decode_value(struct odict *dict, const char *key,
			    struct mbuf *mb);


static int amf_decode_object(struct odict *dict, struct mbuf *mb)
{
	char *key = NULL;
	uint16_t len;
	int err = 0;

	while (mbuf_get_left(mb) > 0) {

		if (mbuf_get_left(mb) < 2)
			return ENODATA;

		len = ntohs(mbuf_read_u16(mb));

		if (len == 0) {
			uint8_t val;

			if (mbuf_get_left(mb) < 1)
				return ENODATA;

			val = mbuf_read_u8(mb);

			if (val == RTMP_AMF_TYPE_OBJECT_END)
				return 0;
			else
				return EBADMSG;
		}

		if (mbuf_get_left(mb) < len)
			return ENODATA;

		err = mbuf_strdup(mb, &key, len);
		if (err)
			return err;

		err = amf_decode_value(dict, key, mb);

		key = mem_deref(key);

		if (err)
			return err;
	}

	return 0;
}


static int amf_decode_value(struct odict *dict, const char *key,
			    struct mbuf *mb)
{
	union {
		uint64_t i;
		double f;
	} num;
	struct odict *object = NULL;
	char *str = NULL;
	uint32_t i, array_len;
	uint8_t type;
	uint16_t len;
	bool boolean;
	int err = 0;

	if (mbuf_get_left(mb) < 1)
		return ENODATA;

	type = mbuf_read_u8(mb);

	switch (type) {

	case RTMP_AMF_TYPE_NUMBER:
		if (mbuf_get_left(mb) < 8)
			return ENODATA;

		num.i = sys_ntohll(mbuf_read_u64(mb));

		err = odict_entry_add(dict, key, ODICT_DOUBLE, num.f);
		break;

	case RTMP_AMF_TYPE_BOOLEAN:
		if (mbuf_get_left(mb) < 1)
			return ENODATA;

		boolean = !!mbuf_read_u8(mb);

		err = odict_entry_add(dict, key, ODICT_BOOL, boolean);
		break;

	case RTMP_AMF_TYPE_STRING:
		if (mbuf_get_left(mb) < 2)
			return ENODATA;

		len = ntohs(mbuf_read_u16(mb));

		if (mbuf_get_left(mb) < len)
			return ENODATA;

		err = mbuf_strdup(mb, &str, len);
		if (err)
			return err;

		err = odict_entry_add(dict, key, ODICT_STRING, str);

		mem_deref(str);
		break;

	case RTMP_AMF_TYPE_NULL:
		err = odict_entry_add(dict, key, ODICT_NULL);
		break;

	case RTMP_AMF_TYPE_ECMA_ARRAY:
		if (mbuf_get_left(mb) < 4)
			return ENODATA;

		array_len = ntohl(mbuf_read_u32(mb));

		(void)array_len;  /* ignore array length */

		/* fallthrough */

	case RTMP_AMF_TYPE_OBJECT:
		err = odict_alloc(&object, 32);
		if (err)
			return err;

		err = amf_decode_object(object, mb);
		if (err) {
			mem_deref(object);
			return err;
		}

		err = odict_entry_add(dict, key, ODICT_OBJECT, object);

		mem_deref(object);
		break;

	case RTMP_AMF_TYPE_STRICT_ARRAY:
		if (mbuf_get_left(mb) < 4)
			return ENODATA;

		array_len = ntohl(mbuf_read_u32(mb));
		if (!array_len)
			return EPROTO;

		err = odict_alloc(&object, 32);
		if (err)
			return err;

		for (i=0; i<array_len; i++) {

			char ix[32];

			re_snprintf(ix, sizeof(ix), "%u", i);

			err = amf_decode_value(object, ix, mb);
			if (err) {
				mem_deref(object);
				return err;
			}
		}

		err = odict_entry_add(dict, key, ODICT_ARRAY, object);

		mem_deref(object);
		break;

	default:
		err = EPROTO;
		break;
	}

	return err;
}


int rtmp_amf_decode(struct odict **msgp, struct mbuf *mb)
{
	struct odict *msg;
	unsigned ix = 0;
	int err;

	if (!msgp || !mb)
		return EINVAL;

	err = odict_alloc(&msg, AMF_HASH_SIZE);
	if (err)
		return err;

	/* decode all entries on root-level */
	while (mbuf_get_left(mb) > 0) {

		char key[16];

		re_snprintf(key, sizeof(key), "%u", ix++);

		/* note: key is the numerical index */
		err = amf_decode_value(msg, key, mb);
		if (err)
			goto out;
	}

 out:
	if (err)
		mem_deref(msg);
	else
		*msgp = msg;

	return err;
}
