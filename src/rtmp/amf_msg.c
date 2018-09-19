/**
 * @file amf_msg.c RTMP Client -- AMF Message
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


/* XXX: add element lookup functions with type */

/* XXX: use odict index string for fast lookup */


#define HASH_SIZE 32


static void destructor(void *data)
{
	struct rtmp_amf_message *msg = data;

	mem_deref(msg->name);
	mem_deref(msg->dict);
}


int rtmp_amf_message_decode(struct rtmp_amf_message **msgp, struct mbuf *mb)
{
	const struct odict_entry *entry;
	struct rtmp_amf_message *msg;
	int err;

	if (!msgp || !mb)
		return EINVAL;

	msg = mem_zalloc(sizeof(*msg), destructor);
	if (!msg)
		return ENOMEM;

	err = odict_alloc(&msg->dict, HASH_SIZE);
	if (err)
		goto out;

	err = rtmp_amf_decode(msg->dict, mb);
	if (err) {
		re_printf("rtmp: amf decode error (%m)\n", err);
		goto out;
	}

	entry = odict_lookup_index(msg->dict, 0, ODICT_STRING);
	if (!entry) {
		re_printf("rtmp: command name missing");
		err = EPROTO;
		goto out;
	}
	err = str_dup(&msg->name, entry->u.str);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(msg);
	else
		*msgp = msg;

	return err;
}


uint64_t rtmp_amf_message_tid(const struct rtmp_amf_message *msg)
{
	const struct odict_entry *entry;

	if (!msg)
		return 0;

	entry = odict_lookup_index(msg->dict, 1, ODICT_DOUBLE);
	if (!entry) {
		re_printf("rtmp: transaction id missing");
		return 0;
	}

	return (uint64_t)entry->u.dbl;
}


const char *rtmp_amf_message_string(const struct rtmp_amf_message *msg,
				    unsigned ix)
{
	const struct odict_entry *entry;
	char key[16];

	if (!msg)
		return NULL;

	re_snprintf(key, sizeof(key), "%u", ix);

	entry = odict_lookup(msg->dict, key);
	if (!entry) {
		re_printf("no entry at index %u\n", ix);
		return NULL;
	}

	if (entry->type != ODICT_STRING) {
		re_printf("entry at index %u is not a string (%s)\n",
			  ix, odict_type_name(entry->type));
		return NULL;
	}

	return entry->u.str;
}


bool rtmp_amf_message_get_number(const struct rtmp_amf_message *msg,
				 uint64_t *num, unsigned ix)
{
	const struct odict_entry *entry;
	char key[16];

	if (!msg)
		return false;

	re_snprintf(key, sizeof(key), "%u", ix);

	entry = odict_lookup(msg->dict, key);
	if (!entry) {
		re_printf("no entry at index %u\n", ix);
		return false;
	}

	if (entry->type != ODICT_DOUBLE) {
		re_printf("entry at index %u is not a number (%s)\n",
			  ix, odict_type_name(entry->type));
		return false;
	}

	if (num)
		*num = entry->u.dbl;

	return true;
}
