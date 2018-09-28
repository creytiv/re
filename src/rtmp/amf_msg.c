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


struct odict *rtmp_amf_message_dict(const struct rtmp_amf_message *msg)
{
	return msg ? msg->dict : NULL;
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


bool rtmp_amf_message_get_boolean(const struct rtmp_amf_message *msg,
				 bool *value, unsigned ix)
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

	if (entry->type != ODICT_BOOL) {
		re_printf("entry at index %u is not a boolean (%s)\n",
			  ix, odict_type_name(entry->type));
		return false;
	}

	if (value)
		*value = entry->u.boolean;

	return true;
}
