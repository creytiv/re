/**
 * @file command.c RTMP Client -- commands
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


const struct odict_entry *odict_lookup_index(const struct odict *o,
					     unsigned ix,
					     int type)
{
	struct le *le;
	unsigned i;

	if (!o)
		return NULL;

	for (le = list_head(&o->lst), i=0; le; le = le->next, ++i) {

		const struct odict_entry *entry = le->data;

		if (ix == i) {
			if ((int)entry->type == type)
				return entry;
			else {
				re_printf("invalid type at index %u\n",
					      i);
				return NULL;
			}
		}
	}

	return NULL;
}


int rtmp_command_header_encode(struct mbuf *mb, const char *name, uint64_t tid)
{
	int err;

	if (!mb || !name)
		return EINVAL;

	err  = rtmp_amf_encode_string(mb, name);
	err |= rtmp_amf_encode_number(mb, tid);

	return err;
}


int rtmp_command_header_decode(struct command_header *hdr,
			       const struct odict *dict)
{
	const struct odict_entry *e;

	if (!hdr || !dict)
		return EINVAL;

	e = odict_lookup_index(dict, 0, ODICT_STRING);
	if (!e) {
		re_printf("rtmp: command name missing");
		return EPROTO;
	}
	str_ncpy(hdr->name, e->u.str, sizeof(hdr->name));

	e = odict_lookup_index(dict, 1, ODICT_DOUBLE);
	if (!e) {
		re_printf("rtmp: transaction id missing");
		return EPROTO;
	}
	hdr->transaction_id = e->u.dbl;

	return 0;
}


int rtmp_command_header_print(struct re_printf *pf,
			      const struct command_header *hdr)
{
	if (!hdr)
		return 0;

	return re_hprintf(pf, "command=\"%s\" transaction_id=%llu",
			  hdr->name, hdr->transaction_id);
}
