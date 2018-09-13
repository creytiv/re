/**
 * @file rtmp/util.c  Real Time Messaging Protocol (RTMP) -- Utility functions
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
