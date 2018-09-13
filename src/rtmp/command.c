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


int rtmp_command_header_encode(struct mbuf *mb, const char *name, uint64_t tid)
{
	int err;

	if (!mb || !name)
		return EINVAL;

	err  = rtmp_amf_encode_string(mb, name);
	err |= rtmp_amf_encode_number(mb, tid);

	return err;
}
