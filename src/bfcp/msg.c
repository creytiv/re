/**
 * @file bfcp/msg.c BFCP Message
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_bfcp.h>
#include "bfcp.h"


struct bfcp_msg {
	struct sa src;
	struct bfcp_hdr hdr;
	struct list attrl;
};


static void destructor(void *arg)
{
	struct bfcp_msg *msg = arg;

	list_flush(&msg->attrl);
}


int bfcp_msg_vencode(struct mbuf *mb, enum bfcp_prim prim,
		     uint32_t confid, uint16_t tid, uint16_t userid,
		     uint32_t attrc, va_list ap)
{
	size_t start;
	uint32_t i;
	uint16_t len;
	int err = 0;

	if (!mb)
		return EINVAL;

	start = mb->pos;
	mb->pos += BFCP_HDR_SIZE;

	for (i=0; i<attrc; i++) {

		uint16_t type = va_arg(ap, int);
		const void *v = va_arg(ap, const void *);
		bool mand = false;

		if (!v)
			continue;

		err = bfcp_attr_encode(mb, mand, type, v);
		if (err)
			return err;
	}

	/* header */
	len = (mb->pos - start - BFCP_HDR_SIZE) / 4;
	mb->pos = start;
	err = bfcp_hdr_encode(mb, prim, len, confid, tid, userid);

	mb->pos = mb->end;

	return err;
}


int bfcp_msg_encode(struct mbuf *mb, enum bfcp_prim prim, uint32_t confid,
		    uint16_t tid, uint16_t userid, uint32_t attrc, ...)
{
	va_list ap;
	int err;

	va_start(ap, attrc);
	err = bfcp_msg_vencode(mb, prim, confid, tid, userid, attrc, ap);
	va_end(ap);

	return err;
}


int bfcp_msg_decode(struct bfcp_msg **msgp, struct mbuf *mb)
{
	struct bfcp_msg *msg;
	size_t start, extra;
	int err;

	if (!msgp || !mb)
		return EINVAL;

	start = mb->pos;

	msg = mem_zalloc(sizeof(*msg), destructor);
	if (!msg)
		return ENOMEM;

	err = bfcp_hdr_decode(mb, &msg->hdr);
	if (err) {
		mb->pos = start;
		goto out;
	}

	extra = mbuf_get_left(mb) - 4*msg->hdr.len;

	while (mbuf_get_left(mb) - extra >= ATTR_HDR_SIZE) {

		struct bfcp_attr *attr;

		err = bfcp_attr_decode(&attr, mb);
		if (err)
			break;

		list_append(&msg->attrl, &attr->le, attr);
	}

 out:
	if (err)
		mem_deref(msg);
	else
		*msgp = msg;

	return err;
}


static bool attr_match(const struct bfcp_attr *attr, void *arg)
{
	return attr->type == *(uint8_t *)arg;
}


struct bfcp_attr *bfcp_msg_attr(const struct bfcp_msg *msg,
				enum bfcp_attrib type)
{
	return bfcp_msg_attr_apply(msg, attr_match, &type);
}


struct bfcp_attr *bfcp_msg_attr_apply(const struct bfcp_msg *msg,
				      bfcp_attr_h *h, void *arg)
{
	struct le *le = msg ? list_head(&msg->attrl) : NULL;

	while (le) {
		struct bfcp_attr *attr = le->data;

		le = le->next;

		if (h && h(attr, arg))
			return attr;
	}

	return NULL;
}


static bool attr_print(const struct bfcp_attr *attr, void *arg)
{
	struct re_printf *pf = arg;

	return 0 != bfcp_attr_print(pf, attr);
}


int bfcp_msg_print(struct re_printf *pf, const struct bfcp_msg *msg)
{
	int err;

	if (!msg)
		return 0;

	err = re_hprintf(pf, "%s (len=%u confid=%u tid=%u userid=%u)\n",
			 bfcp_prim_name(msg->hdr.prim), msg->hdr.len,
			 msg->hdr.confid, msg->hdr.tid, msg->hdr.userid);

	bfcp_msg_attr_apply(msg, attr_print, pf);

	return err;
}


enum bfcp_prim bfcp_msg_prim(const struct bfcp_msg *msg)
{
	return msg ? msg->hdr.prim : 0;
}


uint32_t bfcp_msg_confid(const struct bfcp_msg *msg)
{
	return msg ? msg->hdr.confid : 0;
}


uint16_t bfcp_msg_tid(const struct bfcp_msg *msg)
{
	return msg ? msg->hdr.tid : 0;
}


uint16_t bfcp_msg_userid(const struct bfcp_msg *msg)
{
	return msg ? msg->hdr.userid : 0;
}


const char *bfcp_reqstat_name(enum bfcp_rstat rstat)
{
	switch (rstat) {

	case BFCP_PENDING:    return "Pending";
	case BFCP_ACCEPTED:   return "Accepted";
	case BFCP_GRANTED:    return "Granted";
	case BFCP_DENIED:     return "Denied";
	case BFCP_CANCELLED:  return "Cancelled";
	case BFCP_RELEASED:   return "Released";
	case BFCP_REVOKED:    return "Revoked";
	default:              return "???";
	}
}


const char *bfcp_prim_name(enum bfcp_prim prim)
{
	switch (prim) {

	case BFCP_FLOOR_REQUEST:         return "FloorRequest";
	case BFCP_FLOOR_RELEASE:         return "FloorRelease";
	case BFCP_FLOOR_REQUEST_QUERY:   return "FloorRequestQuery";
	case BFCP_FLOOR_REQUEST_STAT:    return "FloorRequestStatus";
	case BFCP_USER_QUERY:            return "UserQuery";
	case BFCP_USER_STATUS:           return "UserStatus";
	case BFCP_FLOOR_QUERY:           return "FloorQuery";
	case BFCP_FLOOR_STATUS:          return "FloorStatus";
	case BFCP_CHAIR_ACTION:          return "ChairAction";
	case BFCP_CHAIR_ACTION_ACK:      return "ChairActionAck";
	case BFCP_HELLO:                 return "Hello";
	case BFCP_HELLO_ACK:             return "HelloAck";
	case BFCP_ERROR:                 return "Error";
	default:                         return "???";
	}
}


void bfcp_msg_set_src(struct bfcp_msg *msg, const struct sa *src)
{
	if (!msg || !src)
		return;

	msg->src = *src;
}


const struct sa *bfcp_msg_src(const struct bfcp_msg *msg)
{
	return msg ? &msg->src : NULL;
}
