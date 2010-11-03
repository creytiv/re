/**
 * @file sdp/media.c  SDP Media
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <stdlib.h>
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_sdp.h>
#include "sdp.h"


static void destructor(void *arg)
{
	struct sdp_media *m = arg;

	list_flush(&m->lfmtl);
	list_flush(&m->rfmtl);
	list_flush(&m->rattrl);
	list_flush(&m->lattrl);

	if (m->le.list) {
		m->disabled = true;
		mem_ref(m);
		return;
	}

	list_unlink(&m->le);
	mem_deref(m->name);
	mem_deref(m->proto);
}


static int media_alloc(struct sdp_media **mp, struct list *list)
{
	struct sdp_media *m;
	int i;

	m = mem_zalloc(sizeof(*m), destructor);
	if (!m)
		return ENOMEM;

	list_append(list, &m->le, m);

	m->ldir  = SDP_SENDRECV;
	m->rdir  = SDP_SENDRECV;
	m->dynpt = RTP_DYNPT_START;

	sa_init(&m->laddr, AF_INET);
	sa_init(&m->raddr, AF_INET);
	sa_init(&m->laddr_rtcp, AF_INET);
	sa_init(&m->raddr_rtcp, AF_INET);

	for (i=0; i<SDP_BANDWIDTH_MAX; i++) {
		m->lbwv[i] = -1;
		m->rbwv[i] = -1;
	}

	*mp = m;

	return 0;
}


int sdp_media_add(struct sdp_media **mp, struct sdp_session *sess,
		  const char *name, uint16_t port, const char *proto)
{
	struct sdp_media *m;
	int err;

	if (!sess || !name || !proto)
		return EINVAL;

	err = media_alloc(&m, &sess->lmedial);
	if (err)
		return err;

	err  = str_dup(&m->name, name);
	err |= str_dup(&m->proto, proto);
	if (err)
		goto out;

	sa_set_port(&m->laddr, port);

 out:
	if (err)
		mem_deref(m);
	else if (mp)
		*mp = m;

	return err;
}


int sdp_media_radd(struct sdp_media **mp, struct sdp_session *sess,
		   const struct pl *name, const struct pl *proto)
{
	struct sdp_media *m;
	int err;

	if (!mp || !sess || !name || !proto)
		return EINVAL;

	err = media_alloc(&m, &sess->medial);
	if (err)
		return err;

	m->disabled = true;

	err  = pl_strdup(&m->name, name);
	err |= pl_strdup(&m->proto, proto);

	if (err)
		mem_deref(m);
	else
		*mp = m;

	return err;
}


void sdp_media_rreset(struct sdp_media *m)
{
	int i;

	if (!m)
		return;

	sa_init(&m->raddr, AF_INET);
	sa_init(&m->raddr_rtcp, AF_INET);

	list_flush(&m->rfmtl);
	list_flush(&m->rattrl);

	m->rdir = SDP_SENDRECV;

	for (i=0; i<SDP_BANDWIDTH_MAX; i++)
		m->rbwv[i] = -1;
}


struct sdp_media *sdp_media_find(const struct sdp_session *sess,
				 const struct pl *name,
				 const struct pl *proto)
{
	struct le *le;

	if (!sess || !name || !proto)
		return NULL;

	for (le=sess->lmedial.head; le; le=le->next) {

		struct sdp_media *m = le->data;

		if (pl_strcmp(name, m->name))
			continue;

		if (pl_strcmp(proto, m->proto))
			continue;

		return m;
	}

	return NULL;
}


void sdp_media_align_formats(struct sdp_media *m, bool offer)
{
	struct sdp_format *rfmt, *lfmt;
	struct le *rle, *lle;

	if (!m || m->disabled || !sa_port(&m->raddr))
		return;

	for (lle=m->lfmtl.head; lle; lle=lle->next) {

		lfmt = lle->data;

		lfmt->sup = false;
	}

	for (rle=m->rfmtl.head; rle; rle=rle->next) {

		rfmt = rle->data;

		for (lle=m->lfmtl.head; lle; lle=lle->next) {

			lfmt = lle->data;

			if (sdp_format_cmp(lfmt, rfmt))
				break;
		}

		if (!lle) {
			rfmt->sup = false;
			continue;
		}

		lfmt->sup = true;
		rfmt->sup = true;

		if (rfmt->ref)
			rfmt->data = mem_deref(rfmt->data);
		else
			rfmt->data = NULL;

		if (lfmt->ref)
			rfmt->data = mem_ref(lfmt->data);
		else
			rfmt->data = lfmt->data;

		rfmt->ref = lfmt->ref;

		if (offer) {
			mem_deref(lfmt->id);
			lfmt->id = mem_ref(rfmt->id);
			lfmt->pt = atoi(lfmt->id ? lfmt->id : "");

			list_unlink(&lfmt->le);
			list_append(&m->lfmtl, &lfmt->le, lfmt);
		}
	}
}


void sdp_media_set_disabled(struct sdp_media *m, bool disabled)
{
	if (!m)
		return;

	m->disabled = disabled;
}


void sdp_media_set_lport(struct sdp_media *m, uint16_t port)
{
	if (!m)
		return;

	sa_set_port(&m->laddr, port);
}


void sdp_media_set_laddr(struct sdp_media *m, const struct sa *laddr)
{
	if (!m || !laddr)
		return;

	m->laddr = *laddr;
}


void sdp_media_set_lbandwidth(struct sdp_media *m, enum sdp_bandwidth type,
			      int32_t bw)
{
	if (!m || type >= SDP_BANDWIDTH_MAX)
		return;

	m->lbwv[type] = bw;
}


void sdp_media_set_lport_rtcp(struct sdp_media *m, uint16_t port)
{
	if (!m)
		return;

	sa_set_port(&m->laddr_rtcp, port);
}


void sdp_media_set_laddr_rtcp(struct sdp_media *m, const struct sa *laddr)
{
	if (!m || !laddr)
		return;

	m->laddr_rtcp = *laddr;
}


void sdp_media_set_ldir(struct sdp_media *m, enum sdp_dir dir)
{
	if (!m)
		return;

	m->ldir = dir;
}


int sdp_media_set_lattr(struct sdp_media *m, bool replace,
			const char *name, const char *value, ...)
{
	va_list ap;
	int err;

	if (!m || !name)
		return EINVAL;

	if (replace)
		sdp_attr_del(&m->lattrl, name);

	va_start(ap, value);
	err = sdp_attr_addv(&m->lattrl, name, value, ap);
	va_end(ap);

	return err;
}


void sdp_media_del_lattr(struct sdp_media *m, const char *name)
{
	if (!m || !name)
		return;

	sdp_attr_del(&m->lattrl, name);
}


uint16_t sdp_media_rport(const struct sdp_media *m)
{
	return m ? sa_port(&m->raddr) : 0;
}


const struct sa *sdp_media_raddr(const struct sdp_media *m)
{
	return m ? &m->raddr : NULL;
}


void sdp_media_raddr_rtcp(const struct sdp_media *m, struct sa *raddr)
{
	if (!m || !raddr)
		return;

	if (sa_isset(&m->raddr_rtcp, SA_ALL)) {
		*raddr = m->raddr_rtcp;
	}
	else if (sa_isset(&m->raddr_rtcp, SA_PORT)) {
		*raddr = m->raddr;
		sa_set_port(raddr, sa_port(&m->raddr_rtcp));
	}
	else {
		*raddr = m->raddr;
		sa_set_port(raddr, sa_port(&m->raddr) + 1);
	}
}


int32_t sdp_media_rbandwidth(const struct sdp_media *m,
			      enum sdp_bandwidth type)
{
	if (!m || type >= SDP_BANDWIDTH_MAX)
		return 0;

	return m->rbwv[type];
}


enum sdp_dir sdp_media_ldir(const struct sdp_media *m)
{
	return m ? m->ldir : SDP_INACTIVE;
}


enum sdp_dir sdp_media_rdir(const struct sdp_media *m)
{
	return m ? m->rdir : SDP_INACTIVE;
}


enum sdp_dir sdp_media_dir(const struct sdp_media *m)
{
	return m ? (enum sdp_dir)(m->ldir & m->rdir) : SDP_INACTIVE;
}


const struct sdp_format *sdp_media_lformat(const struct sdp_media *m, int pt)
{
	struct le *le;

	if (!m)
		return NULL;

	for (le=m->lfmtl.head; le; le=le->next) {

		const struct sdp_format *fmt = le->data;

		if (pt == fmt->pt)
			return fmt;
	}

	return NULL;
}


const struct sdp_format *sdp_media_rformat(const struct sdp_media *m,
					   const char *name)
{
	struct le *le;

	if (!m || !sa_port(&m->raddr))
		return NULL;

	for (le=m->rfmtl.head; le; le=le->next) {

		const struct sdp_format *fmt = le->data;

		if (!fmt->sup)
			continue;

		if (name && str_casecmp(name, fmt->name))
			continue;

		return fmt;
	}

	return NULL;
}


struct sdp_format *sdp_media_format(const struct sdp_media *m,
				    bool local, const char *id,
				    int pt, const char *name,
				    int32_t srate, int8_t ch)
{
	return sdp_media_format_apply(m, local, id, pt, name, srate, ch,
				      NULL, NULL);
}


struct sdp_format *sdp_media_format_apply(const struct sdp_media *m,
					  bool local, const char *id,
					  int pt, const char *name,
					  int32_t srate, int8_t ch,
					  sdp_format_h *fmth, void *arg)
{
	struct le *le;

	if (!m)
		return NULL;

	le = local ? m->lfmtl.head : m->rfmtl.head;

	while (le) {

		struct sdp_format *fmt = le->data;

		le = le->next;

		if (id && (!fmt->id || strcmp(id, fmt->id)))
			continue;

		if (pt >= 0 && pt != fmt->pt)
			continue;

		if (name && str_casecmp(name, fmt->name))
			continue;

		if (srate >= 0 && (uint32_t)srate != fmt->srate)
			continue;

		if (ch >= 0 && (uint8_t)ch != fmt->ch)
			continue;

		if (!fmth || fmth(fmt, arg))
			return fmt;
	}

	return NULL;
}


const struct list *sdp_media_format_lst(const struct sdp_media *m, bool local)
{
	if (!m)
		return NULL;

	return local ? &m->lfmtl : &m->rfmtl;
}


const char *sdp_media_rattr(const struct sdp_media *m, const char *name)
{
	if (!m || !name)
		return NULL;

	return sdp_attr_apply(&m->rattrl, name, NULL, NULL);
}


const char *sdp_media_rattr_apply(const struct sdp_media *m, const char *name,
				  sdp_attr_h *attrh, void *arg)
{
	if (!m)
		return NULL;

	return sdp_attr_apply(&m->rattrl, name, attrh, arg);
}


const char *sdp_media_name(const struct sdp_media *m)
{
	return m ? m->name : NULL;
}


int sdp_media_debug(struct re_printf *pf, const struct sdp_media *m)
{
	struct le *le;
	int err;

	if (!m)
		return 0;

	err  = re_hprintf(pf, "%s %s\n", m->name, m->proto);

	err |= re_hprintf(pf, "  local formats:\n");

	for (le=m->lfmtl.head; le; le=le->next)
		err |= re_hprintf(pf, "    %H\n", sdp_format_debug, le->data);

	err |= re_hprintf(pf, "  remote formats:\n");

	for (le=m->rfmtl.head; le; le=le->next)
		err |= re_hprintf(pf, "    %H\n", sdp_format_debug, le->data);

	err |= re_hprintf(pf, "  local attributes:\n");

	for (le=m->lattrl.head; le; le=le->next)
		err |= re_hprintf(pf, "    %H\n", sdp_attr_debug, le->data);

	err |= re_hprintf(pf, "  remote attributes:\n");

	for (le=m->rattrl.head; le; le=le->next)
		err |= re_hprintf(pf, "    %H\n", sdp_attr_debug, le->data);

	return err;
}
