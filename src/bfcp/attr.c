/**
 * @file bfcp/attr.c BFCP Attributes
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_bfcp.h>
#include "bfcp.h"


static int attr_decode(struct bfcp_attr *attr, union bfcp_union *v,
		       struct mbuf *mb);


static void destructor(void *arg)
{
	struct bfcp_attr *attr = arg;
	size_t i;

	switch (attr->type) {

	case BFCP_ERROR_INFO:
	case BFCP_PARTICIPANT_PROV_INFO:
	case BFCP_STATUS_INFO:
	case BFCP_USER_DISPLAY_NAME:
	case BFCP_USER_URI:
		mem_deref(attr->v.str);
		break;

	case BFCP_SUPPORTED_ATTRIBUTES:
		mem_deref(attr->v.supattr.attrv);
		break;

	case BFCP_SUPPORTED_PRIMITIVES:
		mem_deref(attr->v.supprim.primv);
		break;

	case BFCP_ERROR_CODE:
		mem_deref(attr->v.errcode.details);
		break;

		/* grouped */

	case BFCP_BENEFICIARY_INFO:
		mem_deref(attr->v.bfi.dname);
		mem_deref(attr->v.bfi.uri);
		break;

	case BFCP_FLOOR_REQUEST_INFO:
		mem_deref(attr->v.fri.ors.statinfo);
		for (i=0; i<attr->v.fri.frsc; i++)
			mem_deref(attr->v.fri.frsv[i].statinfo);
		mem_deref(attr->v.fri.frsv);
		mem_deref(attr->v.fri.bfi.dname);
		mem_deref(attr->v.fri.bfi.uri);
		mem_deref(attr->v.fri.rbi.dname);
		mem_deref(attr->v.fri.rbi.uri);
		mem_deref(attr->v.fri.ppi);
		break;

	case BFCP_REQUESTED_BY_INFO:
		mem_deref(attr->v.rbi.dname);
		mem_deref(attr->v.rbi.uri);
		break;

	case BFCP_FLOOR_REQUEST_STATUS:
		mem_deref(attr->v.frs.statinfo);
		break;

	case BFCP_OVERALL_REQUEST_STATUS:
		mem_deref(attr->v.ors.statinfo);
		break;

	default:
		/* nothing allocated */
		break;
	}
}


int bfcp_attr_encode(struct mbuf *mb, bool mand, enum bfcp_attrib type,
		     const void *v)
{
	const struct bfcp_errcode *ec = v;
	const struct bfcp_supattr *sa = v;
	const struct bfcp_supprim *sp = v;
	const struct bfcp_reqstat *rs = v;
	const struct bfcp_beneficiary_info *bfi = v;
	const struct bfcp_floor_reqinfo *fri = v;
	const struct bfcp_reqby_info *rbi = v;
	const struct bfcp_floor_reqstat *frs = v;
	const struct bfcp_overall_reqstat *ors = v;
	const uint16_t *u16 = v;
	const enum bfcp_prio *prio = v;
	size_t start, len, i;
	int err = 0;

	if (!mb || !v)
		return EINVAL;

	start = mb->pos;
	mb->pos += ATTR_HDR_SIZE;

	switch (type) {

	case BFCP_BENEFICIARY_ID:
	case BFCP_FLOOR_ID:
	case BFCP_FLOOR_REQUEST_ID:
		err |= mbuf_write_u16(mb, htons(*u16));
		break;

	case BFCP_PRIORITY:
		err |= mbuf_write_u8(mb, *prio << 5);
		err |= mbuf_write_u8(mb, 0x00);
		break;

	case BFCP_REQUEST_STATUS:
		err |= mbuf_write_u8(mb, rs->stat);
		err |= mbuf_write_u8(mb, rs->qpos);
		break;

	case BFCP_ERROR_CODE:
		err |= mbuf_write_u8(mb, ec->code);
		if (ec->details && ec->len)
			err |= mbuf_write_mem(mb, ec->details, ec->len);
		break;

	case BFCP_ERROR_INFO:
	case BFCP_PARTICIPANT_PROV_INFO:
	case BFCP_STATUS_INFO:
	case BFCP_USER_DISPLAY_NAME:
	case BFCP_USER_URI:
		err |= mbuf_write_str(mb, v);
		break;

	case BFCP_SUPPORTED_ATTRIBUTES:
		for (i=0; i<sa->attrc; i++)
			err |= mbuf_write_u8(mb, sa->attrv[i] << 1);
		break;

	case BFCP_SUPPORTED_PRIMITIVES:
		for (i=0; i<sp->primc; i++)
			err |= mbuf_write_u8(mb, sp->primv[i]);
		break;

		/* grouped attributes: */

	case BFCP_BENEFICIARY_INFO:
		err |= mbuf_write_u16(mb, htons(bfi->bfid));

		if (bfi->dname)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_USER_DISPLAY_NAME,
						bfi->dname);
		if (bfi->uri)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_USER_URI,
						bfi->uri);
		break;

	case BFCP_FLOOR_REQUEST_INFO:
		err |= mbuf_write_u16(mb, htons(fri->freqid));

		if (fri->ors.freqid)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_OVERALL_REQUEST_STATUS,
						&fri->ors);

		for (i=0; i<fri->frsc; i++) {
			err |= bfcp_attr_encode(mb, mand,
						BFCP_FLOOR_REQUEST_STATUS,
						&fri->frsv[i]);
		}

		if (fri->bfi.bfid)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_BENEFICIARY_INFO,
						&fri->bfi);

		if (fri->rbi.rbid)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_REQUESTED_BY_INFO,
						&fri->rbi);

		err |= bfcp_attr_encode(mb, mand, BFCP_PRIORITY, &fri->prio);

		if (fri->ppi)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_PARTICIPANT_PROV_INFO,
						fri->ppi);
		break;

	case BFCP_REQUESTED_BY_INFO:
		err |= mbuf_write_u16(mb, htons(rbi->rbid));

		if (rbi->dname)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_USER_DISPLAY_NAME,
						rbi->dname);
		if (rbi->uri)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_USER_URI,
						rbi->uri);
		break;

	case BFCP_FLOOR_REQUEST_STATUS:
		err |= mbuf_write_u16(mb, htons(frs->floorid));

		if (frs->reqstat.stat)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_REQUEST_STATUS,
						&frs->reqstat);
		if (frs->statinfo)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_STATUS_INFO,
						frs->statinfo);
		break;

	case BFCP_OVERALL_REQUEST_STATUS:
		err |= mbuf_write_u16(mb, htons(ors->freqid));

		if (ors->reqstat.stat)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_REQUEST_STATUS,
						&ors->reqstat);
		if (ors->statinfo)
			err |= bfcp_attr_encode(mb, mand,
						BFCP_STATUS_INFO,
						ors->statinfo);
		break;

	default:
		err = EINVAL;
		break;
	}

	if (err)
		return err;

	len = mb->pos - start;

	/* padding */
	while ((mb->pos - start) & 0x03)
		err |= mbuf_write_u8(mb, 0x00);

	if (bfcp_attr_isgrouped(type))
		len = mb->pos - start;

	/* header */
	mb->pos = start;
	err |= mbuf_write_u8(mb, (type<<1) | (mand&1));
	err |= mbuf_write_u8(mb, len);
	mb->pos = mb->end;

	return err;
}


static int decv(struct mbuf *mb, uint8_t type, void **vp,
		size_t elemsz, size_t *count)
{
	size_t n = 0;
	void *v = NULL;
	int err = 0;

	while (mbuf_get_left(mb) >= ATTR_HDR_SIZE) {

		struct bfcp_attr attr;
		uint8_t *bp;

		if (type != (mbuf_buf(mb)[0] >> 1))
			break;

		++n;

		if (v) {
			void *v2 = mem_realloc(v, n * elemsz);
			if (!v2) {
				err = ENOMEM;
				break;
			}

			v = v2;
		}
		else {
			v = mem_zalloc(1 * elemsz, NULL);
			if (!v) {
				err = ENOMEM;
				break;
			}
		}

		bp = ((uint8_t *)v) + (n-1) * elemsz;

		err = attr_decode(&attr, (void *)bp, mb);
		if (err)
			break;
	}

	if (err)
		mem_deref(v);
	else {
		*vp = v;
		*count = n;
	}

	return err;
}


/* Decode a Nested attribute */
static int decn(struct mbuf *mb, uint8_t type, void *p)
{
	struct bfcp_attr attr;
	int err;

	/* sanity check of attribute type */
	if (mbuf_get_left(mb) < 1 || type != (mbuf_buf(mb)[0] >> 1))
		return 0;

	err = attr_decode(&attr, p, mb);
	if (err)
		return err;

	return 0;
}


static int attr_decode(struct bfcp_attr *attr, union bfcp_union *v,
		       struct mbuf *mb)
{
	size_t i, start, len;
	uint8_t u8;
	int err = 0;

	if (!attr || !v || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < ATTR_HDR_SIZE)
		return EBADMSG;

	start = mb->pos;

	u8 = mbuf_read_u8(mb);
	attr->type = u8 >> 1;
	attr->mand = u8 & 1;
	len = mbuf_read_u8(mb) - ATTR_HDR_SIZE;

	if (mbuf_get_left(mb) < len)
		goto badmsg;

	switch (attr->type) {

	case BFCP_BENEFICIARY_ID:
	case BFCP_FLOOR_ID:
	case BFCP_FLOOR_REQUEST_ID:
		if (len < 2)
			goto badmsg;

	        v->u16 = ntohs(mbuf_read_u16(mb));
		break;

	case BFCP_PRIORITY:
		if (len < 2)
			goto badmsg;

		v->prio = mbuf_read_u8(mb) >> 5;
		(void)mbuf_read_u8(mb);
		break;

	case BFCP_REQUEST_STATUS:
		if (len < 2)
			goto badmsg;

		v->reqstat.stat = mbuf_read_u8(mb);
		v->reqstat.qpos = mbuf_read_u8(mb);
		break;

	case BFCP_ERROR_CODE:
		if (len < 1)
			goto badmsg;

		v->errcode.len = len - 1;
		v->errcode.code = mbuf_read_u8(mb);

		if (v->errcode.len > 0) {

			v->errcode.details = mem_alloc(v->errcode.len, NULL);
			if (!v->errcode.details) {
				err = ENOMEM;
				goto error;
			}

			(void)mbuf_read_mem(mb, v->errcode.details,
					    v->errcode.len);
		}
		break;

	case BFCP_ERROR_INFO:
	case BFCP_PARTICIPANT_PROV_INFO:
	case BFCP_STATUS_INFO:
	case BFCP_USER_DISPLAY_NAME:
	case BFCP_USER_URI:
		err = mbuf_strdup(mb, &v->str, len);
		break;

	case BFCP_SUPPORTED_ATTRIBUTES:
		v->supattr.attrv = mem_alloc(len * sizeof(*v->supattr.attrv),
					     NULL);
		if (!v->supattr.attrv) {
			err = ENOMEM;
			goto error;
		}

		v->supattr.attrc = (uint32_t)len;
		for (i=0; i<len; i++)
			v->supattr.attrv[i] = mbuf_read_u8(mb) >> 1;
		break;

	case BFCP_SUPPORTED_PRIMITIVES:
		v->supprim.primv = mem_alloc(len * sizeof(*v->supprim.primv),
					     NULL);
		if (!v->supprim.primv) {
			err = ENOMEM;
			goto error;
		}

		v->supprim.primc = (uint32_t)len;
		for (i=0; i<len; i++)
			v->supprim.primv[i] = mbuf_read_u8(mb);
		break;

		/* grouped attributes */

	case BFCP_BENEFICIARY_INFO:
		if (len < 2)
			goto badmsg;

		v->bfi.bfid  = ntohs(mbuf_read_u16(mb));
		err |= decn(mb, BFCP_USER_DISPLAY_NAME, &v->bfi.dname);
		err |= decn(mb, BFCP_USER_URI, &v->bfi.uri);
		break;

	case BFCP_FLOOR_REQUEST_INFO:
		if (len < 2)
			goto badmsg;

	        v->fri.freqid = ntohs(mbuf_read_u16(mb));
		err |= decn(mb, BFCP_OVERALL_REQUEST_STATUS, &v->fri.ors);
		err |= decv(mb, BFCP_FLOOR_REQUEST_STATUS,
			    (void *)&v->fri.frsv, sizeof(*v->fri.frsv),
			    &v->fri.frsc);
		err |= decn(mb, BFCP_BENEFICIARY_INFO, &v->fri.bfi);
		err |= decn(mb, BFCP_REQUESTED_BY_INFO, &v->fri.rbi);
		err |= decn(mb, BFCP_PRIORITY, &v->fri.prio);
		err |= decn(mb, BFCP_PARTICIPANT_PROV_INFO, &v->fri.ppi);
		break;

	case BFCP_REQUESTED_BY_INFO:
		if (len < 2)
			goto badmsg;

		v->rbi.rbid = ntohs(mbuf_read_u16(mb));
		err |= decn(mb, BFCP_USER_DISPLAY_NAME, &v->rbi.dname);
		err |= decn(mb, BFCP_USER_URI, &v->rbi.uri);
		break;

	case BFCP_FLOOR_REQUEST_STATUS:
		if (len < 2)
			goto badmsg;

	        v->frs.floorid = ntohs(mbuf_read_u16(mb));
		err |= decn(mb, BFCP_REQUEST_STATUS, &v->frs.reqstat);
		err |= decn(mb, BFCP_STATUS_INFO, &v->frs.statinfo);
		break;

	case BFCP_OVERALL_REQUEST_STATUS:
		if (len < 2)
			goto badmsg;

		v->ors.freqid = ntohs(mbuf_read_u16(mb));
		err |= decn(mb, BFCP_REQUEST_STATUS, &v->ors.reqstat);
		err |= decn(mb, BFCP_STATUS_INFO, &v->ors.statinfo);
		break;

	default:
		mb->pos += len;
		(void)re_fprintf(stderr, "bfcp decode: unknown attribute %d\n",
				 attr->type);
		break;
	}

	if (err)
		goto error;

	/* padding */
	while (((mb->pos - start) & 0x03) && mbuf_get_left(mb))
		++mb->pos;

	return 0;

 badmsg:
	err = EBADMSG;
 error:
	return err;
}


int bfcp_attr_decode(struct bfcp_attr **attrp, struct mbuf *mb)
{
	struct bfcp_attr *attr;
	int err;

	if (!attrp || !mb)
		return EINVAL;

	attr = mem_zalloc(sizeof(*attr), destructor);
	if (!attr)
		return ENOMEM;

	err = attr_decode(attr, &attr->v, mb);

	if (err)
		mem_deref(attr);
	else
		*attrp = attr;

	return err;
}


/**
 * Get the BFCP attribute name
 *
 * @param attr BFCP attribute
 *
 * @return String with BFCP attribute name
 */
const char *bfcp_attr_name(enum bfcp_attrib attr)
{
	switch (attr) {

	case BFCP_BENEFICIARY_ID:           return "BENEFICIARY-ID";
	case BFCP_FLOOR_ID:                 return "FLOOR-ID";
	case BFCP_FLOOR_REQUEST_ID:         return "FLOOR-REQUEST-ID";
	case BFCP_PRIORITY:                 return "PRIORITY";
	case BFCP_REQUEST_STATUS:           return "REQUEST-STATUS";
	case BFCP_ERROR_CODE:               return "ERROR-CODE";
	case BFCP_ERROR_INFO:               return "ERROR-INFO";
	case BFCP_PARTICIPANT_PROV_INFO:    return "PARTICIPANT-PROVIDED-INFO";
	case BFCP_STATUS_INFO:              return "STATUS-INFO";
	case BFCP_SUPPORTED_ATTRIBUTES:     return "SUPPORTED-ATTRIBUTES";
	case BFCP_SUPPORTED_PRIMITIVES:     return "SUPPORTED-PRIMITIVES";
	case BFCP_USER_DISPLAY_NAME:        return "USER-DISPLAY-NAME";
	case BFCP_USER_URI:                 return "USER-URI";
	case BFCP_BENEFICIARY_INFO:         return "BENEFICIARY-INFORMATION";
	case BFCP_FLOOR_REQUEST_INFO:       return "FLOOR-REQUEST-INFORMATION";
	case BFCP_REQUESTED_BY_INFO:        return "REQUESTED-BY-INFORMATION";
	case BFCP_FLOOR_REQUEST_STATUS:     return "FLOOR-REQUEST-STATUS";
	case BFCP_OVERALL_REQUEST_STATUS:   return "OVERALL-REQUEST-STATUS";
	default:                            return "???";
	}
}


static int leadh(struct re_printf *pf, void *arg)
{
	int16_t level = *(int16_t *)arg;
	int err = 0;

	while (level--)
		err |= re_hprintf(pf, "    ");

	return err;
}


static int attr_print(int16_t level, struct re_printf *pf,
		      enum bfcp_attrib type, const void *p)
{
	const union bfcp_union *v = p;
	uint32_t i;
	int err = 0;

	if (!v)
		return EINVAL;

	++level;

	err |= re_hprintf(pf, "%H%-28s", leadh, &level, bfcp_attr_name(type));

	if (bfcp_attr_isgrouped(type)) {
		const uint16_t level2 = level + 1;
		err |= re_hprintf(pf, "\n%H{\n%H", leadh, &level,
				  leadh, &level2);
	}

	switch (type) {

	case BFCP_BENEFICIARY_ID:
	case BFCP_FLOOR_ID:
	case BFCP_FLOOR_REQUEST_ID:
		err |= re_hprintf(pf, "%u", v->u16);
		break;

	case BFCP_PRIORITY:
		err |= re_hprintf(pf, "%d", v->prio);
		break;

	case BFCP_REQUEST_STATUS:
		err |= re_hprintf(pf, "%s (%d), qpos=%u",
				  bfcp_reqstat_name(v->reqstat.stat),
				  v->reqstat.stat,
				  v->reqstat.qpos);
		break;

	case BFCP_ERROR_CODE:
		err |= re_hprintf(pf, "%u (%s)", v->errcode.code,
				  bfcp_errcode_name(v->errcode.code));
		if (v->errcode.code == BFCP_ERR_UNKNOWN_MAND_ATTR) {
			for (i=0; i<v->errcode.len; i++) {
				uint8_t t = v->errcode.details[i] >> 1;
				err |= re_hprintf(pf, " %s",
						  bfcp_attr_name(t));
			}
		}
		break;

	case BFCP_ERROR_INFO:
	case BFCP_PARTICIPANT_PROV_INFO:
	case BFCP_STATUS_INFO:
	case BFCP_USER_DISPLAY_NAME:
	case BFCP_USER_URI:
		err |= re_hprintf(pf, "\"%s\"", v->str);
		break;

	case BFCP_SUPPORTED_ATTRIBUTES:
		err |= re_hprintf(pf, "%u:", v->supattr.attrc);
		for (i=0; i<v->supattr.attrc; i++) {
			const enum bfcp_attrib attr = v->supattr.attrv[i];
			err |= re_hprintf(pf, " %s", bfcp_attr_name(attr));
		}
		break;

	case BFCP_SUPPORTED_PRIMITIVES:
		err |= re_hprintf(pf, "%u:", v->supprim.primc);
		for (i=0; i<v->supprim.primc; i++) {
			const enum bfcp_prim prim = v->supprim.primv[i];
			err |= re_hprintf(pf, " %s", bfcp_prim_name(prim));
		}
		break;

		/* Grouped Attributes */

	case BFCP_BENEFICIARY_INFO:
		err |= re_hprintf(pf, "bfid=%u\n", v->bfi.bfid);
		err |= attr_print(level, pf, BFCP_USER_DISPLAY_NAME,
				  &v->bfi.dname);
		err |= attr_print(level, pf, BFCP_USER_URI, &v->bfi.uri);
		break;

	case BFCP_FLOOR_REQUEST_INFO:
		err |= re_hprintf(pf, "freqid=%u\n", v->fri.freqid);
		err |= attr_print(level, pf, BFCP_OVERALL_REQUEST_STATUS,
				  &v->fri.ors);
		for (i=0; i<v->fri.frsc; i++) {
			err |= attr_print(level, pf, BFCP_FLOOR_REQUEST_STATUS,
					  &v->fri.frsv[i]);
		}
		err |= attr_print(level, pf, BFCP_BENEFICIARY_INFO,
				  &v->fri.bfi);
		err |= attr_print(level, pf, BFCP_REQUESTED_BY_INFO,
				  &v->fri.rbi);
		err |= attr_print(level, pf, BFCP_PRIORITY, &v->fri.prio);
		err |= attr_print(level, pf, BFCP_PARTICIPANT_PROV_INFO,
				  &v->fri.ppi);
		break;

	case BFCP_REQUESTED_BY_INFO:
		err |= re_hprintf(pf, "rbid=%u\n", v->rbi.rbid);
		err |= attr_print(level, pf, BFCP_USER_DISPLAY_NAME,
				  &v->rbi.dname);
		err |= attr_print(level, pf, BFCP_USER_URI, &v->rbi.uri);
		break;

	case BFCP_FLOOR_REQUEST_STATUS:
		err |= re_hprintf(pf, "floorid=%u\n", v->frs.floorid);
		err |= attr_print(level, pf, BFCP_REQUEST_STATUS,
				  &v->frs.reqstat);
		err |= attr_print(level, pf, BFCP_STATUS_INFO,
				  &v->frs.statinfo);
		break;

	case BFCP_OVERALL_REQUEST_STATUS:
		err |= re_hprintf(pf, "freqid=%u\n", v->ors.freqid);
		err |= attr_print(level, pf, BFCP_REQUEST_STATUS,
				  &v->ors.reqstat);
		err |= attr_print(level, pf, BFCP_STATUS_INFO,
				  &v->ors.statinfo);
		break;

	default:
		err |= re_hprintf(pf, "?");
		break;
	}

	if (bfcp_attr_isgrouped(type))
		err |= re_hprintf(pf, "%H}", leadh, &level);

	err |= re_hprintf(pf, "\n");

	return err;
}


int bfcp_attr_print(struct re_printf *pf, const struct bfcp_attr *a)
{
	if (!a)
		return 0;

	return attr_print(0, pf, a->type, &a->v);
}


bool bfcp_attr_isgrouped(enum bfcp_attrib attr)
{
	switch (attr) {

	case BFCP_BENEFICIARY_INFO:
	case BFCP_FLOOR_REQUEST_INFO:
	case BFCP_REQUESTED_BY_INFO:
	case BFCP_FLOOR_REQUEST_STATUS:
	case BFCP_OVERALL_REQUEST_STATUS:
		return true;

	default:
		return false;
	}
}


/**
 * Get the BFCP Error code name
 *
 * @param code BFCP Error code
 *
 * @return String with error code
 */
const char *bfcp_errcode_name(enum bfcp_err code)
{
	switch (code) {

	case BFCP_ERR_CONF_NOT_EXIST:
		return "Conference does not Exist";
	case BFCP_ERR_USER_NOT_EXIST:
		return "User does not Exist";
	case BFCP_ERR_UNKNOWN_PRIM:
		return "Unknown Primitive";
	case BFCP_ERR_UNKNOWN_MAND_ATTR:
		return "Unknown Mandatory Attribute";
	case BFCP_ERR_UNAUTH_OPERATION:
		return "Unauthorized Operation";
	case BFCP_ERR_INVALID_FLOOR_ID:
		return "Invalid Floor ID";
	case BFCP_ERR_FLOOR_REQ_ID_NOT_EXIST:
		return "Floor Request ID Does Not Exist";
	case BFCP_ERR_MAX_FLOOR_REQ_REACHED:
		return "You have Already Reached the Maximum Number"
			" of Ongoing Floor Requests for this Floor";
	case BFCP_ERR_USE_TLS:
		return "Use TLS";
	default:
		return "???";
	}
}
