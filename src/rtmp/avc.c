/**
 * @file avc.c RTMP Client
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
#include <re_rtmp.h>
#include "rtmp.h"


#define DEBUG_MODULE "rtmpc"
#define DEBUG_LEVEL 6
#include <re_dbg.h>


int avc_config_record_encode(struct mbuf *mb,

			     uint8_t profile_ind,
			     uint8_t profile_compat,
			     uint8_t level_ind,

			     uint16_t spsLength,
			     uint8_t *sps,

			     uint16_t ppsLength,
			     uint8_t *pps)
{
#define CONFIG_VERSION 1
	int err = 0;

	if (!mb || !sps || !pps)
		return EINVAL;

	err |= mbuf_write_u8(mb, CONFIG_VERSION);

	err |= mbuf_write_u8(mb, profile_ind);
	err |= mbuf_write_u8(mb, profile_compat);
	err |= mbuf_write_u8(mb, level_ind);

	err |= mbuf_write_u8(mb, 0xfc | 4-1);

	/* SPS */
	err |= mbuf_write_u8(mb, 0xe0 | 1);
	err |= mbuf_write_u16(mb, htons(spsLength));
	err |= mbuf_write_mem(mb, sps, spsLength);

	/* PPS */
	err |= mbuf_write_u8(mb, 1);
	err |= mbuf_write_u16(mb, htons(ppsLength));
	err |= mbuf_write_mem(mb, pps, ppsLength);

	return err;
}


int avc_config_record_decode(struct config_record *conf, struct mbuf *mb)
{
	uint8_t v;
	size_t lengthSize;
	int err = 0;

	memset(conf, 0, sizeof(*conf));

	conf->version        = mbuf_read_u8(mb);

	if (conf->version != 1)
		return EBADMSG;

	conf->profile_ind    = mbuf_read_u8(mb);
	conf->profile_compat = mbuf_read_u8(mb);
	conf->level_ind      = mbuf_read_u8(mb);

	v = mbuf_read_u8(mb);
	conf->lengthSizeMinusOne = v & 0x03;
	lengthSize = conf->lengthSizeMinusOne + 1;

	if (lengthSize != 4)
		return EPROTO;

	/* SPS */
	v = mbuf_read_u8(mb);
	conf->numOfSequenceParameterSets = v & 0x1f;

	conf->sequenceParameterSetLength = ntohs(mbuf_read_u16(mb));

	conf->sps = mem_alloc(conf->sequenceParameterSetLength, NULL);

	err |= mbuf_read_mem(mb, conf->sps, conf->sequenceParameterSetLength);

	/* PPS */
	conf->numOfPictureParameterSets = mbuf_read_u8(mb);
	conf->pictureParameterSetLength = ntohs(mbuf_read_u16(mb));

	conf->pps = mem_alloc(conf->pictureParameterSetLength, NULL);

	err |= mbuf_read_mem(mb, conf->pps, conf->pictureParameterSetLength);

	re_printf("config: profile_ind    %u\n", conf->profile_ind);
	re_printf("        profile_compat %u\n", conf->profile_compat);
	re_printf("        level_ind      %u\n", conf->level_ind);
	re_printf("        lengthSizeMinusOne %u\n", conf->lengthSizeMinusOne);
	re_printf("        numOfSequenceParameterSets %u\n",
		  conf->numOfSequenceParameterSets);
	re_printf("        sequenceParameterSetLength %u\n",
		  conf->sequenceParameterSetLength);
	re_printf("        sps: %w\n",
		  conf->sps, (size_t)conf->sequenceParameterSetLength);
	re_printf("        numOfPictureParameterSets %u\n",
		  conf->numOfPictureParameterSets);
	re_printf("        pictureParameterSetLength %u\n",
		  conf->pictureParameterSetLength);
	re_printf("        pps: %w\n",
		  conf->pps, (size_t)conf->pictureParameterSetLength);

	return err;
}
