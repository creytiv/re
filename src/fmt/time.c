/**
 * @file time.c  Time formatting
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>


/**
 * Print the human readable time
 *
 * @param pf       Print function for output
 * @param seconds  Pointer to number of seconds
 *
 * @return 0 if success, otherwise errorcode
 */
int fmt_human_time(struct re_printf *pf, const uint32_t *seconds)
{
	/* max 136 years */
	const uint32_t sec  = *seconds%60;
	const uint32_t min  = *seconds/60%60;
	const uint32_t hrs  = *seconds/60/60%24;
	const uint32_t days = *seconds/60/60/24;
	int err = 0;

	if (days)
		err |= re_hprintf(pf, "%u day%s ", days, 1==days?"":"s");

	if (hrs) {
		err |= re_hprintf(pf, "%u hour%s ", hrs, 1==hrs?"":"s");
	}

	if (min) {
		err |= re_hprintf(pf, "%u min%s ", min, 1==min?"":"s");
	}

	if (sec) {
		err |= re_hprintf(pf, "%u sec%s", sec, 1==sec?"":"s");
	}

	return err;
}
