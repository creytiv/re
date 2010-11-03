/**
 * @file b64.c  Base64 encoding/decoding functions
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_base64.h>


static const char b64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";


/**
 * Base-64 encode a buffer
 *
 * @param in   Input buffer
 * @param ilen Length of input buffer
 * @param out  Output buffer
 * @param olen Size of output buffer, actual written on return
 *
 * @return 0 if success, otherwise errorcode
 */
int base64_encode(const uint8_t *in, size_t ilen, char *out, size_t *olen)
{
	const uint8_t *in_end = in + ilen;
	const char *o = out;

	if (!in || !out || !olen)
		return EINVAL;

	if (*olen < ilen*4/3)
		return EOVERFLOW;

	for (; in < in_end; ) {
		uint32_t v;
		int pad = 0;

		v  = *in++ << 16;
		if (in < in_end) {
			v |= *in++ << 8;
		}
		else {
			++pad;
		}
		if (in < in_end) {
			v |= *in++ << 0;
		}
		else {
			++pad;
		}

		*out++ = b64_table[v>>18 & 0x3f];
		*out++ = b64_table[v>>12 & 0x3f];
		*out++ = (pad >= 2) ? '=' : b64_table[v>>6  & 0x3f];
		*out++ = (pad >= 1) ? '=' : b64_table[v>>0  & 0x3f];
	}

	*olen = out - o;

	return 0;
}


/* convert char -> 6-bit value */
static inline uint32_t b64val(char c)
{
	if ('A' <= c && c <= 'Z')
		return c - 'A' + 0;
	else if ('a' <= c && c <= 'z')
		return c - 'a' + 26;
	else if ('0' <= c && c <= '9')
		return c - '0' + 52;
	else if ('+' == c)
		return 62;
	else if ('/' == c)
		return 63;
	else if ('=' == c)
		return 1<<24; /* special trick */
	else
		return 0;
}


/**
 * Decode a Base-64 encoded string
 *
 * @param in   Input buffer
 * @param ilen Length of input buffer
 * @param out  Output buffer
 * @param olen Size of output buffer, actual written on return
 *
 * @return 0 if success, otherwise errorcode
 */
int base64_decode(const char *in, size_t ilen, uint8_t *out, size_t *olen)
{
	const char *in_end = in + ilen;
	const uint8_t *o = out;

	if (!in || !out || !olen)
		return EINVAL;

	if (*olen < ilen*3/4)
		return EOVERFLOW;

	for (;in < in_end; ) {
		uint32_t v;

		v  = b64val(*in++) << 18;
		v |= b64val(*in++) << 12;
		v |= b64val(*in++) << 6;
		v |= b64val(*in++) << 0;

		*out++ = v>>16;
		if (!(v & (1<<30)))
			*out++ = (v>>8) & 0xff;
		if (!(v & (1<<24)))
			*out++ = (v>>0) & 0xff;
	}

	*olen = out - o;

	return 0;
}
