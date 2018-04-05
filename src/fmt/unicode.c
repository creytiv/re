/**
 * @file unicode.c  Unicode character coding
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <ctype.h>
#include <re_types.h>
#include <re_fmt.h>


static const char *hex_chars = "0123456789ABCDEF";


/**
 * UTF-8 encode
 *
 * @param pf  Print function for output
 * @param str Input string to encode
 *
 * @return 0 if success, otherwise errorcode
 */
int utf8_encode(struct re_printf *pf, const char *str)
{
	char ubuf[6] = "\\u00", ebuf[2] = "\\";

	if (!pf)
		return EINVAL;

	if (!str)
		return 0;

	while (*str) {
		const uint8_t c = *str++;  /* NOTE: must be unsigned 8-bit */
		bool unicode = false;
		char ec = 0;
		int err;

		switch (c) {

		case '"':  ec = '"'; break;
		case '\\': ec = '\\'; break;
		case '/':  ec = '/'; break;
		case '\b': ec = 'b'; break;
		case '\f': ec = 'f'; break;
		case '\n': ec = 'n'; break;
		case '\r': ec = 'r'; break;
		case '\t': ec = 't'; break;
		default:
			if (c < ' ') {
				unicode = true;
			}
			/* chars in range 0x80-0xff are not escaped */
			break;
		}

		if (unicode) {
			ubuf[4] = hex_chars[(c>>4) & 0xf];
			ubuf[5] = hex_chars[c & 0xf];

			err = pf->vph(ubuf, sizeof(ubuf), pf->arg);
		}
		else if (ec) {
			ebuf[1] = ec;

			err = pf->vph(ebuf, sizeof(ebuf), pf->arg);
		}
		else {
			err = pf->vph((char *)&c, 1, pf->arg);
		}

		if (err)
			return err;
	}

	return 0;
}


/**
 * UTF-8 decode
 *
 * @param pf Print function for output
 * @param pl Input buffer to decode
 *
 * @return 0 if success, otherwise errorcode
 */
int utf8_decode(struct re_printf *pf, const struct pl *pl)
{
	int uhi = -1;
	size_t i;

	if (!pf)
		return EINVAL;

	if (!pl)
		return 0;

	for (i=0; i<pl->l; i++) {

		char ch = pl->p[i];
		int err;

		if (ch == '\\') {

			unsigned u = 0;
			char ubuf[4];
			size_t ulen;

			++i;

			if (i >= pl->l)
				return EBADMSG;

			ch = pl->p[i];

			switch (ch) {

			case 'b':
				ch = '\b';
				break;

			case 'f':
				ch = '\f';
				break;

			case 'n':
				ch = '\n';
				break;

			case 'r':
				ch = '\r';
				break;

			case 't':
				ch = '\t';
				break;

			case 'u':
				if (i+4 >= pl->l)
					return EBADMSG;

				if (!isxdigit(pl->p[i+1]) ||
				    !isxdigit(pl->p[i+2]) ||
				    !isxdigit(pl->p[i+3]) ||
				    !isxdigit(pl->p[i+4]))
					return EBADMSG;

				u |= ((uint16_t)ch_hex(pl->p[++i])) << 12;
				u |= ((uint16_t)ch_hex(pl->p[++i])) << 8;
				u |= ((uint16_t)ch_hex(pl->p[++i])) << 4;
				u |= ((uint16_t)ch_hex(pl->p[++i])) << 0;

				/* UTF-16 surrogate pair */
				if (u >= 0xd800 && u <= 0xdbff) {
					uhi = (u - 0xd800) * 0x400;
					continue;
				}
				else if (u >= 0xdc00 && u <= 0xdfff) {
					if (uhi < 0)
						continue;

					u = uhi + u - 0xdc00 + 0x10000;
				}

				uhi = -1;

				ulen = utf8_byteseq(ubuf, u);

				err = pf->vph(ubuf, ulen, pf->arg);
				if (err)
					return err;

				continue;
			}
		}

		uhi = -1;

		err = pf->vph(&ch, 1, pf->arg);
		if (err)
			return err;
	}

	return 0;
}


/**
 * Encode Unicode code point into binary UTF-8
 *
 * @param u  Binary UTF-8 buffer
 * @param cp Unicode code point
 *
 * @return length of UTF-8 byte sequence
 */
size_t utf8_byteseq(char u[4], unsigned cp)
{
	if (!u)
		return 0;

	if (cp <= 0x7f) {
		u[0] = cp;
		return 1;
	}
	else if (cp <= 0x7ff) {
		u[0] = 0xc0 | (cp>>6 & 0x1f);
		u[1] = 0x80 | (cp    & 0x3f);
		return 2;
	}
	else if (cp <= 0xffff) {
		u[0] = 0xe0 | (cp>>12 & 0x0f);
		u[1] = 0x80 | (cp>>6  & 0x3f);
		u[2] = 0x80 | (cp     & 0x3f);
		return 3;
	}
	else if (cp <= 0x10ffff) {
		u[0] = 0xf0 | (cp>>18 & 0x07);
		u[1] = 0x80 | (cp>>12 & 0x3f);
		u[2] = 0x80 | (cp>>6  & 0x3f);
		u[3] = 0x80 | (cp     & 0x3f);
		return 4;
	}
	else {
		/* The replacement character (U+FFFD) */
		u[0] = (char)0xef;
		u[1] = (char)0xbf;
		u[2] = (char)0xbd;
		return 3;
	}
}
