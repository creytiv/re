/**
 * @file conf.c  Configuration file parser
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_conf.h>


#ifdef WIN32
#define open _open
#define read _read
#define close _close
#endif


struct conf {
	struct mbuf *mb;
};


static int load_file(struct mbuf *mb, const char *filename)
{
	int err = 0, fd = open(filename, O_RDONLY);
	if (fd < 0)
		return errno;

	for (;;) {
		uint8_t buf[1024];

		const ssize_t n = read(fd, (void *)buf, sizeof(buf));
		if (n < 0) {
			err = errno;
			break;
		}
		else if (n == 0)
			break;

		err |= mbuf_write_mem(mb, buf, n);
	}

	(void)close(fd);

	return err;
}


static void conf_destructor(void *data)
{
	struct conf *conf = data;

	mem_deref(conf->mb);
}


int conf_alloc(struct conf **confp, const char *filename)
{
	struct conf *conf;
	int err = 0;

	if (!confp)
		return EINVAL;

	conf = mem_zalloc(sizeof(*conf), conf_destructor);
	if (!conf)
		return ENOMEM;

	conf->mb = mbuf_alloc(1024);
	if (!conf->mb) {
		err = ENOMEM;
		goto out;
	}

	err |= mbuf_write_u8(conf->mb, '\n');
	if (filename)
		err |= load_file(conf->mb, filename);

 out:
	if (err)
		mem_deref(conf);
	else
		*confp = conf;

	return err;
}


int conf_alloc_buf(struct conf **confp, const uint8_t *buf, size_t sz)
{
	struct conf *conf;
	int err;

	err = conf_alloc(&conf, NULL);
	if (err)
		return err;

	err = mbuf_write_mem(conf->mb, buf, sz);

	if (err)
		mem_deref(conf);
	else
		*confp = conf;

	return err;
}


int conf_get(struct conf *conf, const char *name, struct pl *pl)
{
	char expr[512];
	struct pl spl;

	if (!conf || !name || !pl)
		return EINVAL;

	spl.p = (const char *)conf->mb->buf;
	spl.l = conf->mb->end;

	(void)re_snprintf(expr, sizeof(expr),
			  "[\r\n]+[ \t]*%s[ \t]+[~ \t\r\n]+", name);

	return re_regex(spl.p, spl.l, expr, NULL, NULL, NULL, pl);
}


int conf_get_str(struct conf *conf, const char *name, char *str,
		 size_t size)
{
	struct pl pl;
	int err;

	if (!conf || !name || !str || !size)
		return EINVAL;

	err = conf_get(conf, name, &pl);
	if (err)
		return err;

	return pl_strcpy(&pl, str, size);
}


int conf_get_u32(struct conf *conf, const char *name, uint32_t *num)
{
	struct pl pl;
	int err;

	if (!conf || !name || !num)
		return EINVAL;

	err = conf_get(conf, name, &pl);
	if (err)
		return err;

	*num = pl_u32(&pl);

	return 0;
}


int conf_apply(struct conf *conf, const char *name, conf_h *ch, void *arg)
{
	char expr[512];
	struct pl pl, val;
	int err = 0;

	if (!conf || !name || !ch)
		return EINVAL;

	pl.p = (const char *)conf->mb->buf;
	pl.l = conf->mb->end;

	(void)re_snprintf(expr, sizeof(expr),
			  "[\r\n]+[ \t]*%s[ \t]+[~ \t\r\n]+", name);

	while (!re_regex(pl.p, pl.l, expr, NULL, NULL, NULL, &val)) {

		err = ch(&val, arg);
		if (err)
			break;

		pl.l -= val.p + val.l - pl.p;
		pl.p  = val.p + val.l;
	}

	return err;
}
