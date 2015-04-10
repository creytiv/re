/**
 * @file apple/hmac.c  HMAC using Apple API
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <string.h>
#include <CommonCrypto/CommonHMAC.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_hmac.h>


struct hmac {
	CCHmacContext ctx;
	uint8_t key[20];
	size_t key_len;
};


static void destructor(void *arg)
{
	struct hmac *hmac = arg;

	memset(&hmac->ctx, 0, sizeof(hmac->ctx));
}


int hmac_create(struct hmac **hmacp, enum hmac_hash hash,
		const uint8_t *key, size_t key_len)
{
	struct hmac *hmac;

	if (!hmacp || !key || !key_len)
		return EINVAL;

	if (hash != HMAC_HASH_SHA1)
		return ENOTSUP;

	hmac = mem_zalloc(sizeof(*hmac), destructor);
	if (!hmac)
		return ENOMEM;

	memcpy(hmac->key, key, key_len);
	hmac->key_len = key_len;

	CCHmacInit(&hmac->ctx, kCCHmacAlgSHA1, key, key_len);

	*hmacp = hmac;

	return 0;
}


int hmac_digest(struct hmac *hmac, uint8_t *md, size_t md_len,
		const uint8_t *data, size_t data_len)
{
	if (!hmac || !md || !md_len || !data || !data_len)
		return EINVAL;

	/* reset state */
	CCHmacInit(&hmac->ctx, kCCHmacAlgSHA1, hmac->key, hmac->key_len);

	CCHmacUpdate(&hmac->ctx, data, data_len);
	CCHmacFinal(&hmac->ctx, md);

	return 0;
}
