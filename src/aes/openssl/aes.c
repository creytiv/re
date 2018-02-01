/**
 * @file openssl/aes.c  AES (Advanced Encryption Standard) using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_aes.h>


struct aes {
	EVP_CIPHER_CTX *ctx;
	enum aes_mode mode;
	bool encr;
};


static const EVP_CIPHER *aes_cipher(enum aes_mode mode, size_t key_bits)
{
	if (mode == AES_MODE_CTR) {

		switch (key_bits) {

		case 128: return EVP_aes_128_ctr();
		case 192: return EVP_aes_192_ctr();
		case 256: return EVP_aes_256_ctr();
		default:
			return NULL;
		}
	}
	else if (mode == AES_MODE_GCM) {

		switch (key_bits) {

		case 128: return EVP_aes_128_gcm();
		case 256: return EVP_aes_256_gcm();
		default:
			return NULL;
		}
	}
	else {
		return NULL;
	}
}


static inline bool set_crypt_dir(struct aes *aes, bool encr)
{
	if (aes->encr != encr) {

		/* update the encrypt/decrypt direction */
		if (!EVP_CipherInit_ex(aes->ctx, NULL, NULL,
				       NULL, NULL, encr)) {
			ERR_clear_error();
			return false;
		}

		aes->encr = encr;
	}

	return true;
}


static void destructor(void *arg)
{
	struct aes *st = arg;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (st->ctx)
		EVP_CIPHER_CTX_free(st->ctx);
#else
	if (st->ctx)
		EVP_CIPHER_CTX_cleanup(st->ctx);
	mem_deref(st->ctx);
#endif
}


int aes_alloc(struct aes **aesp, enum aes_mode mode,
	      const uint8_t *key, size_t key_bits,
	      const uint8_t *iv)
{
	const EVP_CIPHER *cipher;
	struct aes *st;
	int err = 0, r;

	if (!aesp || !key)
		return EINVAL;

	cipher = aes_cipher(mode, key_bits);
	if (!cipher)
		return ENOTSUP;

	st = mem_zalloc(sizeof(*st), destructor);
	if (!st)
		return ENOMEM;

	st->mode = mode;
	st->encr = true;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	st->ctx = EVP_CIPHER_CTX_new();
	if (!st->ctx) {
		ERR_clear_error();
		err = ENOMEM;
		goto out;
	}

#else
	st->ctx = mem_zalloc(sizeof(*st->ctx), NULL);
	if (!st->ctx) {
		err = ENOMEM;
		goto out;
	}

	EVP_CIPHER_CTX_init(st->ctx);
#endif

	r = EVP_EncryptInit_ex(st->ctx, cipher, NULL, key, iv);
	if (!r) {
		ERR_clear_error();
		err = EPROTO;
	}

 out:
	if (err)
		mem_deref(st);
	else
		*aesp = st;

	return err;
}


void aes_set_iv(struct aes *aes, const uint8_t *iv)
{
	int r;

	if (!aes || !iv)
		return;

	r = EVP_CipherInit_ex(aes->ctx, NULL, NULL, NULL, iv, -1);
	if (!r)
		ERR_clear_error();
}


int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int c_len = (int)len;

	if (!aes || !in)
		return EINVAL;

	if (!set_crypt_dir(aes, true))
		return EPROTO;

	if (!EVP_EncryptUpdate(aes->ctx, out, &c_len, in, (int)len)) {
		ERR_clear_error();
		return EPROTO;
	}

	return 0;
}


int aes_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int c_len = (int)len;

	if (!aes || !in)
		return EINVAL;

	if (!set_crypt_dir(aes, false))
		return EPROTO;

	if (!EVP_DecryptUpdate(aes->ctx, out, &c_len, in, (int)len)) {
		ERR_clear_error();
		return EPROTO;
	}

	return 0;
}


/**
 * Get the authentication tag for an AEAD cipher (e.g. GCM)
 *
 * @param aes    AES Context
 * @param tag    Authentication tag
 * @param taglen Length of Authentication tag
 *
 * @return 0 if success, otherwise errorcode
 */
int aes_get_authtag(struct aes *aes, uint8_t *tag, size_t taglen)
{
	int tmplen;

	if (!aes || !tag || !taglen)
		return EINVAL;

	switch (aes->mode) {

	case AES_MODE_GCM:
		if (!EVP_EncryptFinal_ex(aes->ctx, NULL, &tmplen)) {
			ERR_clear_error();
			return EPROTO;
		}

		if (!EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_GET_TAG,
					 (int)taglen, tag)) {
			ERR_clear_error();
			return EPROTO;
		}

		return 0;

	default:
		return ENOTSUP;
	}
}


/**
 * Authenticate a decryption tag for an AEAD cipher (e.g. GCM)
 *
 * @param aes    AES Context
 * @param tag    Authentication tag
 * @param taglen Length of Authentication tag
 *
 * @return 0 if success, otherwise errorcode
 *
 * @retval EAUTH if authentication failed
 */
int aes_authenticate(struct aes *aes, const uint8_t *tag, size_t taglen)
{
	int tmplen;

	if (!aes || !tag || !taglen)
		return EINVAL;

	switch (aes->mode) {

	case AES_MODE_GCM:
		if (!EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_SET_TAG,
					 (int)taglen, (void *)tag)) {
			ERR_clear_error();
			return EPROTO;
		}

		if (EVP_DecryptFinal_ex(aes->ctx, NULL, &tmplen) <= 0) {
			ERR_clear_error();
			return EAUTH;
		}

		return 0;

	default:
		return ENOTSUP;
	}
}
