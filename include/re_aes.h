/**
 * @file re_aes.h Interface to AES (Advanced Encryption Standard)
 *
 * Copyright (C) 2010 Creytiv.com
 */


#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

/** AES mode */
enum aes_mode {
	AES_MODE_CTR,  /**< AES Counter mode (CTR) */
	AES_MODE_GCM,  /**< AES Galois Counter Mode (GCM) */
};

struct aes;

int  aes_alloc(struct aes **stp, enum aes_mode mode,
	       const uint8_t *key, size_t key_bits,
	       const uint8_t *iv);
void aes_set_iv(struct aes *aes, const uint8_t *iv);
int  aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len);
int  aes_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len);
int  aes_get_authtag(struct aes *aes, uint8_t *tag, size_t taglen);
int  aes_authenticate(struct aes *aes, const uint8_t *tag, size_t taglen);
