/**
 * @file re_g711.h  Interface to G.711 codec
 *
 * Copyright (C) 2010 Creytiv.com
 */


extern const uint8_t g711_l2u[4096];
extern const uint8_t g711_l2A[2048];
extern const int16_t g711_u2l[256];
extern const int16_t g711_A2l[256];


/**
 * Encode one 16-bit PCM sample to U-law format
 *
 * @param l Signed PCM sample
 *
 * @return U-law byte
 */
static inline uint8_t g711_pcm2ulaw(int16_t l)
{
	const uint8_t mask = (l < 0) ? 0x7f : 0xff;
	if (l < 0)
		l = -l;
	if (l < 4)
		return 0xff & mask;
	l -= 4;
	l >>= 3;

	return g711_l2u[l] & mask;
}


/**
 * Encode one 16-bit PCM sample to A-law format
 *
 * @param l Signed PCM sample
 *
 * @return A-law byte
 */
static inline uint8_t g711_pcm2alaw(int16_t l)
{
	const uint8_t mask = (l < 0) ? 0x7f : 0xff;
	if (l < 0)
		l = -l;
	l >>= 4;

	return g711_l2A[l] & mask;
}


/**
 * Decode one U-law sample to 16-bit PCM sample
 *
 * @param u U-law byte
 *
 * @return Signed PCM sample
 */
static inline int16_t g711_ulaw2pcm(uint8_t u)
{
	return g711_u2l[u];
}


/**
 * Decode one A-law sample to 16-bit PCM sample
 *
 * @param A A-law byte
 *
 * @return Signed PCM sample
 */
static inline int16_t g711_alaw2pcm(uint8_t a)
{
	return g711_A2l[a];
}
