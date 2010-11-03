/**
 * @file func.c  Hashmap functions
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <ctype.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_hash.h>


/**
 * Calculate hash-value using "Jenkins One-at-a-time" hash algorithm.
 *
 * @param key  Pointer to key
 * @param len  Key length
 *
 * @return Calculated hash-value
 */
uint32_t hash_joaat(const uint8_t *key, size_t len)
{
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}


/**
 * Calculate hash-value for a case-insensitive string
 *
 * @param str  String
 * @param len  Length of string
 *
 * @return Calculated hash-value
 */
uint32_t hash_joaat_ci(const char *str, size_t len)
{
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		hash += tolower(str[i]);
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}


/**
 * Calculate hash-value for a NULL-terminated string
 *
 * @param str  String
 *
 * @return Calculated hash-value
 */
uint32_t hash_joaat_str(const char *str)
{
	uint32_t hash = 0;

	while (*str) {
		hash += *str++;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}


/**
 * Calculate hash-value for a case-insensitive NULL-terminated string
 *
 * @param str  String
 *
 * @return Calculated hash-value
 */
uint32_t hash_joaat_str_ci(const char *str)
{
	uint32_t hash = 0;

	while (*str) {
		hash += tolower(*str++);
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}


/**
 * Calculate hash-value for a pointer-length object
 *
 * @param pl Pointer-length object
 *
 * @return Calculated hash-value
 */
uint32_t hash_joaat_pl(const struct pl *pl)
{
	return pl ? hash_joaat((const uint8_t *)pl->p, pl->l) : 0;
}


/**
 * Calculate hash-value for a case-insensitive pointer-length object
 *
 * @param pl Pointer-length object
 *
 * @return Calculated hash-value
 */
uint32_t hash_joaat_pl_ci(const struct pl *pl)
{
	return pl ? hash_joaat_ci(pl->p, pl->l) : 0;
}
