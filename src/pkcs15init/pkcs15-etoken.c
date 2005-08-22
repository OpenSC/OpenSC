/*
 * CardOS specific operation for PKCS15 initialization
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include "pkcs15-init.h"
#include "profile.h"

#ifndef MIN
# define MIN(a, b)	(((a) < (b))? (a) : (b))
#endif

struct tlv {
	unsigned char *		base;
	unsigned char *		end;
	unsigned char *		current;
	unsigned char *		next;
};
#define RSAKEY_MAX_BITS		1024
#define RSAKEY_MAX_SIZE		(RSAKEY_MAX_BITS/8)
struct rsakey {
	struct bignum {
		size_t		len;
		u8		data[RSAKEY_MAX_SIZE];
	}			n, d;
};

/*
 * Local functions
 */
static int	etoken_store_pin(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_pin_info_t *pin_info, int puk_id,
			const u8 *pin, size_t pin_len);
static int	etoken_create_sec_env(sc_profile_t *, sc_card_t *,
			unsigned int, unsigned int);
static int	etoken_put_key(struct sc_profile *, sc_card_t *,
			int, sc_pkcs15_prkey_info_t *,
		       	struct sc_pkcs15_prkey_rsa *);
static int	etoken_key_algorithm(unsigned int, int *);
static int	etoken_extract_pubkey(sc_card_t *, int,
			u8, sc_pkcs15_bignum_t *);

/* Object IDs for PIN objects.
 * SO PIN = 0x01, SO PUK = 0x02
 * each user pin is 2*N+1, each corresponding PUK is 2*N+2
 */
#define ETOKEN_PIN_ID_MIN	1
#define ETOKEN_PIN_ID_MAX	15
#define ETOKEN_KEY_ID_MIN	16
#define ETOKEN_KEY_ID_MAX	31
#define ETOKEN_AC_NEVER		0xFF

#define ETOKEN_ALGO_RSA			0x08
#define ETOKEN_ALGO_RSA_PURE		0x0C
#define ETOKEN_ALGO_RSA_SIG		0x88
#define ETOKEN_ALGO_RSA_PURE_SIG	0x8C
#define ETOKEN_ALGO_RSA_SIG_SHA1	0xC8
#define ETOKEN_ALGO_RSA_PURE_SIG_SHA1	0xCC
#define ETOKEN_SIGN_RSA			ETOKEN_ALGO_RSA_PURE_SIG
#define ETOKEN_DECIPHER_RSA		ETOKEN_ALGO_RSA_PURE
#define ETOKEN_ALGO_PIN			0x87

static inline void
tlv_init(struct tlv *tlv, u8 *base, size_t size)
{
	tlv->base = base;
	tlv->end = base + size;
	tlv->current = tlv->next = base;
}

static inline void
tlv_next(struct tlv *tlv, u8 tag)
{
	assert(tlv->next + 2 < tlv->end);
	tlv->current = tlv->next;
	*(tlv->next++) = tag;
	*(tlv->next++) = 0;
}

static inline void
tlv_add(struct tlv *tlv, u8 val)
{
	assert(tlv->next + 1 < tlv->end);
	*(tlv->next++) = val;
	tlv->current[1]++;
}

static size_t
tlv_len(struct tlv *tlv)
{
	return tlv->next - tlv->base;
}

/*
 * Try to delete pkcs15 structure
 * This is not quite the same as erasing the whole token, but
 * it's close enough to be useful.
 */
static int
etoken_erase(struct sc_profile *profile, sc_card_t *card)
{
	return sc_pkcs15init_erase_card_recursively(card, profile, -1);
}

/*
 * Create the Application DF
 */
static int
etoken_create_dir(sc_profile_t *profile, sc_card_t *card, sc_file_t *df)
{
	int	r;

	/* Create the application DF */
	if ((r = sc_pkcs15init_create_file(profile, card, df)) < 0)
		return r;

	if ((r = sc_select_file(card, &df->path, NULL)) < 0)
		return r;

	/* Create a default security environment for this DF.
	 * This SE autometically becomes the current SE when the
	 * DF is selected. */
	if ((r = etoken_create_sec_env(profile, card, 0x01, 0x00)) < 0)
		return r;

	return 0;
}

/*
 * Caller passes in a suggested PIN reference.
 * See if it's good, and if it isn't, propose something better
 */
static int
etoken_select_pin_reference(sc_profile_t *profile, sc_card_t *card,
		sc_pkcs15_pin_info_t *pin_info)
{
	int	preferred, current;

	if ((current = pin_info->reference) < 0)
		current = ETOKEN_PIN_ID_MIN;

	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		preferred = 1;
	} else {
		preferred = current;
		/* PINs are even numbered, PUKs are odd */
		if (!(preferred & 1))
			preferred++;
		if (preferred >= 126)
			return SC_ERROR_TOO_MANY_OBJECTS;
	}

	if (current > preferred || preferred > ETOKEN_PIN_ID_MAX)
		return SC_ERROR_TOO_MANY_OBJECTS;
	pin_info->reference = preferred;
	return 0;
}

/*
 * Store a PIN
 */
static int
etoken_create_pin(sc_profile_t *profile, sc_card_t *card, sc_file_t *df,
		sc_pkcs15_object_t *pin_obj,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	sc_pkcs15_pin_info_t *pin_info = (sc_pkcs15_pin_info_t *) pin_obj->data;
	unsigned int	puk_id = ETOKEN_AC_NEVER;
	int		r;

	if (!pin || !pin_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	r = sc_select_file(card, &df->path, NULL);
	if (r < 0)
		return r;

	if (puk && puk_len) {
		struct sc_pkcs15_pin_info puk_info;

		sc_profile_get_pin_info(profile,
				SC_PKCS15INIT_USER_PUK, &puk_info);
		puk_info.reference = puk_id = pin_info->reference + 1;
		r = etoken_store_pin(profile, card,
				&puk_info, ETOKEN_AC_NEVER,
				puk, puk_len);
	}

	if (r >= 0) {
		r = etoken_store_pin(profile, card,
				pin_info, puk_id,
				pin, pin_len);
	}

	return r;
}

/*
 * Select a key reference
 */
static int
etoken_select_key_reference(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_prkey_info_t *key_info)
{
	struct sc_file	*df = profile->df_info->file;

	if (key_info->key_reference < ETOKEN_KEY_ID_MIN)
		key_info->key_reference = ETOKEN_KEY_ID_MIN;
	if (key_info->key_reference > ETOKEN_KEY_ID_MAX)
		return SC_ERROR_TOO_MANY_OBJECTS;

	key_info->path = df->path;
	return 0;
}

/*
 * Create a private key object.
 * This is a no-op.
 */
static int
etoken_create_key(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_object_t *obj)
{
	return 0;
}

/*
 * Store a private key object.
 */
static int
etoken_store_key(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_object_t *obj,
			sc_pkcs15_prkey_t *key)
{
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	int		algorithm, r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_error(card->ctx, "CardOS supports RSA keys only.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (etoken_key_algorithm(key_info->usage, &algorithm) < 0) {
		sc_error(card->ctx, "CardOS does not support keys "
			       "that can both sign _and_ decrypt.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = etoken_put_key(profile, card, algorithm, key_info, &key->u.rsa);

	return r;
}

/*
 * Key generation
 */
static int
etoken_generate_key(sc_profile_t *profile, sc_card_t *card,
		sc_pkcs15_object_t *obj,
		sc_pkcs15_pubkey_t *pubkey)
{
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_pkcs15_prkey_rsa key_obj;
	struct sc_cardctl_etoken_genkey_info args;
	struct sc_file	*temp;
	u8		abignum[RSAKEY_MAX_SIZE];
	unsigned int	keybits;
	int		algorithm, r, delete_it = 0;
	
	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_error(card->ctx, "CardOS supports only RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (etoken_key_algorithm(key_info->usage, &algorithm) < 0) {
		sc_error(card->ctx, "CardOS does not support keys "
			       "that can both sign _and_ decrypt.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	keybits = key_info->modulus_length & ~7UL;
	if (keybits > RSAKEY_MAX_BITS) {
		sc_error(card->ctx, "Unable to generate key, max size is %d",
				RSAKEY_MAX_BITS);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (sc_profile_get_file(profile, "tempfile", &temp) < 0) {
		sc_error(card->ctx, "Profile doesn't define temporary file "
				"for key generation.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	memset(pubkey, 0, sizeof(*pubkey));

	if ((r = sc_pkcs15init_create_file(profile, card, temp)) < 0)
		goto out;
	delete_it = 1;

	/* Create a key object, initializing components to 0xff */
	memset(&key_obj, 0, sizeof(key_obj));
	memset(abignum, 0xFF, sizeof(abignum));
	key_obj.modulus.data = abignum;
	key_obj.modulus.len = keybits >> 3;
	key_obj.d.data = abignum;
	key_obj.d.len = keybits >> 3;
	r = etoken_put_key(profile, card, algorithm, key_info, &key_obj);
	if (r < 0)
		goto out;

	memset(&args, 0, sizeof(args));
	args.key_id = key_info->key_reference;
	args.key_bits = keybits;
	args.fid = temp->id;
	r = sc_card_ctl(card, SC_CARDCTL_ETOKEN_GENERATE_KEY, &args);
	if (r < 0)
		goto out;

	/* extract public key from file and delete it */
	if ((r = sc_select_file(card, &temp->path, NULL)) < 0)
		goto out;
	r = etoken_extract_pubkey(card, 1, 0x10, &pubkey->u.rsa.modulus);
	if (r < 0)
		goto out;
	r = etoken_extract_pubkey(card, 2, 0x11, &pubkey->u.rsa.exponent);
	if (r < 0)
		goto out;
	pubkey->algorithm = SC_ALGORITHM_RSA;

out:	if (delete_it) {
		sc_pkcs15init_rmdir(card, profile, temp);
	}
	sc_file_free(temp);
	if (r < 0) {
		if (pubkey->u.rsa.modulus.data)
			free (pubkey->u.rsa.modulus.data);
		if (pubkey->u.rsa.exponent.data)
			free (pubkey->u.rsa.exponent.data);
	}
	return r;
}

/*
 * Store a PIN or PUK
 */
static int
etoken_store_pin(sc_profile_t *profile, sc_card_t *card,
		sc_pkcs15_pin_info_t *pin_info, int puk_id,
		const u8 *pin, size_t pin_len)
{
	struct sc_cardctl_etoken_obj_info args;
	unsigned char	buffer[256];
	unsigned char	pinpadded[16];
	struct tlv	tlv;
	unsigned int	attempts, minlen, maxlen;

	/* We need to do padding because pkcs15-lib.c does it.
	 * Would be nice to have a flag in the profile that says
	 * "no padding required". */
	maxlen = MIN(profile->pin_maxlen, sizeof(pinpadded));
	if (pin_len > maxlen)
		pin_len = maxlen;
	memcpy(pinpadded, pin, pin_len);
	while (pin_len < maxlen)
		pinpadded[pin_len++] = profile->pin_pad_char;
	pin = pinpadded;

	attempts = pin_info->tries_left;
	minlen = pin_info->min_length;

	tlv_init(&tlv, buffer, sizeof(buffer));

	/* object address: class, id */
	tlv_next(&tlv, 0x83);
	tlv_add(&tlv, 0x00);		/* class byte: usage TEST, k=0 */
	tlv_add(&tlv, pin_info->reference);

	/* parameters */
	tlv_next(&tlv, 0x85);
	tlv_add(&tlv, 0x02);		/* options byte */
	tlv_add(&tlv, attempts & 0xf);	/* flags byte */
	tlv_add(&tlv, ETOKEN_ALGO_PIN);	/* algorithm = pin-test */
	tlv_add(&tlv, attempts & 0xf);	/* errcount = attempts */

	/* usecount: not documented, but seems to work like this:
	 *  -	value of 0xff means pin can be presented any number
	 *	of times
	 *  -	anything less: max # of times before BS object is blocked.
	 */
	tlv_add(&tlv, 0xff);

	/* DEK: not documented, no idea what it means */
	tlv_add(&tlv, 0x00);

	/* ARA counter: Nils says this is the userConsent field */
	tlv_add(&tlv, 0x00);

	tlv_add(&tlv, minlen);			/* minlen */

	/* AC conditions */
	tlv_next(&tlv, 0x86);
	tlv_add(&tlv, 0x00);			/* use: always */
	tlv_add(&tlv, pin_info->reference);	/* change: PIN */
	tlv_add(&tlv, puk_id);			/* unblock: PUK */

	/* data: PIN */
	tlv_next(&tlv, 0x8f);
	while (pin_len--)
		tlv_add(&tlv, *pin++);

	args.data = buffer;
	args.len = tlv_len(&tlv);

	return sc_card_ctl(card, SC_CARDCTL_ETOKEN_PUT_DATA_OCI, &args);
}

/*
 * Create an empty security environment
 */
static int
etoken_create_sec_env(struct sc_profile *profile, sc_card_t *card,
		unsigned int se_id, unsigned int key_id)
{
	struct sc_cardctl_etoken_obj_info args;
	struct tlv	tlv;
	unsigned char	buffer[64];

	tlv_init(&tlv, buffer, sizeof(buffer));
	tlv_next(&tlv, 0x83);
	tlv_add(&tlv, se_id);

	tlv_next(&tlv, 0x86);
	tlv_add(&tlv, 0);
	tlv_add(&tlv, 0);

	tlv_next(&tlv, 0x8f);
	tlv_add(&tlv, key_id);
	tlv_add(&tlv, key_id);
	tlv_add(&tlv, key_id);
	tlv_add(&tlv, key_id);
	tlv_add(&tlv, key_id);
	tlv_add(&tlv, key_id);

	args.data = buffer;
	args.len = tlv_len(&tlv);
	return sc_card_ctl(card, SC_CARDCTL_ETOKEN_PUT_DATA_SECI, &args);
}

/*
 * Determine the key algorithm based on the intended usage
 * Note that CardOS/M4 does not support keys that can be used
 * for signing _and_ decipherment
 */
#define USAGE_ANY_SIGN		(SC_PKCS15_PRKEY_USAGE_SIGN|\
				 SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
#define USAGE_ANY_DECIPHER	(SC_PKCS15_PRKEY_USAGE_DECRYPT|\
				 SC_PKCS15_PRKEY_USAGE_UNWRAP)

static int
etoken_key_algorithm(unsigned int usage, int *algop)
{
	int	sign = 0, decipher = 0;

	if (usage & USAGE_ANY_SIGN) {
		*algop = ETOKEN_SIGN_RSA;
		sign = 1;
	}
	if (usage & USAGE_ANY_DECIPHER) {
		*algop = ETOKEN_DECIPHER_RSA;
		decipher = 1;
	}
	return (sign == decipher)? -1 : 0;
}

/*
 * Create a private key object
 */
#define ETOKEN_KEY_OPTIONS	0x02
#define ETOKEN_KEY_FLAGS	0x00
static int
etoken_store_key_component(sc_card_t *card,
		int algorithm,
		unsigned int key_id, unsigned int pin_id,
		unsigned int num,
		const u8 *data, size_t len,
		int last)
{
	struct sc_cardctl_etoken_obj_info args;
	struct tlv	tlv;
	unsigned char	buffer[256];
	unsigned int	n;

	/* Initialize the TLV encoder */
	tlv_init(&tlv, buffer, sizeof(buffer));

	/* Object address */
	tlv_next(&tlv, 0x83);
	tlv_add(&tlv, 0x20|num);	/* PSO, n-th component */
	tlv_add(&tlv, key_id);

	/* Object parameters */
	tlv_next(&tlv, 0x85);
	tlv_add(&tlv, ETOKEN_KEY_OPTIONS|(last? 0x00 : 0x20));
	tlv_add(&tlv, ETOKEN_KEY_FLAGS);
	tlv_add(&tlv, algorithm);
	tlv_add(&tlv, 0x00);
	tlv_add(&tlv, 0xFF);	/* use count */
	tlv_add(&tlv, 0xFF);	/* DEK (whatever this is) */
	tlv_add(&tlv, 0x00);
	tlv_add(&tlv, 0x00);

	/* AC bytes */
	tlv_next(&tlv, 0x86);
	tlv_add(&tlv, pin_id);	/* AC USE */
	tlv_add(&tlv, pin_id);	/* AC CHANGE */
	tlv_add(&tlv, pin_id);	/* UNKNOWN */
	/* The next 4 AC bytes are sent by the eToken run-time
	 * as well, but aren't documented anywhere.
	 * Key generation won't work without them, however. */
	tlv_add(&tlv, 0);
	tlv_add(&tlv, 0);
	tlv_add(&tlv, 0);
	tlv_add(&tlv, 0);

	/* SM bytes */
	tlv_next(&tlv, 0x8B);
	for (n = 0; n < 16; n++)
		tlv_add(&tlv, 0xFF);

	/* key component */
	tlv_next(&tlv, 0x8f);
	tlv_add(&tlv, len+1);
	tlv_add(&tlv, 0);
	while (len--)
		tlv_add(&tlv, *data++);

	args.data = buffer;
	args.len = tlv_len(&tlv);
	return sc_card_ctl(card, SC_CARDCTL_ETOKEN_PUT_DATA_OCI, &args);
}

static int
etoken_put_key(sc_profile_t *profile, sc_card_t *card,
		int algorithm, sc_pkcs15_prkey_info_t *key_info,
		struct sc_pkcs15_prkey_rsa *key)
{
	int	r, key_id, pin_id;

	key_id = key_info->key_reference;
	pin_id = sc_keycache_find_named_pin(&key_info->path, SC_PKCS15INIT_USER_PIN);
	if (pin_id < 0)
		pin_id = 0;

	r = etoken_store_key_component(card, algorithm, key_id, pin_id, 0,
			key->modulus.data, key->modulus.len, 0);
	if (r < 0)
		return r;
	r = etoken_store_key_component(card, algorithm, key_id, pin_id, 1,
			key->d.data, key->d.len, 1);

	return r;
}

/*
 * Extract a key component from the public key file populated by
 * GENERATE KEY PAIR
 */
static int
etoken_extract_pubkey(sc_card_t *card, int nr, u8 tag,
			sc_pkcs15_bignum_t *bn)
{
	u8	buf[256];
	int	r, count;

	r = sc_read_record(card, nr, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
	if (r < 0)
		return r;
	count = r - 4;
	if (count <= 0 || buf[0] != tag || buf[1] != count + 2
	 || buf[2] != count + 1 || buf[3] != 0)
		return SC_ERROR_INTERNAL;
	bn->len = count;
	bn->data = (u8 *) malloc(count);
	memcpy(bn->data, buf + 4, count);
	return 0;
}

static struct sc_pkcs15init_operations sc_pkcs15init_etoken_operations = {
	etoken_erase,
	NULL,				/* init_card */
	etoken_create_dir,
	NULL,				/* create_domain */
	etoken_select_pin_reference,
	etoken_create_pin,
	etoken_select_key_reference,
	etoken_create_key,
	etoken_store_key,
	etoken_generate_key,
	NULL, NULL, 			/* encode private/public key */
	NULL,				/* finalize_card */
	NULL, NULL, NULL, NULL, NULL,	/* old style api */
	NULL 				/* delete_object */
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_etoken_ops(void)
{
	return &sc_pkcs15init_etoken_operations;
}
