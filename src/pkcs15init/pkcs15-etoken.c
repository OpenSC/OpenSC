/*
 * eToken PRO specific operation for PKCS15 initialization
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
#include <opensc/scrandom.h>
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
static int	etoken_new_file(struct sc_profile *, struct sc_card *,
			unsigned int, unsigned int,
			struct sc_file **);
static void	error(struct sc_profile *, const char *, ...);

/* Object IDs for PIN objects.
 * SO PIN = 0x01, SO PUK = 0x02
 * each user pin is 2*N+1, each corresponding PUK is 2*N+2
 */
#define ETOKEN_PIN_ID(idx)	(((idx) << 1) + 0x01)
#define ETOKEN_PUK_ID(idx)	(((idx) << 1) + 0x02)
#define ETOKEN_MAX_PINS		0x10
#define ETOKEN_KEY_ID(idx)	(0x40 + (idx))
#define ETOKEN_SE_ID(idx)	(0x40 + (idx))
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
etoken_erase(struct sc_profile *profile, struct sc_card *card)
{
	return sc_pkcs15init_erase_card_recursively(card, profile, -1);
}

/*
 * Initialize pin file
 */
static int
etoken_store_pin(struct sc_profile *profile, struct sc_card *card,
		int pin_type, unsigned int pin_id, unsigned int puk_id,
		const u8 *pin, size_t pin_len)
{
	struct sc_pkcs15_pin_info params;
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

	sc_profile_get_pin_info(profile, pin_type, &params);
	attempts = params.tries_left;
	minlen = params.min_length;

	/* Set the profile's PIN reference */
	params.reference = pin_id;
	params.path = profile->df_info->file->path;
	sc_profile_set_pin_info(profile, pin_type, &params);

	tlv_init(&tlv, buffer, sizeof(buffer));

	/* object address: class, id */
	tlv_next(&tlv, 0x83);
	tlv_add(&tlv, 0x00);		/* class byte: usage TEST, k=0 */
	tlv_add(&tlv, pin_id);

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

	/* ARA counter: not documented, no idea what it means */
	tlv_add(&tlv, 0x00);

	tlv_add(&tlv, minlen);		/* minlen */

	/* AC conditions */
	tlv_next(&tlv, 0x86);
	tlv_add(&tlv, 0x00);		/* use: always */
	tlv_add(&tlv, pin_id);		/* change: PIN */
	tlv_add(&tlv, puk_id);		/* unblock: PUK */

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
etoken_create_sec_env(struct sc_profile *profile, struct sc_card *card,
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
 * Initialize the Application DF and pin file
 */
static int
etoken_init_app(struct sc_profile *profile, struct sc_card *card,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	struct sc_file	*df = profile->df_info->file;
	int		r;

	/* Create the application DF */
	r = sc_pkcs15init_create_file(profile, card, df);

	if (r >= 0)
		r = sc_select_file(card, &df->path, NULL);

	/* Create the PIN objects.
	 * First, the SO pin and PUK. Don't create objects for
	 * these if none specified. */
	if (pin && pin_len) {
		u8	puk_id = ETOKEN_AC_NEVER;

		if (r >= 0 && puk && puk_len) {
			puk_id = ETOKEN_PUK_ID(0);
			r = etoken_store_pin(profile, card,
					SC_PKCS15INIT_SO_PUK,
					puk_id, ETOKEN_AC_NEVER,
					puk, puk_len);
		}
		if (r >= 0) {
			r = etoken_store_pin(profile, card,
					SC_PKCS15INIT_SO_PIN,
					ETOKEN_PIN_ID(0), puk_id,
					pin, pin_len);
		}
	}

	/* Create a default security environment for this DF.
	 * This SE autometically becomes the current SE when the
	 * DF is selected. */
	if (r >= 0)
		r = etoken_create_sec_env(profile, card, 0x01, 0x00);

	return r;
}

/*
 * Store a PIN
 */
static int
etoken_new_pin(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *info, unsigned int index,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	struct sc_file	*df = profile->df_info->file;
	unsigned int	puk_id = ETOKEN_AC_NEVER, pin_id;
	int		r;

	if (!pin || !pin_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	r = sc_select_file(card, &df->path, NULL);
	if (r < 0)
		return r;

	if (index >= ETOKEN_MAX_PINS)
		return SC_ERROR_TOO_MANY_OBJECTS;

	if (puk && puk_len) {
		puk_id = ETOKEN_PUK_ID(index);
		r = etoken_store_pin(profile, card,
				SC_PKCS15INIT_USER_PUK,
				puk_id, ETOKEN_AC_NEVER,
				puk, puk_len);
	}

	if (r >= 0) {
		pin_id = ETOKEN_PIN_ID(index);
		r = etoken_store_pin(profile, card,
				SC_PKCS15INIT_USER_PIN,
				pin_id, puk_id,
				pin, pin_len);
		info->reference = pin_id;
		info->path = df->path;
	}

	return r;
}

/*
 * Determine the key algorithm based on the intended usage
 * Note that CardOS/M4 does not support keys that can be used
 * for signing _and_ decipherment
 */
#define USAGE_ANY_SIGN		(SC_PKCS15_PRKEY_USAGE_SIGN)
#define USAGE_ANY_DECIPHER	(SC_PKCS15_PRKEY_USAGE_DECRYPT|\
				 SC_PKCS15_PRKEY_USAGE_UNWRAP)

static int
etoken_key_algorithm(unsigned int usage, int *algop)
{
	int	sign = 0, decipher = 0;

	if (usage & USAGE_ANY_SIGN) {
		*algop = ETOKEN_SIGN_RSA;
		sign++;
	}
	if (usage & USAGE_ANY_DECIPHER) {
		*algop = ETOKEN_DECIPHER_RSA;
		decipher++;
	}
	return (sign && decipher)? -1 : 0;
}

/*
 * Create a private key object
 */
#define ETOKEN_KEY_OPTIONS	0x02
#define ETOKEN_KEY_FLAGS	0x00
static int
etoken_store_key_component(struct sc_card *card,
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
etoken_store_key(struct sc_profile *profile, struct sc_card *card,
		int algorithm, unsigned int key_id,
		struct sc_pkcs15_prkey_rsa *key)
{
	struct sc_pkcs15_pin_info pin_info;
	int		r, pin_id;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &pin_info);
	if ((pin_id = pin_info.reference) < 0)
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
 * Store a private key
 */
static int
etoken_new_key(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_prkey *key, unsigned int index,
		struct sc_pkcs15_prkey_info *info)
{
	struct sc_pkcs15_prkey_rsa *rsa;
	int		algorithm, key_id, r;

	if (key->algorithm != SC_ALGORITHM_RSA) {
		error(profile, "eToken supports RSA keys only.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (etoken_key_algorithm(info->usage, &algorithm) < 0) {
		error(profile, "eToken does not support keys "
			       "that can both sign _and_ decrypt.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	rsa = &key->u.rsa;
	key_id = ETOKEN_KEY_ID(index);
	r = etoken_store_key(profile, card, algorithm, key_id, rsa);
	if (r >= 0) {
		info->path = profile->df_info->file->path;
		info->key_reference = key_id;
	}

	return r;
}

/*
 * Allocate a file
 */
static int
etoken_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num,
		struct sc_file **out)
{
	struct sc_file	*file;
	struct sc_path	*p;
	char		name[64], *tag, *desc;

	desc = tag = NULL;
	while (1) {
		switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			desc = "RSA private key";
			tag = "private-key";
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			desc = "RSA public key";
			tag = "public-key";
			break;
#ifdef SC_PKCS15_TYPE_PRKEY_DSA
		case SC_PKCS15_TYPE_PRKEY_DSA:
			desc = "DSA private key";
			tag = "private-key";
			break;
		case SC_PKCS15_TYPE_PUBKEY_DSA:
			desc = "DSA public key";
			tag = "public-key";
			break;
#endif
		case SC_PKCS15_TYPE_PRKEY:
			desc = "extractable private key";
			tag = "extractable-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			desc = "certificate";
			tag = "certificate";
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			desc = "data object";
			tag = "data";
			break;
		}
		if (tag)
			break;
		/* If this is a specific type such as
		 * SC_PKCS15_TYPE_CERT_FOOBAR, fall back to
		 * the generic class (SC_PKCS15_TYPE_CERT)
		 */
		if (!(type & ~SC_PKCS15_TYPE_CLASS_MASK)) {
			error(profile, "File type not supported by card driver");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) {
		error(profile, "Profile doesn't define %s template (%s)\n",
				desc, name);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Now construct file from template */
	file->id += num;

	p = &file->path;
	*p = profile->df_info->file->path;
	p->value[p->len++] = file->id >> 8;
	p->value[p->len++] = file->id;

	*out = file;
	return 0;
}

/*
 * Extract a key component from the public key file populated by
 * GENERATE KEY PAIR
 */
static int
etoken_extract_pubkey(struct sc_card *card, int nr, u8 tag,
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

/*
 * Key generation
 */
static int
etoken_generate_key(struct sc_profile *profile, struct sc_card *card,
		unsigned int index, unsigned int keybits,
		sc_pkcs15_pubkey_t *pubkey,
		struct sc_pkcs15_prkey_info *info)
{
	struct sc_pkcs15_prkey_rsa key_obj;
	struct sc_cardctl_etoken_genkey_info args;
	struct sc_file	*temp;
	u8		abignum[RSAKEY_MAX_SIZE];
	u8		randbuf[64], key_id;
	int		algorithm, r, delete_it = 0;

	keybits &= ~7UL;
	if (keybits > RSAKEY_MAX_BITS) {
		error(profile, "Unable to generate key, max size is %d\n",
				RSAKEY_MAX_BITS);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (etoken_key_algorithm(info->usage, &algorithm) < 0) {
		error(profile, "eToken does not support keys "
			       "that can both sign _and_ decrypt.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (sc_profile_get_file(profile, "tempfile", &temp) < 0) {
		error(profile, "Profile doesn't define temporary file "
				"for key generation.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	memset(pubkey, 0, sizeof(*pubkey));

	if ((r = sc_pkcs15init_create_file(profile, card, temp)) < 0)
		goto out;
	delete_it = 1;

	key_id = ETOKEN_KEY_ID(index);

	/* Create a key object, initializing components to 0xff */
	memset(&key_obj, 0, sizeof(key_obj));
	memset(abignum, 0xFF, sizeof(abignum));
	key_obj.modulus.data = abignum;
	key_obj.modulus.len = keybits >> 3;
	key_obj.d.data = abignum;
	key_obj.d.len = keybits >> 3;
	r = etoken_store_key(profile, card, algorithm, key_id, &key_obj);
	if (r < 0)
		goto out;

	memset(&args, 0, sizeof(args));
#ifdef notyet
	if ((r = scrandom_get_data(randbuf, sizeof(randbuf))) < 0)
		goto out;

	/* For now, we have to rely on the card's internal number
	 * generator because libscrandom is static, which causes
	 * all sorts of headaches when linking against it
	 * (some platforms don't allow non-PIC code in a shared lib,
	 * such as ia64).
	 */
	args.random_data = randbuf;
	args.random_len = sizeof(randbuf);
#endif
	args.key_id = key_id;
	args.key_bits = keybits;
	args.fid = temp->id;
	r = sc_card_ctl(card, SC_CARDCTL_ETOKEN_GENERATE_KEY, &args);
	memset(randbuf, 0, sizeof(randbuf));
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
	info->key_reference = key_id;
	info->path = profile->df_info->file->path;

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

static void
error(struct sc_profile *profile, const char *fmt, ...)
{
	char	buffer[256];
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);
	if (profile->cbs)
		profile->cbs->error("%s", buffer);
}

struct sc_pkcs15init_operations sc_pkcs15init_etoken_operations = {
	etoken_erase,
	etoken_init_app,
	etoken_new_pin,
	etoken_new_key,
	etoken_new_file,
	etoken_generate_key
};
