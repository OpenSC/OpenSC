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

/*
 * Local functions
 */
static int	etoken_new_file(struct sc_profile *, struct sc_card *,
			unsigned int, unsigned int,
			struct sc_file **);
static void	error(struct sc_profile *, const char *, ...);

/* We should make these object IDs configurable via the profile */
#define ETOKEN_SO_PIN_ID	0x01
#define ETOKEN_SO_PUK_ID	0x02
#define ETOKEN_PIN_ID		0x03
#define ETOKEN_PUK_ID		0x04
#define ETOKEN_AC_NEVER		0xFF

#define ETOKEN_ALGO_PIN		0x87

struct etoken_pin_info {
	int		profile_id;
	u8		id;
	u8		unblock;
};
static struct etoken_pin_info	etoken_so_pin = {
	SC_PKCS15INIT_SO_PIN,
	ETOKEN_SO_PIN_ID,
	ETOKEN_SO_PUK_ID
};
static struct etoken_pin_info	etoken_so_puk = {
	SC_PKCS15INIT_SO_PUK,
	ETOKEN_SO_PUK_ID,
	ETOKEN_AC_NEVER
};
static struct etoken_pin_info	etoken_user_pin = {
	SC_PKCS15INIT_USER_PIN,
	ETOKEN_PIN_ID,
	ETOKEN_PUK_ID
};
static struct etoken_pin_info	etoken_user_puk = {
	SC_PKCS15INIT_USER_PUK,
	ETOKEN_PUK_ID,
	ETOKEN_SO_PIN_ID
};
static u8	etoken_default_pin[8];

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

static int
etoken_set_ac(struct sc_file *file, int op, struct sc_acl_entry *acl)
{
	/* XXX TBD */
	return 0;
}

/*
 * Initialize pin file
 */
static int
etoken_new_pin(struct sc_profile *profile, struct sc_card *card,
		struct etoken_pin_info *info,
		const u8 *pin, size_t pin_len,
		int allow_unblock)
{
	struct sc_pkcs15_pin_info params;
	struct sc_cardctl_etoken_pin_info args;
	unsigned char	buffer[256];
	unsigned char	pinpadded[16];
	struct tlv	tlv;
	unsigned int	pin_id, puk_id, attempts, minlen, maxlen;

	if (!pin_len) {
		pin = etoken_default_pin;
		pin_len = sizeof(etoken_default_pin);
	}
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

	sc_profile_get_pin_info(profile, info->profile_id, &params);
	attempts = params.tries_left;
	minlen = params.min_length;

	pin_id = info->id;
	puk_id = allow_unblock? info->unblock : ETOKEN_AC_NEVER;

	/* Set the profile's SOPIN reference */
	params.reference = info->id;
	params.path = profile->df_info->file->path;
	sc_profile_set_pin_info(profile, info->profile_id, &params);

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

	/* ARA counted: not documented, no idea what it means */
	tlv_add(&tlv, 0x00);

	tlv_add(&tlv, minlen);		/* minlen */

	/* AC conditions */
	tlv_next(&tlv, 0x86);
	tlv_add(&tlv, 0x00);		/* use: always */
	tlv_add(&tlv, puk_id);		/* change: PUK */
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
 * Initialize the Application DF and pin file
 */
static int
etoken_init_app(struct sc_profile *profile, struct sc_card *card,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	struct sc_file	*df = profile->df_info->file;
	int		r, unblock = 0;

	/* Create the application DF */
	r = sc_pkcs15init_create_file(profile, card, df);

	if (r >= 0)
		r = sc_select_file(card, &df->path, NULL);

	/* Create the PIN objects.
	 * First, the SO pin and PUK. Don't create objects for
	 * these if none specified. */
	if (pin && pin_len) {
		if (r >= 0 && puk && puk_len)
			r = etoken_new_pin(profile, card,
				&etoken_so_puk, puk, puk_len, unblock++);
		if (r >= 0)
			r = etoken_new_pin(profile, card,
				&etoken_so_pin, pin, pin_len, unblock++);
	}
	/* Create objects for user PIN and PUK. */
	if (r >= 0)
		r = etoken_new_pin(profile, card,
				&etoken_user_pin, 0, 0, unblock++);
	if (r >= 0)
		r = etoken_new_pin(profile, card,
				&etoken_user_puk, 0, 0, unblock);

#if 0
	r = sc_verify(card, SC_AC_CHV, 0x04,
			etoken_default_pin, sizeof(etoken_default_pin),
			NULL);
#endif

	return r;
}

/*
 * Store a PIN
 */
static int
etoken_put_pin(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *info, unsigned int index,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	return SC_ERROR_NOT_SUPPORTED;
#if 0
	unsigned char	nulpin[8];
	int		r;

	/* Profile must define a "pinfile" */
	if (sc_profile_get_path(profile, "pinfile", &info->path) < 0) {
		error(profile, "Profile doesn't define a \"pinfile\"");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (info->path.len > 2)
		info->path.len -= 2;

	r = sc_select_file(card, &info->path, NULL);
	if (r < 0)
		return r;

	index <<= 2;
	if (index >= GPK_MAX_PINS)
		return SC_ERROR_TOO_MANY_OBJECTS;
	if (puk == NULL || puk_len == 0) {
		puk = pin;
		puk_len = pin_len;
	}

	/* Current PIN is 00:00:00:00:00:00:00:00 */
	memset(nulpin, 0, sizeof(nulpin));
	r = sc_change_reference_data(card, SC_AC_CHV,
			0x8 | index,
			nulpin, sizeof(nulpin),
			pin, pin_len, NULL);
	if (r < 0)
		return r;

	/* Current PUK is 00:00:00:00:00:00:00:00 */
	r = sc_change_reference_data(card, SC_AC_CHV,
			0x8 | (index + 1),
			nulpin, sizeof(nulpin),
			puk, puk_len, NULL);

	info->reference = 0x8 | index;
	return r;
#endif
}

/*
 * Store a private key
 */
static int
etoken_new_key(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_prkey *key, unsigned int index,
		struct sc_pkcs15_prkey_info *info)
{
	return SC_ERROR_NOT_SUPPORTED;
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
	NULL,
	etoken_init_app,
	etoken_put_pin,
	etoken_new_key,
	etoken_new_file,
};
