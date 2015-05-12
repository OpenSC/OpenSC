/*
 * GPK specific operation for PKCS15 initialization
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

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

/* this could be removed once we include libopensc/internal.h */
#ifndef _WIN32
#define msleep(t)	usleep((t) * 1000)
#else
#include <windows.h>
#define msleep(t)	Sleep(t)
#define sleep(t)	Sleep((t) * 1000)
#endif

#define PK_INIT_IMMEDIATELY

#define GPK_MAX_PINS		8
#define GPK_PIN_SCOPE		8
#define GPK_FTYPE_SECRET_CODE	0x21
#define GPK_FTYPE_PUBLIC_KEY	0x2C

/*
 * Key components (for storing private keys)
 */
struct pkcomp {
	unsigned char	tag;
	u8 *		data;
	unsigned int	size;
};

struct pkpart {
	struct pkcomp	components[7];
	unsigned int	count;
	unsigned int	size;
};

struct pkdata {
	unsigned int	algo;
	unsigned int	usage;
	struct pkpart _public, _private;
	unsigned int	bits, bytes;
};

/*
 * Local functions
 */
static int	gpk_pkfile_create(sc_profile_t *, sc_pkcs15_card_t *, sc_file_t *);
static int	gpk_encode_rsa_key(sc_profile_t *, sc_card_t *,
			struct sc_pkcs15_prkey_rsa *, struct pkdata *,
			struct sc_pkcs15_prkey_info *);
static int	gpk_encode_dsa_key(sc_profile_t *, sc_card_t *,
			struct sc_pkcs15_prkey_dsa *, struct pkdata *,
			struct sc_pkcs15_prkey_info *);
static int	gpk_store_pk(struct sc_profile *, sc_pkcs15_card_t *,
			sc_file_t *, struct pkdata *);
static int	gpk_init_pinfile(sc_profile_t *, sc_pkcs15_card_t *, sc_file_t *);
static int	gpk_pkfile_init_public(sc_profile_t *, sc_pkcs15_card_t *,
			sc_file_t *, unsigned int, unsigned int, unsigned int);
static int	gpk_pkfile_init_private(sc_card_t *, sc_file_t *, unsigned int);
static int	gpk_read_rsa_key(sc_card_t *, struct sc_pkcs15_pubkey_rsa *);


/*
 * Erase the card
 */
static int
gpk_erase_card(struct sc_profile *pro, sc_pkcs15_card_t *p15card)
{
	int	locked;

	if (sc_card_ctl(p15card->card, SC_CARDCTL_GPK_IS_LOCKED, &locked) == 0
	 && locked) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
			"This card is already personalized, unable to "
			"create PKCS#15 structure.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	return sc_card_ctl(p15card->card, SC_CARDCTL_ERASE_CARD, NULL);
}

/*
 * Create a new DF
 * This will usually be the application DF
 */
static int
gpk_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df)
{
	struct sc_file	*pinfile;
	int		r, locked;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (sc_card_ctl(p15card->card, SC_CARDCTL_GPK_IS_LOCKED, &locked) == 0
			&& locked) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
			"This card is already personalized, unable to "
			"create PKCS#15 structure.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Create the DF. */
	r = sc_pkcs15init_create_file(profile, p15card, df);
	if (r < 0)
		return r;

	/* See if there's a file called "pinfile" that resides within
	 * this DF. If so, create it */
	if (sc_profile_get_file(profile, "pinfile", &pinfile) >= 0) {
		/* Build the pin file's path from the DF path + its
		 * file ID */
		pinfile->path = df->path;
		sc_append_file_id(&pinfile->path, pinfile->id);

		r = gpk_init_pinfile(profile, p15card, pinfile);
		sc_file_free(pinfile);
		if (r < 0)
			return r;

		/* TODO: What for it was used ?
		for (i = 0; i < GPK_MAX_PINS; i++)
		*	sc_keycache_put_pin(&df->path, GPK_PIN_SCOPE|i, (const u8 *) "        ");
		*/
	}

	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/*
 * Select a PIN reference
 */
static int
gpk_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_auth_info_t *auth_info)
{
	int	preferred, current;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if ((current = auth_info->attrs.pin.reference) < 0)
		current = 0;

	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		preferred = GPK_PIN_SCOPE | 0;
	} else {
		preferred = current | GPK_PIN_SCOPE;

		if (preferred & 1)
			preferred++;
		if (preferred < (GPK_PIN_SCOPE | 2))
			preferred = GPK_PIN_SCOPE | 2;
		if (preferred > 15)
			return SC_ERROR_TOO_MANY_OBJECTS;
	}

	if (current > preferred)
		return SC_ERROR_TOO_MANY_OBJECTS;
	auth_info->attrs.pin.reference = preferred;
	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, 0);
}

/*
 * Store a PIN
 */
static int
gpk_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df,
		sc_pkcs15_object_t *pin_obj,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
	u8	nulpin[8];
	int	r;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		/* SO PIN reference must be 0 */
		if (pin_attrs->reference != (GPK_PIN_SCOPE | 0))
			return SC_ERROR_INVALID_ARGUMENTS;
	} else {
		/* PIN references must be even numbers
		 * (the odd numbered PIN entries contain the
		 * PUKs).
		 * Returning SC_ERROR_INVALID_PIN_REFERENCE will
		 * tell the caller to pick a different value.
		 */
		if ((pin_attrs->reference & 1) || !(pin_attrs->reference & GPK_PIN_SCOPE))
			return SC_ERROR_INVALID_PIN_REFERENCE;
		if (pin_attrs->reference >= (GPK_PIN_SCOPE + GPK_MAX_PINS))
			return SC_ERROR_TOO_MANY_OBJECTS;
	}

	/* No PUK given, but the PIN file specifies an unblock
	 * PIN for every PIN.
	 * Use the same value for the PUK for now.
	 * Alternatively, we could leave the unblock PIN at the default
	 * value, but deliberately block it. */
	if (puk == NULL || puk_len == 0) {
		puk = pin;
		puk_len = pin_len;
	}

	r = sc_select_file(p15card->card, &df->path, NULL);
	sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "select df path: %i", r);
	if (r < 0)
		return r;

	/* Current PIN is 00:00:00:00:00:00:00:00 */
	memset(nulpin, 0, sizeof(nulpin));
	r = sc_change_reference_data(p15card->card, SC_AC_CHV,
			pin_attrs->reference,
			nulpin, sizeof(nulpin),
			pin, pin_len, NULL);
	sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "change  CHV %i", r);
	if (r < 0)
		return r;

	/* Current PUK is 00:00:00:00:00:00:00:00 */
	r = sc_change_reference_data(p15card->card, SC_AC_CHV,
			pin_attrs->reference + 1,
			nulpin, sizeof(nulpin),
			puk, puk_len, NULL);
	sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "change  CHV+1 %i", r);
	if (r < 0)
		return r;

	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, r);
}


/*
 * Lock a file operation
 */
static int
gpk_lock(sc_card_t *card, sc_file_t *file, unsigned int op)
{
	struct sc_cardctl_gpk_lock	args;

	args.file = file;
	args.operation = op;
	return sc_card_ctl(card, SC_CARDCTL_GPK_LOCK, &args);
}

/*
 * Lock the pin file
 */
static int
gpk_lock_pinfile(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		sc_file_t *pinfile)
{
	struct sc_path	path;
	struct sc_file	*parent = NULL;
	int		r;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* Select the parent DF */
	path = pinfile->path;
	if (path.len >= 2)
		path.len -= 2;
	if (path.len == 0)
		sc_format_path("3F00", &path);
	if ((r = sc_select_file(p15card->card, &path, &parent)) < 0)
		return r;

	/* Present PINs etc as necessary */
	r = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_LOCK);
	if (r >= 0)
		r = gpk_lock(p15card->card, pinfile, SC_AC_OP_WRITE);

	sc_file_free(parent);
	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/*
 * Initialize pin file
 */
static int
gpk_init_pinfile(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		sc_file_t *file)
{
	const sc_acl_entry_t *acl;
	unsigned char	buffer[GPK_MAX_PINS * 8], *blk;
	struct sc_file	*pinfile;
	unsigned int	so_attempts[2], user_attempts[2];
	unsigned int	npins, i, j, cks;
	int		r;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* Set defaults */
	so_attempts[0] = sc_profile_get_pin_retries(profile, SC_PKCS15INIT_SO_PIN);
	so_attempts[1] = sc_profile_get_pin_retries(profile, SC_PKCS15INIT_SO_PUK);
	user_attempts[0] = sc_profile_get_pin_retries(profile, SC_PKCS15INIT_USER_PIN);
	user_attempts[1] = sc_profile_get_pin_retries(profile, SC_PKCS15INIT_USER_PUK);

	sc_file_dup(&pinfile, file);
	if (pinfile == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	/* Create the PIN file. */
	acl = sc_file_get_acl_entry(pinfile, SC_AC_OP_WRITE);
	if (acl->method != SC_AC_NEVER) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
			"PIN file most be protected by WRITE=NEVER");
		sc_file_free(pinfile);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_file_add_acl_entry(pinfile, SC_AC_OP_WRITE, SC_AC_NONE, 0);

	if (pinfile->size == 0)
		pinfile->size = GPK_MAX_PINS * 8;

	sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "Now create file");
	/* Now create the file */
	if ((r = sc_pkcs15init_create_file(profile, p15card, pinfile)) < 0
	 || (r = sc_select_file(p15card->card, &pinfile->path, NULL)) < 0)   {
		goto out;
	}

	/* Set up the PIN file contents.
	 * We assume the file will contain pairs of PINs/PUKs */
	npins = pinfile->size / 8;
	memset(buffer, 0, sizeof(buffer));
	for (i = 0, blk = buffer; i < npins; blk += 8, i += 1) {
		/* Determine the number of PIN/PUK presentation
		 * attempts. If the profile defines a SO PIN,
		 * it will be stored in the first PIN/PUK pair.
		 */
		blk[0] = user_attempts[i & 1];
		if (i < 2 && so_attempts[0])
			blk[0] = so_attempts[i & 1];
		if ((i & 1) == 0) {
			/* This is a PIN. If there's room in the file,
			 * the next will be a PUK so take note of the
			 * unlock code */
			if (i + 1 < npins)
				blk[2] = GPK_PIN_SCOPE | (i + 1);
		}

		/* Compute the CKS */
		for (j = 0, cks = 0; j < 8; j++)
			cks ^= blk[j];
		blk[3] = ~cks;
	}

	r = sc_write_binary(p15card->card, 0, buffer, npins * 8, 0);
	if (r >= 0)
		r = gpk_lock_pinfile(profile, p15card, pinfile);

out:	sc_file_free(pinfile);
	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/*
 * Create a key file
 */
static int
gpk_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *obj)
{
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_file	*keyfile = NULL;
	size_t		bytes, mod_len, exp_len, prv_len, pub_len;
	int		r, algo;

	/* The caller is supposed to have chosen a key file path for us */
	if (key_info->path.len == 0 || key_info->modulus_length == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Get the file we're supposed to create */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &keyfile);
	if (r < 0)
		return r;

	/* Compute the file size.
	 * We assume private keys are stored as CRT elements.
	 *  -	512, 768 bit keys: all CRT elements fit into one record
	 *  -	>= 1024: each CRT element into a record of its own
	 *
	 * We also assume the public exponent is 32bit max
	 *
	 * Rules
	 *  -	private key records must have a length divisible by 8
	 */
	mod_len = key_info->modulus_length / 8;
	exp_len = 4;
	bytes   = mod_len / 2;
	pub_len = 8 + ((3 + mod_len + 3 + exp_len + 3) & ~3UL);
	if (5 * bytes < 256) {
		prv_len = 8 + ((3 + 5 * bytes + 7) & ~7UL);
	} else {
		prv_len = 8 + 5 * ((3 + bytes + 7) & ~7UL);
	}
	keyfile->size = pub_len + prv_len;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		algo = SC_ALGORITHM_RSA; break;
	case SC_PKCS15_TYPE_PRKEY_DSA:
		algo = SC_ALGORITHM_DSA; break;
	default:
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "Unsupported public key algorithm");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Fix up PIN references in file ACL and create the PK file */
	if ((r = sc_pkcs15init_fixup_file(profile, p15card, keyfile)) < 0
	 || (r = gpk_pkfile_create(profile, p15card, keyfile)) < 0)
		goto done;

#ifdef PK_INIT_IMMEDIATELY
	/* Initialize the public key header */
	r = gpk_pkfile_init_public(profile, p15card, keyfile, algo,
			key_info->modulus_length,
			key_info->usage);
	if (r < 0)
		goto done;

	/* Create the private key portion */
	r = gpk_pkfile_init_private(p15card->card, keyfile, prv_len);
#endif

done:
	sc_file_free(keyfile);
	return r;
}

/*
 * Store a private key
 */
static int
gpk_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, struct sc_pkcs15_prkey *key)
{
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_file	*keyfile = NULL;
	struct pkdata	data;
	int		r;

	/* The caller is supposed to have chosen a key file path for us */
	if (key_info->path.len == 0 || key_info->modulus_length == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Get the file we're supposed to create */
	r = sc_select_file(p15card->card, &key_info->path, &keyfile);
	if (r < 0)
		return r;

	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		r = gpk_encode_rsa_key(profile, p15card->card, &key->u.rsa,
					&data, key_info);
		break;

	case SC_ALGORITHM_DSA:
		r = gpk_encode_dsa_key(profile, p15card->card, &key->u.dsa,
					&data, key_info);
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (r >= 0)
		r = gpk_store_pk(profile, p15card, keyfile, &data);

	if (keyfile)
		sc_file_free(keyfile);
	return r;
}

/*
 * On-board key generation.
 */
static int
gpk_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                        sc_pkcs15_object_t *obj,
                        sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_gpk_genkey args;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	unsigned int    keybits;
	sc_file_t	*keyfile;
	int             r, n;

	sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "path=%s, %d bits\n", sc_print_path(&key_info->path),
			key_info->modulus_length);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "GPK supports generating only RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* The caller is supposed to have chosen a key file path for us */
	if (key_info->path.len == 0 || key_info->modulus_length == 0)
		return SC_ERROR_INVALID_ARGUMENTS;
	keybits = key_info->modulus_length;

	if ((r = sc_select_file(p15card->card, &key_info->path, &keyfile)) < 0)
		return r;

#ifndef PK_INIT_IMMEDIATELY
	r = gpk_pkfile_init_public(profile, p15card, keyfile, SC_ALGORITHM_RSA,
			keybits, key_info->usage);
	if (r < 0) {
		sc_file_free(keyfile);
		return r;
	}

	if ((r = gpk_pkfile_init_private(p15card->card, keyfile, 5 * ((3 + keybits / 16 + 7) & ~7UL))) < 0) {
		sc_file_free(keyfile);
		return r;
	}
#endif
	sc_file_free(keyfile);

	memset(&args, 0, sizeof(args));
	/*args.exponent = 0x10001;*/
	n = key_info->path.len;
	args.fid = (key_info->path.value[n-2] << 8) | key_info->path.value[n-1];
	args.privlen = keybits;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_GPK_GENERATE_KEY, &args);
	if (r < 0)
		return r;

	/* This is fairly weird. The GENERATE RSA KEY command returns
	 * immediately, but obviously it needs more time to complete.
	 * This is why we sleep here. */
	sleep(20);

	pubkey->algorithm = SC_ALGORITHM_RSA;
	return gpk_read_rsa_key(p15card->card, &pubkey->u.rsa);
}

/*
 * GPK public/private key file handling is hideous.
 * 600 lines of coke sweat and tears...
 */
/*
 * Create the PK file
 * XXX: Handle the UPDATE ACL = NEVER case just like for EFsc files
 */
static int
gpk_pkfile_create(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *file)
{
	struct sc_file	*found = NULL;
	int		r;

	r = sc_select_file(p15card->card, &file->path, &found);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		r = sc_pkcs15init_create_file(profile, p15card, file);
		if (r >= 0)
			r = sc_select_file(p15card->card, &file->path, &found);
	} else {
		/* XXX: make sure the file has correct type and size? */
	}

	if (r >= 0)
		r = sc_pkcs15init_authenticate(profile, p15card, file,
				SC_AC_OP_UPDATE);
	if (found)
		sc_file_free(found);

	return r;
}

static int
gpk_pkfile_keybits(unsigned int bits, unsigned char *p)
{
	switch (bits) {
	case  512: *p = 0x00; return 0;
	case  768: *p = 0x10; return 0;
	case 1024: *p = 0x11; return 0;
	}
	return SC_ERROR_NOT_SUPPORTED;
}

static int
gpk_pkfile_keyalgo(unsigned int algo, unsigned char *p)
{
	switch (algo) {
	case SC_ALGORITHM_RSA: *p = 0x00; return 0;
	case SC_ALGORITHM_DSA: *p = 0x01; return 0;
	}
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Set up the public key record for a signature only public key
 */
static int
gpk_pkfile_init_public(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *file,
		unsigned int algo, unsigned int bits,
		unsigned int usage)
{
	struct sc_context *ctx = p15card->card->ctx;
	const sc_acl_entry_t *acl;
	sc_file_t	*tmp = NULL;
	u8		sysrec[7], buffer[256];
	unsigned int	n, npins;
	int		r, card_type;

	/* Find out what sort of GPK we're using */
	if ((r = sc_card_ctl(p15card->card, SC_CARDCTL_GPK_VARIANT, &card_type)) < 0)
		return r;

	/* Set up the system record */
	memset(sysrec, 0, sizeof(sysrec));

	/* Mapping keyUsage to sysrec[2]:
	 * 	0x00	sign & unwrap
	 * 	0x10	sign only
	 * 	0x20	unwrap only
	 * 	0x30	CA key
	 *
	 * We start with a value of 0x30.
	 * If the key allows decryption, clear the sign only bit.
	 * Likewise, if it allows signing, clear the unwrap only bit.
	 */
	sysrec[2] = 0x30;
	if (usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP))
		sysrec[2] &= ~0x10;
	if (usage & (SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_NONREPUDIATION))
		sysrec[2] &= ~0x20;
	if (sysrec[2] == 0x30) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Key usage should specify at least one of sign or decipher");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Set the key size and algorithm */
	if ((r = gpk_pkfile_keybits(bits, &sysrec[1])) < 0
	 || (r = gpk_pkfile_keyalgo(algo, &sysrec[5])) < 0)
		return r;

	/* Set PIN protection if requested.
	 * As the crypto ACLs are stored inside the file,
	 * we have to get them from the profile here. */
	r = sc_profile_get_file_by_path(profile, &file->path, &tmp);
	if (r < 0)
		return r;
	/* Fix up PIN references in file ACL */
	if ((r = sc_pkcs15init_fixup_file(profile, p15card, tmp)) < 0)
		goto out;

	acl = sc_file_get_acl_entry(tmp, SC_AC_OP_CRYPTO);
	for (npins = 0; acl; acl = acl->next) {
		if (acl->method == SC_AC_NONE
		 || acl->method == SC_AC_NEVER)
			continue;
		if (acl->method != SC_AC_CHV) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Authentication method not "
				"supported for private key files.\n");
			r = SC_ERROR_NOT_SUPPORTED;
			goto out;
		}
		if (++npins >= 2) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Too many pins for PrKEY file!\n");
			r = SC_ERROR_NOT_SUPPORTED;
			goto out;
		}
		sysrec[2] += 0x40;
		sysrec[3] >>= 4;
		sysrec[3] |= acl->key_ref << 4;
	}

	/* compute checksum - yet another slightly different
	 * checksum algorithm courtesy of Gemplus */
	if (card_type >= SC_CARD_TYPE_GPK_GPK8000) {
		/* This is according to the gpk reference manual */
		sysrec[6] = 0xA5;
	} else {
		/* And this is what you have to use for the GPK4000 */
		sysrec[6] = 0xFF;
	}
	for (n = 0; n < 6; n++)
		sysrec[6] ^= sysrec[n];

	r = sc_read_record(p15card->card, 1, buffer, sizeof(buffer),
			SC_RECORD_BY_REC_NR);
	if (r >= 0) {
		if (r != 7 || buffer[0] != 0) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "first record of public key file is not Lsys0");
			r = SC_ERROR_OBJECT_NOT_VALID;
			goto out;
		}

		r = sc_update_record(p15card->card, 1, sysrec, sizeof(sysrec),
				SC_RECORD_BY_REC_NR);
	} else {
		r = sc_append_record(p15card->card, sysrec, sizeof(sysrec), 0);
	}

out:	if (tmp)
		sc_file_free(tmp);
	return r;
}

static int
gpk_pkfile_update_public(struct sc_profile *profile,
		sc_pkcs15_card_t *p15card, struct pkpart *part)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct pkcomp	*pe;
	unsigned char	buffer[256];
	unsigned int	m, n, tag;
	int		r = 0, found;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Updating public key elements\n");

	/* If we've been given a key with public parts, write them now */
	for (n = 2; n < 256; n++) {
		r = sc_read_record(p15card->card, n, buffer, sizeof(buffer),
				SC_RECORD_BY_REC_NR);
		if (r < 0) {
			r = 0;
			break;
		}

		/* Check for bad record */
		if (r < 2) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "key file format error: "
				"record %u too small (%u bytes)\n",
				n, r);
			return SC_ERROR_OBJECT_NOT_VALID;
		}

		tag = buffer[0];

		for (m = 0, found = 0; m < part->count; m++) {
			pe = part->components + m;
			if (pe->tag == tag) {
				r = sc_update_record(p15card->card, n,
						pe->data, pe->size,
						SC_RECORD_BY_REC_NR);
				if (r < 0)
					return r;
				pe->tag = 0; /* mark as stored */
				found++;
				break;
			}
		}

		if (!found)
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "GPK unknown PK tag %u\n", tag);
	}

	/* Write all remaining elements */
	for (m = 0; r >= 0 && m < part->count; m++) {
		pe = part->components + m;
		if (pe->tag != 0)
			r = sc_append_record(p15card->card, pe->data, pe->size, 0);
	}

	return r;
}

static int
gpk_pkfile_init_private(sc_card_t *card,
		sc_file_t *file, unsigned int privlen)
{
	struct sc_cardctl_gpk_pkinit args;

	args.file = file;
	args.privlen = privlen;
	return sc_card_ctl(card, SC_CARDCTL_GPK_PKINIT, &args);
}

static int
gpk_pkfile_load_private(sc_card_t *card, sc_file_t *file,
			u8 *data, unsigned int len, unsigned int datalen)
{
	struct sc_cardctl_gpk_pkload args;

	args.file = file;
	args.data = data;
	args.len  = len;
	args.datalen = datalen;
	return sc_card_ctl(card, SC_CARDCTL_GPK_PKLOAD, &args);
}

static int
gpk_pkfile_update_private(struct sc_profile *profile,
			sc_pkcs15_card_t *p15card, sc_file_t *file,
			struct pkpart *part)
{
	unsigned int	m, size, nb, cks;
	struct pkcomp	*pe;
	u8		data[256];
	int		r = 0;

	sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "Updating private key elements\n");

	for (m = 0; m < part->count; m++) {
		pe = part->components + m;

		if (pe->size + 8 > sizeof(data))
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(data, pe->data, pe->size);
		size = pe->size;

		/* We must set a secure messaging key before each
		 * Load Private Key command. Any key will do...
		 * The GPK _is_ weird. */
		r = sc_pkcs15init_verify_secret(profile, p15card, NULL, SC_AC_PRO, 1);
		if (r < 0)
			break;

		/* Pad out data to a multiple of 8 and checksum.
		 * The GPK manual is a bit unclear about whether you
		 * checksum first and then pad, or vice versa.
		 * The following code does seem to work though: */
		for (nb = 0, cks = 0xff; nb < size; nb++)
			cks ^= data[nb];
		data[nb++] = cks;
		while (nb & 7)
			data[nb++] = 0;

		r = gpk_pkfile_load_private(p15card->card, file, data, size-1, nb);
		if (r < 0)
			break;
	}
	return r;
}

/* Sum up the size of the public key elements
 * Each element is type + tag + bignum
 */
static void
gpk_compute_publen(struct pkpart *part)
{
	unsigned int	n, publen = 8;	/* length of sysrec0 */

	for (n = 0; n < part->count; n++)
		publen += 2 + part->components[n].size;
	part->size = (publen + 3) & ~3UL;
}

/* Sum up the size of the private key elements
 * Each element is type + tag + bignum + checksum, padded to a multiple
 * of eight
 */
static void
gpk_compute_privlen(struct pkpart *part)
{
	unsigned int	n, privlen = 8;

	for (n = 0; n < part->count; n++)
		privlen += (3 + part->components[n].size + 7) & ~7UL;
	part->size = privlen;
}

/*
 * Convert BIGNUM to GPK representation, optionally zero padding to size.
 * Note that the bignum's we're given are big-endian, while the GPK
 * wants them little-endian.
 */
static void
gpk_bn2bin(unsigned char *dest, sc_pkcs15_bignum_t *bn, unsigned int size)
{
	u8		*src;
	unsigned int	n;

	assert(bn->len <= size);
	memset(dest, 0, size);
	for (n = bn->len, src = bn->data; n--; src++)
		dest[n] = *src;
}

/*
 * Add a BIGNUM component, optionally padding out the number to size bytes
 */
static void
gpk_add_bignum(struct pkpart *part, unsigned int tag,
		sc_pkcs15_bignum_t *bn, size_t size)
{
	struct pkcomp	*comp;

	if (size == 0)
		size = bn->len;

	comp = &part->components[part->count++];
	memset(comp, 0, sizeof(*comp));
	comp->tag  = tag;
	comp->size = size + 1;
	comp->data = malloc(size + 1);

	/* Add the tag */
	comp->data[0] = tag;

	/* Add the BIGNUM */
	gpk_bn2bin(comp->data + 1, bn, size);

	/* printf("TAG 0x%02x, len=%u\n", tag, comp->size); */
}

static int gpk_encode_rsa_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey_rsa *rsa, struct pkdata *p,
		sc_pkcs15_prkey_info_t *info)
{
	if (!rsa->modulus.len || !rsa->exponent.len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"incomplete RSA public key");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Make sure the exponent is 0x10001 because that's
	 * the only exponent supported by GPK4000 and GPK8000 */
	if (rsa->exponent.len != 3
	 || memcmp(rsa->exponent.data, "\001\000\001", 3)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"unsupported RSA exponent");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(p, 0, sizeof(*p));
	p->algo  = SC_ALGORITHM_RSA;
	p->usage = info->usage;
	p->bytes = rsa->modulus.len;
	p->bits  = p->bytes << 3;

	/* Set up the list of public elements */
	gpk_add_bignum(&p->_public, 0x01, &rsa->modulus, 0);
	gpk_add_bignum(&p->_public, 0x07, &rsa->exponent, 0);

	/* Set up the list of private elements */
	if (!rsa->p.len || !rsa->q.len || !rsa->dmp1.len || !rsa->dmq1.len || !rsa->iqmp.len) {
		/* No or incomplete CRT information */
		if (!rsa->d.len) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"incomplete RSA private key");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		gpk_add_bignum(&p->_private, 0x04, &rsa->d, 0);
	} else if (5 * (p->bytes / 2) < 256) {
		/* All CRT elements are stored in one record */
		struct pkcomp	*comp;
		unsigned int	K = p->bytes / 2;
		u8		*crtbuf;

		crtbuf = malloc(5 * K + 1);

		crtbuf[0] = 0x05;
		gpk_bn2bin(crtbuf + 1 + 0 * K, &rsa->p, K);
		gpk_bn2bin(crtbuf + 1 + 1 * K, &rsa->q, K);
		gpk_bn2bin(crtbuf + 1 + 2 * K, &rsa->iqmp, K);
		gpk_bn2bin(crtbuf + 1 + 3 * K, &rsa->dmp1, K);
		gpk_bn2bin(crtbuf + 1 + 4 * K, &rsa->dmq1, K);

		comp = &p->_private.components[p->_private.count++];
		comp->tag  = 0x05;
		comp->size = 5 * K + 1;
		comp->data = crtbuf;
	} else {
		/* CRT elements stored in individual records.
		 * Make sure they're all fixed length even if they're
		 * shorter */
		gpk_add_bignum(&p->_private, 0x51, &rsa->p, p->bytes/2);
		gpk_add_bignum(&p->_private, 0x52, &rsa->q, p->bytes/2);
		gpk_add_bignum(&p->_private, 0x53, &rsa->iqmp, p->bytes/2);
		gpk_add_bignum(&p->_private, 0x54, &rsa->dmp1, p->bytes/2);
		gpk_add_bignum(&p->_private, 0x55, &rsa->dmq1, p->bytes/2);
	}

	return 0;
}

/*
 * Encode a DSA key.
 * Confusingly, the GPK manual says that the GPK8000 can handle
 * DSA with 512 as well as 1024 bits, but all byte sizes shown
 * in the tables are 512 bits only...
 */
static int gpk_encode_dsa_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey_dsa *dsa, struct pkdata *p,
		sc_pkcs15_prkey_info_t *info)
{
	if (!dsa->p.len || !dsa->q.len || !dsa->g.len
	 || !dsa->pub.len || !dsa->priv.len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"incomplete DSA public key");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(p, 0, sizeof(*p));
	p->algo  = SC_ALGORITHM_RSA;
	p->usage = info->usage;
	p->bytes = dsa->q.len;
	p->bits  = dsa->q.len << 3;

	/* Make sure the key is either 512 or 1024 bits */
	if (p->bytes <= 64) {
		p->bits  = 512;
		p->bytes = 64;
	} else if (p->bytes <= 128) {
		p->bits  = 1024;
		p->bytes = 128;
	} else {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"incompatible DSA key size (%u bits)", p->bits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Set up the list of public elements */
	gpk_add_bignum(&p->_public, 0x09, &dsa->p, 0);
	gpk_add_bignum(&p->_public, 0x0a, &dsa->q, 0);
	gpk_add_bignum(&p->_public, 0x0b, &dsa->g, 0);
	gpk_add_bignum(&p->_public, 0x0c, &dsa->pub, 0);

	/* Set up the list of private elements */
	gpk_add_bignum(&p->_private, 0x0d, &dsa->priv, 0);

	return 0;
}

static int
gpk_store_pk(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		sc_file_t *file, struct pkdata *p)
{
	struct sc_context *ctx = p15card->card->ctx;
	size_t	fsize;
	int	r;

	/* Compute length of private/public key parts */
	gpk_compute_publen(&p->_public);
	gpk_compute_privlen(&p->_private);

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Storing pk: %u bits, pub %u bytes, priv %u bytes\n",
			p->bits, p->_public.size, p->_private.size);

	fsize = p->_public.size + p->_private.size;
	if (fsize > file->size)
		return SC_ERROR_FILE_TOO_SMALL;

	/* Put the system record */
#ifndef PK_INIT_IMMEDIATELY
	r = gpk_pkfile_init_public(profile, p15card, file, p->algo,
		       	p->bits, p->usage);
	if (r < 0)
		return r;
#endif

	/* Put the public key elements */
	r = gpk_pkfile_update_public(profile, p15card, &p->_public);
	if (r < 0)
		return r;

	/* Create the private key part */
#ifndef PK_INIT_IMMEDIATELY
	r = gpk_pkfile_init_private(p15card->card, file, p->_private.size);
	if (r < 0)
		return r;
#endif

	/* Now store the private key elements */
	r = gpk_pkfile_update_private(profile, p15card, file, &p->_private);

	return r;
}

static int
gpk_read_rsa_key(sc_card_t *card, struct sc_pkcs15_pubkey_rsa *rsa)
{
	int	n, r;

	/* Read modulus and exponent */
	for (n = 2; ; n++) {
		sc_pkcs15_bignum_t *bn;
		u8		buffer[256];
		size_t		m;

		r = sc_read_record(card, n, buffer, sizeof(buffer),
				SC_RECORD_BY_REC_NR);
		if (r < 1)
			break;

		if (buffer[0] == 0x01)
			bn = &rsa->modulus;
		else if  (buffer[0] == 0x07)
			bn = &rsa->exponent;
		else
			continue;
		bn->len  = r - 1;
		bn->data = malloc(bn->len);
		for (m = 0; m < bn->len; m++)
			bn->data[m] = buffer[bn->len - m];
	}

	return 0;
}

static struct sc_pkcs15init_operations sc_pkcs15init_gpk_operations = {
	gpk_erase_card,
	NULL,				/* init_card     */
	gpk_create_dir,
	NULL,				/* create_domain */
	gpk_select_pin_reference,
	gpk_create_pin,
	NULL,				/* select_key_reference */
	gpk_create_key,
	gpk_store_key,
	gpk_generate_key,
	NULL, NULL,			/* encode private/public key */
	NULL,				/* finalize_card */
	NULL, 				/* delete_object */
	NULL, NULL, NULL, NULL, NULL, 	/* pkcs15init emulation */
	NULL                            /* sanity_check */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_gpk_ops(void)
{
	return &sc_pkcs15init_gpk_operations;
}
