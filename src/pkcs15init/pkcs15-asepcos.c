/*
 * Copyright (c) 2007  Athena Smartcard Solutions Inc.
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

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

/* delete a EF/DF if present. This function does not return an
 * error if the requested file is not present.
 */
static int asepcos_cond_delete(sc_profile_t *pro, sc_pkcs15_card_t *p15card,
	const sc_path_t *path)
{
	int r;
	sc_file_t *tfile = NULL;

	r = sc_select_file(p15card->card, path, &tfile);
	if (r == SC_SUCCESS) {
		r = sc_pkcs15init_authenticate(pro, p15card, tfile, SC_AC_OP_DELETE_SELF);
		sc_file_free(tfile);
		if (r != SC_SUCCESS)
			return r;
		r = sc_delete_file(p15card->card, path);
	} else if (r == SC_ERROR_FILE_NOT_FOUND)
		r = SC_SUCCESS;
	return r;
}

/* checks whether the file with the transport key exists. If existent
 * the transport key is verified and stored in the keycache (as a
 * normal user PIN with the same reference).
 * @param  profile  profile information for this card
 * @param  card     sc_card_t object to use
 * @return SC_SUCCESS on success and an error code otherwise
 */
static int asepcos_check_verify_tpin(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	int r;
	sc_path_t path;

	/* check whether the file with the transport PIN exists */
	sc_format_path("3f000001", &path);
	r = sc_select_file(p15card->card, &path, NULL);
	if (r == SC_SUCCESS) {
		/* try to verify the transport key */
		sc_file_t *tfile = NULL;

		sc_format_path("3f00", &path);
		r = sc_profile_get_file_by_path(profile, sc_get_mf_path(), &tfile);
		if (r != SC_SUCCESS)
			return r;
		/* we need to temporarily disable the SC_CARD_CAP_USE_FCI_AC
		 * flag to trick sc_pkcs15init_authenticate() to use access
		 * information form the profile file */
		p15card->card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
		r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_CRYPTO);
		p15card->card->caps |=  SC_CARD_CAP_USE_FCI_AC;
		sc_file_free(tfile);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "unable to authenticate for 'CRYPTO' operation");
	}
	return SC_SUCCESS;
}

/* erase card: erase all EFs/DFs created by OpenSC
 * @param  profile  the sc_profile_t object with the configurable profile
 *                  information
 * @param  card     the card from which the opensc application should be
 *                  erased.
 * @return SC_SUCCESS on success and an error code otherwise
 */
static int asepcos_erase(struct sc_profile *profile, sc_pkcs15_card_t *p15card)
{
	int r;
	sc_path_t path;

	/* TODO: - only remove the OpenSC entry in EF(DIR)
	 *       - use EF(DIR) to get the DF of the OpenSC
	 *         pkcs15 application.
	 */
	/* Check wether a transport exists and verify it if present */

	p15card->opts.use_pin_cache = 1;
	r = asepcos_check_verify_tpin(profile, p15card);
	if (r != SC_SUCCESS)
		return r;
	/* EF(DIR) */
	sc_format_path("3f002f00", &path);
	r = asepcos_cond_delete(profile, p15card, &path);
	if (r != SC_SUCCESS)
		return r;
	/* DF(PKCS15) */
	sc_format_path("3f005015", &path);
	r = asepcos_cond_delete(profile, p15card, &path);
	if (r != SC_SUCCESS)
		return r;

	return SC_SUCCESS;
}

/* create application DF
 * @param  profile  sc_profile_t object with the configurable profile
 *                  information
 * @param  cardd    sc_card_t object to be used
 * @param  df       sc_file_t with the application DF to create
 * @return SC_SUCCESS on success and an error value otherwise
 */
static int asepcos_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df)
{
	int r;
	static const u8 pa_acl[] = {0x80,0x01,0x5f,0x90,0x00};
	sc_file_t *tfile;
	sc_context_t *ctx = p15card->card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
	/* Check wether a transport exists and verify it if present */
	r = asepcos_check_verify_tpin(profile, p15card);
	if (r != SC_SUCCESS)
		return r;
	/* As we don't know whether or not a SO-PIN is used to protect the AC
	 * in the application DF we set the preliminary security attributes
	 * of the DF(PKCS15) to allow everything. Once a SO-PIN is set
	 * we tighten security attributes to values specified in the profile.
	 */
	sc_file_dup(&tfile, df);
	/* we use a separate copy of the sc_file_t object so we don't
	 * override the permissions specified in the profile */
	if (tfile == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	r = sc_file_set_sec_attr(tfile, pa_acl, sizeof(pa_acl));
	if (r != SC_SUCCESS) {
		sc_file_free(tfile);
		return r;
	}
	/* create application DF */
	r = sc_pkcs15init_create_file(profile, p15card, tfile);
	sc_file_free(tfile);
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
}


/* select PIN reference: do nothing special, the real PIN reference if
 * determined when the PIN is created. This is just helper function to
 * determine the next best file id of the PIN file.
 */
static int asepcos_select_pin_reference(sc_profile_t *profile,
		sc_pkcs15_card_t *p15card, sc_pkcs15_auth_info_t *auth_info)
{
	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		return SC_SUCCESS;
	if (auth_info->attrs.pin.reference <= 0)
		auth_info->attrs.pin.reference = 1;
	/* as we want to use <fileid of PIN> + 1 for the PUK we need to
	 * ensure that all references are odd => if the reference is
	 * even add one */
	if ((auth_info->attrs.pin.reference & 1) == 0)
		auth_info->attrs.pin.reference++;
        return SC_SUCCESS;
}

/* asepcos_pinid_to_akn: returns the AKN of a PIN EF
 * This functions calls SELECT FILE and extracts the AKN from the
 * proprietary FCP attributes.
 * @param  card    sc_card_t object to use
 * @param  fileid  IN  file id of the PIN file
 * @param  akn     OUT the AKN of the PIN
 * @return SC_SUCCESS on success and an error code otherwise
 */
static int asepcos_pinid_to_akn(sc_card_t *card, int fileid, int *akn)
{
	int r;
	u8  fid[2];
	sc_path_t path;
	sc_file_t *nfile = NULL;

	fid[0] = (fileid >> 8) & 0xff;
	fid[1] = fileid & 0xff;
	r = sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, 0);
	if (r != SC_SUCCESS)
		return r;
	r = sc_select_file(card, &path, &nfile);
	if (r != SC_SUCCESS)
		return r;
	if (nfile->prop_attr == NULL || nfile->prop_attr_len != 11) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to determine AKN");
		sc_file_free(nfile);
		return SC_ERROR_INTERNAL;
	}
	*akn = nfile->prop_attr[10];
	sc_file_free(nfile);
	return SC_SUCCESS;
}

static int asepcos_do_store_pin(sc_profile_t *profile, sc_card_t *card,
	sc_pkcs15_auth_info_t *auth_info, const u8* pin, size_t pinlen,
	int puk, int pinid)
{
	sc_file_t *nfile = NULL;
	u8  buf[64], sbuf[64], *p = buf, *q = sbuf;
	int r, akn;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	/* outter tag */
	*p++ = 0x85;
	p++;
	/* as a file id for pin with use 0x00:<key id> */
	*p++ = (pinid >> 8) & 0xff;
	*p++ = pinid & 0xff;
	/* pin length */
	if (pinlen < 4 || pinlen > 16) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid PIN length");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	*p++ = 0x00;
	*p++ = pinlen & 0xff;
	/* max tries */
	*p++ = auth_info->tries_left & 0xff;
	/* algorithm id and key key usage and padding bytes */
	*p++ = 0x00;
	*p++ = 0x00;
	/* key attributes (SO PIN) */
	*p++ = 0x00;
	/* the PIN */
	*p++ = 0x81;
	*p++ = pinlen & 0xff;
	memcpy(p, pin, pinlen);
	p += pinlen;
	/* set outer length */
	buf[1] = p - buf - 2;

	nfile = sc_file_new();
	if (nfile == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	nfile->type = SC_FILE_TYPE_INTERNAL_EF;
	nfile->id   = pinid & 0xffff;
	r = sc_file_set_prop_attr(nfile, buf, p - buf);
	if (r != SC_SUCCESS) {
		sc_file_free(nfile);
		return r;
	}

	/* set security attributes */
	*q++ = 0x80;
	*q++ = 0x01;
	*q++ = 0x92;
	*q++ = 0xa0;
	q++;
	*q++ = 0x89;
	*q++ = 0x03;
	*q++ = (pinid >> 16) & 0xff;
	*q++ = (pinid >> 8 ) & 0xff;
	*q++ = pinid & 0xff;
	if (puk != 0) {
		*q++ = 0x89;
		*q++ = 0x03;
		*q++ = (puk >> 16) & 0xff;
		*q++ = (puk >> 8 ) & 0xff;
		*q++ = puk & 0xff;
	}
	sbuf[4] = q - sbuf - 5;
	/* we need to set the security attributes separately as PIN itself
	 * is used to protect the UPDATE access permission.
	 */
	r = sc_file_set_sec_attr(nfile, sbuf, q - sbuf);
	if (r != SC_SUCCESS) {
		sc_file_free(nfile);
		return r;
	}

	r = sc_create_file(card, nfile);
	sc_file_free(nfile);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to create PIN file");
		return r;
	}
	/* get AKN of the newly created PIN  */
	r = asepcos_pinid_to_akn(card, pinid, &akn);
	if (r != SC_SUCCESS)
		return r;
	/* use the AKN as reference */
	auth_info->attrs.pin.reference = akn;
	/* set the correct PIN length */
	auth_info->attrs.pin.min_length    = 4;
	auth_info->attrs.pin.stored_length = pinlen;
	auth_info->attrs.pin.max_length    = 16;

	return r;
}

/* simple function to detect whether or not the "onepin" profile is used
 * (copied from pkcs15-starcos.c).
 */
static int have_onepin(sc_profile_t *profile)
{
        sc_pkcs15_auth_info_t sopin;

        sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &sopin);

        if (!(sopin.attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
                return 1;
        else
                return 0;
}


/* create PIN and, if specified, PUK files
 * @param  profile  profile information for this card
 * @param  card     sc_card_t object to use
 * @param  pin_obj  sc_pkcs15_object_t for the PIN
 * @param  pin      PIN value
 * @param  len_len  PIN length
 * @param  puk      PUK value (optional)
 * @param  puk_len  PUK length (optional)
 * @return SC_SUCCESS on success and an error code otherwise
 */
static int asepcos_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df, sc_pkcs15_object_t *pin_obj,
	const u8 *pin, size_t pin_len, const u8 *puk, size_t puk_len)
{
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	struct sc_card *card = p15card->card;
	int       r, pid, puk_id;
	sc_path_t tpath = df->path;
	sc_file_t *tfile = NULL;
	sc_context_t *ctx = p15card->card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
	if (!pin || !pin_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
        	return SC_ERROR_OBJECT_NOT_VALID;

	pid = (auth_info->attrs.pin.reference & 0xff) | (((tpath.len >> 1) - 1) << 16);

	/* get the ACL of the application DF */
	r = sc_select_file(card, &df->path, &tfile);
	if (r != SC_SUCCESS)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
	/* verify the PIN protecting the CREATE acl (if necessary) */
	r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_CREATE);
	sc_file_free(tfile);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to create PIN file, insufficent rights");
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
	}

	do {
		sc_path_t pin_path;
		memset(&pin_path, 0, sizeof(sc_path_t));
		pin_path.type = SC_PATH_TYPE_FILE_ID;
		/* XXX: check the pkcs15 structure whether this file id
		 * is already used */
		r = sc_append_file_id(&pin_path, pid & 0xff);
		if (r != SC_SUCCESS)
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		r = sc_select_file(card, &pin_path, NULL);
		if (r == SC_SUCCESS)
			pid += 2;
		else if (r != SC_ERROR_FILE_NOT_FOUND) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "error selecting PIN file");
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		}
	} while (r != SC_ERROR_FILE_NOT_FOUND);

	if (puk != NULL && puk_len != 0) {
		/* Create PUK (if specified). Note: we need to create the PUK
		 * the PIN as the PUK fileid is used in the PIN acl.
		 */
		struct sc_pkcs15_auth_info puk_ainfo;

		if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PUK, &puk_ainfo);
		else
			sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &puk_ainfo);

		/* If a PUK we use "file id of the PIN" + 1  as the file id
		 * of the PUK.
		 */
		puk_id = pid + 1;
		r = asepcos_do_store_pin(profile, card, &puk_ainfo, puk, puk_len, 0, puk_id);
		if (r != SC_SUCCESS)
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
	} else
		puk_id = 0;

	r = asepcos_do_store_pin(profile, card, auth_info, pin, pin_len, puk_id, pid);
	if (r != SC_SUCCESS)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);

#if 1
	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN ||
	    (have_onepin(profile) && pid == 0x010001)) {
		sc_cardctl_asepcos_activate_file_t st;
		/* Once the SO PIN or ,in case of the "onepin" profile", the
		 * first USER PIN has been set we can tighten the ACLs of
		 * the application DF.
		 */
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "finalizing application DF");
		r = sc_select_file(card, &df->path, NULL);
		if (r != SC_SUCCESS)
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		/* remove symbolic references from the ACLs */
		r = sc_pkcs15init_fixup_file(profile, p15card, df);
		if (r != SC_SUCCESS)
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		r = sc_card_ctl(card, SC_CARDCTL_ASEPCOS_SET_SATTR, df);
		if (r != SC_SUCCESS) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to change the security attributes");
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		}
		/* finally activate the application DF (fix ACLs) */
		/* 1. select MF */
		r = sc_select_file(card, sc_get_mf_path(), NULL);
		if (r != SC_SUCCESS)
			return r;
		/* 2. activate the application DF */
		st.fileid = df->id;
		st.is_ef  = 0;
		r = sc_card_ctl(card, SC_CARDCTL_ASEPCOS_ACTIVATE_FILE, &st);
		if (r != SC_SUCCESS) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to activate DF");
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
		}
	}
#endif

#ifdef asepcos_USE_PIN_PATH
	/* using the real path to the PIN file would be nice but unfortunately
	 * it currently causes some problems with the keycache code
	 */
	r = sc_append_file_id(&tpath, pid & 0xff);
	if (r != SC_SUCCESS)
		return r;
	auth_info->path = tpath;
#endif
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
}

/* internal wrapper for sc_pkcs15init_authenticate()
 * @param  profile  information for this card
 * @param  card     sc_card_t object to use
 * @param  path     path to the EF/DF for which the credential is required
 * @param  op       the required access method
 * @return SC_SUCCESS on success and an error code otherwise
 */
static int asepcos_do_authenticate(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	const sc_path_t *path, int op)
{
	int r;
	sc_file_t *prkey = NULL;
	r = sc_profile_get_file_by_path(profile, path, &prkey);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to find file in profile");
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, prkey, op);
	sc_file_free(prkey);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to authenticate");
		return r;
	}
	return SC_SUCCESS;
}


#define SET_TLV_LENGTH(p,l)	do { \
					if ((l) < 128) \
						*(p)++ = (l) & 0x7f; \
					else if ((l) < 256) { \
						*(p)++ = 0x81; \
						*(p)++ = (l) & 0xff; \
					} else { \
						*(p)++ = 0x82; \
						*(p)++ = ((l) >> 8 ) & 0xff; \
						*(p)++ = (l) & 0xff; \
					} \
				} while(0)

static int asepcos_do_create_key(sc_card_t *card, size_t ksize, int fileid,
	const u8 *keydata, size_t kdlen)
{
	int       r;
	size_t    len;
	sc_file_t *nfile = NULL;
	u8        buf[1024], *p = buf;

	if (sizeof(buf) < kdlen + 12)
		return SC_ERROR_BUFFER_TOO_SMALL;

	*p++ = 0x85;
	*p++ = 0x82;
	p   += 2;
	/* file id */
	*p++ = (fileid >> 8) & 0xff;
	*p++ = fileid & 0xff;
	/* key size */
	*p++ = (ksize >> 8) & 0xff;
	*p++ = ksize & 0xff;
	/* max attempts */
	*p++ = 0x03;
	/* key attributes */
	*p++ = 0xc0;
	*p++ = 0x80;
	*p++ = 0x00;
	/* key parts */
	memcpy(p, keydata, kdlen);
	p   += kdlen;
	/* set outer TLV length */
	len = p - buf - 4;
	buf[2] = (len >> 8) & 0xff;
	buf[3] = len & 0xff;

	nfile = sc_file_new();
	if (nfile == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	nfile->type = SC_FILE_TYPE_INTERNAL_EF;
	nfile->id   = fileid & 0xffff;
	r = sc_file_set_prop_attr(nfile, buf, p - buf);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to set key prop. attributes");
		sc_file_free(nfile);
		return r;
	}

	r = sc_create_file(card, nfile);
	sc_file_free(nfile);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to create key file");
		return r;
	}
	return r;
}

/* creates a key file
 */
static int asepcos_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj)
{
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	int       r, len;
	u8        buf[512], *p = buf;
	size_t    blen = kinfo->modulus_length / 8;
	int       afileid = -1,
	          fileid = (kinfo->path.value[kinfo->path.len-2]) << 8 |
	                   kinfo->path.value[kinfo->path.len-1];

	if (obj->auth_id.len != 0) {
		/* the key is protected by a PIN */
		sc_pkcs15_object_t *pin;
		struct sc_pkcs15_auth_info *auth_info;
		sc_cardctl_asepcos_akn2fileid_t st;

		r = sc_pkcs15_find_pin_by_auth_id(p15card, &obj->auth_id, &pin);
		if (r != SC_SUCCESS) {
			sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to determine reference for the PIN");
			return r;
		}

		auth_info = (struct sc_pkcs15_auth_info *)pin->data;

		st.akn = auth_info->attrs.pin.reference;
		r = sc_card_ctl(p15card->card, SC_CARDCTL_ASEPCOS_AKN2FILEID, &st);
		if (r != SC_SUCCESS) {
			sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to determine file id of the PIN");
			return r;
		}
		afileid = st.fileid;
	}

	/* authenticate if necessary */
	r = asepcos_do_authenticate(profile, p15card, &profile->df_info->file->path, SC_AC_OP_CREATE);
	if (r != SC_SUCCESS)
		return r;

	/* first: create private key (file id = 0x0100 | <ref & 0xff>) */
	/* key parts */
	*p++ = 0xc1;
	*p++ = 0x82;
	p   += 2;
	/* public exponent */
	*p++ = 0x90;
	SET_TLV_LENGTH(p, 3);
	memset(p, 0xff, 3);
	p   += 3;
	/* primes p, q */
	*p++ = 0x93;
	SET_TLV_LENGTH(p, blen);
	memset(p, 0xff, blen);
	p += blen;

	/* key TLV length */
	len = p - buf - 4;
	buf[2] = (len >> 8) & 0xff;
	buf[3] = len & 0xff;

	/* security attributes */
	*p++ = 0x80;
	*p++ = 0x01;
	*p++ = 0xa2;		/* compute signature and generate key pair */
	if (afileid > 0) {
		*p++ = 0xa0;
		*p++ = 0x05;
		*p++ = 0x89;
		*p++ = 0x03;
		*p++ = (afileid >> 16) & 0xff;
		*p++ = (afileid >> 8 ) & 0xff;
		*p++ = afileid & 0xff;
	} else {
		*p++ = 0x90;
		*p++ = 0x00;
	}

	r = asepcos_do_create_key(p15card->card, kinfo->modulus_length, fileid, buf, p - buf);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to create private key file");
		return r;
	}

	kinfo->key_reference = fileid & 0xFF;
	return r;
}

/* stores a rsa private key in a internal EF
 */
static int asepcos_do_store_rsa_key(sc_pkcs15_card_t *p15card, sc_profile_t *profile,
	sc_pkcs15_object_t *obj, sc_pkcs15_prkey_info_t *kinfo,
	struct sc_pkcs15_prkey_rsa *key)
{
	int       r, klen;
	u8        buf[512], *p = buf;
	sc_path_t tpath;
	sc_cardctl_asepcos_change_key_t	ckdata;

	/* authenticate if necessary */
	if (obj->auth_id.len != 0) {
		r = asepcos_do_authenticate(profile, p15card, &kinfo->path, SC_AC_OP_UPDATE);
		if (r != SC_SUCCESS)
			return r;
	}

	/* select the rsa private key */
	memset(&tpath, 0, sizeof(sc_path_t));
	tpath.type = SC_PATH_TYPE_FILE_ID;
	tpath.len  = 2;
	tpath.value[0] = kinfo->path.value[kinfo->path.len-2];
	tpath.value[1] = kinfo->path.value[kinfo->path.len-1];
	r = sc_select_file(p15card->card, &tpath, NULL);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to select rsa key file");
		return r;
	}

	/* store key parts in buffer */
	*p++ = 0xc1;
	*p++ = 0x82;
	p   += 2;
	/* public exponent */
	*p++ = 0x90;
	SET_TLV_LENGTH(p, key->exponent.len);
	memcpy(p, key->exponent.data, key->exponent.len);
	p   += key->exponent.len;
	/* primes p, q */
	*p++ = 0x93;
	SET_TLV_LENGTH(p, (key->p.len + key->q.len));
	memcpy(p, key->p.data, key->p.len);
	p += key->p.len;
	memcpy(p, key->q.data, key->q.len);
	p += key->q.len;

	/* key TLV length */
	klen = p - buf - 4;
	buf[2] = (klen >> 8) & 0xff;
	buf[3] = klen & 0xff;

	ckdata.data    = buf;
	ckdata.datalen = p - buf;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_ASEPCOS_CHANGE_KEY, &ckdata);
	if (r != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "unable to change key data");
		return r;
	}

	return SC_SUCCESS;
}

/* Stores an external (RSA) on the card.
 * @param  profile  profile information for this card
 * @param  card     sc_card_t object to use
 * @param  obj      sc_pkcs15_object_t object with pkcs15 information
 * @param  key      the private key
 * @return SC_SUCCESS on success and an error code otherwise
 */
static int asepcos_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "only RSA is currently supported");
		return SC_ERROR_NOT_SUPPORTED;
	}

	return asepcos_do_store_rsa_key(p15card, profile, obj, kinfo, &key->u.rsa);
}

/* Generates a new (RSA) key pair using an existing key file.
 * @param  profile  IN profile information for this card
 * @param  card     IN sc_card_t object to use
 * @param  obj      IN sc_pkcs15_object_t object with pkcs15 information
 * @param  pukkey   OUT the newly created public key
 * @return SC_SUCCESS on success and an error code otherwise
 */
static int asepcos_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	int r;
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	sc_card_t *card = p15card->card;
	sc_apdu_t apdu;
	sc_path_t tpath;
	u8  rbuf[SC_MAX_APDU_BUFFER_SIZE],
	    sbuf[SC_MAX_APDU_BUFFER_SIZE];

	/* authenticate if necessary */
	r = asepcos_do_authenticate(profile, p15card, &kinfo->path, SC_AC_OP_UPDATE);
	if (r != SC_SUCCESS)
		return r;

	/* select the rsa private key */
	memset(&tpath, 0, sizeof(sc_path_t));
	tpath.type = SC_PATH_TYPE_FILE_ID;
	tpath.len  = 2;
	tpath.value[0] = kinfo->path.value[kinfo->path.len-2];
	tpath.value[1] = kinfo->path.value[kinfo->path.len-1];
	r = sc_select_file(card, &tpath, NULL);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to select rsa key file");
		return r;
	}

	sbuf[0] = 0x01;
	sbuf[1] = 0x00;
	sbuf[2] = 0x01;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x46, 0x00, 0x00);
	apdu.lc      = 3;
	apdu.datalen = 3;
	apdu.data    = sbuf;
	apdu.le      = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp    = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "error creating key");
		return SC_ERROR_INTERNAL;
	}

	pubkey->u.rsa.modulus.len  = apdu.resplen;
	pubkey->u.rsa.modulus.data = malloc(apdu.resplen);
	if (pubkey->u.rsa.modulus.data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(pubkey->u.rsa.modulus.data, apdu.resp, apdu.resplen);

	pubkey->u.rsa.exponent.len  = 3;
	pubkey->u.rsa.exponent.data = malloc(3);
	if (pubkey->u.rsa.exponent.data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(pubkey->u.rsa.exponent.data, sbuf, 3);

	kinfo->key_reference = tpath.value[1];
	return SC_SUCCESS;
}


static struct sc_pkcs15init_operations sc_pkcs15init_asepcos_operations = {
	asepcos_erase,
	NULL,				/* init_card */
	asepcos_create_dir,
	NULL,				/* create_domain */
	asepcos_select_pin_reference,
	asepcos_create_pin,
	NULL,				/* select key reference */
	asepcos_create_key,
	asepcos_store_key,
	asepcos_generate_key,
	NULL, NULL, 			/* encode private/public key */
	NULL,				/* finalize_card */
	NULL, 				/* delete_object */
	NULL, NULL, NULL, NULL, NULL, 	/* pkcs15init emulation */
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations * sc_pkcs15init_get_asepcos_ops(void)
{
	return &sc_pkcs15init_asepcos_operations;
}
