/*
 * Starcos SPK 2.3 specific operation for PKCS15 initialization
 *
 * Copyright (C) 2004 Nils Larsch <larsch@trustcenter.de>
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

#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "pkcs15-init.h"
#include "profile.h"

#define STARCOS_AC_NEVER	0x5f
#define STARCOS_AC_ALWAYS	0x9f

#define STARCOS_SOPIN_GID	0x01
#define STARCOS_SOPIN_STATE	0x01
#define STARCOS_SOPIN_GAC	0x01
#define STARCOS_SOPIN_LID	0x81
#define STARCOS_SOPIN_LAC	0x11;

static int starcos_finalize_card(sc_card_t *card);

static int starcos_erase_card(struct sc_profile *pro, sc_pkcs15_card_t *p15card)
{
	return sc_card_ctl(p15card->card, SC_CARDCTL_ERASE_CARD, NULL);
}

static u8 get_so_ac(const sc_file_t *file, unsigned int op,
	const sc_pkcs15_auth_info_t *auth, unsigned int def,
	unsigned int need_global)
{
	int is_global = 1;
	const sc_acl_entry_t *acl;

	if (auth->attrs.pin.flags & SC_PKCS15_PIN_FLAG_LOCAL)
		is_global = 0;
	if (!is_global && need_global)
		return def & 0xff;
	acl = sc_file_get_acl_entry(file, op);
	if (acl->method == SC_AC_NONE)
		return STARCOS_AC_ALWAYS;
	else if (acl->method == SC_AC_NEVER)
		return STARCOS_AC_NEVER;
	else if (acl->method == SC_AC_SYMBOLIC) {
		if (is_global)
			return STARCOS_SOPIN_GAC;
		else
			return STARCOS_SOPIN_LAC;
	} else
		return def;
}


static int starcos_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	struct sc_card *card = p15card->card;
	static const u8 key[]  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	int		ret;
	sc_starcos_create_data  mf_data, ipf_data;
	sc_file_t	*mf_file, *isf_file, *ipf_file;
	sc_path_t	tpath;
	u8		*p = mf_data.data.mf.header, tmp = 0;
	sc_pkcs15_auth_info_t sopin;

	/* test if we already have a MF */
	memset(&tpath, 0, sizeof(sc_path_t));
	tpath.value[0] = 0x3f;
	tpath.value[1] = 0x00;
	tpath.len      = 2;
	tpath.type     = SC_PATH_TYPE_PATH;
	ret = sc_select_file(card, &tpath, NULL);
	if (ret == SC_SUCCESS)
		/* we already have a MF => return OK */
		return ret;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &sopin);

	/* get mf profile */
	ret = sc_profile_get_file(profile, "MF", &mf_file);
	if (ret < 0)
		return ret;
	/* get size of the isf */
	ret = sc_profile_get_file(profile, "mf_isf", &isf_file);
	if (ret < 0) {
		sc_file_free(mf_file);
		return ret;
	}
	mf_data.type = SC_STARCOS_MF_DATA;
	memcpy(p, key, 8);
	p   += 8;
	*p++ = (mf_file->size  >> 8) & 0xff;
	*p++ = mf_file->size  & 0xff;
	*p++ = (isf_file->size >> 8) & 0xff;
	*p++ = isf_file->size & 0xff;
	/* AC CREATE EF   */
	*p++ = get_so_ac(mf_file, SC_AC_OP_CREATE, &sopin, STARCOS_AC_ALWAYS, 1);
	/* AC CREATE KEY  */
	*p++ = get_so_ac(isf_file, SC_AC_OP_WRITE, &sopin, STARCOS_AC_NEVER,  1);
	/* AC CREATE DF   */
	*p++ = get_so_ac(mf_file, SC_AC_OP_CREATE, &sopin, STARCOS_AC_ALWAYS, 1);
	/* AC REGISTER DF */
	*p++ = get_so_ac(mf_file, SC_AC_OP_CREATE, &sopin, STARCOS_AC_ALWAYS, 1);
	*p++ = 0x00;	/* SM CR:  no */
	*p++ = 0x00;	/* SM EF:  no */
	*p = 0x00;	/* SM ISF: no */
	sc_file_free(mf_file);
	sc_file_free(isf_file);
	/* call CREATE MF  */
	ret = sc_card_ctl(card, SC_CARDCTL_STARCOS_CREATE_FILE, &mf_data);
	if (ret != SC_SUCCESS)
		return ret;
	/* create IPF */
	/* get size of the ipf */
	ret = sc_profile_get_file(profile, "mf_ipf", &ipf_file);
	if (ret < 0)
		return ret;
	ipf_data.type = SC_STARCOS_EF_DATA;
	p = ipf_data.data.ef.header;
	*p++ = (ipf_file->id >> 8) & 0xff;
	*p++ = ipf_file->id & 0xff;
	*p++ = STARCOS_AC_ALWAYS;	/* AC READ: always */
	/* AC WRITE IPF */
	*p++ = get_so_ac(ipf_file,SC_AC_OP_CREATE, &sopin, STARCOS_AC_ALWAYS, 1);
	*p++ = STARCOS_AC_NEVER;	/* AC ERASE    */
	*p++ = STARCOS_AC_NEVER;	/* AC LOCK     */
	*p++ = STARCOS_AC_NEVER;	/* AC UNLOCK   */
	*p++ = STARCOS_AC_NEVER;	/* AC INCREASE */
	*p++ = STARCOS_AC_NEVER;	/* AC_DECREASE */
	*p++ = STARCOS_AC_NEVER;	/* RFU         */
	*p++ = STARCOS_AC_NEVER;	/* RFU         */
	*p++ = 0x00;			/* SM          */
	*p++ = 0x00;			/* SID         */
	*p++ = 0xA1;			/* IPF         */
	*p++ = (ipf_file->size >> 8) & 0xff;
	*p = ipf_file->size & 0xff;
	ret  = sc_card_ctl(card, SC_CARDCTL_STARCOS_CREATE_FILE, &ipf_data);
	if (ret != SC_SUCCESS) {
		free(ipf_file);
		return ret;
	}
	/* init IPF */
	ret = sc_select_file(card, &ipf_file->path, NULL);
	sc_file_free(ipf_file);
	if (ret < 0)
		return ret;
	ret = sc_update_binary(card, 0, &tmp, 1, 0);
	if (ret < 0)
		return ret;
	return SC_SUCCESS;
}

static int starcos_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df)
{
	struct sc_card *card = p15card->card;
	int             ret;
	sc_starcos_create_data df_data, ipf_data;
	sc_file_t	*isf_file, *ipf_file;
	u8		*p = df_data.data.df.header, tmp = 0;
	sc_pkcs15_auth_info_t sopin;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &sopin);

	/* get p15_isf profile */
	ret = sc_profile_get_file(profile, "p15_isf", &isf_file);
	if (ret < 0)
		return ret;

	df_data.type = SC_STARCOS_DF_DATA;
	memset(p, 0, 25);
	*p++ = (df->id >> 8) & 0xff;
	*p++ = df->id & 0xff;
	*p++ = df->namelen & 0xff;
	memcpy(p, df->name, (u8) df->namelen);
	p   += 16;
	*p++ = (isf_file->size >> 8) & 0xff;
	*p++ = isf_file->size & 0xff;
	/* AC CREATE EF  */
	*p++ = get_so_ac(df, SC_AC_OP_CREATE, &sopin, STARCOS_AC_ALWAYS, 0);
	/* AC CREATE KEY */
	*p++ = get_so_ac(isf_file, SC_AC_OP_WRITE, &sopin, STARCOS_AC_NEVER, 0);
	*p++ = 0x00;		/* SM EF:  no */
	*p = 0x00;		/* SM ISF: no */
	df_data.data.df.size[0] = (df->size >> 8) & 0xff;
	df_data.data.df.size[1] = df->size & 0xff;
	sc_file_free(isf_file);
	/* call CREATE DF  */
	ret = sc_card_ctl(card, SC_CARDCTL_STARCOS_CREATE_FILE, &df_data);
	if (ret != SC_SUCCESS)
		return ret;
	/* create IPF */
	ret = sc_select_file(card, &df->path, NULL);
	if (ret != SC_SUCCESS)
		return ret;
	ret = sc_profile_get_file(profile, "p15_ipf", &ipf_file);
	if (ret < 0)
		return ret;
	ipf_data.type = SC_STARCOS_EF_DATA;
	p = ipf_data.data.ef.header;
	*p++ = (ipf_file->id >> 8) & 0xff;
	*p++ = ipf_file->id & 0xff;
	*p++ = STARCOS_AC_ALWAYS;	/* AC READ     */
	/* AC WRITE IPF */
	*p++ = get_so_ac(ipf_file, SC_AC_OP_CREATE, &sopin, STARCOS_AC_ALWAYS, 0);
	*p++ = STARCOS_AC_NEVER;	/* AC ERASE    */
	*p++ = STARCOS_AC_NEVER;	/* AC LOCK     */
	*p++ = STARCOS_AC_NEVER;	/* AC UNLOCK   */
	*p++ = STARCOS_AC_NEVER;	/* AC INCREASE */
	*p++ = STARCOS_AC_NEVER;	/* AC_DECREASE */
	*p++ = STARCOS_AC_NEVER;	/* RFU         */
	*p++ = STARCOS_AC_NEVER;	/* RFU         */
	*p++ = 0x00;			/* SM          */
	*p++ = 0x00;			/* SID         */
	*p++ = 0xA1;			/* IPF         */
	*p++ = (ipf_file->size >> 8) & 0xff;
	*p = ipf_file->size & 0xff;
	ret  = sc_card_ctl(card, SC_CARDCTL_STARCOS_CREATE_FILE, &ipf_data);
	if (ret != SC_SUCCESS) {
		free(ipf_file);
		return ret;
	}
	/* init IPF */
	ret = sc_select_file(card, &ipf_file->path, NULL);
	sc_file_free(ipf_file);
	if (ret < 0)
		return ret;
	ret = sc_update_binary(card, 0, &tmp, 1, 0);
	if (ret < 0)
		return ret;
	return SC_SUCCESS;
}

static int have_onepin(sc_profile_t *profile)
{
	sc_pkcs15_auth_info_t sopin;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &sopin);

	if (!(sopin.attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
		return 1;
	else
		return 0;
}

/* range of possible key ids for pins (note: the key id of the puk
 * is the key id of the pin plus one)
 */
#define STARCOS_MIN_LPIN_ID	0x83
#define STARCOS_MAX_LPIN_ID	0x8f
#define STARCOS_MIN_GPIN_ID	0x03
#define STARCOS_MAX_GPIN_ID	0x0f
static int starcos_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_auth_info_t *auth_info)
{
	int tmp;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	tmp = auth_info->attrs.pin.reference;

	if (have_onepin(profile)) {
		/* we have the onepin profile */
		auth_info->attrs.pin.reference = STARCOS_SOPIN_GID;
		return SC_SUCCESS;
	}

	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_LOCAL) {
		/* use local KID */
		/* SO-pin */
		if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			tmp = STARCOS_SOPIN_LID;
		else {
			if (tmp < STARCOS_MIN_LPIN_ID)
				tmp = STARCOS_MIN_LPIN_ID;
			if (!(tmp & 0x01))
				/* odd KIDs for PINs and even KIDs for PUKs */
				tmp++;
			if (tmp > STARCOS_MAX_LPIN_ID)
				return SC_ERROR_TOO_MANY_OBJECTS;
		}
	} else {
		/* use global KID */
		/* SO-pin */
		if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			tmp = STARCOS_SOPIN_GID;
		else {
			if (tmp < STARCOS_MIN_GPIN_ID)
				tmp = STARCOS_MIN_GPIN_ID;
			if (!(tmp & 0x01))
				/* odd KIDs for PINs and even KIDs for PUKs */
			tmp++;
			if (tmp > STARCOS_MAX_GPIN_ID)
				return SC_ERROR_TOO_MANY_OBJECTS;
		}
	}
	auth_info->attrs.pin.reference = tmp;

	return SC_SUCCESS;
}

/* About STARCOS_PINID2STATE
 * Starcos SPK 2.3 uses a state machine to control the access
 * to files or keys. This means that the access to a certain
 * object is granted if the current state (of either the current
 * DF or the MF) is =, <, >= or != a specified state (see
 * Starcos S 2.1 manual). To map the pkcs15 access control model
 *(one object is protected by one pin etc.) to the Starcos S 2.1
 * model the following approach is used:
 * the pin with the key id 3 (or 0x81) sets the global (or local)
 * state to 15 (note: 16 is the lowest initial state).
 * the pin with the key id 4 (or 0x82) is reserved for the PUK
 * the pin with the key id 5 (or 0x83) sets the global (or local)
 * state to 14.
 * ...
 * Note: the key id 1 and 2 (or local 0x81 and 0x82) is used for
 * the 'SO-pin' which sets the state to 0x01.
 * XXX: some card operations, like terminate card usage are only
 * possible in state 0x00
 *
 * Nils
 */
#define STARCOS_PINID2STATE(a)	(((a) == STARCOS_SOPIN_GID) ? STARCOS_SOPIN_STATE : (0x0f - ((0x0f & (a)) >> 1)))

static int starcos_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df, sc_pkcs15_object_t *pin_obj,
	const unsigned char *pin, size_t pin_len,
	const unsigned char *puk, size_t puk_len)
{
	struct sc_card *card = p15card->card;
	int	r, is_local, pin_id, tmp, need_finalize = 0;
	size_t	akd;
	sc_file_t            *tfile;
	const sc_acl_entry_t *acl_entry;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	sc_starcos_wkey_data  pin_d, puk_d;
	u8		      tpin[8];

	if (!pin || !pin_len || pin_len > 8)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	is_local = 0x80 & auth_info->attrs.pin.reference;
	if (is_local)
		r = sc_select_file(card, &df->path, NULL);
	else
		r = sc_select_file(card, &profile->mf_info->file->path, NULL);
	if (r < 0)
		return r;
	/* get and verify sopin if necessary */
	r = sc_profile_get_file(profile, "p15_isf", &tfile);
        if (r < 0)
                return r;
	acl_entry = sc_file_get_acl_entry(tfile, SC_AC_OP_WRITE);
	if (acl_entry->method != SC_AC_NONE) {
		if ((auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN) || have_onepin(profile))
			need_finalize = 1;
		else
			r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_WRITE);
	}
	sc_file_free(tfile);
	if (r < 0)
		return r;

	/* pad pin with 0 */
	memset(tpin, 0, 8);
	memcpy(tpin, pin, pin_len);

	/* write PIN */
	tmp    = auth_info->tries_left;
	pin_id = auth_info->attrs.pin.reference;

	pin_d.mode    = 0;	/* install */
	pin_d.kid     = (u8) pin_id;
	pin_d.key     = tpin;
	pin_d.key_len = 8;
	pin_d.key_header[0]  = pin_d.kid;
	pin_d.key_header[1]  = 0;
	pin_d.key_header[2]  = 8;
	pin_d.key_header[3]  = STARCOS_AC_ALWAYS;
	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		pin_d.key_header[4] = STARCOS_SOPIN_STATE;
	else
		pin_d.key_header[4] = STARCOS_PINID2STATE(pin_id);
	pin_d.key_header[5]  = STARCOS_AC_ALWAYS;
	pin_d.key_header[6]  = ((0x0f & tmp) << 4) | (0x0f & tmp);
	pin_d.key_header[7]  = 0x00;
	pin_d.key_header[8]  = 0x00;
	akd = auth_info->attrs.pin.min_length;
	if (akd < 4)
		akd = 4;
	if (akd > 8)
		akd = 8;
	akd--;
	akd |= 0x08;
	pin_d.key_header[9]  = akd;	/* AKD: standard + every char != 0 +
					 * pin min length */
	pin_d.key_header[10] = 0x00;	/* never allow WRITE KEY    */
	pin_d.key_header[11] = 0x81;	/* key attribute: akd + pin */
	/* create/write PIN */
	r = sc_card_ctl(card, SC_CARDCTL_STARCOS_WRITE_KEY, &pin_d);
	if (r != SC_SUCCESS)
		return r;

	if (puk && puk_len) {
		sc_pkcs15_auth_info_t puk_info;

		if (puk_len > 8)
			return SC_ERROR_INVALID_ARGUMENTS;
		memset(tpin, 0, 8);
		memcpy(tpin, puk, puk_len);

		sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &puk_info);
		tmp = puk_info.tries_left;

		puk_d.mode    = 0;	/* install */
		puk_d.kid     = (u8) pin_id + 1;
		puk_d.key     = tpin;
		puk_d.key_len = 8;
		puk_d.key_header[0]  = puk_d.kid;
		puk_d.key_header[1]  = 0;
		puk_d.key_header[2]  = 8;
		puk_d.key_header[3]  = STARCOS_AC_ALWAYS;
		puk_d.key_header[4]  = ((pin_id & 0x1f) << 3) | 0x05;
		puk_d.key_header[5]  = 0x01;
		puk_d.key_header[6]  = ((0x0f & tmp) << 4) | (0x0f & tmp);
		puk_d.key_header[7]  = 0x0;
		puk_d.key_header[8]  = 0x0;
		puk_d.key_header[9]  = 0x0;
		puk_d.key_header[10] = 0x00;
		puk_d.key_header[11] = 0x02;
		/* create/write PUK */
		r = sc_card_ctl(card, SC_CARDCTL_STARCOS_WRITE_KEY, &puk_d);
		if (r != SC_SUCCESS)
			return r;
	}

	/* in case of a global pin: write dummy entry in df isf */
	if (!is_local) {
		r = sc_select_file(card, &df->path, NULL);
		if (r < 0)
			return r;
		pin_d.key     = NULL;
		pin_d.key_len = 0;
		pin_d.key_header[1] = 0;
		pin_d.key_header[2] = 0;
		/* create/write dummy PIN */
		r = sc_card_ctl(card, SC_CARDCTL_STARCOS_WRITE_KEY, &pin_d);
		if (r != SC_SUCCESS)
			return r;
	}

	/* in case of a SOPIN: if AC WRITE KEY is protected by the
	 * SOPIN, call starcos_finalize_card to activate the ACs  */
	if (need_finalize)
		 r = starcos_finalize_card(card);

	return r;
}

/* range of possible key ids for private keys
 */
#define STARCOS_MIN_LPKEY_ID	0x91
#define STARCOS_MAX_LPKEY_ID	0x9f
#define STARCOS_MIN_GPKEY_ID	0x11
#define STARCOS_MAX_GPKEY_ID	0x1f
static int starcos_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_prkey_info_t *prkey)
{
	/* use (local) KIDs 0x91-0x9f for private rsa keys */
	if (prkey->key_reference < STARCOS_MIN_LPKEY_ID)
		prkey->key_reference = STARCOS_MIN_LPKEY_ID;
	if (prkey->key_reference > STARCOS_MAX_LPKEY_ID)
		return SC_ERROR_TOO_MANY_OBJECTS;
	return SC_SUCCESS;
}

#define STARCOS_MAX_PR_KEYSIZE	370

static int starcos_encode_prkey(struct sc_pkcs15_prkey_rsa *rsa, u8 *buf)
{
	size_t	i = 0;
	u8	*p = buf;

	/* clear key buffer */
	memset(buf, 0, STARCOS_MAX_PR_KEYSIZE);

	if (rsa->p.len && rsa->q.len && rsa->dmp1.len &&
		rsa->dmq1.len && rsa->iqmp.len) {
		/* CRT RSA key     */
		/* get number of 0x00 bytes */
		i = STARCOS_MAX_PR_KEYSIZE - rsa->p.len - rsa->q.len -
		    rsa->dmp1.len - rsa->dmq1.len - 45 - rsa->p.len;

		/* key format list */
		*p++ = 0x0c;
		*p++ = 0x91;
		*p++ = (u8) rsa->p.len;
		*p++ = 0x92;
		*p++ = (u8) rsa->q.len;
		*p++ = 0x94;
		*p++ = (u8) rsa->dmp1.len + 16;
		*p++ = 0x95;
		*p++ = (u8) rsa->dmq1.len + 16;
		*p++ = 0x97;
		*p++ = (u8) rsa->p.len;
		*p++ = 0x00;
		*p++ = (u8) i;
		/* copy key components */
		for (i = rsa->q.len; i != 0; i--)
			*p++ = rsa->q.data[i - 1];
		for (i = rsa->p.len; i != 0; i--)
			*p++ = rsa->p.data[i - 1];
		for (i = 16; i != 0; i--)
			*p++ = 0x00;
		for (i = rsa->dmp1.len; i != 0; i--)
			*p++ = rsa->dmq1.data[i - 1];
		for (i = 16; i != 0; i--)
			*p++ = 0x00;
		for (i = rsa->dmq1.len; i != 0; i--)
			*p++ = rsa->dmp1.data[i - 1];
		for (i = rsa->iqmp.len; i != 0; i--)
			*p++ = rsa->iqmp.data[i - 1];
		for (i = rsa->p.len - rsa->iqmp.len; i != 0; i--)
			*p++ = 0x00;
	} else if (rsa->modulus.len && rsa->d.len) {
		/* normal RSA key  */
		i = STARCOS_MAX_PR_KEYSIZE - 7 - rsa->modulus.len
                    - rsa->d.len - 16;
		/* key format list */
		*p++ = 6;
		*p++ = 0x90;
		*p++ = (u8) rsa->modulus.len;
		*p++ = 0x93;
		*p++ = (u8) rsa->d.len + 16;
		*p++ = 0x00;
		*p++ = (u8) i;
		/* copy key components */
		for (i = rsa->modulus.len; i != 0; i--)
			*p++ = rsa->modulus.data[i - 1];
		for (i = 16; i != 0; i--)
			*p++ = 0x00;
		for (i = rsa->d.len; i != 0; i--)
			*p++ = rsa->d.data[i - 1];
	} else
		return SC_ERROR_INTERNAL;

	return SC_SUCCESS;
}

/* XXX the whole IPF stuff doesn't really work very well */
/** starcos_ipf_get_lastpos
 * returns the offset to the first byte after the last key
 */
static size_t starcos_ipf_get_lastpos(u8 *ipf, size_t ipf_len)
{
	size_t	num_keys, tmp;
	u8	*p = ipf;

	if (!ipf || ipf_len < 13)
		return 0;
	num_keys = *p++; /* the first bytes contains the number of keys*/
	if (num_keys == 0xff)
		num_keys = 0;
	if (!num_keys)
		return 1;
	while (num_keys--) {
		size_t offset = p - ipf;	/* note: p > ipf */
		/* get offset to the next key header */
		tmp = 12 + (p[1] << 8) + p[2];
		if (tmp + offset > ipf_len)
			return 0;
		p += tmp;
	}

	return p - ipf;
}

static int starcos_encode_pukey(struct sc_pkcs15_prkey_rsa *rsa, u8 *buf,
	sc_pkcs15_prkey_info_t *kinfo)
{
	size_t	i = 0;
	u8	*p = buf;

	/* if rsa == NULL return key header for key generation    */
	if (!rsa) {
		if (!buf)
			/* if buf == NULL return length of the encoded key */
			return (int) 12 + (kinfo->modulus_length >> 3);
		*p++ = 0x06;			/* length key header */
		*p++ = 0x01; 			/* CHA byte */
		*p++ = 0x01;
		*p++ = 0x10;			/* RSA: n   */
		*p++ = (kinfo->modulus_length >> 3) & 0xff;
		*p++ = 0x13;			/* RSA: e   */
		*p++ = 0x04;
		*p = (u8) kinfo->key_reference;	/* CHA byte */
	} else {
		/* encode normal public key  */
		size_t	mod_len = rsa->modulus.len  & 0xff,
			exp_len = rsa->exponent.len & 0xff;

		if (!buf)
			return (int) 8 + mod_len + exp_len + 1;

		*p++ = 0x06;			/* length key header */
		*p++ = 0x01; 			/* CHA byte */
		*p++ = 0x01;
		*p++ = 0x10;			/* RSA: n   */
		*p++ = mod_len;
		*p++ = 0x13;			/* RSA: e   */
		*p++ = exp_len + 1;
		*p++ = (u8) kinfo->key_reference;	/* CHA byte */
		/* copy modulus  */
		for (i = mod_len; i != 0; i--)
			*p++ = rsa->modulus.data[i - 1];
		/* copy exponent */
		for (i = exp_len; i != 0; i--)
			*p++ = rsa->exponent.data[i - 1];
		*p = 0x00;
	}
	return SC_SUCCESS;
}

static int starcos_write_pukey(sc_profile_t *profile, sc_card_t *card,
	 struct sc_pkcs15_prkey_rsa *rsa, sc_pkcs15_prkey_info_t *kinfo)
{
	int		r;
	size_t		len, keylen, endpos;
	u8		*buf, key[280], *p, num_keys;
	sc_file_t	*tfile = NULL;
	sc_path_t	tpath;

	/* get ipf profile */
	tpath = kinfo->path;
	r = sc_profile_get_file_in(profile, &tpath, "p15_ipf", &tfile);
	if (r < 0)
		return r;
	tpath = tfile->path;
	sc_file_free(tfile);
	tfile = NULL;
	r = sc_select_file(card, &tpath, &tfile);
	if (r != SC_SUCCESS)
		/* unable to select ipf */
		return r;
	len = tfile->size;
	sc_file_free(tfile);
	buf = malloc(len);
	if (!buf)
		return SC_ERROR_OUT_OF_MEMORY;
	/* read the complete IPF */
	r = sc_read_binary(card, 0, buf, len, 0);
	if (r < 0 || r != (int)len)
		return r;
	/* get/fix number of keys */
	num_keys = buf[0];
	if (num_keys == 0xff)
		num_keys = 0;
	/* encode public key */
	keylen  = starcos_encode_pukey(rsa, NULL, kinfo);
	if (!keylen) {
		free(buf);
		return SC_ERROR_INTERNAL;
	}
	p = key;
	*p++ = (u8) kinfo->key_reference;
	*p++ = (keylen >> 8) & 0xff;
	*p++ = keylen & 0xff;
	*p++ = STARCOS_AC_ALWAYS;	/* AC WRITE etc XXX */
	*p++ = 0x0f;
	*p++ = 0;
	*p++ = 0x09;			/* ALGO XXX */
	*p++ = 0x4a;			/* AKD  XXX */
	*p++ = ((keylen >> 8) & 0xff) | 0x80;
	*p++ = keylen & 0xff;
	r = starcos_encode_pukey(rsa, p, kinfo);
	if (r != SC_SUCCESS) {
		free(buf);
		return SC_ERROR_INTERNAL;
	}
	p   += keylen;
	*p++ = 0x04;				/* CPI */
	*p = (u8) kinfo->key_reference;	/* CHA */
	/* updated IPF (XXX: currently append only) */
	num_keys++;
	r = sc_update_binary(card, 0, &num_keys, 1, 0);
	if (r < 0)
		return r;
	endpos = starcos_ipf_get_lastpos(buf, len);
	free(buf);
	return sc_update_binary(card, endpos, key, keylen + 12, 0);
}

static int starcos_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj)
{
	struct sc_card *card = p15card->card;
	int	r, pin_id;
	u8	akd = 0, state;

	sc_file_t              *tfile;
	const sc_acl_entry_t   *acl_entry;
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *)obj->data;
	sc_starcos_wkey_data    tkey;

	/* get and verify sopin if necessary */
	r = sc_profile_get_file(profile, "p15_isf", &tfile);
        if (r < 0)
                return r;
	acl_entry = sc_file_get_acl_entry(tfile, SC_AC_OP_WRITE);
	if (acl_entry->method  != SC_AC_NONE) {
		r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_WRITE);
	}
	else   {
		r = sc_select_file(card, &tfile->path, NULL);
	}
	sc_file_free(tfile);
	if (r < 0)
		return r;

	/* create sc_starcos_wkey_data */
	tkey.mode    = 0x00;	/* install new key */
	tkey.kid     = (u8) kinfo->key_reference;
	tkey.key_header[0] = (u8) kinfo->key_reference;
	tkey.key_header[1] = (STARCOS_MAX_PR_KEYSIZE >> 8) & 0xff;
	tkey.key_header[2] = STARCOS_MAX_PR_KEYSIZE & 0xff;

	pin_id = sc_pkcs15init_get_pin_reference(p15card, profile, SC_AC_SYMBOLIC,
			SC_PKCS15INIT_USER_PIN);
	if (pin_id < 0)
		state = STARCOS_AC_ALWAYS;
	else {
		state  = STARCOS_PINID2STATE(pin_id);	/* get the necessary state */
		state |= pin_id & 0x80 ? 0x10 : 0x00;	/* local vs. global key id */
	}
	tkey.key_header[3] = state;		/* AC to access key        */
	if (obj->user_consent)
		tkey.key_header[4] = 0x0f;	/* do state transition */
	else
		tkey.key_header[4] = 0x8f;	/* no state transition */
	tkey.key_header[5] = 0x11; /* require local state == 1 to update key */
	tkey.key_header[6] = 0x33;
	tkey.key_header[7] = 0x00;
	tkey.key_header[8] = 0x09;
	if (kinfo->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
		akd |= 0x10;
	if (kinfo->usage & SC_PKCS15_PRKEY_USAGE_SIGN)
		akd |= 0x31;	/* allow DS, IA and PKCS11 */
	if (kinfo->usage & SC_PKCS15_PRKEY_USAGE_SIGNRECOVER)
		akd |= 0x31;	/* allow DS, IA and PKCS11 */
	if (kinfo->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT ||
	    kinfo->usage & SC_PKCS15_PRKEY_USAGE_UNWRAP)
		akd |= 0x02;
	tkey.key_header[9]  = akd;
	tkey.key_header[10] = 0x03;
	tkey.key_header[11] = 0xa0;
	tkey.key     = NULL;
	tkey.key_len = 0;

	return sc_card_ctl(card, SC_CARDCTL_STARCOS_WRITE_KEY, &tkey);
}

static int starcos_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	int     r;
	u8	key_buf[STARCOS_MAX_PR_KEYSIZE];

	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	const sc_acl_entry_t   *acl_entry;
	sc_file_t              *tfile;
	struct sc_pkcs15_prkey_rsa *rsa = &key->u.rsa;
	sc_starcos_wkey_data tkey;

	if (key->algorithm != SC_ALGORITHM_RSA)
		/* ignore DSA keys */
		return SC_ERROR_INVALID_ARGUMENTS;

	/* create sc_starcos_wkey_data */
	if (starcos_encode_prkey(rsa, key_buf))
		return SC_ERROR_INTERNAL;

	/* get and verify sopin if necessary */
	r = sc_profile_get_file(profile, "p15_isf", &tfile);
        if (r < 0)
                return r;
	acl_entry = sc_file_get_acl_entry(tfile, SC_AC_OP_WRITE);
	if (acl_entry->method  != SC_AC_NONE) {
		r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_WRITE);
	}
	sc_file_free(tfile);
	if (r < 0)
		return r;

	tkey.mode    = 0x01;	/* update key */
	tkey.kid     = (u8) kinfo->key_reference;
	tkey.key     = key_buf;
	tkey.key_len = STARCOS_MAX_PR_KEYSIZE;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_STARCOS_WRITE_KEY, &tkey);
	if (r != SC_SUCCESS)
		return r;
	/* store public key in the IPF */
	return starcos_write_pukey(profile, p15card->card, rsa, kinfo);
}

static int starcos_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	int r;
	const sc_acl_entry_t   *acl_entry;
	sc_file_t              *tfile;
	sc_starcos_gen_key_data	gendat;
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA)
		return SC_ERROR_NOT_SUPPORTED;

	/* get and verify sopin if necessary */
	r = sc_profile_get_file(profile, "p15_isf", &tfile);
        if (r < 0)
                return r;
	acl_entry = sc_file_get_acl_entry(tfile, SC_AC_OP_WRITE);
	if (acl_entry->method  != SC_AC_NONE) {
		r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_WRITE);
	}
	sc_file_free(tfile);
	if (r < 0)
		return r;

	/* XXX It would be better to write the public key header
	 * in the IPF when the private key header is created, but
	 * as we don't know the size of the exponent at this time
	 * we would waste space.
	 */
	/* create (empty) public key entry */
	r = starcos_write_pukey(profile, p15card->card, NULL, kinfo);
	if (r < 0)
		return r;
	/* generate key pair */
	gendat.key_id     = (u8) kinfo->key_reference;
	gendat.key_length = (size_t) kinfo->modulus_length;
	gendat.modulus    = NULL;
	r = sc_card_ctl(p15card->card, SC_CARDCTL_STARCOS_GENERATE_KEY, &gendat);
	if (r != SC_SUCCESS)
		return r;
	/* get the modulus via READ PUBLIC KEY */
	if (pubkey) {
		u8 *buf;
		struct sc_pkcs15_pubkey_rsa *rsa = &pubkey->u.rsa;
		/* set the modulus */
		rsa->modulus.data = gendat.modulus;
		rsa->modulus.len  = kinfo->modulus_length >> 3;
		/* set the exponent (always 0x10001) */
		buf = malloc(3);
		if (!buf)
			return SC_ERROR_OUT_OF_MEMORY;
		buf[0] = 0x01;
		buf[1] = 0x00;
		buf[2] = 0x01;
		rsa->exponent.data = buf;
		rsa->exponent.len  = 3;

		pubkey->algorithm = SC_ALGORITHM_RSA;
	} else
		/* free public key */
		free(gendat.modulus);

	return SC_SUCCESS;
}

static int starcos_finalize_card(sc_card_t *card)
{
	int       r;
	sc_file_t tfile;
	sc_path_t tpath;

	/* SELECT FILE MF */
	sc_format_path("3F00", &tpath);
	r = sc_select_file(card, &tpath, NULL);
	if (r < 0)
		return r;

	/* call CREATE END for the MF (ignore errors) */
	tfile.type = SC_FILE_TYPE_DF;
	tfile.id   = 0x3f00;
	r = sc_card_ctl(card, SC_CARDCTL_STARCOS_CREATE_END, &tfile);
	if (r < 0)
		sc_log(card->ctx,  "failed to call CREATE END for the MF\n");
	/* call CREATE END for the apps (pkcs15) DF */
	tfile.type = SC_FILE_TYPE_DF;
	tfile.id   = 0x5015;
	r = sc_card_ctl(card, SC_CARDCTL_STARCOS_CREATE_END, &tfile);
	if (r == SC_ERROR_NOT_ALLOWED)
		/* card is already finalized */
		return SC_SUCCESS;
	return r;
}

static struct sc_pkcs15init_operations sc_pkcs15init_starcos_operations = {
	starcos_erase_card,
	starcos_init_card,
	starcos_create_dir,
	NULL,				/* create_domain */
	starcos_pin_reference,
	starcos_create_pin,
	starcos_key_reference,
	starcos_create_key,
	starcos_store_key,
	starcos_generate_key,
	NULL, NULL,			/* encode private/public key */
	starcos_finalize_card,
	NULL, 				/* delete_object */
	NULL, NULL, NULL, NULL, NULL,	/* pkcs15init emulation */
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_starcos_ops(void)
{
	return &sc_pkcs15init_starcos_operations;
}
