/*
 * framework-pkcs15.c: PKCS#15 framework and related objects
 *
 * Copyright (C) 2002  Timo Teräs <timo.teras@iki.fi>
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "libopensc/asn1.h"
#include "libopensc/cardctl.h"
#include "ui/notify.h"
#include "common/compat_strnlen.h"
#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#else
#define SHA_DIGEST_LENGTH	20
#endif

#include "sc-pkcs11.h"
#ifdef USE_PKCS15_INIT
#include "pkcs15init/pkcs15-init.h"
#endif

struct pkcs15_slot_data {
	struct sc_pkcs15_object *auth_obj;
};
#define slot_data(p)		((struct pkcs15_slot_data *) (p))
#define slot_data_auth(p)	(((p) && slot_data(p)) ? slot_data(p)->auth_obj : NULL)
#define slot_data_auth_info(p)	(((p) && slot_data_auth(p))? \
		(struct sc_pkcs15_auth_info *) slot_data_auth(p)->data : NULL)

#define check_attribute_buffer(attr,size)	\
	if (attr->pValue == NULL_PTR) {         \
		attr->ulValueLen = size;        \
		return CKR_OK;                  \
	}                                       \
	if (attr->ulValueLen < size) {		\
		attr->ulValueLen = size;	\
		return CKR_BUFFER_TOO_SMALL;    \
	}                                       \
	attr->ulValueLen = size;

#define MAX_OBJECTS	128
struct pkcs15_fw_data {
	struct sc_pkcs15_card *		p15_card;
	struct pkcs15_any_object *	objects[MAX_OBJECTS];
	unsigned int			num_objects;
	unsigned int			locked;
	unsigned char user_puk[64];
	unsigned int user_puk_len;
};

struct pkcs15_any_object {
	struct sc_pkcs11_object		base;
	unsigned int			refcount;
	size_t				size;
	struct sc_pkcs15_object *	p15_object;
	struct pkcs15_pubkey_object *	related_pubkey;
	struct pkcs15_cert_object *	related_cert;
	struct pkcs15_prkey_object *	related_privkey;
};

struct pkcs15_cert_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_cert_info *	cert_info;
	struct sc_pkcs15_cert *		cert_data;
};
#define cert_flags		base.base.flags
#define cert_p15obj		base.p15_object
#define cert_pubkey		base.related_pubkey
#define cert_issuer		base.related_cert
#define cert_prvkey		base.related_privkey

struct pkcs15_prkey_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_prkey_info *	prv_info;
	struct sc_pkcs15_pubkey *	pub_data;
};
#define prv_flags		base.base.flags
#define prv_p15obj		base.p15_object
#define prv_pubkey		base.related_pubkey
#define prv_next		base.related_privkey

struct pkcs15_pubkey_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_pubkey_info *	pub_info;	/* NULL for key extracted from cert */
	struct sc_pkcs15_pubkey *	pub_data;
};
#define pub_flags		base.base.flags
#define pub_p15obj		base.p15_object
#define pub_genfrom		base.related_cert

#define __p15_type(obj)		(((obj) && (obj)->p15_object)? ((obj)->p15_object->type) : (unsigned int)-1)
#define is_privkey(obj)		((__p15_type(obj) & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY)
#define is_pubkey(obj)		((__p15_type(obj) & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PUBKEY)
#define is_cert(obj)		(__p15_type(obj) == SC_PKCS15_TYPE_CERT_X509)

struct pkcs15_data_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_data_info *info;
	struct sc_pkcs15_data *value;
};
#define data_flags		base.base.flags
#define data_p15obj		base.p15_object
#define is_data(obj) (__p15_type(obj) == SC_PKCS15_TYPE_DATA_OBJECT)

struct pkcs15_skey_object {
	struct pkcs15_any_object    base;

	struct sc_pkcs15_skey_info *info;
	struct sc_pkcs15_skey *valueXXXX;
};

#define is_skey(obj) ((__p15_type(obj) & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_SKEY)

#define skey_flags	base.base.flags
#define skey_p15obj	base.p15_object

extern struct sc_pkcs11_object_ops pkcs15_cert_ops;
extern struct sc_pkcs11_object_ops pkcs15_prkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_pubkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_dobj_ops;
extern struct sc_pkcs11_object_ops pkcs15_skey_ops;

const CK_BYTE gostr3410_paramset_A_encoded_oid[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
const unsigned int gostr3410_paramset_A_oid[] = {1, 2, 643, 2, 2, 35, 1, (unsigned int)-1};
const CK_BYTE gostr3410_paramset_B_encoded_oid[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02 };
const unsigned int gostr3410_paramset_B_oid[] = {1, 2, 643, 2, 2, 35, 2, (unsigned int)-1};
const CK_BYTE gostr3410_paramset_C_encoded_oid[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03 };
const unsigned int gostr3410_paramset_C_oid[] = {1, 2, 643, 2, 2, 35, 3, (unsigned int)-1};

static const struct {
	const CK_BYTE *encoded_oid;
	const unsigned int encoded_oid_size;
	const unsigned int *oid;
	const unsigned int oid_size;
	unsigned char oid_id;
} gostr3410_param_oid [] = {
	{ &gostr3410_paramset_A_encoded_oid[0],
		sizeof(gostr3410_paramset_A_encoded_oid),
		&gostr3410_paramset_A_oid[0],
		sizeof(gostr3410_paramset_A_oid),
		SC_PKCS15_PARAMSET_GOSTR3410_A },
	{ &gostr3410_paramset_B_encoded_oid[0],
		sizeof(gostr3410_paramset_B_encoded_oid),
		&gostr3410_paramset_B_oid[0],
		sizeof(gostr3410_paramset_B_oid),
		SC_PKCS15_PARAMSET_GOSTR3410_B },
	{ &gostr3410_paramset_C_encoded_oid[0],
		sizeof(gostr3410_paramset_C_encoded_oid),
		&gostr3410_paramset_C_oid[0],
		sizeof(gostr3410_paramset_C_oid),
		SC_PKCS15_PARAMSET_GOSTR3410_C }
};

const CK_BYTE gostr3411_94_cryptopro_paramset_encoded_oid[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };
const unsigned int gostr3411_94_cryptopro_paramset_oid[] = {1, 2, 643, 2, 2, 30, 1, (unsigned int)-1};

#ifdef USE_PKCS15_INIT
static const struct {
	const CK_BYTE *encoded_oid;
	const unsigned int encoded_oid_size;
	const unsigned int *oid;
	const unsigned int oid_size;
} gostr3410_hash_param_oid [] = {
	{ &gostr3411_94_cryptopro_paramset_encoded_oid[0],
		sizeof(gostr3411_94_cryptopro_paramset_encoded_oid),
		&gostr3411_94_cryptopro_paramset_oid[0],
		sizeof(gostr3411_94_cryptopro_paramset_oid)}
};
#endif

static int	__pkcs15_release_object(struct pkcs15_any_object *);
static CK_RV	register_mechanisms(struct sc_pkcs11_card *p11card);
static CK_RV	get_public_exponent(struct sc_pkcs15_pubkey *,
					CK_ATTRIBUTE_PTR);
static CK_RV	get_modulus(struct sc_pkcs15_pubkey *,
					CK_ATTRIBUTE_PTR);
static CK_RV	get_modulus_bits(struct sc_pkcs15_pubkey *,
					CK_ATTRIBUTE_PTR);
static CK_RV	get_usage_bit(unsigned int usage, CK_ATTRIBUTE_PTR attr);
static CK_RV	get_gostr3410_params(const u8 *, size_t, CK_ATTRIBUTE_PTR);
static CK_RV	get_ec_pubkey_point(struct sc_pkcs15_pubkey *, CK_ATTRIBUTE_PTR);
static CK_RV	get_ec_pubkey_params(struct sc_pkcs15_pubkey *, CK_ATTRIBUTE_PTR);
static int	lock_card(struct pkcs15_fw_data *);
static int	unlock_card(struct pkcs15_fw_data *);
static int	reselect_app_df(sc_pkcs15_card_t *p15card);

#ifdef USE_PKCS15_INIT
static CK_RV	set_gost3410_params(struct sc_pkcs15init_prkeyargs *,
			struct sc_pkcs15init_pubkeyargs *,
			CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG);
static CK_RV	pkcs15_create_slot(struct sc_pkcs11_card *p11card, struct pkcs15_fw_data *fw_data,
			struct sc_pkcs15_object *auth, struct sc_app_info *app,
			struct sc_pkcs11_slot **out);
static int pkcs11_get_pin_callback(struct sc_profile *profile, int id,
		const struct sc_pkcs15_auth_info *info, const char *label,
		unsigned char *pinbuf, size_t *pinsize);

static struct sc_pkcs15init_callbacks pkcs15init_callbacks = {
	pkcs11_get_pin_callback,       /* get_pin() */
	NULL
};
static char *pkcs15init_sopin = NULL;
static size_t pkcs15init_sopin_len = 0;

static int pkcs11_get_pin_callback(struct sc_profile *profile, int id,
		const struct sc_pkcs15_auth_info *info, const char *label,
		unsigned char *pinbuf, size_t *pinsize)
{
	char	*secret = NULL;
	size_t	len = 0;

	if (info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_NOT_SUPPORTED;

	sc_log(context, "pkcs11_get_pin_callback() auth-method %X", info->auth_method);
	if (info->auth_method == SC_AC_CHV)   {
		unsigned int flags = info->attrs.pin.flags;

		sc_log(context, "pkcs11_get_pin_callback() PIN flags %X", flags);
		if ((flags & SC_PKCS15_PIN_FLAG_SO_PIN) && !(flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))    {
			if (pkcs15init_sopin_len)
				secret = pkcs15init_sopin;
		}
	}
	if (secret)
		len = strlen(secret);

	sc_log(context, "pkcs11_get_pin_callback() secret '%s'", secret ? secret : "<null>");

	if (!secret)
		return SC_ERROR_OBJECT_NOT_FOUND;
	if (len > *pinsize)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(pinbuf, secret, len + 1);
	*pinsize = len;
	return 0;
}
#endif

/* Returns WF data corresponding to the given application or,
 * if application info is not supplied, returns first available WF data. */
static struct pkcs15_fw_data *
get_fw_data(struct sc_pkcs11_card *p11card, struct sc_app_info *app_info, int *out_idx)
{
	struct pkcs15_fw_data *out = NULL;
	int idx;

	if (!p11card)
		return NULL;
	for (idx=0; p11card && idx < SC_PKCS11_FRAMEWORK_DATA_MAX_NUM; idx++)   {
		struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fws_data[idx];
		struct sc_file *file_app = NULL;

		if (!fw_data || !fw_data->p15_card)
			continue;

		file_app = fw_data->p15_card->file_app;
		if (app_info && file_app)   {
			if (file_app->path.len != app_info->path.len)
				continue;
			if (file_app->path.aid.len != app_info->path.aid.len)
				continue;
			if (memcmp(file_app->path.aid.value, app_info->path.aid.value, app_info->path.aid.len))
				continue;
			if (memcmp(file_app->path.value, app_info->path.value, app_info->path.len))
				continue;
		}

		out = fw_data;
		if (out_idx)
			*out_idx = idx;
		break;
	}

	return out;
}

/* PKCS#15 Framework */
static CK_RV
pkcs15_bind(struct sc_pkcs11_card *p11card, struct sc_app_info *app_info)
{
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_aid *aid = app_info ? &app_info->aid : NULL;
	int rc, idx;
	CK_RV ck_rv;

	sc_log(context, "Bind PKCS#15 '%s' application", app_info ? app_info->label : "<anonymous>");
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	for (idx=0; idx<SC_PKCS11_FRAMEWORK_DATA_MAX_NUM; idx++)
		if (!p11card->fws_data[idx])
			break;
	if (idx == SC_PKCS11_FRAMEWORK_DATA_MAX_NUM)
		return CKR_USER_TOO_MANY_TYPES;

	if (!(fw_data = calloc(1, sizeof(*fw_data))))
		return CKR_HOST_MEMORY;
	p11card->fws_data[idx] = fw_data;

	rc = sc_pkcs15_bind(p11card->card, aid, &fw_data->p15_card);
	if (rc != SC_SUCCESS) {
		sc_log(context, "sc_pkcs15_bind failed: %d", rc);
		return sc_to_cryptoki_error(rc, NULL);
	}

	/* Mechanisms are registered globally per card. Checking
	 * p11card->nmechanisms avoids registering the same mechanisms twice for a
	 * card with multiple slots. */
	if (!p11card->nmechanisms) {
		ck_rv = register_mechanisms(p11card);
		if (ck_rv != CKR_OK) {
			sc_log(context, "cannot register mechanisms; CKR 0x%lX",
			       ck_rv);
			return ck_rv;
		}
	}

	if (idx == 0) {
		/* send a notification only for the first application that's bound */
		sc_notify_id(p11card->card->ctx, &p11card->reader->atr, fw_data->p15_card,
				NOTIFY_CARD_INSERTED);
	}

	return CKR_OK;
}


static CK_RV
pkcs15_unbind(struct sc_pkcs11_card *p11card)
{
	unsigned int i, idx;
	int rv = SC_SUCCESS;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	for (idx=0; p11card && idx<SC_PKCS11_FRAMEWORK_DATA_MAX_NUM; idx++)   {
		struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fws_data[idx];

		if (!fw_data)
			break;
		for (i = 0; i < fw_data->num_objects; i++) {
			struct pkcs15_any_object *obj = fw_data->objects[i];

			/* use object specific release method if existing */
			if (obj->base.ops && obj->base.ops->release)
				obj->base.ops->release(obj);
			else
				__pkcs15_release_object(obj);
		}

		unlock_card(fw_data);

		if (fw_data->p15_card && fw_data->p15_card->card) {
			if (idx == 0) {
				int rc = sc_detect_card_presence(fw_data->p15_card->card->reader);
				if (rc <= 0 || rc & SC_READER_CARD_CHANGED) {
					/* send a notification only if the card was removed/changed
					 * and only for the first application that's unbound */
					sc_notify_id(fw_data->p15_card->card->ctx,
							&fw_data->p15_card->card->reader->atr,
							fw_data->p15_card,
							NOTIFY_CARD_REMOVED);
				}
			}
			rv = sc_pkcs15_unbind(fw_data->p15_card);
		}
		fw_data->p15_card = NULL;

		free(fw_data);
		p11card->fws_data[idx] = NULL;
	}

	return sc_to_cryptoki_error(rv, NULL);
}


static void
pkcs15_init_token_info(struct sc_pkcs15_card *p15card, CK_TOKEN_INFO_PTR pToken)
{
	scconf_block *conf_block = NULL;
	char *model = NULL;

	conf_block = sc_get_conf_block(p15card->card->ctx, "framework", "pkcs15", 1);
	if (conf_block && p15card->file_app)   {
		scconf_block **blocks = NULL;
		char str_path[SC_MAX_AID_STRING_SIZE];

		memset(str_path, 0, sizeof(str_path));
		sc_bin_to_hex(p15card->file_app->path.value, p15card->file_app->path.len, str_path, sizeof(str_path), 0);
		blocks = scconf_find_blocks(p15card->card->ctx->conf, conf_block, "application", str_path);
		if (blocks)   {
			if (blocks[0])
				model = (char *)scconf_get_str(blocks[0], "model", NULL);
			free(blocks);
		}
	}

	if (model)
		strcpy_bp(pToken->model, model, sizeof(pToken->model));
	else if (p15card->flags & SC_PKCS15_CARD_FLAG_EMULATED)
		strcpy_bp(pToken->model, "PKCS#15 emulated", sizeof(pToken->model));
	else
		strcpy_bp(pToken->model, "PKCS#15", sizeof(pToken->model));

	if (p15card->tokeninfo) {
		strcpy_bp(pToken->manufacturerID, p15card->tokeninfo->manufacturer_id, 32);

		/* Take the last 16 chars of the serial number (if the are more than 16).
		 * _Assuming_ that the serial number is a Big Endian counter, this
		 * will assure that the serial within each type of card will be
		 * unique in pkcs11 (at least for the first 8^16 cards :-) */
		if (p15card->tokeninfo->serial_number != NULL) {
			size_t sn_start = strlen(p15card->tokeninfo->serial_number);

			if (sn_start <= 16)
				sn_start = 0;
			else
				sn_start -= 16;

			strcpy_bp(pToken->serialNumber, p15card->tokeninfo->serial_number + sn_start, 16);
		}
	}

	pToken->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pToken->ulSessionCount = 0; /* FIXME */
	pToken->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pToken->ulRwSessionCount = 0; /* FIXME */
	pToken->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->hardwareVersion.major = p15card->card->version.hw_major;
	pToken->hardwareVersion.minor = p15card->card->version.hw_minor;
	pToken->firmwareVersion.major = p15card->card->version.fw_major;
	pToken->firmwareVersion.minor = p15card->card->version.fw_minor;
}

#ifdef USE_PKCS15_INIT
static char *
set_cka_label(CK_ATTRIBUTE_PTR attr, char *label)
{
	char *l = (char *)attr->pValue;
	unsigned long len = attr->ulValueLen;

	if (len >= SC_PKCS15_MAX_LABEL_SIZE)
		len = SC_PKCS15_MAX_LABEL_SIZE-1;
	memcpy(label, l, len);
	label[len] = '\0';
	return label;
}
#endif

static int
__pkcs15_create_object(struct pkcs15_fw_data *fw_data,
		       struct pkcs15_any_object **result,
		       struct sc_pkcs15_object *p15_object,
		       struct sc_pkcs11_object_ops *ops,
		       size_t size)
{
	struct pkcs15_any_object *obj;

	if (fw_data->num_objects >= MAX_OBJECTS)
		return SC_ERROR_TOO_MANY_OBJECTS;

	if (!(obj = calloc(1, size)))
		return SC_ERROR_OUT_OF_MEMORY;

	fw_data->objects[fw_data->num_objects++] = obj;

	obj->base.ops = ops;
	obj->p15_object = p15_object;
	obj->refcount = 1;
	obj->size = size;

	*result = obj;
	return 0;
}

static int
__pkcs15_release_object(struct pkcs15_any_object *obj)
{
	if (--(obj->refcount) != 0)
		return obj->refcount;

	sc_mem_clear(obj, obj->size);
	free(obj);

	return 0;
}

#ifdef USE_PKCS15_INIT
static int
__pkcs15_delete_object(struct pkcs15_fw_data *fw_data, struct pkcs15_any_object *obj)
{
	unsigned int i;

	if (fw_data->num_objects == 0)
		return SC_ERROR_INTERNAL;

	for (i = 0; i < fw_data->num_objects; ++i)   {
		if (fw_data->objects[i] == obj) {
			fw_data->objects[i] = fw_data->objects[--fw_data->num_objects];
			if (__pkcs15_release_object(obj) > 0)
				return SC_ERROR_INTERNAL;
			return SC_SUCCESS;
		}
	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}
#endif

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_pkcs15_object *auth;
	struct sc_pkcs15_auth_info *pin_info;
	CK_RV rv;

	sc_log(context, "C_GetTokenInfo(%lx)", slotID);
	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)   {
		sc_log(context, "C_GetTokenInfo() get token: rv 0x%lX", rv);
		goto out;
	}

	if (slot->p11card == NULL) {
		rv = CKR_TOKEN_NOT_PRESENT;
		goto out;
	}

	fw_data = (struct pkcs15_fw_data *) slot->p11card->fws_data[slot->fw_data_idx];
	if (!fw_data) {
		rv = sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetTokenInfo");
		goto out;
	}
	p15card = fw_data->p15_card;

	/* User PIN flags are cleared before re-calculation */
	slot->token_info.flags &= ~(CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED);
	auth = slot_data_auth(slot->fw_data);
	sc_log(context,
		"C_GetTokenInfo() auth. object %p, token-info flags 0x%lX", auth,
		slot->token_info.flags);
	if (auth) {
		pin_info = (struct sc_pkcs15_auth_info*) auth->data;

		sc_pkcs15_get_pin_info(p15card, auth);

		if (pin_info->tries_left >= 0) {
			if (pin_info->tries_left == 1 || pin_info->max_tries == 1)
				slot->token_info.flags |= CKF_USER_PIN_FINAL_TRY;
			else if (pin_info->tries_left == 0)
				slot->token_info.flags |= CKF_USER_PIN_LOCKED;
			else if (pin_info->max_tries > 1 && pin_info->tries_left < pin_info->max_tries)
				slot->token_info.flags |= CKF_USER_PIN_COUNT_LOW;
		}
	}
	memcpy(pInfo, &slot->token_info, sizeof(CK_TOKEN_INFO));
out:
	sc_pkcs11_unlock();
	sc_log(context, "C_GetTokenInfo(%lx) returns 0x%lX", slotID, rv);
	return rv;
}


static int
public_key_created(struct pkcs15_fw_data *fw_data, const struct sc_pkcs15_id *id,
		struct pkcs15_any_object **obj2)
{
	size_t ii;

	for(ii=0; ii<fw_data->num_objects; ii++) {
		struct pkcs15_any_object *any_object = fw_data->objects[ii];
		struct sc_pkcs15_object *p15_object = any_object->p15_object;

		if (!p15_object)
			continue;

		if ((p15_object->type & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_PUBKEY)
			continue;

		if (sc_pkcs15_compare_id(id, &((struct sc_pkcs15_pubkey_info *)p15_object->data)->id))   {
			if (obj2)
				*obj2 = any_object;
			return SC_SUCCESS;
		}
	}

	return SC_ERROR_OBJECT_NOT_FOUND;
}

static void
pkcs15_cert_extract_label(struct pkcs15_cert_object *cert)
{
	if (!cert || !cert->cert_p15obj || !cert->cert_data)
		return;

	sc_log(context, "pkcs15_cert_extract_label() called. Current label: %s", cert->cert_p15obj->label);

	/* if we didn't get a label, set one based on the CN */
	if (*cert->cert_p15obj->label == '\0') { /* can't be NULL -- static array */
		static const struct sc_object_id cn_oid = {{ 2, 5, 4, 3, -1 }};
		u8 *cn_name = NULL;
		size_t cn_len = 0;
		int rv = sc_pkcs15_get_name_from_dn(context,
			cert->cert_data->subject, cert->cert_data->subject_len,
			&cn_oid, &cn_name, &cn_len);
		if (rv == SC_SUCCESS) {
			sc_log(context, "pkcs15_cert_extract_label(): Name from DN is %.*s",
					(unsigned int) cn_len, cn_name);
			cn_len = MIN(cn_len, SC_PKCS15_MAX_LABEL_SIZE-1);
			memcpy(cert->cert_p15obj->label, cn_name, cn_len);
			cert->cert_p15obj->label[cn_len] = '\0';
		}
		free(cn_name);
	}
}

static int
__pkcs15_create_cert_object(struct pkcs15_fw_data *fw_data, struct sc_pkcs15_object *cert,
		struct pkcs15_any_object **cert_object)
{
	struct sc_pkcs15_cert_info *p15_info = NULL;
	struct sc_pkcs15_cert *p15_cert = NULL;
	struct pkcs15_cert_object *object = NULL;
	struct pkcs15_pubkey_object *obj2 = NULL;
	int rv;

	p15_info = (struct sc_pkcs15_cert_info *) cert->data;

	if (cert->flags & SC_PKCS15_CO_FLAG_PRIVATE)  {	/* is the cert private? */
		p15_cert = NULL;			/* will read cert when needed */
	}
	else    {
		rv = sc_pkcs15_read_certificate(fw_data->p15_card, p15_info, &p15_cert);
		if (rv < 0)
			return rv;
	}

	/* Certificate object */
	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
			cert, &pkcs15_cert_ops, sizeof(struct pkcs15_cert_object));
	if (rv < 0) {
		if (p15_cert != NULL)
			sc_pkcs15_free_certificate(p15_cert);
		return rv;
	}

	object->cert_info = p15_info;
	object->cert_data = p15_cert;

	/* Corresponding public key */
	rv = public_key_created(fw_data, &p15_info->id, (struct pkcs15_any_object **) &obj2);
	if (rv != SC_SUCCESS)
		rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &obj2,
				NULL, &pkcs15_pubkey_ops, sizeof(struct pkcs15_pubkey_object));
	if (rv < 0)
		return rv;

	if (p15_cert) {
		 /* make a copy of public key from the cert */
		if (!obj2->pub_data)
			rv = sc_pkcs15_pubkey_from_cert(context, &p15_cert->data, &obj2->pub_data);
		if (rv < 0)
			return rv;
	}

	obj2->pub_genfrom = object;
	object->cert_pubkey = obj2;

	/* Find missing labels for certificate */
	pkcs15_cert_extract_label(object);

	if (cert_object != NULL)
		*cert_object = (struct pkcs15_any_object *) object;

	return 0;
}


static int
__pkcs15_create_pubkey_object(struct pkcs15_fw_data *fw_data,
	struct sc_pkcs15_object *pubkey, struct pkcs15_any_object **pubkey_object)
{
	struct pkcs15_pubkey_object *object = NULL;
	struct sc_pkcs15_pubkey *p15_key = NULL;
	int rv;

	/* Read public key from card */
	/* Attempt to read pubkey from card or file.
	 * During initialization process, the key may have been created
	 * and saved as a file before the certificate has been created.
	 */
	if (pubkey->flags & SC_PKCS15_CO_FLAG_PRIVATE)   {	/* is the key private? */
		sc_log(context, "No pubkey");
		p15_key = NULL;					/* will read key when needed */
	}
	else {
		/* if emulation already created pubkey use it */
		if (pubkey->emulated && (fw_data->p15_card->flags & SC_PKCS15_CARD_FLAG_EMULATED)) {
			sc_log(context, "Use emulated pubkey");
			p15_key = (struct sc_pkcs15_pubkey *) pubkey->emulated;
		}
		else {
			sc_log(context, "Get pubkey from PKCS#15 object");
			rv = sc_pkcs15_read_pubkey(fw_data->p15_card, pubkey, &p15_key);
			if (rv < 0)
				 p15_key = NULL;
		}
	}

	/* Public key object */
	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
			pubkey, &pkcs15_pubkey_ops, sizeof(struct pkcs15_pubkey_object));
	if (rv >= 0) {
		object->pub_info = (struct sc_pkcs15_pubkey_info *) pubkey->data;
		object->pub_data = p15_key;
		if (p15_key && object->pub_info->modulus_length == 0 && p15_key->algorithm == SC_ALGORITHM_RSA)
			object->pub_info->modulus_length = 8 * p15_key->u.rsa.modulus.len;
	} else if (!(pubkey->emulated && (fw_data->p15_card->flags & SC_PKCS15_CARD_FLAG_EMULATED))) {
		sc_pkcs15_free_pubkey(p15_key);
	}
	if (object && object->pub_data) {
		if ((object->pub_data->alg_id)&&(object->pub_data->algorithm == SC_ALGORITHM_GOSTR3410))
			object->pub_data->alg_id->params = &((object->pub_data->u).gostr3410.params);
	}
	if (pubkey_object != NULL)
		*pubkey_object = (struct pkcs15_any_object *) object;

	return rv;
}


static int
__pkcs15_create_prkey_object(struct pkcs15_fw_data *fw_data,
	struct sc_pkcs15_object *prkey, struct pkcs15_any_object **prkey_object)
{
	struct pkcs15_prkey_object *object = NULL;
	int rv;

	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
			prkey, &pkcs15_prkey_ops, sizeof(struct pkcs15_prkey_object));
	if (rv >= 0)
		object->prv_info = (struct sc_pkcs15_prkey_info *) prkey->data;

	if (prkey_object != NULL)
		*prkey_object = (struct pkcs15_any_object *) object;

	return rv;
}


static int
__pkcs15_create_data_object(struct pkcs15_fw_data *fw_data,
		struct sc_pkcs15_object *object, struct pkcs15_any_object **data_object)
{
	struct pkcs15_data_object *dobj = NULL;
	int rv;

	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &dobj,
			object, &pkcs15_dobj_ops, sizeof(struct pkcs15_data_object));
	if (rv >= 0)   {
		dobj->info = (struct sc_pkcs15_data_info *) object->data;
		dobj->value = NULL;
	}

	if (data_object != NULL)
		*data_object = (struct pkcs15_any_object *) dobj;

	return rv;
}


static int
__pkcs15_create_secret_key_object(struct pkcs15_fw_data *fw_data,
		struct sc_pkcs15_object *object, struct pkcs15_any_object **skey_object)
{
	struct pkcs15_skey_object *skey = NULL;
	int rv;

	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &skey,
			object, &pkcs15_skey_ops, sizeof(struct pkcs15_skey_object));
	if (rv >= 0)
		skey->info = (struct sc_pkcs15_skey_info *) object->data;

	if (skey_object != NULL)
		*skey_object = (struct pkcs15_any_object *) skey;

	return rv;
}


static int
pkcs15_create_pkcs11_objects(struct pkcs15_fw_data *fw_data, int p15_type, const char *name,
		int (*create)(struct pkcs15_fw_data *, struct sc_pkcs15_object *,
			struct pkcs15_any_object **any_object))
{
	struct sc_pkcs15_object *p15_object[MAX_OBJECTS];
	int i, count, rv;

	rv = count = sc_pkcs15_get_objects(fw_data->p15_card, p15_type, p15_object, MAX_OBJECTS);
	if (rv >= 0)
		sc_log(context, "Found %d %s%s", count, name, (count == 1)? "" : "s");

	for (i = 0; rv >= 0 && i < count; i++)
		rv = create(fw_data, p15_object[i], NULL);

	return count;
}


static void
__pkcs15_prkey_bind_related(struct pkcs15_fw_data *fw_data, struct pkcs15_prkey_object *pk)
{
	struct sc_pkcs15_id *id = &pk->prv_info->id;
	unsigned int i;

	sc_log(context, "Object is a private key and has id %s", sc_pkcs15_print_id(id));

	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		if (obj->base.flags & SC_PKCS11_OBJECT_HIDDEN)
			continue;
		if (is_privkey(obj) && obj != (struct pkcs15_any_object *) pk) {
			/* merge private keys with the same ID and
			 * different usage bits */
			struct pkcs15_prkey_object *other, **pp;

			other = (struct pkcs15_prkey_object *) obj;
			if (sc_pkcs15_compare_id(&other->prv_info->id, id)) {
				obj->base.flags |= SC_PKCS11_OBJECT_HIDDEN;
				for (pp = &pk->prv_next; *pp; pp = &(*pp)->prv_next)
					;
				*pp = (struct pkcs15_prkey_object *) obj;
			}
		}
		else if (is_pubkey(obj) && !pk->prv_pubkey) {
			struct pkcs15_pubkey_object *pubkey;

			pubkey = (struct pkcs15_pubkey_object *) obj;
			if (sc_pkcs15_compare_id(&pubkey->pub_info->id, id)) {
				sc_log(context, "Associating object %d as public key", i);
				pk->prv_pubkey = pubkey;
				if (pubkey->pub_data) {
					sc_pkcs15_dup_pubkey(context, pubkey->pub_data, &pk->pub_data);
					if (pk->prv_info->modulus_length == 0)
						pk->prv_info->modulus_length = pubkey->pub_info->modulus_length;
				}
			}
		}
	}
}


static void
__pkcs15_cert_bind_related(struct pkcs15_fw_data *fw_data, struct pkcs15_cert_object *cert)
{
	struct sc_pkcs15_cert *c1 = cert->cert_data;
	struct sc_pkcs15_id *id = &cert->cert_info->id;
	unsigned int i;

	sc_log(context, "Object is a certificate and has id %s", sc_pkcs15_print_id(id));

	/* Loop over all objects to see if we find the certificate of
	 * the issuer and the associated private key */
	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		if (is_cert(obj) && obj != (struct pkcs15_any_object *) cert) {
			struct pkcs15_cert_object *cert2;
			struct sc_pkcs15_cert *c2;

			cert2 = (struct pkcs15_cert_object *) obj;
			c2 = cert2->cert_data;

			if (!c1 || !c2 || !c1->issuer_len || !c2->subject_len)
				continue;
			if (c1->issuer_len == c2->subject_len
			 && !memcmp(c1->issuer, c2->subject, c1->issuer_len)) {
				sc_log(context, "Associating object %d (id %s) as issuer",
						i, sc_pkcs15_print_id(&cert2->cert_info->id));
				cert->cert_issuer = (struct pkcs15_cert_object *) obj;
				return;
			}
		} else
		if (is_privkey(obj) && !cert->cert_prvkey) {
			struct pkcs15_prkey_object *pk;

			pk = (struct pkcs15_prkey_object *) obj;
			if (sc_pkcs15_compare_id(&pk->prv_info->id, id)) {
				sc_log(context, "Associating object %d as private key", i);
				cert->cert_prvkey = pk;
			}
		}
	}
}

static void
pkcs15_bind_related_objects(struct pkcs15_fw_data *fw_data)
{
	unsigned int i;

	/* Loop over all private keys and attached related certificate
	 * and/or public key
	 */
	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		if (obj->base.flags & SC_PKCS11_OBJECT_HIDDEN)
			continue;

		sc_log(context, "Looking for objects related to object %d", i);
		if (is_privkey(obj))
			__pkcs15_prkey_bind_related(fw_data, (struct pkcs15_prkey_object *) obj);
		else if (is_cert(obj))
			__pkcs15_cert_bind_related(fw_data, (struct pkcs15_cert_object *) obj);
	}
}


/* We deferred reading of the cert until needed, as it may be
 * a private object, so we must wait till login to read  */
static int
check_cert_data_read(struct pkcs15_fw_data *fw_data, struct pkcs15_cert_object *cert)
{
	struct pkcs15_pubkey_object *obj2;
	int rv;

	if (!cert)
		return SC_ERROR_OBJECT_NOT_FOUND;

	if (cert->cert_data)
		return 0;
	rv = sc_pkcs15_read_certificate(fw_data->p15_card, cert->cert_info, &cert->cert_data);
	if (rv < 0)
		return rv;

	obj2 = cert->cert_pubkey;
	/* make a copy of public key from the cert data */
	if (!obj2->pub_data)
		rv = sc_pkcs15_pubkey_from_cert(context, &cert->cert_data->data, &obj2->pub_data);

	/* Find missing labels for certificate */
	pkcs15_cert_extract_label(cert);

	/* now that we have the cert and pub key, lets see if we can bind anything else */
	pkcs15_bind_related_objects(fw_data);

	return rv;
}


static void
pkcs15_add_object(struct sc_pkcs11_slot *slot, struct pkcs15_any_object *obj,
		  CK_OBJECT_HANDLE_PTR pHandle)
{
	unsigned int i;
	struct pkcs15_fw_data *card_fw_data;
	CK_OBJECT_HANDLE handle =
		(CK_OBJECT_HANDLE)(uintptr_t)obj; /* cast pointer to long, will truncate on Win64 */

	if (obj == NULL || slot == NULL)
		return;
	if (obj->base.flags & (SC_PKCS11_OBJECT_HIDDEN | SC_PKCS11_OBJECT_RECURS))
		return;

	if (list_contains(&slot->objects, obj))
		return;

	if (pHandle != NULL)
		*pHandle = handle;

	list_append(&slot->objects, obj);
	sc_log(context, "Slot:%lX Setting object handle of 0x%lx to 0x%lx",
		   slot->id, obj->base.handle, handle);
	obj->base.handle = handle;
	obj->base.flags |= SC_PKCS11_OBJECT_SEEN;
	obj->refcount++;

	/* Add related objects
	 * XXX prevent infinite recursion when a card specifies two certificates
	 * referring to each other.
	 */
	obj->base.flags |= SC_PKCS11_OBJECT_RECURS;

	switch (__p15_type(obj)) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PRKEY_EC:
		if (slot->p11card != NULL) {
			pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
			if (!slot->p11card)
				return;
			card_fw_data = (struct pkcs15_fw_data *) slot->p11card->fws_data[slot->fw_data_idx];
			for (i = 0; i < card_fw_data->num_objects; i++) {
				struct pkcs15_any_object *obj2 = card_fw_data->objects[i];
				struct pkcs15_cert_object *cert;

				if (!is_cert(obj2))
					continue;

				cert = (struct pkcs15_cert_object*) obj2;

				if ((struct pkcs15_any_object*)(cert->cert_prvkey) != obj)
					continue;

				pkcs15_add_object(slot, obj2, NULL);
			}
		}
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_cert, NULL);
		break;
	}

	obj->base.flags &= ~SC_PKCS11_OBJECT_RECURS;
}


static void
pkcs15_init_slot(struct sc_pkcs15_card *p15card, struct sc_pkcs11_slot *slot,
		struct sc_pkcs15_object *auth, struct sc_app_info *app_info)
{
	struct pkcs15_slot_data *fw_data;
	struct sc_pkcs15_auth_info *pin_info = NULL;
	int write_protected;
	scconf_block *atrblock;

	sc_log(context, "Called");
	pkcs15_init_token_info(p15card, &slot->token_info);
	slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
	if (auth != NULL)
		slot->token_info.flags |= CKF_USER_PIN_INITIALIZED;

	if ((p15card->card->reader->capabilities & SC_READER_CAP_PIN_PAD) || (p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH))
		slot->token_info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;

	if (p15card->card->caps & SC_CARD_CAP_RNG && p15card->card->ops->get_challenge != NULL)
		slot->token_info.flags |= CKF_RNG;

	if (p15card->tokeninfo && p15card->tokeninfo->flags & SC_PKCS15_TOKEN_READONLY) {
		write_protected = 1;
	} else {
		write_protected = 0;
	}
	atrblock = _sc_match_atr_block(p15card->card->ctx, NULL, &p15card->card->atr);
	if (atrblock) {
		write_protected = scconf_get_bool(atrblock, "read_only", write_protected);
	}
	if (write_protected) {
		slot->token_info.flags |= CKF_WRITE_PROTECTED;
	}

	slot->fw_data = fw_data = calloc(1, sizeof(*fw_data));
	if (!fw_data) {
		return;
	}
	fw_data->auth_obj = auth;

	if (auth != NULL) {
		pin_info = (struct sc_pkcs15_auth_info*) auth->data;

		if (pin_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)   {
			pin_info = NULL;
		}
		else   {
			size_t pin_len = 0;
			if (auth->label[0] && strncmp(auth->label, "PIN", 4) != 0)
				pin_len = strlen(auth->label);

			if (pin_len) {
				size_t tokeninfo_len = 0;
				if (p15card->tokeninfo)
					tokeninfo_len = strlen(p15card->tokeninfo->label);
				/* Print the possibly truncated token label with at least 4
				 * characters followed by the PIN label in paranthesis */
				if (tokeninfo_len == 0
						|| pin_len + strlen("L... ()") > 32) {
					/* There is no token label or it doesn't fit,
					 * print only PIN label */
					strcpy_bp(slot->token_info.label, auth->label, 32);
				} else {
					size_t max_tokeninfo_len = MIN(tokeninfo_len,
							32 - pin_len - strlen(" ()"));
					strcpy_bp(slot->token_info.label,
							p15card->tokeninfo->label,
							max_tokeninfo_len);
					slot->token_info.label[max_tokeninfo_len]           = ' ';
					slot->token_info.label[max_tokeninfo_len+1]         = '(';
					slot->token_info.label[max_tokeninfo_len+2+pin_len] = ')';
					strcpy_bp(slot->token_info.label+max_tokeninfo_len+2,
							auth->label, pin_len);
				}
			} else {
				/* PIN label is empty or just says non-useful "PIN",
				 * print only token label */
				strcpy_bp(slot->token_info.label,
						p15card->tokeninfo ? p15card->tokeninfo->label : "",
						32);
			}
			slot->token_info.flags |= CKF_LOGIN_REQUIRED;
		}
	}

	if (pin_info) {
		slot->token_info.ulMaxPinLen = pin_info->attrs.pin.max_length;
		slot->token_info.ulMinPinLen = pin_info->attrs.pin.min_length;
	}
	else {
		/* choose reasonable defaults */
		slot->token_info.ulMaxPinLen = 8;
		slot->token_info.ulMinPinLen = 4;
		strcpy_bp(slot->token_info.label,
				p15card->tokeninfo ? p15card->tokeninfo->label : "",
				32);
	}

	slot->app_info = app_info;
	sc_log(context, "Initialized slot 0x%lx with token %*s", slot->id,
			(int)sizeof(slot->token_info.label), slot->token_info.label);
}


static CK_RV
pkcs15_create_slot(struct sc_pkcs11_card *p11card, struct pkcs15_fw_data *fw_data,
		struct sc_pkcs15_object *auth, struct sc_app_info *app_info,
		struct sc_pkcs11_slot **out)
{
	struct sc_pkcs11_slot *slot = NULL;
	CK_RV rv;

	rv = slot_allocate(&slot, p11card);
	if (rv != CKR_OK)
		return rv;

	/* There's a token in this slot */
	slot->slot_info.flags |= CKF_TOKEN_PRESENT;

	/* Fill in the slot/token info from pkcs15 data */
	if (fw_data)
		pkcs15_init_slot(fw_data->p15_card, slot, auth, app_info);
	else {
		/* Token is not initialized, announce pinpad capability nevertheless */
		if (slot->reader->capabilities & SC_READER_CAP_PIN_PAD)
			slot->token_info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
	}

	*out = slot;
	return CKR_OK;
}


static int
_pkcs15_create_typed_objects(struct pkcs15_fw_data *fw_data)
{
	int rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_PRKEY_RSA, "RSA private key",
			__pkcs15_create_prkey_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_PUBKEY_RSA, "RSA public key",
			__pkcs15_create_pubkey_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_PRKEY_EC, "EC private key",
			__pkcs15_create_prkey_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_PUBKEY_EC, "EC public key",
			__pkcs15_create_pubkey_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_PRKEY_GOSTR3410, "GOSTR3410 private key",
			__pkcs15_create_prkey_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_PUBKEY_GOSTR3410, "GOSTR3410 public key",
			__pkcs15_create_pubkey_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_CERT_X509, "certificate",
			__pkcs15_create_cert_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_DATA_OBJECT, "data object",
			__pkcs15_create_data_object);
	if (rv < 0)
		return rv;

	rv = pkcs15_create_pkcs11_objects(fw_data, SC_PKCS15_TYPE_SKEY_GENERIC, "Generic secret key",
			__pkcs15_create_secret_key_object);
	if (rv < 0)
		return rv;

	/* Match up related keys and certificates */
	pkcs15_bind_related_objects(fw_data);
	sc_log(context, "found %i FW objects", fw_data->num_objects);

	return rv;
}


int
_is_slot_auth_object(struct sc_pkcs15_auth_info *pin_info)
{

	/* Ignore all but PIN authentication objects */
	if (pin_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 0;

	/* Ignore any non-authentication PINs */
	if ((pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN) != 0)
		return 0;

	/* Ignore unblocking pins */
	if (!sc_pkcs11_conf.create_puk_slot)
		if (pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
			return 0;

	return 1;
}

int slot_get_logged_in_state(struct sc_pkcs11_slot *slot)
{
	int logged_in = SC_PIN_STATE_UNKNOWN;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *pin_info;

	if (slot->p11card == NULL) {
		goto out;
	}

	fw_data = (struct pkcs15_fw_data *) slot->p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		goto out;
	p15card = fw_data->p15_card;

	if (slot->login_user == CKU_SO) {
		sc_pkcs15_find_so_pin(p15card, &pin_obj);
	} else {
		pin_obj = slot_data_auth(slot->fw_data);
	}

	if (!pin_obj)
		goto out;

	pin_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
	if (!pin_info)
		goto out;
	sc_pkcs15_get_pin_info(p15card, pin_obj);
	logged_in = pin_info->logged_in;
out:
	return logged_in;
}


struct sc_pkcs15_object *
_get_auth_object_by_name(struct sc_pkcs15_card *p15card, char *name)
{
	struct sc_pkcs15_object *out = NULL;
	int rv = SC_ERROR_OBJECT_NOT_FOUND;

	/* please keep me in sync with md_get_pin_by_role() in minidriver */
	if (!strcmp(name, "UserPIN"))   {
		/* Try to get 'global' PIN; if no, get the 'local' one */
		rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &out);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
					SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &out);
	}
	else if (!strcmp(name, "SignPIN"))   {
		int idx = 0;

		/* Get the 'global' user PIN */
		rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &out);
		if (!rv)   {
			/* Global (user) PIN exists, get the local one -- sign PIN */
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
					SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &out);
		}
		else   {
			/* No global PIN, try to get first local one -- user PIN */
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
					SC_PKCS15_PIN_TYPE_FLAGS_MASK, &idx, &out);
			if (!rv)   {
				/* User PIN is local, try to get the second local -- sign PIN */
				idx++;
				rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
						SC_PKCS15_PIN_TYPE_FLAGS_MASK, &idx, &out);
			}
		}
	}
	else if (!strcmp(name, "UserPUK"))   {
		/* Get the 'global' PUK; if no, get the 'local' one */
		rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &out);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL,
					SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &out);
	}
	else if (!strcmp(name, "SignPUK"))   {
		/* TODO: Sign PUK to be defined */
	}
	else if (!strcmp(name, "SoPIN"))   {
		rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_SOPIN,
				SC_PKCS15_PIN_TYPE_FLAGS_SOPIN, NULL, &out);
	}

	return rv ? NULL : out;
}


static void
_add_pin_related_objects(struct sc_pkcs11_slot *slot, struct sc_pkcs15_object *pin_obj,
		struct pkcs15_fw_data *fw_data, struct pkcs15_fw_data *move_to_fw)
{
	struct sc_pkcs15_auth_info *pin_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
	unsigned i;

	sc_log(context, "Add objects related to PIN('%.*s',ID:%s)", (int) sizeof pin_obj->label, pin_obj->label, sc_pkcs15_print_id(&pin_info->auth_id));
	for (i=0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		/* "Fake" objects we've generated */
		if (__p15_type(obj) == (unsigned int)-1)
			continue;
		/* Some objects have an auth_id even though they are
		 * not private. Just ignore those... */
		if (!(obj->p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE))
			continue;
		sc_log(context, "ObjID(%p,%.*s,%x):%s", obj, (int) sizeof obj->p15_object->label, obj->p15_object->label,
				obj->p15_object->type, sc_pkcs15_print_id(&obj->p15_object->auth_id));
		if (!sc_pkcs15_compare_id(&pin_info->auth_id, &obj->p15_object->auth_id))   {
			sc_log(context, "Ignoring object %d", i);
			continue;
		}

		if (is_privkey(obj)) {
			sc_log(context, "Slot:%p, obj:%p  Adding private key %d to PIN '%.*s'", slot, obj, i, (int) sizeof pin_obj->label, pin_obj->label);
			pkcs15_add_object(slot, obj, NULL);
		}
		else if (is_data(obj)) {
			sc_log(context, "Slot:%p Adding data object %d to PIN '%.*s'", slot, i, (int) sizeof pin_obj->label, pin_obj->label);
			pkcs15_add_object(slot, obj, NULL);
		}
		else if (is_cert(obj)) {
			sc_log(context, "Slot:%p Adding cert object %d to PIN '%.*s'", slot, i, (int) sizeof pin_obj->label, pin_obj->label);
			pkcs15_add_object(slot, obj, NULL);
		}
		else if (is_skey(obj)) {
			sc_log(context, "Slot:%p Adding secret key object %d to PIN '%.*s'", slot, i, (int) sizeof pin_obj->label, pin_obj->label);
			pkcs15_add_object(slot, obj, NULL);
		}
		else   {
			sc_log(context, "Slot:%p Object %d skipped", slot, i);
			continue;
		}

		if (move_to_fw && move_to_fw != fw_data && move_to_fw->num_objects < MAX_OBJECTS)   {
			int tail = fw_data->num_objects - i - 1;

			move_to_fw->objects[move_to_fw->num_objects++] = obj;
			if (tail)
				memcpy(&fw_data->objects[i], &fw_data->objects[i + 1], sizeof(fw_data->objects[0]) * tail);
			i--;
			fw_data->num_objects--;
		}
	}
}


static void
_add_public_objects(struct sc_pkcs11_slot *slot, struct pkcs15_fw_data *fw_data)
{
	unsigned i;

	if (slot == NULL || fw_data == NULL)
		return;

	sc_log(context, "%i public objects to process", fw_data->num_objects);
	for (i=0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		/* "Fake" objects we've generated */
		if (__p15_type(obj) == (unsigned int)-1)
			continue;
		/* Ignore seen object */
		if (obj->base.flags & SC_PKCS11_OBJECT_SEEN)
			continue;
		/* Ignore 'private' object */
		if (obj->p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE)
			continue;
		/* PKCS#15 4.1.3 is a little vague, but implies if not PRIVATE it is readable
		 * even if there is an auth_id to allow writing for example.
		 * See bug issue #291
		 * treat pubkey and cert as readable.a
		 */
		if (obj->p15_object->auth_id.len && !(is_pubkey(obj) || is_cert(obj)))
			continue;

		sc_log(context, "Add public object(%p,%.*s,%x)", obj, (int) sizeof obj->p15_object->label, obj->p15_object->label, obj->p15_object->type);
		pkcs15_add_object(slot, obj, NULL);
	}
}


static CK_RV
pkcs15_create_tokens(struct sc_pkcs11_card *p11card, struct sc_app_info *app_info)
{
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15_object *auth_user_pin = NULL, *auth_sign_pin = NULL;
	struct sc_pkcs11_slot *slot = NULL, *sign_slot = NULL;
	unsigned int cs_flags = sc_pkcs11_conf.create_slots_flags;
	CK_RV rv;
	int rc, i, idx;

	if (p11card) {
		sc_log(context, "create PKCS#15 tokens; fws:%p,%p,%p", p11card->fws_data[0], p11card->fws_data[1], p11card->fws_data[2]);
	}
	sc_log(context, "create slots flags 0x%X", cs_flags);

	/* Find out framework data corresponding to the given application */
	fw_data = get_fw_data(p11card, app_info, &idx);
	if (!fw_data)   {
		if (p11card) {
			sc_log(context, "Create slot for the non-binded card");
			pkcs15_create_slot(p11card, NULL, NULL, app_info, &slot);
		}
		return CKR_OK;
	}
	sc_log(context, "Use FW data with index %i; fw_data->p15_card %p", idx, fw_data->p15_card);

	/* Try to identify UserPIN and SignPIN by their symbolic name */
	auth_user_pin = _get_auth_object_by_name(fw_data->p15_card, "UserPIN");
	if (cs_flags & SC_PKCS11_SLOT_FOR_PIN_SIGN)
		auth_sign_pin = _get_auth_object_by_name(fw_data->p15_card, "SignPIN");
	sc_log(context, "Flags:0x%X; Auth User/Sign PINs %p/%p", cs_flags, auth_user_pin, auth_sign_pin);

	/* Add PKCS#15 objects of the known types to the framework data */
	rc = _pkcs15_create_typed_objects(fw_data);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, NULL);
	sc_log(context, "Found %d FW objects objects", fw_data->num_objects);

	/* Create slots for all non-unblock, non-so PINs if:
	 *  - 'UserPIN' cannot be identified (VT: for some cards with incomplete PIN flags);
	 *  - configuration impose to create slot for all PINs.
	 */
	if (!auth_user_pin || cs_flags & SC_PKCS11_SLOT_CREATE_ALL)   {
		struct sc_pkcs15_object *auths[MAX_OBJECTS];
		int auth_count;

		memset(auths, 0, sizeof(auths));
		/* Get authentication PKCS#15 objects present in the associated on-card application */
		rc = sc_pkcs15_get_objects(fw_data->p15_card, SC_PKCS15_TYPE_AUTH_PIN, auths, SC_PKCS15_MAX_PINS);
		if (rc < 0)
			return sc_to_cryptoki_error(rc, NULL);
		auth_count = rc;
		sc_log(context, "Found %d authentication objects", auth_count);

		for (i = 0; i < auth_count; i++) {
			struct sc_pkcs15_auth_info *pin_info = (struct sc_pkcs15_auth_info*)auths[i]->data;
			struct sc_pkcs11_slot *islot = NULL;

			/* Check if a slot could be created with this PIN */
			if (!_is_slot_auth_object(pin_info))
				continue;
			sc_log(context, "Found authentication object '%.*s'", (int) sizeof auths[i]->label, auths[i]->label);

			rv = pkcs15_create_slot(p11card, fw_data, auths[i], app_info, &islot);
			if (rv != CKR_OK)
				return CKR_OK; /* no more slots available for this card */
			islot->fw_data_idx = idx;
			_add_pin_related_objects(islot, auths[i], fw_data, NULL);

			/* Get slot to which the public objects will be associated */
			if (!slot && !auth_user_pin)
				slot = islot;
			else if (!slot && auth_user_pin && auth_user_pin == auths[i])
				slot = islot;
		}
	}
	else   {
		sc_log(context, "User/Sign PINs %p/%p", auth_user_pin, auth_sign_pin);
		if (auth_user_pin && (cs_flags & SC_PKCS11_SLOT_FOR_PIN_USER)) {
			/* For the UserPIN of the first slot create slot */
			sc_log(context, "Create slot for User PIN '%.*s'", (int) sizeof auth_user_pin->label, auth_user_pin->label);
			rv = pkcs15_create_slot(p11card, fw_data, auth_user_pin, app_info, &slot);
			if (rv != CKR_OK)
				return CKR_OK; /* no more slots available for this card */
			slot->fw_data_idx = idx;
			_add_pin_related_objects(slot, auth_user_pin, fw_data, NULL);
		}

		if (auth_sign_pin && (cs_flags & SC_PKCS11_SLOT_FOR_PIN_SIGN))   {
			/* Only Sign PIN slot needs to be exposed */
			sc_log(context, "Create slot for Sign PIN '%.*s'", (int) sizeof auth_sign_pin->label, auth_sign_pin->label);
			rv = pkcs15_create_slot(p11card, fw_data, auth_sign_pin, app_info, &sign_slot);
			if (rv != CKR_OK)
				return CKR_OK; /* no more slots available for this card */
			sign_slot->fw_data_idx = idx;
			_add_pin_related_objects(sign_slot, auth_sign_pin, fw_data, NULL);
		}

		if (!slot && sign_slot)
			slot = sign_slot;
	}

	if (!slot && (cs_flags == SC_PKCS11_SLOT_CREATE_ALL))   {
		sc_log(context, "Now create slot without AUTH object");
		pkcs15_create_slot(p11card, fw_data, NULL, app_info, &slot);
		sc_log(context, "Created slot without AUTH object: %p", slot);
	}

	if (slot)   {
		sc_log(context, "Add public objects to slot %p", slot);
		_add_public_objects(slot, fw_data);
	}

	sc_log(context, "All tokens created");
	return CKR_OK;
}


static CK_RV
pkcs15_release_token(struct sc_pkcs11_card *p11card, void *fw_token)
{
	sc_log(context, "pkcs15_release_token() not implemented");
	free(fw_token);
	return CKR_FUNCTION_REJECTED;
}


static CK_RV
pkcs15_login(struct sc_pkcs11_slot *slot, CK_USER_TYPE userType,
		CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	struct sc_pkcs11_card *p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_pkcs15_object *auth_object = NULL;
	struct sc_pkcs15_auth_info *pin_info = NULL;
	int rc;

	if (slot->p11card == NULL) {
		return CKR_TOKEN_NOT_RECOGNIZED;
	}
	p11card = slot->p11card;

	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_Login");
	p15card = fw_data->p15_card;

	sc_log(context, "pkcs15-login: userType 0x%lX, PIN length %li", userType, ulPinLen);
	switch (userType) {
	case CKU_USER:
		auth_object = slot_data_auth(slot->fw_data);
		if (auth_object == NULL)
			return CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case CKU_SO:
		/* A card with no SO PIN is treated as if no SO login
		 * is required */
		rc = sc_pkcs15_find_so_pin(p15card, &auth_object);
		sc_log(context, "pkcs15-login: find SO PIN: rc %i", rc);

		/* If there's no SO PIN on the card, silently
		 * accept any PIN, and lock the card if required */
		if (rc == SC_ERROR_OBJECT_NOT_FOUND)   {
			rc = 0;
			if (sc_pkcs11_conf.lock_login)
				rc = lock_card(fw_data);

			if (sc_pkcs11_conf.pin_unblock_style == SC_PKCS11_PIN_UNBLOCK_SO_LOGGED_INITPIN)   {
				if (ulPinLen && ulPinLen < sizeof(fw_data->user_puk))   {
					memcpy(fw_data->user_puk, pPin, ulPinLen);
					fw_data->user_puk_len = (unsigned int) ulPinLen;
				}
			}

			sc_log(context, "No SOPIN found; returns %d", rc);
			return sc_to_cryptoki_error(rc, "C_Login");
		}
		else if (rc < 0)   {
			return sc_to_cryptoki_error(rc, "C_Login");
		}

		break;
	case CKU_CONTEXT_SPECIFIC:
		/*
		 * A session should already be open for user or SO
		 * All we need to do is authenticate to the card
		 * using the correct auth_object.
		 * TODO: handle the CK_SO case
		 */
		sc_log(context, "context specific login %d", slot->login_user);
		if (slot->login_user == CKU_USER) {
			auth_object = slot_data_auth(slot->fw_data);
			if (auth_object == NULL)
				return CKR_USER_PIN_NOT_INITIALIZED;
			break;
		}
		/* TODO looks like this was never executed,
		 * And even if it was, why the lock as a session
		 * should already be open and the card locked.
		 */
		/* For a while, used only to unblock User PIN. */
		rc = 0;
		if (sc_pkcs11_conf.lock_login)
			rc = lock_card(fw_data);
		sc_log(context, "context specific login returns %d", rc);
		return sc_to_cryptoki_error(rc, "C_Login");
	default:
		return CKR_USER_TYPE_INVALID;
	}
	pin_info = (struct sc_pkcs15_auth_info *) auth_object->data;
	if (pin_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return CKR_FUNCTION_REJECTED;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	if (p11card->card->reader->capabilities & SC_READER_CAP_PIN_PAD
			|| (p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH)) {
		/* pPin should be NULL in case of a pin pad reader, but
		 * some apps (e.g. older Netscapes) don't know about it.
		 * So we don't require that pPin == NULL, but set it to
		 * NULL ourselves. This way, you can supply an empty (if
		 * possible) or fake PIN if an application asks a PIN).
		 */
		/* But we want to be able to specify a PIN on the command
		 * line (e.g. for the test scripts). So we don't do anything
		 * here - this gives the user the choice of entering
		 * an empty pin (which makes us use the pin pad) or
		 * a valid pin (which is processed normally). --okir */
		if (ulPinLen == 0)
			pPin = NULL;
	}

	/* By default, we make the reader resource manager keep other
	 * processes from accessing the card while we're logged in.
	 * Otherwise an attacker could perform some crypto operation
	 * after we've authenticated with the card */

	/* Context specific login is not real login but only a
	 * reassertion of the PIN to the card.
	 * And we don't want to do any extra operations to the card
	 * that could invalidate the assertion of the pin
	 * before the crypto operation that requires the assertion
	 */
	if (userType != CKU_CONTEXT_SPECIFIC) {
		if (sc_pkcs11_conf.lock_login && (rc = lock_card(fw_data)) < 0)   {
			return sc_to_cryptoki_error(rc, "C_Login");
		}
	}

	if (userType  == CKU_CONTEXT_SPECIFIC) {
		int auth_meth_saved = pin_info->auth_method;

		sc_log(context, "Setting SC_AC_CONTEXT_SPECIFIC");
		pin_info->auth_method = SC_AC_CONTEXT_SPECIFIC;
		rc = sc_pkcs15_verify_pin(p15card, auth_object, pPin, ulPinLen);
		pin_info->auth_method = auth_meth_saved;
	} else
		rc = sc_pkcs15_verify_pin(p15card, auth_object, pPin, ulPinLen);

	sc_log(context, "PKCS15 verify PIN returned %d", rc);

	if (rc != SC_SUCCESS)
		return sc_to_cryptoki_error(rc, "C_Login");

	if (userType == CKU_USER)   {
		sc_pkcs15_object_t *p15_obj = p15card->obj_list;
		sc_pkcs15_search_key_t sk;

		sc_log(context, "Check if pkcs15 object list can be completed.");

		/* Ensure non empty list */
		if (p15_obj == NULL)
			return CKR_OK;

		/* Select last object in list */
		while(p15_obj->next)
			p15_obj = p15_obj->next;

		/* Trigger enumeration of EF.XXX files */
		memset(&sk, 0, sizeof(sk));
		sk.class_mask = SC_PKCS15_SEARCH_CLASS_PRKEY | SC_PKCS15_SEARCH_CLASS_PUBKEY |
				SC_PKCS15_SEARCH_CLASS_CERT  | SC_PKCS15_SEARCH_CLASS_DATA;
		sc_pkcs15_search_objects(p15card, &sk, NULL, 0);

		/* Iterate over newly discovered objects */
		while(p15_obj->next) {
			struct pkcs15_any_object *fw_obj;

			p15_obj = p15_obj->next;

			if (!sc_pkcs15_compare_id(&pin_info->auth_id, &p15_obj->auth_id))
				continue;

			switch (p15_obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
			case SC_PKCS15_TYPE_PRKEY:
				__pkcs15_create_prkey_object(fw_data, p15_obj, &fw_obj); break;
			case SC_PKCS15_TYPE_PUBKEY:
				__pkcs15_create_pubkey_object(fw_data, p15_obj, &fw_obj); break;
			case SC_PKCS15_TYPE_CERT:
				__pkcs15_create_cert_object(fw_data, p15_obj, &fw_obj); break;
			case SC_PKCS15_TYPE_DATA_OBJECT:
				__pkcs15_create_data_object(fw_data, p15_obj, &fw_obj); break;
			default: continue;
			}

			sc_log(context, "new object found: type=0x%03X", p15_obj->type);
			pkcs15_add_object(slot, fw_obj, NULL);
		}
	}

	return CKR_OK;
}


static CK_RV
pkcs15_logout(struct sc_pkcs11_slot *slot)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	CK_RV ret = CKR_OK;
	int rc;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_Logout");

	memset(fw_data->user_puk, 0, sizeof(fw_data->user_puk));
	fw_data->user_puk_len = 0;

	sc_pkcs15_pincache_clear(fw_data->p15_card);

	rc = sc_logout(fw_data->p15_card->card);

	/* Ignore missing card specific logout functions. #302 */
	if (rc == SC_ERROR_NOT_SUPPORTED)
		rc = SC_SUCCESS;

	if (rc != SC_SUCCESS)
		ret = sc_to_cryptoki_error(rc, "C_Logout");

	if (sc_pkcs11_conf.lock_login) {
		rc = unlock_card(fw_data);
		if (rc != SC_SUCCESS)
			ret = sc_to_cryptoki_error(rc, "C_Logout");
	}

	/* TODO DEE free any session objects ? */

	return ret;
}


static CK_RV
pkcs15_change_pin(struct sc_pkcs11_slot *slot,
		CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
		CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct sc_pkcs15_card *p15card = NULL;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
	struct sc_pkcs15_object *pin_obj = NULL;
	int login_user = slot->login_user;
	int rc;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_SetPin");

	p15card = fw_data->p15_card;

	if (login_user == CKU_SO) {
		rc = sc_pkcs15_find_so_pin(p15card, &pin_obj);
		sc_log(context, "pkcs15-login: find SO PIN: rc %i", rc);
	} else {
		pin_obj = slot_data_auth(slot->fw_data);
	}

	if (!pin_obj)
		return CKR_USER_PIN_NOT_INITIALIZED;

	auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
	if (!auth_info)
		return CKR_USER_PIN_NOT_INITIALIZED;

	sc_log(context, "Change '%.*s' (ref:%i,type:%i)", (int) sizeof pin_obj->label, pin_obj->label, auth_info->attrs.pin.reference, login_user);
	if ((p11card->card->reader->capabilities & SC_READER_CAP_PIN_PAD)
			|| (p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH)) {
		/* pPin should be NULL in case of a pin pad reader, but
		 * some apps (e.g. older Netscapes) don't know about it.
		 * So we don't require that pPin == NULL, but set it to
		 * NULL ourselves. This way, you can supply an empty (if
		 * possible) or fake PIN if an application asks a PIN).
		 */
		pOldPin = pNewPin = NULL;
		ulOldLen = ulNewLen = 0;
	}
	else if (ulNewLen < auth_info->attrs.pin.min_length || ulNewLen > auth_info->attrs.pin.max_length)  {
		return CKR_PIN_LEN_RANGE;
	}

	if (login_user < 0) {
		if (sc_pkcs11_conf.pin_unblock_style != SC_PKCS11_PIN_UNBLOCK_UNLOGGED_SETPIN) {
			sc_log(context, "PIN unlock is not allowed in unlogged session");
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
		rc = sc_pkcs15_unblock_pin(fw_data->p15_card, pin_obj, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	else if (login_user == CKU_CONTEXT_SPECIFIC)   {
		if (sc_pkcs11_conf.pin_unblock_style != SC_PKCS11_PIN_UNBLOCK_SCONTEXT_SETPIN) {
			sc_log(context, "PIN unlock is not allowed with CKU_CONTEXT_SPECIFIC login");
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
		rc = sc_pkcs15_unblock_pin(fw_data->p15_card, pin_obj, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	else if ((login_user == CKU_USER) || (login_user == CKU_SO)) {
		rc = sc_pkcs15_change_pin(fw_data->p15_card, pin_obj, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	else {
		sc_log(context, "cannot change PIN: non supported login type: %i", login_user);
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	sc_log(context, "PIN change returns %d", rc);
	return sc_to_cryptoki_error(rc, "C_SetPIN");
}



#ifdef USE_PKCS15_INIT
static CK_RV
pkcs15_initialize(struct sc_pkcs11_slot *slot, void *ptr,
		CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		CK_UTF8CHAR_PTR pLabel)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct sc_cardctl_pkcs11_init_token args;
	scconf_block *conf_block = NULL;
	int rc, enable_InitToken = 0;
	CK_RV rv;

	sc_log(context, "Get 'enable-InitToken' card configuration option");
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	conf_block = sc_get_conf_block(p11card->card->ctx, "framework", "pkcs15", 1);
	enable_InitToken = scconf_get_bool(conf_block, "pkcs11_enable_InitToken", 0);

	memset(&args, 0, sizeof(args));
	args.so_pin = pPin;
	args.so_pin_len = ulPinLen;
	args.label = (const char *) pLabel;

	sc_log(context, "Try card specific token initialize procedure");
	rc = sc_card_ctl(p11card->card, SC_CARDCTL_PKCS11_INIT_TOKEN, &args);
	if (rc == SC_ERROR_NOT_SUPPORTED && enable_InitToken)   {
		struct sc_profile *profile = NULL;
		struct pkcs15_fw_data *fw_data = NULL;
		struct sc_pkcs15_card *p15card = NULL;

		sc_log(context, "Using generic token initialize procedure");
		fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
		if (!fw_data)
			return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_Login");
		p15card = fw_data->p15_card;

		rc = sc_lock(p11card->card);
		if (rc < 0)
			return sc_to_cryptoki_error(rc, "C_InitToken");

		rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, NULL, &profile);
		if (rc < 0) {
			sc_log(context, "pkcs15init bind error %i", rc);
			sc_unlock(p11card->card);
			return sc_to_cryptoki_error(rc, "C_InitToken");
		}

		rc = sc_pkcs15init_finalize_profile(p11card->card, profile, NULL);
		if (rc) {
			sc_log(context, "finalize profile error %i", rc);
			return sc_to_cryptoki_error(rc, "C_InitToken");
		}

		sc_log(context, "set pkcs15init callbacks");
		pkcs15init_sopin = (char *)pPin;
		pkcs15init_sopin_len = ulPinLen;
		sc_pkcs15init_set_callbacks(&pkcs15init_callbacks);

		if (p15card)   {
			sc_log(context, "pkcs15init erase card");
			sc_pkcs15init_erase_card(p15card, profile, NULL);

			sc_log(context, "pkcs15init unbind");
			sc_pkcs15init_unbind(profile);

			rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, NULL, &profile);
			if (rc < 0) {
				sc_log(context, "pkcs15init bind error %i", rc);
				sc_pkcs15init_set_callbacks(NULL);
				sc_unlock(p11card->card);
				return sc_to_cryptoki_error(rc, "C_InitToken");
			}

			rc = sc_pkcs15init_finalize_profile(p11card->card, profile, NULL);
			if (rc) {
				sc_pkcs15init_set_callbacks(NULL);
				sc_log(context, "Cannot finalize profile: %i", rc);
				return sc_to_cryptoki_error(rc, "C_InitToken");
			}
		}
		else   {
			sc_log(context, "No erase for the non-initialized card");
		}

		if (!rc)  {
			struct sc_pkcs15init_initargs init_args;

			memset(&init_args, 0, sizeof(init_args));
			init_args.so_pin = pPin;
			init_args.so_pin_len = ulPinLen;
			init_args.label = (char *)pLabel;

			sc_log(context, "pkcs15init: create application on '%s' card", p11card->card->name);
			rc = sc_pkcs15init_add_app(p11card->card, profile, &init_args);
			sc_log(context, "pkcs15init: create application returns %i", rc);
		}

		pkcs15init_sopin = NULL;
		pkcs15init_sopin_len = 0;

		sc_log(context, "pkcs15init: unset callbacks");
		sc_pkcs15init_set_callbacks(NULL);

		sc_log(context, "pkcs15init: unbind");
		sc_pkcs15init_unbind(profile);

		sc_unlock(p11card->card);
	}

	if (rc < 0)   {
		sc_log(context, "init token error %i", rc);
		return sc_to_cryptoki_error(rc, "C_InitToken");
	}

	rv = card_removed(p11card->reader);
	if (rv != CKR_OK)   {
		sc_log(context, "remove card error 0x%lX", rv);
		return rv;
	}

	rv = card_detect_all();
	if (rv != CKR_OK)   {
		sc_log(context, "detect all card error 0x%lX", rv);
		return rv;
	}

	return CKR_OK;
}


static CK_RV
pkcs15_init_pin(struct sc_pkcs11_slot *slot, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15init_pinargs args;
	struct sc_profile	*profile = NULL;
	struct sc_pkcs15_object	*auth_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
	struct sc_cardctl_pkcs11_init_pin p11args;
	int rc;

	memset(&p11args, 0, sizeof(p11args));
	p11args.pin = pPin;
	p11args.pin_len = ulPinLen;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	rc = sc_card_ctl(p11card->card, SC_CARDCTL_PKCS11_INIT_PIN, &p11args);
	if (rc != SC_ERROR_NOT_SUPPORTED) {
		if (rc == SC_SUCCESS)
			return CKR_OK;
		return sc_to_cryptoki_error(rc, "C_InitPin");
	}

	sc_log(context, "Init PIN: pin %p:%lu; unblock style %i", pPin,
		ulPinLen, sc_pkcs11_conf.pin_unblock_style);

	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_InitPin");

	auth_info = slot_data_auth_info(slot->fw_data);
	if (auth_info && sc_pkcs11_conf.pin_unblock_style == SC_PKCS11_PIN_UNBLOCK_SO_LOGGED_INITPIN)   {
		/* C_InitPIN is used to unblock User PIN or set it in the SO session .*/
		auth_obj = slot_data_auth(slot->fw_data);
		if (fw_data->user_puk_len)
			rc = sc_pkcs15_unblock_pin(fw_data->p15_card, auth_obj,
					fw_data->user_puk, fw_data->user_puk_len, pPin, ulPinLen);
		else
			/* FIXME (VT): Actually sc_pkcs15_unblock_pin() do not accepts zero length PUK.
			 * Something like sc_pkcs15_set_pin() should be introduced.
			 * For a while, use the 'libopensc' API to set PIN. */
			rc = sc_reset_retry_counter(fw_data->p15_card->card, SC_AC_CHV, auth_info->attrs.pin.reference,
					NULL, 0, pPin, ulPinLen);

		return sc_to_cryptoki_error(rc, "C_InitPIN");
	}

	rc = sc_lock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_InitPIN");

	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, NULL, &profile);
	if (rc < 0) {
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rc, "C_InitPIN");
	}

	rc = sc_pkcs15init_finalize_profile(p11card->card, profile, NULL);
	if (rc != CKR_OK) {
		sc_log(context, "Cannot finalize profile: %i", rc);
		return sc_to_cryptoki_error(rc, "C_InitPIN");
	}

	memset(&args, 0, sizeof(args));
	args.label = "User PIN";
	args.pin = pPin;
	args.pin_len = ulPinLen;
	rc = sc_pkcs15init_store_pin(fw_data->p15_card, profile, &args);

	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_InitPIN");

	rc = sc_pkcs15_find_pin_by_auth_id(fw_data->p15_card, &args.auth_id, &auth_obj);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_InitPIN");

	/* Re-initialize the slot */
	free(slot->fw_data);
	pkcs15_init_slot(fw_data->p15_card, slot, auth_obj, slot->app_info);

	return CKR_OK;
}


static unsigned long
pkcs15_check_bool_cka(CK_ATTRIBUTE_PTR attr, unsigned long flag)
{
	if (attr->ulValueLen != sizeof(CK_BBOOL) || !attr->pValue)
		return 0;

	if (*((CK_BBOOL *)attr->pValue))
		return flag;

	return 0;
}


static CK_RV
pkcs15_create_private_key(struct sc_pkcs11_slot *slot, struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15init_prkeyargs args;
	struct pkcs15_any_object *key_any_obj = NULL;
	struct sc_pkcs15_object	*key_obj = NULL;
	struct sc_pkcs15_auth_info *pin = NULL;
	CK_KEY_TYPE key_type;
	struct sc_pkcs15_prkey_rsa *rsa = NULL;
	struct sc_pkcs15_prkey_gostr3410 *gost = NULL;
	int rc;
	CK_RV rv;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	memset(&args, 0, sizeof(args));
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_CreateObject");

	/* See if the "slot" is pin protected. If so, get the PIN id */
	if ((pin = slot_data_auth_info(slot->fw_data)) != NULL)
		args.auth_id = pin->auth_id;

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &key_type, NULL);
	if (rv != CKR_OK)
		return rv;
	switch (key_type) {
		case CKK_RSA:
			args.key.algorithm = SC_ALGORITHM_RSA;
			rsa = &args.key.u.rsa;
			break;
		case CKK_GOSTR3410:
			set_gost3410_params(&args, NULL, pTemplate, ulCount, NULL, 0);
			args.key.algorithm = SC_ALGORITHM_GOSTR3410;
			gost = &args.key.u.gostr3410;
			break;
		case CKK_EC:
			args.key.algorithm = SC_ALGORITHM_EC;
			/* TODO: -DEE Do not have PKCS15 card with EC to test this */
			/* fall through */
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;
		sc_pkcs15_bignum_t *bn = NULL;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
		case CKA_KEY_TYPE:
		case CKA_MODULUS_BITS:
		case CKA_PRIVATE:
			break;
		case CKA_LABEL:
			args.label = set_cka_label(attr, label);
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_MODULUS:
			bn = &rsa->modulus; break;
		case CKA_PUBLIC_EXPONENT:
			bn = &rsa->exponent; break;
		case CKA_PRIVATE_EXPONENT:
			bn = &rsa->d; break;
		case CKA_PRIME_1:
			bn = &rsa->p; break;
		case CKA_PRIME_2:
			bn = &rsa->q; break;
		case CKA_VALUE:
			if (key_type == CKK_GOSTR3410)
				bn = &gost->d;
			break;
		case CKA_SIGN:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_SIGN);
			break;
		case CKA_SIGN_RECOVER:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_SIGNRECOVER);
			break;
		case CKA_DECRYPT:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_DECRYPT);
			break;
		case CKA_UNWRAP:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_UNWRAP);
			break;
		case CKA_OPENSC_NON_REPUDIATION:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_NONREPUDIATION);
			break;
		case CKA_ALWAYS_AUTHENTICATE:
			args.user_consent = (int) (pkcs15_check_bool_cka(attr, 1));
			break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}

		if (bn) {
			if (attr->ulValueLen > 1024)   {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			bn->len = attr->ulValueLen;
			bn->data = (u8 *) attr->pValue;
		}
	}

	if (key_type == CKK_RSA)   {
		if (!rsa->modulus.len || !rsa->exponent.len || !rsa->d.len || !rsa->p.len || !rsa->q.len) {
			sc_log(context, "Template to store the RSA key is incomplete");
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto out;
		}
	}
	else if (key_type == CKK_GOSTR3410)   {
		if (!gost->d.len)   {
			sc_log(context, "Template to store the GOST key is incomplete");
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		/* CKA_VALUE arrives in little endian form. pkcs15init framework expects it in a big endian one. */
		rc = sc_mem_reverse(gost->d.data, gost->d.len);
		if (rc != SC_SUCCESS)  {
			rv = sc_to_cryptoki_error(rc, "C_CreateObject");
			goto out;
		}
	}

	rc = sc_pkcs15init_store_private_key(fw_data->p15_card, profile, &args, &key_obj);
	if (rc < 0) {
		rv = sc_to_cryptoki_error(rc, "C_CreateObject");
		goto out;
	}

	/* Create a new pkcs11 object for it */
	__pkcs15_create_prkey_object(fw_data, key_obj, &key_any_obj);
	pkcs15_add_object(slot, key_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}


/*
 * Secret key objects can be stored on card, if the card supports them
 *
 * Session objects have CKA_TOKEN=false
 *
 * CKA_TOKEN = FALSE can mean two things:
 *		1. If the card supports on card session objects, the object is stored on card for duration of the PKCS#11 session.
 *		   Depending on card implementation, it can be automatically deleted during the card's reset.
 *		   This kind of objects are not written to the PKCS#15 directory file.
 *		2. If the card doesn't support on card session objects, a CKA_TOKEN = FALSE object is stored only in OpenSC's memory.
 *
 * This is used by the C_DeriveKey with ECDH to hold the
 * key, and the calling application can then retrieve the attributes as needed.
 * .
 */
static CK_RV
pkcs15_create_secret_key(struct sc_pkcs11_slot *slot, struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15init_skeyargs args;
	struct pkcs15_any_object *key_any_obj = NULL;
	struct sc_pkcs15_object	*key_obj = NULL;
	struct sc_pkcs15_auth_info *pin = NULL;
	struct sc_pkcs15_skey_info *skey_info;
	CK_KEY_TYPE key_type;
	CK_BBOOL _token = FALSE;
	CK_RV rv;
	int rc;
	char label[SC_PKCS15_MAX_LABEL_SIZE];
	CK_BBOOL temp_object = FALSE;

	memset(&args, 0, sizeof(args));
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_CreateObject");

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &key_type, NULL);
	if (rv != CKR_OK)
		return rv;

	/* CKA_TOKEN defaults to false */
	rv = attr_find(pTemplate, ulCount, CKA_TOKEN, &_token, NULL);
	if (rv != CKR_OK)
		return rv;

	/* See if the "slot" is pin protected. If so, get the PIN id */
	if ((pin = slot_data_auth_info(slot->fw_data)) != NULL)
		args.auth_id = pin->auth_id;

	switch (key_type) {
		case CKK_GENERIC_SECRET:
			args.algorithm = SC_ALGORITHM_UNDEFINED;
			break;
		case CKK_AES:
			args.algorithm = SC_ALGORITHM_AES;
			break;
		case CKK_DES3:
			args.algorithm = SC_ALGORITHM_3DES;
			break;
		case CKK_DES:
			args.algorithm = SC_ALGORITHM_DES;
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
		case CKA_KEY_TYPE:
		case CKA_MODULUS_BITS:
		case CKA_PRIVATE:
			break;
		case CKA_LABEL:
			args.label = set_cka_label(attr, label);
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_VALUE_LEN:
			attr_extract(attr, &args.value_len, NULL);
			break;
		case CKA_VALUE:
			if (attr->pValue) {
				free(args.key.data);
				args.key.data = calloc(1,attr->ulValueLen);
				if (!args.key.data)
					return CKR_HOST_MEMORY;
				memcpy(args.key.data, attr->pValue, attr->ulValueLen);
				args.key.data_len = attr->ulValueLen;
			}
			break;
		case CKA_DECRYPT:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_DECRYPT);
			break;
		case CKA_ENCRYPT:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_ENCRYPT);
			break;
		case CKA_WRAP:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_WRAP);
			break;
		case CKA_UNWRAP:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_UNWRAP);
			break;
		case CKA_EXTRACTABLE:
			if (pkcs15_check_bool_cka(attr, 1))
				args.access_flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
			break;
		case CKA_OPENSC_ALWAYS_AUTH_ANY_OBJECT:
			args.user_consent = (int) (pkcs15_check_bool_cka(attr, 1));
			break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}
	}

	/* If creating a PKCS#11 session object, i.e. one that is only in memory */
	if (_token == FALSE && (fw_data->p15_card->card->caps & SC_CARD_CAP_ONCARD_SESSION_OBJECTS) == 0) {

		/* TODO Have 3 choices as to how to create the object.
		 * (1)create a sc_pkcs15init_store_secret_key routine like the others
		 * (2)use the sc_pkcs15emu_ routines
		 * (3)do it inline here (Will do this for now)
		 */

		key_obj = calloc(1, sizeof(sc_pkcs15_object_t));
		if (key_obj == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		temp_object = TRUE;
		key_obj->type = SC_PKCS15_TYPE_SKEY;

		if (args.id.len)
			memcpy(key_obj->label, args.id.value, args.id.len);

		key_obj->flags = 2; /* TODO not sure what these mean */

		skey_info = calloc(1, sizeof(sc_pkcs15_skey_info_t));
		if (skey_info == NULL) {
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		key_obj->data = skey_info;
		skey_info->usage = (unsigned int) args.usage;
		skey_info->native = 0; /* card can not use this */
		skey_info->access_flags = 0; /* looks like not needed */
		skey_info->key_type = key_type; /* PKCS#11 CKK_* */
		skey_info->data.value = args.key.data;
		skey_info->data.len = args.key.data_len;
		skey_info->value_len = args.value_len * 8; /* key length comes in number of bytes, use length in bits in PKCS#15. */
		args.key.data = NULL;
		key_obj->session_object = 1;
	}
	else {
		if(_token == FALSE)
			args.session_object = 1;	/* store the object on card for duration of the session. */

		args.value_len = args.value_len * 8; /* CKA_VALUE_LEN is number of bytes, PKCS#15 needs key length in bits */
		rc = sc_pkcs15init_store_secret_key(fw_data->p15_card, profile, &args, &key_obj);
		if (rc < 0) {
			rv = sc_to_cryptoki_error(rc, "C_CreateObject");
			goto out;
		}
	}

	/* Create a new pkcs11 object for it */
	__pkcs15_create_secret_key_object(fw_data, key_obj, &key_any_obj);
	pkcs15_add_object(slot, key_any_obj, phObject);

	rv = CKR_OK;

out:
	free(args.key.data); /* if allocated */
	if (temp_object)
		free(key_obj); /* do not free if the object was created by pkcs15init. It will be freed in C_Finalize */
	return rv;
}


static CK_RV
pkcs15_create_public_key(struct sc_pkcs11_slot *slot, struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15init_pubkeyargs args;
	struct pkcs15_any_object *key_any_obj = NULL;
	struct sc_pkcs15_object	*key_obj = NULL;
	struct sc_pkcs15_auth_info *pin = NULL;
	CK_KEY_TYPE key_type;
	struct sc_pkcs15_pubkey_rsa *rsa = NULL;
	int rc;
	CK_RV rv;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	memset(&args, 0, sizeof(args));
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_CreateObject");

	/* See if the "slot" is pin protected. If so, get the PIN id */
	if ((pin = slot_data_auth_info(slot->fw_data)) != NULL)
		args.auth_id = pin->auth_id;

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &key_type, NULL);
	if (rv != CKR_OK)
		return rv;
	switch (key_type) {
		case CKK_RSA:
			args.key.algorithm = SC_ALGORITHM_RSA;
			rsa = &args.key.u.rsa;
			break;
		case CKK_EC:
			/* TODO: -DEE Do not have real pkcs15 card with EC */
			/* fall through */
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;
		sc_pkcs15_bignum_t *bn = NULL;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
		case CKA_KEY_TYPE:
		case CKA_MODULUS_BITS:
		case CKA_PRIVATE:
			break;
		case CKA_LABEL:
			args.label = set_cka_label(attr, label);
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				return rv;
			break;
		case CKA_MODULUS:
			bn = &rsa->modulus; break;
		case CKA_PUBLIC_EXPONENT:
			bn = &rsa->exponent; break;
		case CKA_VERIFY:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_VERIFY);
			break;
		case CKA_VERIFY_RECOVER:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER);
			break;
		case CKA_ENCRYPT:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_ENCRYPT);
			break;
		case CKA_WRAP:
			args.usage |= pkcs15_check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_WRAP);
			break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}

		if (bn) {
			if (attr->ulValueLen > 1024)
				return CKR_ATTRIBUTE_VALUE_INVALID;
			bn->len = attr->ulValueLen;
			bn->data = (u8 *) attr->pValue;
		}
	}

	if (!rsa->modulus.len || !rsa->exponent.len)
		return CKR_TEMPLATE_INCOMPLETE;

	rc = sc_pkcs15init_store_public_key(fw_data->p15_card, profile, &args, &key_obj);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_CreateObject");

	/* Create a new pkcs11 object for it */
	__pkcs15_create_pubkey_object(fw_data, key_obj, &key_any_obj);
	pkcs15_add_object(slot, key_any_obj, phObject);

	return CKR_OK;
}


static CK_RV
pkcs15_create_certificate(struct sc_pkcs11_slot *slot,
		struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15init_certargs args;
	struct pkcs15_any_object *cert_any_obj = NULL;
	struct sc_pkcs15_object	*cert_obj = NULL;
	CK_CERTIFICATE_TYPE	cert_type;
	CK_BBOOL		bValue;
	int			rc;
	CK_RV rv;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	memset(&args, 0, sizeof(args));
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_CreateObject");

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_CERTIFICATE_TYPE,
				&cert_type, NULL);
	if (rv != CKR_OK)
		return rv;
	if (cert_type != CKC_X_509)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
			break;
		case CKA_PRIVATE:
			attr_extract(attr, &bValue, NULL);
			if (bValue) {
				rv = CKR_TEMPLATE_INCONSISTENT;
				goto out;
			}
			break;
		case CKA_LABEL:
			args.label = set_cka_label(attr, label);
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_VALUE:
			args.der_encoded.len = attr->ulValueLen;
			args.der_encoded.value = (u8 *) attr->pValue;
			break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}
	}

	if (args.der_encoded.len == 0) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto out;
	}

	rc = sc_pkcs15init_store_certificate(fw_data->p15_card, profile, &args, &cert_obj);
	if (rc < 0) {
		rv = sc_to_cryptoki_error(rc, "C_CreateObject");
		goto out;
	}
	/* Create a new pkcs11 object for it */
	__pkcs15_create_cert_object(fw_data, cert_obj, &cert_any_obj);
	pkcs15_add_object(slot, cert_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}


static CK_RV
pkcs15_create_data(struct sc_pkcs11_slot *slot, struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15init_dataargs args;
	struct pkcs15_any_object *data_any_obj = NULL;
	struct sc_pkcs15_object	*data_obj = NULL;
	struct sc_pkcs15_auth_info *pin = NULL;
	CK_BBOOL bValue;
	int rc;
	CK_RV rv;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	memset(&args, 0, sizeof(args));
	sc_init_oid(&args.app_oid);

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_CreateObject");

	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
			break;
		case CKA_PRIVATE:
			attr_extract(attr, &bValue, NULL);
			if (bValue) {
				pin = slot_data_auth_info(slot->fw_data);
				if (pin == NULL) {
					rv = CKR_TEMPLATE_INCOMPLETE;
					goto out;
				}
				args.auth_id = pin->auth_id;
			}
			break;
		case CKA_LABEL:
			args.label = set_cka_label(attr, label);
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_APPLICATION:
			args.app_label = (char *) attr->pValue;
			break;
		case CKA_OBJECT_ID:
			if (sc_asn1_decode_object_id(attr->pValue, attr->ulValueLen, &args.app_oid)) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				goto out;
			}
			break;
		case CKA_VALUE:
			args.der_encoded.len = attr->ulValueLen;
			args.der_encoded.value = (u8 *) attr->pValue;
			break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}
	}

	rc = sc_pkcs15init_store_data_object(fw_data->p15_card, profile, &args, &data_obj);
	if (rc < 0) {
		rv = sc_to_cryptoki_error(rc, "C_CreateObject");
		goto out;
	}
	/* Create a new pkcs11 object for it */
	__pkcs15_create_data_object(fw_data, data_obj, &data_any_obj);
	pkcs15_add_object(slot, data_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}


static CK_RV
pkcs15_create_object(struct sc_pkcs11_slot *slot, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_profile *profile = NULL;
	CK_OBJECT_CLASS	_class;
	CK_BBOOL _token = FALSE;
	CK_RV rv;
	int rc;
	CK_BBOOL p15init_create_object;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_CreateObject");

	rv = attr_find(pTemplate, ulCount, CKA_CLASS, &_class, NULL);
	if (rv != CKR_OK)
		return rv;

	rv = attr_find(pTemplate, ulCount, CKA_TOKEN, &_token, NULL);
	if (rv == CKR_TEMPLATE_INCOMPLETE) {
		/* TODO OpenSC has not checked CKA_TOKEN == TRUE, so only
		 * so only enforce for secret_key
		 */
		if (_class != CKO_SECRET_KEY)
			_token = TRUE; /* default if not in template */
	}
	else if (rv != CKR_OK) {
		return rv;
	}

	/* TODO The previous code does not check for CKA_TOKEN=TRUE
	 * PKCS#11 CreatObject examples always have it, but
	 * PKCS#11 says the default is false.
	 * for backward compatibility, will default to TRUE
	 */
	 /* Dont need profile id creating session only objects,
		except when the card supports temporary on card session objects */
	p15init_create_object = _token == TRUE || (p11card->card->caps & SC_CARD_CAP_ONCARD_SESSION_OBJECTS) == SC_CARD_CAP_ONCARD_SESSION_OBJECTS;

	if (p15init_create_object) {
		struct sc_aid *aid = NULL;

		rc = sc_lock(p11card->card);
		if (rc < 0)
			return sc_to_cryptoki_error(rc, "C_CreateObject");

		/* Bind the profile */
		rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, slot->app_info, &profile);
		if (rc < 0) {
			sc_unlock(p11card->card);
			return sc_to_cryptoki_error(rc, "C_CreateObject");
		}

		if (slot->app_info)
			aid = &slot->app_info->aid;

		rc = sc_pkcs15init_finalize_profile(p11card->card, profile, aid);
		if (rc != CKR_OK) {
			sc_log(context, "Cannot finalize profile: %i", rc);
			sc_unlock(p11card->card);
			return sc_to_cryptoki_error(rc, "C_CreateObject");
		}

		sc_pkcs15init_set_p15card(profile, fw_data->p15_card);
	}
	switch (_class) {
	case CKO_PRIVATE_KEY:
		rv = pkcs15_create_private_key(slot, profile, pTemplate, ulCount, phObject);
		break;
	case CKO_PUBLIC_KEY:
		rv = pkcs15_create_public_key(slot, profile, pTemplate, ulCount, phObject);
		break;
	case CKO_CERTIFICATE:
		rv = pkcs15_create_certificate(slot, profile, pTemplate, ulCount, phObject);
		break;
	case CKO_DATA:
		rv = pkcs15_create_data(slot, profile, pTemplate, ulCount, phObject);
		break;
	case CKO_SECRET_KEY:
		rv = pkcs15_create_secret_key(slot, profile, pTemplate, ulCount, phObject);
		break;
	default:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (p15init_create_object) {
		// TODO: after sc_pkcs15init_unbind, user may have to enter PIN on a pin pad reader even though authentication state
		// is supposed to remain open. Check why this happens.
		sc_pkcs15init_unbind(profile);
		sc_unlock(p11card->card);
	}

	return rv;
}


static CK_RV
get_X509_usage_privk(CK_ATTRIBUTE_PTR pTempl, CK_ULONG ulCount, unsigned long *x509_usage)
{
	CK_ULONG i;
	for (i = 0; i < ulCount; i++) {
		CK_ATTRIBUTE_TYPE typ = pTempl[i].type;
		CK_BBOOL *val = (CK_BBOOL *) pTempl[i].pValue;
		if (val == NULL)
			continue;
		if (typ == CKA_SIGN && *val)
			*x509_usage |= SC_PKCS15INIT_X509_DIGITAL_SIGNATURE;
		if (typ == CKA_UNWRAP && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_ENCIPHERMENT;
		if (typ == CKA_DECRYPT && *val)
			*x509_usage |= SC_PKCS15INIT_X509_DATA_ENCIPHERMENT;
		if (typ == CKA_DERIVE && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_AGREEMENT;
		if (typ == CKA_OPENSC_NON_REPUDIATION && *val)
			*x509_usage |= SC_PKCS15INIT_X509_NON_REPUDIATION;
		if (typ == CKA_VERIFY || typ == CKA_WRAP || typ == CKA_ENCRYPT) {
			sc_log(context,
				"get_X509_usage_privk(): invalid typ = 0x%0lx",
				typ);
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	return CKR_OK;
}


static CK_RV
get_X509_usage_pubk(CK_ATTRIBUTE_PTR pTempl, CK_ULONG ulCount, unsigned long *x509_usage)
{
	CK_ULONG i;
	for (i = 0; i < ulCount; i++) {
		CK_ATTRIBUTE_TYPE typ = pTempl[i].type;
		CK_BBOOL *val = (CK_BBOOL *) pTempl[i].pValue;
		if (val == NULL)
			continue;
		if (typ == CKA_VERIFY && *val)
			*x509_usage |= SC_PKCS15INIT_X509_DIGITAL_SIGNATURE;
		if (typ == CKA_WRAP && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_ENCIPHERMENT;
		if (typ == CKA_ENCRYPT && *val)
			*x509_usage |= SC_PKCS15INIT_X509_DATA_ENCIPHERMENT;
		if (typ == CKA_DERIVE && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_AGREEMENT;
		if (typ == CKA_SIGN || typ == CKA_UNWRAP || typ == CKA_DECRYPT) {
			sc_log(context,
				"get_X509_usage_pubk(): invalid typ = 0x%0lx",
				typ);
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	return CKR_OK;
}


static CK_RV
set_gost3410_params(struct sc_pkcs15init_prkeyargs *prkey_args,
		struct sc_pkcs15init_pubkeyargs *pubkey_args,
		CK_ATTRIBUTE_PTR pPubTpl, CK_ULONG ulPubCnt,
		CK_ATTRIBUTE_PTR pPrivTpl, CK_ULONG ulPrivCnt)
{
	const CK_BYTE * gost_params_encoded_oid_from_template;
	const CK_BYTE * gost_hash_params_encoded_oid_from_template;
	size_t len, param_index, hash_index;
	CK_RV rv;

	/* If template has CKA_GOSTR3410_PARAMS attribute, set param_index to
	 * corresponding item's index in gostr3410_param_oid[] */
	if (pPrivTpl && ulPrivCnt)
		rv = attr_find_ptr2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt, CKA_GOSTR3410_PARAMS, (void **)&gost_params_encoded_oid_from_template, &len);
	else
		rv = attr_find_ptr(pPubTpl, ulPubCnt, CKA_GOSTR3410_PARAMS, (void **)&gost_params_encoded_oid_from_template, &len);

	if (rv == CKR_OK) {
		size_t nn = sizeof(gostr3410_param_oid)/sizeof(gostr3410_param_oid[0]);

		for (param_index = 0; param_index < nn; ++param_index) {
			if (len != gostr3410_param_oid[param_index].encoded_oid_size)
				continue;
			if (!memcmp(gost_params_encoded_oid_from_template, gostr3410_param_oid[param_index].encoded_oid, len))
				break;
		}

		if (param_index == nn)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	else if (rv == CKR_TEMPLATE_INCOMPLETE)
		/* Default used parameters' index */
		param_index = 0;
	else
		return rv;

	/* If template has CKA_GOSTR3411_PARAMS attribute, set hash_index to
	 * corresponding item's index in gostr3410_hash_param_oid[] */
	if (pPrivTpl && ulPrivCnt)
		rv = attr_find_ptr2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt, CKA_GOSTR3411_PARAMS, (void **)&gost_hash_params_encoded_oid_from_template, &len);
	else
		rv = attr_find_ptr(pPubTpl, ulPubCnt, CKA_GOSTR3411_PARAMS, (void **)&gost_hash_params_encoded_oid_from_template, &len);

	if (rv == CKR_OK) {
		size_t nn = sizeof(gostr3410_hash_param_oid)/sizeof(gostr3410_hash_param_oid[0]);

		for (hash_index = 0; hash_index < nn; ++hash_index) {
			if (len != gostr3410_hash_param_oid[hash_index].encoded_oid_size)
				continue;
			if (!memcmp(gost_hash_params_encoded_oid_from_template, gostr3410_hash_param_oid[hash_index].encoded_oid, len))
				break;
		}

		if (hash_index == nn)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	else if (rv == CKR_TEMPLATE_INCOMPLETE)
		/* Default used hash parameters' index */
		hash_index = 0;
	else
		return rv;

	/* Set params and hash oids in priv and pub keys' gostr3410 params
	 * and set params oid_id in priv key */
	if (prkey_args) {
		(prkey_args->params).gost.gostr3410 = gostr3410_param_oid[param_index].oid_id;
		memcpy(&(prkey_args->key).u.gostr3410.params.key,
			gostr3410_param_oid[param_index].oid,
			gostr3410_param_oid[param_index].oid_size);
		memcpy(&(prkey_args->key).u.gostr3410.params.hash,
			gostr3410_hash_param_oid[hash_index].oid,
			gostr3410_hash_param_oid[hash_index].oid_size);
	}
	if (pubkey_args) {
		(pubkey_args->params).gost.gostr3410 = gostr3410_param_oid[param_index].oid_id;
		memcpy(&(pubkey_args->key).u.gostr3410.params.key,
			gostr3410_param_oid[param_index].oid,
			gostr3410_param_oid[param_index].oid_size);
		memcpy(&(pubkey_args->key).u.gostr3410.params.hash,
			gostr3410_hash_param_oid[hash_index].oid,
			gostr3410_hash_param_oid[hash_index].oid_size);
	}

	return CKR_OK;
}

/* FIXME: check for the public exponent in public key template and use this value */
static CK_RV
pkcs15_gen_keypair(struct sc_pkcs11_slot *slot, CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPubTpl, CK_ULONG ulPubCnt,
			CK_ATTRIBUTE_PTR pPrivTpl, CK_ULONG ulPrivCnt,
			CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey)                /* gets priv. key handle */
{
	struct sc_profile *profile = NULL;
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct sc_pkcs15_auth_info *pin = NULL;
	struct sc_aid *aid = NULL;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15init_keygen_args keygen_args;
	struct sc_pkcs15init_pubkeyargs pub_args;
	struct sc_pkcs15_object	 *priv_key_obj = NULL, *pub_key_obj = NULL;
	struct pkcs15_any_object *priv_any_obj = NULL, *pub_any_obj = NULL;
	struct pkcs15_prkey_object *priv_prk_obj = NULL;
	struct sc_pkcs15_id id;
	size_t		len;
	CK_KEY_TYPE	keytype;
	CK_ULONG	keybits = 0;
	char		pub_label[SC_PKCS15_MAX_LABEL_SIZE];
	char		priv_label[SC_PKCS15_MAX_LABEL_SIZE];
	int		rc;
	CK_RV rv = CKR_OK;
	CK_BBOOL always_auth = CK_FALSE;

	sc_log(context, "Keypair generation, mech = 0x%0lx",
		   pMechanism->mechanism);

	if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN
			&& pMechanism->mechanism != CKM_GOSTR3410_KEY_PAIR_GEN
			&& pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN)
		return CKR_MECHANISM_INVALID;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GenerateKeyPair");

	rc = sc_lock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_GenerateKeyPair");

	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, slot->app_info, &profile);
	if (rc < 0) {
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
	}

	if(slot->app_info)
		aid = &slot->app_info->aid;

	rc = sc_pkcs15init_finalize_profile(p11card->card, profile, aid);
	if (rc != CKR_OK) {
		sc_log(context, "Cannot finalize profile: %i", rc);
		return sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
	}

	memset(&keygen_args, 0, sizeof(keygen_args));
	memset(&pub_args, 0, sizeof(pub_args));

	/* 1. Convert the pkcs11 attributes to pkcs15init args */

	if ((pin = slot_data_auth_info(slot->fw_data)) != NULL)
		keygen_args.prkey_args.auth_id = pub_args.auth_id = pin->auth_id;

	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt, CKA_KEY_TYPE,
		&keytype, NULL);
	if (rv != CKR_OK && pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
		keytype = CKK_RSA;
	else if (rv != CKR_OK && pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN)
		keytype = CKK_EC;
	else if (rv != CKR_OK && pMechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN)
		keytype = CKK_GOSTR3410;
	else if (rv != CKR_OK)
		goto kpgen_done;

	if (keytype == CKK_GOSTR3410)   {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_GOSTR3410;
		pub_args.key.algorithm               = SC_ALGORITHM_GOSTR3410;
		rv = set_gost3410_params(&keygen_args.prkey_args, &pub_args,
				pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt);
		if (rv != CKR_OK)
			goto kpgen_done;
		keybits = SC_PKCS15_GOSTR3410_KEYSIZE;
	}
	else if (keytype == CKK_RSA)   {
		/* default value (CKA_KEY_TYPE isn't set) or CKK_RSA is set */
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm               = SC_ALGORITHM_RSA;

		rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt,	CKA_MODULUS_BITS, &keybits, NULL);
		if (rv != CKR_OK)
			keybits = 1024; /* Default key size */
		/* TODO: check allowed values of keybits */
	}
	else if (keytype == CKK_EC)   {
		struct sc_lv_data *der = &keygen_args.prkey_args.key.u.ec.params.der;

		der->len = sizeof(struct sc_object_id);
		rv = attr_find_and_allocate_ptr(pPubTpl, ulPubCnt, CKA_EC_PARAMS, (void **)&der->value, &der->len);
		if (rv != CKR_OK)   {
			sc_unlock(p11card->card);
			return sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
		}

		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_EC;
		pub_args.key.algorithm               = SC_ALGORITHM_EC;
	}
	else   {
		/* CKA_KEY_TYPE is set, but keytype isn't correct */
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto kpgen_done;
	}

	id.len = SC_PKCS15_MAX_ID_SIZE;
	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt,	CKA_ID, &id.value, &id.len);
	if (rv == CKR_OK)
		keygen_args.prkey_args.id = pub_args.id = id;

	len = sizeof(priv_label) - 1;
	rv = attr_find(pPrivTpl, ulPrivCnt, CKA_LABEL, priv_label, &len);
	if (rv == CKR_OK) {
		priv_label[len] = '\0';
		keygen_args.prkey_args.label = priv_label;
	}
	len = sizeof(pub_label) - 1;
	rv = attr_find(pPubTpl, ulPubCnt, CKA_LABEL, pub_label, &len);
	if (rv == CKR_OK) {
		pub_label[len] = '\0';
		keygen_args.pubkey_label = pub_label;
		pub_args.label = pub_label;
	}

	rv = get_X509_usage_privk(pPrivTpl, ulPrivCnt, &keygen_args.prkey_args.x509_usage);
	if (rv == CKR_OK)
		rv = get_X509_usage_pubk(pPubTpl, ulPubCnt, &keygen_args.prkey_args.x509_usage);
	if (rv != CKR_OK)
		goto kpgen_done;
	pub_args.x509_usage = keygen_args.prkey_args.x509_usage;

	len = sizeof(always_auth);
	rv = attr_find(pPrivTpl, ulPrivCnt, CKA_ALWAYS_AUTHENTICATE, &always_auth, &len);
	if (rv == CKR_OK && always_auth == CK_TRUE) {
		keygen_args.prkey_args.user_consent = 1;
	}

	/* 3.a Try on-card key pair generation */

	sc_pkcs15init_set_p15card(profile, fw_data->p15_card);

	sc_log(context, "Try on-card key pair generation");
	rc = sc_pkcs15init_generate_key(fw_data->p15_card, profile, &keygen_args, (unsigned int) keybits, &priv_key_obj);
	if (rc >= 0) {
		id = ((struct sc_pkcs15_prkey_info *) priv_key_obj->data)->id;
		rc = sc_pkcs15_find_pubkey_by_id(fw_data->p15_card, &id, &pub_key_obj);
		if (rc != 0) {
			sc_log(context, "sc_pkcs15_find_pubkey_by_id returned %d", rc);
			rv = sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
			goto kpgen_done;
		}
	}
	else {
		sc_log(context, "sc_pkcs15init_generate_key returned %d", rc);
		rv = sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
		goto kpgen_done;
	}

	/* 4. Create new pkcs11 public and private key object */

	rc = __pkcs15_create_prkey_object(fw_data, priv_key_obj, &priv_any_obj);
	if (rc == 0)
		rc = __pkcs15_create_pubkey_object(fw_data, pub_key_obj, &pub_any_obj);
	if (rc != 0) {
		sc_log(context, "__pkcs15_create_pr/pubkey_object returned %d", rc);
		rv = sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
		goto kpgen_done;
	}
	pkcs15_add_object(slot, priv_any_obj, phPrivKey);
	pkcs15_add_object(slot, pub_any_obj, phPubKey);

	priv_prk_obj = (struct pkcs15_prkey_object *) priv_any_obj;

	priv_prk_obj->prv_pubkey = (struct pkcs15_pubkey_object *)pub_any_obj;

	/* Duplicate public key so that parameters can be retrieved even if public key object is deleted */
	rv = sc_pkcs15_dup_pubkey(context, ((struct pkcs15_pubkey_object *)pub_any_obj)->pub_data, &priv_prk_obj->pub_data);

kpgen_done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);

	return rv;
}
#endif


static CK_RV
pkcs15_skey_destroy(struct sc_pkcs11_session *session, void *object)
{
#ifndef USE_PKCS15_INIT
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	struct pkcs15_any_object *any_obj = (struct pkcs15_any_object*) object;
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	int rv;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GenerateKeyPair");
	/* TODO assuming this is a session only object. */
	rv = sc_lock(p11card->card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_DestroyObject");

	/* Oppose to pkcs15_add_object */
	--any_obj->refcount; /* correct refcount */
	list_delete(&session->slot->objects, any_obj);
	/* Delete object in pkcs15 */
	rv = __pkcs15_delete_object(fw_data, any_obj);

	sc_unlock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_DestroyObject");

	return CKR_OK;
#endif
}

static CK_RV
pkcs15_any_destroy(struct sc_pkcs11_session *session, void *object)
{
#ifndef USE_PKCS15_INIT
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	struct pkcs15_data_object *obj = (struct pkcs15_data_object*) object;
	struct pkcs15_any_object *any_obj = (struct pkcs15_any_object*) object;
	struct sc_pkcs11_slot *slot = session->slot;
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_aid *aid = NULL;
	struct sc_profile *profile = NULL;
	int rv;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_DestroyObject");

	rv = sc_lock(p11card->card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_DestroyObject");

	/* Bind the profile */
	rv = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, slot->app_info, &profile);
	if (rv < 0) {
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rv, "C_DestroyObject");
	}

	if(slot->app_info)
		aid = &slot->app_info->aid;
	rv = sc_pkcs15init_finalize_profile(p11card->card, profile, aid);
	if (rv) {
		sc_log(context, "Cannot finalize profile: %i", rv);
		return sc_to_cryptoki_error(rv, "C_DestroyObject");
	}

	if (any_obj->related_pubkey)   {
		struct pkcs15_any_object *ao_pubkey = (struct pkcs15_any_object *)any_obj->related_pubkey;
		struct pkcs15_pubkey_object *pubkey = any_obj->related_pubkey;

		/* Check if key is not removed in between */
		if (list_locate(&session->slot->objects, ao_pubkey) > 0) {
			sc_log(context, "Found related pubkey %p", any_obj->related_pubkey);

			/* Delete reference to related certificate of the public key PKCS#11 object */
			pubkey->pub_genfrom = NULL;
			if (ao_pubkey->p15_object == NULL)   {
				sc_log(context, "Found related p15 object %p", ao_pubkey->p15_object);
				/* Unlink related public key FW object if it has no corresponding PKCS#15 object
				 * and was created from certificate. */
				--ao_pubkey->refcount;
				list_delete(&session->slot->objects, ao_pubkey);
				/* Delete public key object in pkcs15 */
				if (pubkey->pub_data)   {
					sc_log(context, "Found pub_data %p", pubkey->pub_data);
					sc_pkcs15_free_pubkey(pubkey->pub_data);
					pubkey->pub_data = NULL;
				}
				__pkcs15_delete_object(fw_data, ao_pubkey);
			}
		}
	}

	/* Delete object in smartcard (if corresponding PKCS#15 object exists) */
	if (obj->base.p15_object)
		rv = sc_pkcs15init_delete_object(fw_data->p15_card, profile, obj->base.p15_object);
	if (rv >= 0) {
		/* Oppose to pkcs15_add_object */
		--any_obj->refcount; /* correct refcount */
		list_delete(&session->slot->objects, any_obj);
		/* Delete object in pkcs15 */
		rv = __pkcs15_delete_object(fw_data, any_obj);
	}

	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_DestroyObject");

	return CKR_OK;
#endif
}


static CK_RV
pkcs15_get_random(struct sc_pkcs11_slot *slot, CK_BYTE_PTR p, CK_ULONG len)
{
	struct sc_pkcs11_card *p11card = slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	int rc;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GenerateRandom");

	rc = sc_get_challenge(fw_data->p15_card->card, p, (size_t)len);
	return sc_to_cryptoki_error(rc, "C_GenerateRandom");
}


struct sc_pkcs11_framework_ops framework_pkcs15 = {
	pkcs15_bind,
	pkcs15_unbind,
	pkcs15_create_tokens,
	pkcs15_release_token,
	pkcs15_login,
	pkcs15_logout,
	pkcs15_change_pin,
#ifdef USE_PKCS15_INIT
	pkcs15_initialize,
	pkcs15_init_pin,
	pkcs15_create_object,
	pkcs15_gen_keypair,
#else
	NULL,
	NULL,
	NULL,
	NULL,
#endif
	pkcs15_get_random
};


static CK_RV
pkcs15_set_attrib(struct sc_pkcs11_session *session, struct sc_pkcs15_object *p15_object,
		CK_ATTRIBUTE_PTR attr)
{
#ifndef USE_PKCS15_INIT
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	struct sc_profile *profile = NULL;
	struct sc_pkcs11_slot *slot = session->slot;
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_aid *aid = NULL;
	struct sc_pkcs15_id id;
	int rv = 0;
	CK_RV ck_rv = CKR_OK;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_SetAttributeValue");

	rv = sc_lock(p11card->card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_SetAttributeValue");

	rv = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, slot->app_info, &profile);
	if (rv < 0) {
		sc_log(context, "C_SetAttributeValue: pkcs15init bind failed: %i", rv);
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rv, "C_SetAttributeValue");
	}

	if(slot->app_info)
		aid = &slot->app_info->aid;

	rv = sc_pkcs15init_finalize_profile(p11card->card, profile, aid);
	if (rv != CKR_OK) {
		sc_log(context, "C_SetAttributeValue: cannot finalize profile: %i", rv);
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rv, "C_SetAttributeValue");
	}

	switch(attr->type) {
	case CKA_LABEL:
		rv = sc_pkcs15init_change_attrib(fw_data->p15_card, profile, p15_object,
				P15_ATTR_TYPE_LABEL, attr->pValue, (unsigned int) attr->ulValueLen);
		break;
	case CKA_ID:
		if (attr->ulValueLen > SC_PKCS15_MAX_ID_SIZE) {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			break;
		}
		memcpy(id.value, attr->pValue, attr->ulValueLen);
		id.len = attr->ulValueLen;
		rv = sc_pkcs15init_change_attrib(fw_data->p15_card, profile, p15_object,
				P15_ATTR_TYPE_ID, &id, sizeof(id));
		break;
	case CKA_SUBJECT:
		rv = SC_SUCCESS;
		break;
	case CKA_VALUE:
		if ((p15_object->type & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_DATA_OBJECT) {
			ck_rv = CKR_ATTRIBUTE_READ_ONLY;
			goto set_attr_done;
		}
		rv = sc_pkcs15init_change_attrib(fw_data->p15_card, profile, p15_object, 
				P15_ATTR_TYPE_VALUE, attr->pValue, (unsigned int) attr->ulValueLen);
		break;
	default:
		ck_rv = CKR_ATTRIBUTE_READ_ONLY;
		goto set_attr_done;
	}

	ck_rv = sc_to_cryptoki_error(rv, "C_SetAttributeValue");

set_attr_done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);

	return ck_rv;
#endif
}

/*
 * PKCS#15 Certificate Object
 */
static void
pkcs15_cert_release(void *obj)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object *) obj;
	struct sc_pkcs15_cert      *cert_data = cert->cert_data;

	if (__pkcs15_release_object((struct pkcs15_any_object *) obj) == 0)
		if (cert_data) /* may never have been read */
			sc_pkcs15_free_certificate(cert_data);
}


static CK_RV
pkcs15_cert_set_attribute(struct sc_pkcs11_session *session, void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
	return pkcs15_set_attrib(session, cert->base.p15_object, attr);
}


static CK_RV
pkcs15_cert_get_attribute(struct sc_pkcs11_session *session, void *object, CK_ATTRIBUTE_PTR attr)
{
	struct sc_pkcs11_card *p11card = NULL;
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
	struct pkcs15_fw_data *fw_data = NULL;
	size_t len;

	sc_log(context, "pkcs15_cert_get_attribute() called");
	p11card = session->slot->p11card;
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetAttributeValue");

	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_CERTIFICATE;
		break;
	case CKA_TOKEN:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
		break;
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (cert->base.p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		break;
	case CKA_MODIFIABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
		break;
	case CKA_LABEL:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		len = strnlen(cert->cert_p15obj->label, sizeof cert->cert_p15obj->label);
		check_attribute_buffer(attr, len);
		memcpy(attr->pValue, cert->cert_p15obj->label, len);
		break;
	case CKA_CERTIFICATE_TYPE:
		check_attribute_buffer(attr, sizeof(CK_CERTIFICATE_TYPE));
		*(CK_CERTIFICATE_TYPE*)attr->pValue = CKC_X_509;
		break;
	case CKA_ID:
#ifdef ZERO_CKAID_FOR_CA_CERTS
		if (cert->cert_info->authority) {
			check_attribute_buffer(attr, 1);
			*(unsigned char*)attr->pValue = 0;
			break;
		}
#endif
		check_attribute_buffer(attr, cert->cert_info->id.len);
		memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
		break;
	case CKA_TRUSTED:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = cert->cert_info->authority ? TRUE : FALSE;
		break;
	case CKA_VALUE:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		check_attribute_buffer(attr, cert->cert_data->data.len);
		memcpy(attr->pValue, cert->cert_data->data.value, cert->cert_data->data.len);
		break;
	case CKA_SERIAL_NUMBER:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		check_attribute_buffer(attr, cert->cert_data->serial_len);
		memcpy(attr->pValue, cert->cert_data->serial, cert->cert_data->serial_len);
		break;
	case CKA_SUBJECT:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		check_attribute_buffer(attr, cert->cert_data->subject_len);
		memcpy(attr->pValue, cert->cert_data->subject, cert->cert_data->subject_len);
		return CKR_OK;
	case CKA_ISSUER:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		check_attribute_buffer(attr, cert->cert_data->issuer_len);
		memcpy(attr->pValue, cert->cert_data->issuer, cert->cert_data->issuer_len);
		return CKR_OK;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	return CKR_OK;
}


#define ASN1_SET_TAG (SC_ASN1_SET | SC_ASN1_TAG_CONSTRUCTED)
#define ASN1_SEQ_TAG (SC_ASN1_SEQUENCE | SC_ASN1_TAG_CONSTRUCTED)
static CK_RV
pkcs15_cert_cmp_attribute(struct sc_pkcs11_session *session,
		void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	const unsigned char *data = NULL, *_data = NULL;
	size_t	len, _len;

	sc_log(context, "pkcs15_cert_cmp_attribute() called");
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)   {
		sc_log(context, "pkcs15_cert_cmp_attribute() returns SC_ERROR_INTERNAL");
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetAttributeValue");
	}

	switch (attr->type) {
	/* Check the issuer/subject. Some pkcs11 callers (i.e. netscape) will pass
	 * in the ASN.1 encoded SEQUENCE OF SET,
	 * while OpenSC just keeps the SET in the issuer/subject field. */
	case CKA_ISSUER:
		if (check_cert_data_read(fw_data, cert) != 0)
			break;
		if (cert->cert_data->issuer_len == 0)
			break;

		data = _data = (u8 *) attr->pValue;
		len = _len = attr->ulValueLen;
		if (cert->cert_data->issuer[0] == ASN1_SET_TAG && data[0] == ASN1_SEQ_TAG && len >= 2)
			data = sc_asn1_skip_tag(context, &_data, &_len, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, &len);

		if (len == cert->cert_data->issuer_len && !memcmp(cert->cert_data->issuer, data, len))   {
			sc_log(context, "pkcs15_cert_cmp_attribute() returns CKA_ISSUER matched");
			return 1;
		}
		break;
	case CKA_SUBJECT:
		if (check_cert_data_read(fw_data, cert) != 0)
			break;
		if (cert->cert_data->subject_len == 0)
			break;

		data = _data = (u8 *) attr->pValue;
		len = _len = attr->ulValueLen;
		if (cert->cert_data->subject[0] == ASN1_SET_TAG && data[0] == ASN1_SEQ_TAG && len >= 2)
			data = sc_asn1_skip_tag(context, &_data, &_len, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, &len);

		if (len == cert->cert_data->subject_len && !memcmp(cert->cert_data->subject, data, len))   {
			sc_log(context, "pkcs15_cert_cmp_attribute() returns CKA_SUBJECT matched");
			return 1;
		}
		break;
	default:
		return sc_pkcs11_any_cmp_attribute(session, object, attr);
	}
	sc_log(context, "pkcs15_cert_cmp_attribute() returns not matched");
	return 0;
}

struct sc_pkcs11_object_ops pkcs15_cert_ops = {
	pkcs15_cert_release,
	pkcs15_cert_set_attribute,
	pkcs15_cert_get_attribute,
	pkcs15_cert_cmp_attribute,
	pkcs15_any_destroy,
	NULL,	/* get_size */
	NULL,	/* sign */
	NULL,	/* unwrap_key */
	NULL,	/* decrypt */
	NULL,	/* derive */
	NULL,	/* can_do */
	NULL,	/* init_params */
	NULL	/* wrap_key */
};

/*
 * PKCS#15 Private Key Object
 */
static void pkcs15_prkey_release(void *object)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
	struct sc_pkcs15_pubkey *key_data = prkey->pub_data;

	if (__pkcs15_release_object((struct pkcs15_any_object *) object) == 0)
		if (key_data)
			sc_pkcs15_free_pubkey(key_data);
}

static CK_RV pkcs15_prkey_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
	return pkcs15_set_attrib(session, prkey->base.p15_object, attr);
}


static CK_RV
pkcs15_prkey_get_attribute(struct sc_pkcs11_session *session,
		void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
	struct sc_pkcs11_card *p11card = NULL;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_pkcs15_pubkey *key = NULL;
	unsigned int usage;
	size_t len;

	sc_log(context, "pkcs15_prkey_get_attribute() called");
	p11card = session->slot->p11card;
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetAttributeValue");

	/* PKCS#11 requires us to supply CKA_MODULUS for private keys,
	 * although that is not generally available from a smart card
	 * (the key is supposed to be safely locked away after all).
	 *
	 * To work around this, we hope that we either have an associated
	 * public key, or we try to find a certificate with the
	 * corresponding public key.
	 *
	 * Note: We do the same thing for CKA_PUBLIC_EXPONENT as some
	 *       applications assume they can get that from the private
	 *       key, something PKCS#11 doesn't guarantee.
	 */
	if ((attr->type == CKA_MODULUS) || (attr->type == CKA_PUBLIC_EXPONENT) ||
		((attr->type == CKA_MODULUS_BITS) && (prkey->prv_p15obj->type == SC_PKCS15_TYPE_PRKEY_EC)) ||
		(attr->type == CKA_ECDSA_PARAMS)) {
		/* First see if we have an associated public key */
		if (prkey->pub_data) {
			key = prkey->pub_data;
		} else {
			/* Try to find public key or certificate with the public key */
			unsigned int i;

			for (i = 0; i < fw_data->num_objects; i++) {
				struct pkcs15_any_object *obj = fw_data->objects[i];
				struct pkcs15_cert_object *cert;

				if (is_cert(obj))   {
					cert = (struct pkcs15_cert_object*) obj;

					if (cert->cert_prvkey != prkey)
						continue;

					if (check_cert_data_read(fw_data, cert) == 0)   {
						key = cert->cert_pubkey->pub_data;
						sc_log(context, "found friend certificate's public key %p", key);
					}
				}
				else if (is_pubkey(obj)) {
					struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object *) obj;

					if (!pubkey->pub_data)
						continue;

					if (sc_pkcs15_compare_id(&pubkey->pub_info->id, &prkey->prv_info->id))   {
						prkey->prv_pubkey = pubkey;
						key = pubkey->pub_data;
						sc_log(context, "found friend public key %p", key);
					}
				}
			}
		}
	}

	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_PRIVATE_KEY;
		break;
	case CKA_TOKEN:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
		break;
	case CKA_ALWAYS_SENSITIVE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (prkey->prv_info->access_flags & SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE) != 0;
		break;
	case CKA_NEVER_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (prkey->prv_info->access_flags & SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE) != 0;
		break;
	case CKA_SENSITIVE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (prkey->prv_info->access_flags & SC_PKCS15_PRKEY_ACCESS_SENSITIVE) != 0;
		break;
	case CKA_LOCAL:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (prkey->prv_info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL) != 0;
		break;
    case CKA_ALWAYS_AUTHENTICATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = prkey->prv_p15obj->user_consent >= 1 ? CK_TRUE : CK_FALSE;
		break;
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (prkey->prv_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		break;
	case CKA_MODIFIABLE:
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
		break;
	case CKA_LABEL:
		len = strnlen(prkey->prv_p15obj->label, sizeof prkey->prv_p15obj->label);
		check_attribute_buffer(attr, len);
		memcpy(attr->pValue, prkey->prv_p15obj->label, len);
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
		switch (prkey->prv_p15obj->type) {
			case SC_PKCS15_TYPE_PRKEY_RSA:
				*(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
				break;
			case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
				*(CK_KEY_TYPE*)attr->pValue = CKK_GOSTR3410;
				break;
			case SC_PKCS15_TYPE_PRKEY_EC:
				*(CK_KEY_TYPE*)attr->pValue = CKK_EC;
				break;
			default:
				return CKR_GENERAL_ERROR; /* Internal error*/
		}
		break;
	case CKA_ID:
		check_attribute_buffer(attr, prkey->prv_info->id.len);
		memcpy(attr->pValue, prkey->prv_info->id.value, prkey->prv_info->id.len);
		break;
	case CKA_KEY_GEN_MECHANISM:
		check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
		*(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
		break;
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_UNWRAP:
	case CKA_DERIVE:
	case CKA_OPENSC_NON_REPUDIATION:
		/* TODO seems to be obsolete */
		/* Combine the usage bits of all split keys */
		for (usage = 0; prkey; prkey = prkey->prv_next)
			usage |= prkey->prv_info->usage;
		return get_usage_bit(usage, attr);
	case CKA_MODULUS:
		return get_modulus(key, attr);
	case CKA_MODULUS_BITS:
		check_attribute_buffer(attr, sizeof(CK_ULONG));
		switch (prkey->prv_p15obj->type) {
			case SC_PKCS15_TYPE_PRKEY_EC:
				if (key) {
					if (key->u.ec.params.field_length > 0)
						*(CK_ULONG *) attr->pValue = key->u.ec.params.field_length;
					else
						*(CK_ULONG *) attr->pValue = (key->u.ec.ecpointQ.len - 1) / 2 *8;
				}
				return CKR_OK;
			default:
				*(CK_ULONG *) attr->pValue = prkey->prv_info->modulus_length;
				return CKR_OK;
		}
	case CKA_PUBLIC_EXPONENT:
		return get_public_exponent(key, attr);
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		return CKR_ATTRIBUTE_SENSITIVE;
	case CKA_SUBJECT:
	case CKA_START_DATE:
	case CKA_END_DATE:
		attr->ulValueLen = 0;
		return CKR_OK;
	case CKA_GOSTR3410_PARAMS:
		if (prkey->prv_info && prkey->prv_info->params.len)
			return get_gostr3410_params(prkey->prv_info->params.data,
					prkey->prv_info->params.len, attr);
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;
	case CKA_EC_PARAMS:
		return get_ec_pubkey_params(key, attr); /* get from pubkey for now */
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	return CKR_OK;
}



static CK_RV
pkcs15_prkey_check_pss_param(CK_MECHANISM_PTR pMechanism, CK_ULONG hlen)
{
	CK_RSA_PKCS_PSS_PARAMS *pss_param;
	int i;
	const unsigned int hash_lens[5] = { 160, 256, 385, 512, 224 };
	const unsigned int hashes[5] = { CKM_SHA_1, CKM_SHA256,
		CKM_SHA384, CKM_SHA512, CKM_SHA224 };

	pss_param = (CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;

	// Hash parameter must match length of data supplied for CKM_RSA_PKCS_PSS
	for (i = 0; i < 5; i++) {
		if (pss_param->hashAlg == hashes[i]
			&& hlen != hash_lens[i]/8)
			return CKR_MECHANISM_PARAM_INVALID;
	}
	/* other aspects of pss params were already verified during SignInit */

	return CKR_OK;
}

static int mgf2flags(CK_RSA_PKCS_MGF_TYPE mgf)
{
	switch (mgf) {
	case CKG_MGF1_SHA224:
		return SC_ALGORITHM_MGF1_SHA224;
		break;
	case CKG_MGF1_SHA256:
		return SC_ALGORITHM_MGF1_SHA256;
	case CKG_MGF1_SHA384:
		return SC_ALGORITHM_MGF1_SHA384;
	case CKG_MGF1_SHA512:
		return SC_ALGORITHM_MGF1_SHA512;
	case CKG_MGF1_SHA1:
		return SC_ALGORITHM_MGF1_SHA1;
	default:
		return -1;
	}
}


static CK_RV
pkcs15_prkey_sign(struct sc_pkcs11_session *session, void *obj,
			CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulDataLen)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object *) obj;
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	CK_RV rv;
	int flags = 0, prkey_has_path = 0, rc;
	unsigned sign_flags = SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
			| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;

	sc_log(context, "Initiating signing operation, mechanism 0x%lx.",
		   pMechanism->mechanism);
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_Sign");

	/* See which of the alternative keys supports signing */
	while (prkey && !(prkey->prv_info->usage & sign_flags))
		prkey = prkey->prv_next;

	if (prkey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	if (prkey->prv_info->path.len || prkey->prv_info->path.aid.len)
		prkey_has_path = 1;

	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
		break;
	case CKM_MD5_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_MD5;
		break;
	case CKM_SHA1_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1;
		break;
	case CKM_SHA224_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA224;
		break;
	case CKM_SHA256_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256;
		break;
	case CKM_SHA384_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA384;
		break;
	case CKM_SHA512_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA512;
		break;
	case CKM_RIPEMD160_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_RIPEMD160;
		break;
	case CKM_RSA_X_509:
		flags = SC_ALGORITHM_RSA_RAW;
		break;
	case CKM_RSA_PKCS_PSS:
		flags = SC_ALGORITHM_RSA_PAD_PSS;
		/* The hash was done ouside of the module */
		flags |= SC_ALGORITHM_RSA_HASH_NONE;
		/* Omited parameter can use MGF1-SHA1 ? */
		if (pMechanism->pParameter == NULL) {
			flags |= SC_ALGORITHM_MGF1_SHA1;
			if (ulDataLen != SHA_DIGEST_LENGTH)
				return CKR_MECHANISM_PARAM_INVALID;
			break;
		}

		/* Check the data length matches the selected hash */
		rv = pkcs15_prkey_check_pss_param(pMechanism, (int)ulDataLen);
		if (rv != CKR_OK) {
			sc_log(context, "Invalid data lenght for the selected "
			    "PSS parameters");
			return rv;
		}

		/* The MGF parameter was already verified in SignInit() */
		flags |=  mgf2flags(((CK_RSA_PKCS_PSS_PARAMS*)pMechanism->pParameter)->mgf);

		/* Assuming salt is the size of hash */
		break;
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
		flags = SC_ALGORITHM_RSA_PAD_PSS;
		/* Omited parameter can use MGF1-SHA1 and SHA1 hash ? */
		if (pMechanism->pParameter == NULL) {
			flags |= SC_ALGORITHM_RSA_HASH_SHA1;
			flags |= SC_ALGORITHM_MGF1_SHA1;
			break;
		}

		switch (((CK_RSA_PKCS_PSS_PARAMS*)pMechanism->pParameter)->hashAlg) {
		case CKM_SHA_1:
			flags |= SC_ALGORITHM_RSA_HASH_SHA1;
			break;
		case CKM_SHA224:
			flags |= SC_ALGORITHM_RSA_HASH_SHA224;
			break;
		case CKM_SHA256:
			flags |= SC_ALGORITHM_RSA_HASH_SHA256;
			break;
		case CKM_SHA384:
			flags |= SC_ALGORITHM_RSA_HASH_SHA384;
			break;
		case CKM_SHA512:
			flags |= SC_ALGORITHM_RSA_HASH_SHA512;
			break;
		default:
			return CKR_MECHANISM_PARAM_INVALID;
		}

		/* The MGF parameter was already verified in SignInit() */
		flags |= mgf2flags(((CK_RSA_PKCS_PSS_PARAMS*)pMechanism->pParameter)->mgf);

		/* Assuming salt is the size of hash */
		break;
	case CKM_GOSTR3410:
		flags = SC_ALGORITHM_GOSTR3410_HASH_NONE;
		break;
	case CKM_GOSTR3410_WITH_GOSTR3411:
		flags = SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411;
		break;
	case CKM_ECDSA:
		flags = SC_ALGORITHM_ECDSA_HASH_NONE;
		break;
	case CKM_ECDSA_SHA1:
		flags = SC_ALGORITHM_ECDSA_HASH_SHA1;
		break;
	default:
		sc_log(context, "DEE - need EC for %lu", pMechanism->mechanism);
		return CKR_MECHANISM_INVALID;
	}

	rc = sc_lock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_Sign");

	sc_log(context,
	       "Selected flags %X. Now computing signature for %lu bytes. %lu bytes reserved.",
	       flags, ulDataLen, *pulDataLen);
	rc = sc_pkcs15_compute_signature(fw_data->p15_card, prkey->prv_p15obj, flags,
			pData, ulDataLen, pSignature, *pulDataLen);
	if (rc < 0 && !sc_pkcs11_conf.lock_login && !prkey_has_path) {
		/* If private key PKCS#15 object do not have 'path' attribute,
		 * and if PKCS#11 login session is not locked,
		 * the compute signature could fail because of concurrent access to the card
		 * by other application that could change the current DF.
		 * In this particular case try to 'reselect' application DF.
		 */
		if (reselect_app_df(fw_data->p15_card) == SC_SUCCESS)
			rc = sc_pkcs15_compute_signature(fw_data->p15_card, prkey->prv_p15obj, flags,
					pData, ulDataLen, pSignature, *pulDataLen);
	}

	sc_unlock(p11card->card);

	sc_log(context, "Sign complete. Result %d.", rc);

	if (rc > 0) {
		*pulDataLen = rc;
		return CKR_OK;
	}

	return sc_to_cryptoki_error(rc, "C_Sign");
}


static CK_RV
pkcs15_prkey_unwrap(struct sc_pkcs11_session *session, void *obj,
			CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pWrappedKey,
			CK_ULONG ulWrappedKeyLen,
			void *targetKey)
{
	struct	sc_pkcs11_card *p11card = session->slot->p11card;
	struct	pkcs15_fw_data *fw_data = NULL;
	struct	pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object *) obj;
	struct	pkcs15_any_object *targetKeyObj = (struct pkcs15_any_object *) targetKey;
	int	rv;	

	sc_log(context, "Initiating unwrapping with private key.");

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_UnwrapKey");

	if (pMechanism == NULL || pWrappedKey == NULL || ulWrappedKeyLen == 0 || targetKeyObj == NULL) {
		sc_log(context, "One or more of mandatory arguments were NULL.");
	    return CKR_ARGUMENTS_BAD;
	}

	/* See which of the alternative keys supports unwrap */
	while (prkey && !(prkey->prv_info->usage & SC_PKCS15_PRKEY_USAGE_UNWRAP))
		prkey = prkey->prv_next;

	if (prkey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	sc_log(context, "Using mechanism %lx.", pMechanism->mechanism);

#if 0
	/* FIXME https://github.com/OpenSC/OpenSC/issues/1595 */
	/* Select the proper padding mechanism */
	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		break;
	case CKM_RSA_X_509:
		flags |= SC_ALGORITHM_RSA_RAW;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}
#endif

	rv = sc_lock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_UnwrapKey");

	/* Call the card to do the unwrap operation */
	rv = sc_pkcs15_unwrap(fw_data->p15_card, prkey->prv_p15obj, targetKeyObj->p15_object, 0,
		pWrappedKey, ulWrappedKeyLen, NULL, 0);

	sc_unlock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_UnwrapKey");

	return CKR_OK;
}

static CK_RV
pkcs15_prkey_decrypt(struct sc_pkcs11_session *session, void *obj,
		CK_MECHANISM_PTR pMechanism,
		CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct pkcs15_prkey_object *prkey;
	unsigned char decrypted[512]; /* FIXME: Will not work for keys above 4096 bits */
	int	buff_too_small, rv, flags = 0, prkey_has_path = 0;

	sc_log(context, "Initiating decryption.");

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_Decrypt");

	/* See which of the alternative keys supports decrypt */
	prkey = (struct pkcs15_prkey_object *) obj;
	while (prkey  && !(prkey->prv_info->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP)))
		prkey = prkey->prv_next;
	if (prkey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	if (prkey->prv_info->path.len || prkey->prv_info->path.aid.len)
		prkey_has_path = 1;

	/* Select the proper padding mechanism */
	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		break;
	case CKM_RSA_X_509:
		flags |= SC_ALGORITHM_RSA_RAW;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	rv = sc_lock(p11card->card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_Decrypt");

	rv = sc_pkcs15_decipher(fw_data->p15_card, prkey->prv_p15obj, flags,
			pEncryptedData, ulEncryptedDataLen, decrypted, sizeof(decrypted));

	if (rv < 0 && !sc_pkcs11_conf.lock_login && !prkey_has_path)
		if (reselect_app_df(fw_data->p15_card) == SC_SUCCESS)
			rv = sc_pkcs15_decipher(fw_data->p15_card, prkey->prv_p15obj, flags,
					pEncryptedData, ulEncryptedDataLen, decrypted, sizeof(decrypted));

	sc_unlock(p11card->card);

	sc_log(context, "Decryption complete. Result %d.", rv);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_Decrypt");

	buff_too_small = (*pulDataLen < (CK_ULONG)rv);
	*pulDataLen = rv;
	if (pData == NULL_PTR)
		return CKR_OK;
	if (buff_too_small)
		return CKR_BUFFER_TOO_SMALL;
	memcpy(pData, decrypted, *pulDataLen);

	return CKR_OK;
}


static CK_RV
pkcs15_prkey_derive(struct sc_pkcs11_session *session, void *obj,
		CK_MECHANISM_PTR pMechanism,
		CK_BYTE_PTR pParameters, CK_ULONG ulParametersLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object *) obj;
	int	need_unlock = 0, prkey_has_path = 0;
	int	rv, flags = 0;
	CK_BYTE_PTR pSeedData = NULL;
	CK_ULONG ulSeedDataLen = 0;

	sc_log(context, "Initiating derivation");

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_DeriveKey");

	/* See which of the alternative keys supports derivation */
	while (prkey && !(prkey->prv_info->usage & SC_PKCS15_PRKEY_USAGE_DERIVE))
		prkey = prkey->prv_next;

	if (prkey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	if (prkey->prv_info->path.len || prkey->prv_info->path.aid.len)
		prkey_has_path = 1;

	if (pData != NULL && *pulDataLen > 0) { /* TODO DEE only test for NULL? */
		need_unlock = 1;
		rv = sc_lock(p11card->card);
		if (rv < 0)
			return sc_to_cryptoki_error(rv, "C_DeriveKey");
	}

	/* TODO DEE This may not be the place to get the parameters,
	 * But its the last PKCS11 aware routine.
	 * RSA parameters would be null.
	 */
	switch (prkey->base.p15_object->type) {
		case SC_PKCS15_TYPE_PRKEY_EC:
		{
			CK_ECDH1_DERIVE_PARAMS * ecdh_params = (CK_ECDH1_DERIVE_PARAMS *) pParameters;
			ulSeedDataLen = ecdh_params->ulPublicDataLen;
			pSeedData = ecdh_params->pPublicData;
			flags = SC_ALGORITHM_ECDH_CDH_RAW;
		}
		break;
	}

	size_t len = *pulDataLen;
	rv = sc_pkcs15_derive(fw_data->p15_card, prkey->prv_p15obj, flags,
			pSeedData, ulSeedDataLen, pData, &len);
	if (rv < 0 && !sc_pkcs11_conf.lock_login && !prkey_has_path && need_unlock)
		if (reselect_app_df(fw_data->p15_card) == SC_SUCCESS)
			rv = sc_pkcs15_derive(fw_data->p15_card, prkey->prv_p15obj, flags,
					pSeedData, ulSeedDataLen, pData, &len);
	*pulDataLen = len;

	/* this may have been a request for size */

	if (need_unlock)
		sc_unlock(p11card->card);

	sc_log(context, "Derivation complete. Result %d.", rv);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_DeriveKey");

	return CKR_OK;
}


static CK_RV
pkcs15_prkey_can_do(struct sc_pkcs11_session *session, void *obj,
		CK_MECHANISM_TYPE mech_type, unsigned int flags)
{
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object *) obj;
	struct sc_pkcs15_prkey_info *pkinfo = NULL;
	struct sc_supported_algo_info *token_algos = NULL;
	int ii, jj;

	if (!prkey || !prkey->prv_info)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	pkinfo = prkey->prv_info;
	/* Return in there are no usage algorithms specified for this key. */
	if (!pkinfo->algo_refs[0])
		return CKR_FUNCTION_NOT_SUPPORTED;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	token_algos = &fw_data->p15_card->tokeninfo->supported_algos[0];

	for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS && pkinfo->algo_refs[ii];ii++)   {
		/* Look for algorithm supported by token referenced in the list of key's algorithms */
		for (jj=0;jj<SC_MAX_SUPPORTED_ALGORITHMS && (token_algos + jj)->reference; jj++)
			if (pkinfo->algo_refs[ii] == (token_algos + jj)->reference)
				break;
		if ((jj == SC_MAX_SUPPORTED_ALGORITHMS) || !(token_algos + jj)->reference)
			return CKR_GENERAL_ERROR;

		if ((token_algos + jj)->mechanism != mech_type)
			continue;

		if (flags == CKF_SIGN)
			if ((token_algos + jj)->operations & SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE)
				break;

		if (flags == CKF_DECRYPT)
			if ((token_algos + jj)->operations & SC_PKCS15_ALGO_OP_DECIPHER)
				break;
	}

	if (ii == SC_MAX_SUPPORTED_ALGORITHMS || !pkinfo->algo_refs[ii])
		return CKR_MECHANISM_INVALID;

	return CKR_OK;
}


static CK_RV
pkcs15_prkey_init_params(struct sc_pkcs11_session *session,
			CK_MECHANISM_PTR pMechanism)
{
	const CK_RSA_PKCS_PSS_PARAMS *pss_params;
	unsigned int expected_hash = 0, i;
	unsigned int expected_salt_len = 0;
	const unsigned int salt_lens[5] = { 160, 256, 384, 512, 224 };
	const unsigned int hashes[5] = { CKM_SHA_1, CKM_SHA256,
		CKM_SHA384, CKM_SHA512, CKM_SHA224 };

	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
		if (!pMechanism->pParameter ||
			pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
			return CKR_MECHANISM_PARAM_INVALID;

		pss_params = (CK_RSA_PKCS_PSS_PARAMS*)pMechanism->pParameter;
		if (pss_params->mgf < CKG_MGF1_SHA1 || pss_params->mgf > CKG_MGF1_SHA224)
			return CKR_MECHANISM_PARAM_INVALID;

		/* The hashAlg field can have any value for CKM_RSA_PKCS_PSS and must be
		 * used again in the PSS padding; for the other mechanisms it strictly
		 * must match the padding declared in the mechanism.
		 */
		if (pMechanism->mechanism == CKM_SHA1_RSA_PKCS_PSS) {
			expected_hash = CKM_SHA_1;
			expected_salt_len = 160;
		} else if (pMechanism->mechanism == CKM_SHA224_RSA_PKCS_PSS) {
			expected_hash = CKM_SHA224;
			expected_salt_len = 224;
		} else if (pMechanism->mechanism == CKM_SHA256_RSA_PKCS_PSS) {
			expected_hash = CKM_SHA256;
			expected_salt_len = 256;
		} else if (pMechanism->mechanism == CKM_SHA384_RSA_PKCS_PSS) {
			expected_hash = CKM_SHA384;
			expected_salt_len = 384;
		} else if (pMechanism->mechanism == CKM_SHA512_RSA_PKCS_PSS) {
			expected_hash = CKM_SHA512;
			expected_salt_len = 512;
		} else if (pMechanism->mechanism == CKM_RSA_PKCS_PSS) {
			for (i = 0; i < 5; ++i) {
				if (hashes[i] == pss_params->hashAlg) {
					expected_hash = hashes[i];
					expected_salt_len = salt_lens[i];
				}
			}
		}

		if (expected_hash != pss_params->hashAlg)
			return CKR_MECHANISM_PARAM_INVALID;

		/* We're strict, and only do PSS signatures with a salt length that
		 * matches the digest length (any shorter is rubbish, any longer
		 * is useless). */
		if (pss_params->sLen != expected_salt_len / 8)
			return CKR_MECHANISM_PARAM_INVALID;

		/* TODO support different salt lengths */
		break;
	}
	return CKR_OK;
}


struct sc_pkcs11_object_ops pkcs15_prkey_ops = {
	pkcs15_prkey_release,
	pkcs15_prkey_set_attribute,
	pkcs15_prkey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	pkcs15_any_destroy,
	NULL,	/* get_size */
	pkcs15_prkey_sign,
	pkcs15_prkey_unwrap,
	pkcs15_prkey_decrypt,
	pkcs15_prkey_derive,
	pkcs15_prkey_can_do,
	pkcs15_prkey_init_params,
	NULL	/* wrap_key */
};

/*
 * PKCS#15 RSA Public Key Object
 */
static void
pkcs15_pubkey_release(void *object)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	struct sc_pkcs15_pubkey *key_data = pubkey->pub_data;

	if (__pkcs15_release_object((struct pkcs15_any_object *) object) == 0)
		if (key_data)
			sc_pkcs15_free_pubkey(key_data);
}


static CK_RV
pkcs15_pubkey_set_attribute(struct sc_pkcs11_session *session,
		void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	return pkcs15_set_attrib(session, pubkey->base.p15_object, attr);
}


static CK_RV
pkcs15_pubkey_get_attribute(struct sc_pkcs11_session *session, void *object, CK_ATTRIBUTE_PTR attr)
{
	struct sc_pkcs11_card *p11card = NULL;
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	struct pkcs15_cert_object *cert = NULL;
	struct pkcs15_fw_data *fw_data = NULL;
	size_t len;

	sc_log(context, "pkcs15_pubkey_get_attribute() called");

	p11card = session->slot->p11card;
	cert = pubkey->pub_genfrom;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetAttributeValue");
	/* We may need to get these from cert */
	switch (attr->type) {
		case CKA_MODULUS:
		case CKA_MODULUS_BITS:
		case CKA_VALUE:
		case CKA_SPKI:
		case CKA_PUBLIC_EXPONENT:
		case CKA_EC_PARAMS:
		case CKA_EC_POINT:
			if (pubkey->pub_data == NULL)
				if (SC_SUCCESS != check_cert_data_read(fw_data, cert))
					return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "check_cert_data_read");
			break;
	}

	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_PUBLIC_KEY;
		break;
	case CKA_TOKEN:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
		break;
	case CKA_SENSITIVE:
		/* By PKCS#11 v2.20 public key cannot have SENSITIVE attr TRUE */
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
		break;
	case CKA_LOCAL:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		if (pubkey->pub_info)
			*(CK_BBOOL*)attr->pValue = (pubkey->pub_info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL) != 0;
		else /* no pub_info structure, falling back to TRUE */
			*(CK_BBOOL*)attr->pValue = TRUE;
		break;
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		if (pubkey->pub_p15obj)
			*(CK_BBOOL*)attr->pValue = (pubkey->pub_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		else if (cert && cert->cert_p15obj)
			*(CK_BBOOL*)attr->pValue = (cert->pub_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;
		break;
	case CKA_MODIFIABLE:
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
		break;
	case CKA_LABEL:
		if (pubkey->pub_p15obj) {
			len = strnlen(pubkey->pub_p15obj->label, sizeof pubkey->pub_p15obj->label);
			check_attribute_buffer(attr, len);
			memcpy(attr->pValue, pubkey->pub_p15obj->label, len);
		}
		else if (cert && cert->cert_p15obj) {
			len = strnlen(cert->cert_p15obj->label, sizeof cert->cert_p15obj->label);
			check_attribute_buffer(attr, len);
			memcpy(attr->pValue, cert->cert_p15obj->label, len);
		}
		else {
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
		/* TODO: -DEE why would we not have a pubkey->pub_data? */
		/* even if we do not, we should not assume RSA */
		if (pubkey->pub_data && pubkey->pub_data->algorithm == SC_ALGORITHM_GOSTR3410)
			*(CK_KEY_TYPE*)attr->pValue = CKK_GOSTR3410;
		else if (pubkey->pub_data && pubkey->pub_data->algorithm == SC_ALGORITHM_EC)
			*(CK_KEY_TYPE*)attr->pValue = CKK_EC;
		else
			*(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
		break;
	case CKA_ID:
		if (pubkey->pub_info) {
			check_attribute_buffer(attr, pubkey->pub_info->id.len);
			memcpy(attr->pValue, pubkey->pub_info->id.value, pubkey->pub_info->id.len);
		}
		else if (cert && cert->cert_info) {
			check_attribute_buffer(attr, cert->cert_info->id.len);
			memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
		}
		else {
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		break;
	case CKA_KEY_GEN_MECHANISM:
		check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
		*(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
		break;
	case CKA_ENCRYPT:
	case CKA_WRAP:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
		if (pubkey->pub_info)
			return get_usage_bit(pubkey->pub_info->usage, attr);
		else
			return get_usage_bit(SC_PKCS15_PRKEY_USAGE_ENCRYPT |SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER, attr);
	case CKA_MODULUS:
		return get_modulus(pubkey->pub_data, attr);
	case CKA_MODULUS_BITS:
		return get_modulus_bits(pubkey->pub_data, attr);
	case CKA_PUBLIC_EXPONENT:
		return get_public_exponent(pubkey->pub_data, attr);
	/* 
	 * PKCS#11 does not define a CKA_VALUE for a CKO_PUBLIC_KEY.
	 * OpenSC does, but it is not consistent it what it returns
	 * Internally to do verify, with OpenSSL, we need a SPKI that
	 * can be converted into a EVP_KEY with d2i_PUBKEY
	 * CKA_SPKI is defined internally as a CKA_VENDOR_DFINED attribute.
	 */
	case CKA_VALUE:
	case CKA_SPKI:

		if (attr->type != CKA_SPKI && pubkey->pub_info && pubkey->pub_info->direct.raw.value && pubkey->pub_info->direct.raw.len)   {
			check_attribute_buffer(attr, pubkey->pub_info->direct.raw.len);
			memcpy(attr->pValue, pubkey->pub_info->direct.raw.value, pubkey->pub_info->direct.raw.len);
		}
		else if (pubkey->pub_info && pubkey->pub_info->direct.spki.value && pubkey->pub_info->direct.spki.len)   {
			check_attribute_buffer(attr, pubkey->pub_info->direct.spki.len);
			memcpy(attr->pValue, pubkey->pub_info->direct.spki.value, pubkey->pub_info->direct.spki.len);
		}
		else if (pubkey->pub_data)   {
			unsigned char *value = NULL;
			size_t len;

			if (attr->type != CKA_SPKI) {
				if (sc_pkcs15_encode_pubkey(context, pubkey->pub_data, &value, &len))
					return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetAttributeValue");
				} else {
					if (sc_pkcs15_encode_pubkey_as_spki(context, pubkey->pub_data, &value, &len))
					return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetAttributeValue");
				}

			if (attr->pValue == NULL_PTR) {
				attr->ulValueLen = len;
				free(value);
				return CKR_OK;
			}
			if (attr->ulValueLen < len) {
				attr->ulValueLen = len;
				free(value);
				return CKR_BUFFER_TOO_SMALL;
			}
			attr->ulValueLen = len;
			memcpy(attr->pValue, value, len);

			free(value);
		}
		else if (attr->type != CKA_SPKI && pubkey->base.p15_object && pubkey->base.p15_object->content.value && pubkey->base.p15_object->content.len)   {
			check_attribute_buffer(attr, pubkey->base.p15_object->content.len);
			memcpy(attr->pValue, pubkey->base.p15_object->content.value, pubkey->base.p15_object->content.len);
		}
		else if (cert && cert->cert_data) {
			check_attribute_buffer(attr, cert->cert_data->data.len);
			memcpy(attr->pValue, cert->cert_data->data.value, cert->cert_data->data.len);
		}
		else   {
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		break;
	case CKA_GOSTR3410_PARAMS:
		if (pubkey->pub_info && pubkey->pub_info->params.len)
			return get_gostr3410_params(pubkey->pub_info->params.data, pubkey->pub_info->params.len, attr);
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;
	case CKA_EC_PARAMS:
		return get_ec_pubkey_params(pubkey->pub_data, attr);
	case CKA_EC_POINT:
		return get_ec_pubkey_point(pubkey->pub_data, attr);

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_pubkey_ops = {
	pkcs15_pubkey_release,
	pkcs15_pubkey_set_attribute,
	pkcs15_pubkey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	pkcs15_any_destroy,
	NULL,	/* get_size */
	NULL,	/* sign */
	NULL,	/* unwrap_key */
	NULL,	/* decrypt */
	NULL,	/* derive */
	NULL,	/* can_do */
	NULL,	/* init_params */
	NULL	/* wrap_key */
};


/* PKCS#15 Data Object*/
static void
pkcs15_dobj_release(void *object)
{
	__pkcs15_release_object((struct pkcs15_any_object *) object);
}


static CK_RV
pkcs15_dobj_set_attribute(struct sc_pkcs11_session *session,
		void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_data_object *dobj = (struct pkcs15_data_object*) object;

	return pkcs15_set_attrib(session, dobj->base.p15_object, attr);
}


static CK_RV
pkcs15_dobj_get_value(struct sc_pkcs11_session *session,
		struct pkcs15_data_object *dobj,
		struct sc_pkcs15_data **out_data)
{
	struct sc_pkcs11_card *p11card = session->slot->p11card;
	struct pkcs15_fw_data *fw_data = NULL;
	struct sc_card *card;
	int rv;

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	card = session->slot->p11card->card;
	if (!out_data)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (dobj->info->data.len == 0)
	/* CKA_VALUE is empty we may need to read it */
	{
		*out_data = NULL;
	}

	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_GetAttributeValue");

	rv = sc_lock(card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_GetAttributeValue");

	rv = sc_pkcs15_read_data_object(fw_data->p15_card, dobj->info, out_data);

	sc_unlock(card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_GetAttributeValue");

	return rv;
}


static CK_RV
data_value_to_attr(CK_ATTRIBUTE_PTR attr, struct sc_pkcs15_data *data)
{
	if (!attr || !data)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	check_attribute_buffer(attr, data->data_len);
	memcpy(attr->pValue, data->data, data->data_len);
	return CKR_OK;
}


static CK_RV
pkcs15_dobj_get_attribute(struct sc_pkcs11_session *session, void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_data_object *dobj = (struct pkcs15_data_object*) object;
	struct sc_pkcs15_data *data = NULL;
	CK_RV rv;
	size_t len;
	int r;
	unsigned char *buf = NULL;

	sc_log(context, "pkcs15_dobj_get_attribute() called");
	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_DATA;
		break;
	case CKA_TOKEN:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
		break;
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (dobj->base.p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		break;
	case CKA_MODIFIABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (dobj->base.p15_object->flags & 0x02) != 0;
		break;
	case CKA_LABEL:
		len = strnlen(dobj->base.p15_object->label, sizeof dobj->base.p15_object->label);
		check_attribute_buffer(attr, len);
		memcpy(attr->pValue, dobj->base.p15_object->label, len);
		break;
	case CKA_APPLICATION:
		len = strlen(dobj->info->app_label);
		check_attribute_buffer(attr, len);
		memcpy(attr->pValue, dobj->info->app_label, len);
		break;
#if 0
	case CKA_ID:
		check_attribute_buffer(attr, dobj->info->id.len);
		memcpy(attr->pValue, dobj->info->id.value, dobj->info->id.len);
		break;
#endif
	case CKA_OBJECT_ID:
		if (!sc_valid_oid(&dobj->info->app_oid))   {
			attr->ulValueLen = -1;
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		r = sc_asn1_encode_object_id(NULL, &len, &dobj->info->app_oid);
		if (r)   {
			sc_log(context, "data_get_attr(): encode OID error %i", r);
			return CKR_FUNCTION_FAILED;
		}

		check_attribute_buffer(attr, len);

		r = sc_asn1_encode_object_id(&buf, &len, &dobj->info->app_oid);
		if (r)   {
			sc_log(context, "data_get_attr(): encode OID error %i", r);
			return CKR_FUNCTION_FAILED;
		}

		memcpy(attr->pValue, buf, len);
		free(buf);
		break;
	case CKA_VALUE:
		/* if CKA_VALUE is empty, sets data to NULL */
		rv = pkcs15_dobj_get_value(session, dobj, &data);
		if (rv == CKR_OK) {
			if (data) {
				rv = data_value_to_attr(attr, data);
			}
			else {
				attr->ulValueLen = 0;
				attr->pValue = NULL_PTR;
			}
		}
		if (data) {
			free(data->data);
			free(data);
		}
		if (rv != CKR_OK)
			return rv;
		break;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_dobj_ops = {
	pkcs15_dobj_release,
	pkcs15_dobj_set_attribute,
	pkcs15_dobj_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	pkcs15_any_destroy,
	NULL,	/* get_size */
	NULL,	/* sign */
	NULL,	/* unwrap_key */
	NULL,	/* decrypt */
	NULL,	/* derive */
	NULL,	/* can_do */
	NULL,	/* init_params */
	NULL	/* wrap_key */
};


/* PKCS#15 Secret Key Objects */
/* TODO Currently only session objects */
static void
pkcs15_skey_release(void *object)
{
	__pkcs15_release_object((struct pkcs15_any_object *) object);
}


static CK_RV
pkcs15_skey_set_attribute(struct sc_pkcs11_session *session,
		void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_skey_object *skey = (struct pkcs15_skey_object*) object;

	/* TODO DEE Assume a session based token, and only
	 * change in memory, and only selected types
	 * The pkcs15_set_attrib assumes the object is on the card....
	 * When skey support on the card is added this needs to be changed */

	switch (attr->type) {
	case CKA_VALUE:
		if (attr->pValue) {
			skey->info->data.value = calloc(1,attr->ulValueLen);
			if (!skey->info->data.value)
				return CKR_HOST_MEMORY;
			memcpy(skey->info->data.value, attr->pValue, attr->ulValueLen);
			skey->info->data.len = attr->ulValueLen;
		}
		break;
	default:
		return pkcs15_set_attrib(session, skey->base.p15_object, attr);
	}
	return CKR_OK;
}


static CK_RV
pkcs15_skey_get_attribute(struct sc_pkcs11_session *session,
		void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_skey_object *skey = (struct pkcs15_skey_object*) object;
	size_t len;

	sc_log(context, "pkcs15_skey_get_attribute() called");
	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_SECRET_KEY;
		break;
	case CKA_TOKEN:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = skey->base.p15_object->session_object == 0 ? CK_TRUE : CK_FALSE;
		break;
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (skey->base.p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0 ? CK_TRUE : CK_FALSE;
		break;
	case CKA_MODIFIABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (skey->base.p15_object->flags & 0x02) != 0 ? CK_TRUE : CK_FALSE;
		/*TODO Why no definition of the flag */
		break;
	case CKA_LABEL:
		len = strnlen(skey->base.p15_object->label, sizeof skey->base.p15_object->label);
		check_attribute_buffer(attr, len);
		memcpy(attr->pValue, skey->base.p15_object->label, len);
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
		if (skey->info)
			*(CK_OBJECT_CLASS*)attr->pValue = skey->info->key_type;
		break;
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
		if (skey->info)
			return get_usage_bit(skey->info->usage, attr);
		else
			return get_usage_bit(SC_PKCS15_PRKEY_USAGE_ENCRYPT
					|SC_PKCS15_PRKEY_USAGE_DECRYPT
					|SC_PKCS15_PRKEY_USAGE_WRAP
					|SC_PKCS15_PRKEY_USAGE_UNWRAP, attr);
		break;
	case CKA_ID:
		check_attribute_buffer(attr, skey->info->id.len);
		memcpy(attr->pValue, skey->info->id.value, skey->info->id.len);
		break;
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (((skey->base.p15_object->flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE) == SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE)
					&& (skey->base.p15_object->flags & SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE) == 0
					&& (skey->base.p15_object->flags & SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE) == 0) ? CK_TRUE : CK_FALSE;
		break;
	case CKA_ALWAYS_SENSITIVE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (skey->info->access_flags & SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE) != 0;
		break;
	case CKA_NEVER_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (skey->info->access_flags & SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE) != 0;
		break;
	case CKA_SENSITIVE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (skey->info->access_flags & SC_PKCS15_PRKEY_ACCESS_SENSITIVE) != 0;
		break;
	case CKA_LOCAL:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (skey->info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL) != 0;
		break;
	case CKA_OPENSC_ALWAYS_AUTH_ANY_OBJECT:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = skey->base.p15_object->user_consent >= 1 ? CK_TRUE : CK_FALSE;
		break;
	case CKA_VALUE_LEN:
		check_attribute_buffer(attr, sizeof(CK_ULONG));
		*(CK_ULONG*)attr->pValue = skey->info->data.len;
		break;
	case CKA_VALUE:
		check_attribute_buffer(attr, skey->info->data.len);
		memcpy(attr->pValue, skey->info->data.value, skey->info->data.len);
		break;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	return CKR_OK;
}

static CK_RV
pkcs15_skey_unwrap(struct sc_pkcs11_session *session, void *obj,
			CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pWrappedKey,
			CK_ULONG ulWrappedKeyLen,
			void *targetKey)
{
	struct	sc_pkcs11_card *p11card = session->slot->p11card;
	struct	pkcs15_fw_data *fw_data = NULL;
	struct	pkcs15_skey_object *skey = (struct pkcs15_skey_object *) obj;
	struct	pkcs15_skey_object *targetKeyObj = (struct pkcs15_skey_object *) targetKey;
	int	rv, flags = 0;

	sc_log(context, "Initiating unwrapping with a secret key.");

	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];
	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_UnwrapKey");

	if (pMechanism == NULL || pWrappedKey == NULL || ulWrappedKeyLen == 0 || targetKeyObj == NULL) {
		sc_log(context, "One or more of mandatory arguments were NULL.");
		return CKR_ARGUMENTS_BAD;
	}

	/* Check whether this key supports unwrap */
	if (skey && !(skey->info->usage & SC_PKCS15_PRKEY_USAGE_UNWRAP))
		skey = NULL;

	/* TODO: should we look for a compatible key automatically? prv_next not implemented yet. */
	/* skey = skey->prv_next; */

	if (skey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	sc_log(context, "Using mechanism %lx.", pMechanism->mechanism);
	/* Select the proper padding mechanism */
	switch (pMechanism->mechanism) {
	case CKM_AES_ECB:
		flags |= SC_ALGORITHM_AES_ECB;
		break;
	case CKM_AES_CBC_PAD:
		flags |= SC_ALGORITHM_AES_CBC_PAD;
		break;
	case CKM_AES_CBC:
		flags |= SC_ALGORITHM_AES_CBC; /* in this case, pMechanism->pParameter contains IV */
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	rv = sc_lock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_UnwrapKey");

	/* Call the card to do the unwrap operation */
	rv = sc_pkcs15_unwrap(fw_data->p15_card, skey->prv_p15obj, targetKeyObj->prv_p15obj, flags,
		pWrappedKey, ulWrappedKeyLen, pMechanism->pParameter, pMechanism->ulParameterLen);

	sc_unlock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_UnwrapKey");

	return CKR_OK;
}

/*
 * Wrap a key using a secret key. obj = wrapping key, targetKey = key to be wrapped.
 * Wrapped key data is returned in pData
 */

static CK_RV
pkcs15_skey_wrap(struct sc_pkcs11_session *session, void *obj,
			CK_MECHANISM_PTR pMechanism,
			void *targetKey,
			CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)

{
	struct	sc_pkcs11_card *p11card;
	struct	pkcs15_fw_data *fw_data = NULL;
	struct	pkcs15_skey_object *skey = (struct pkcs15_skey_object *) obj;
	struct	pkcs15_skey_object *targetKeyObj = (struct pkcs15_skey_object *) targetKey;
	size_t len = pulDataLen ? *pulDataLen : 0;
	int rv, flags = 0;

	sc_log(context, "Initializing wrapping with a secret key.");

	if (session == NULL || pMechanism == NULL || obj == NULL || targetKey == NULL) {
		sc_log(context, "One or more of mandatory arguments were NULL.");
		return CKR_ARGUMENTS_BAD;
	}

	p11card = session->slot->p11card;
	if (!p11card)
		return CKR_TOKEN_NOT_RECOGNIZED;
	fw_data = (struct pkcs15_fw_data *) p11card->fws_data[session->slot->fw_data_idx];

	if (!fw_data)
		return sc_to_cryptoki_error(SC_ERROR_INTERNAL, "C_WrapKey");

	/* Verify that the key supports wrapping */
	if (skey && !(skey->info->usage & SC_PKCS15_PRKEY_USAGE_WRAP))
		skey = NULL;
	/* TODO: browse for a key that supports, like other similar funcs */

	if (skey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	sc_log(context, "Using mechanism %lx.", pMechanism->mechanism);

	/* Select the proper padding mechanism */
	switch (pMechanism->mechanism) {
	case CKM_AES_ECB:
		flags |= SC_ALGORITHM_AES_ECB;
		break;
	case CKM_AES_CBC_PAD:	/* with CBC, pMechanism->pParameter contains IV */
		flags |= SC_ALGORITHM_AES_CBC_PAD;
		break;
	case CKM_AES_CBC:
		flags |= SC_ALGORITHM_AES_CBC;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	rv = sc_lock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_UnwrapKey");

	/* Call the card to do the wrapping operation */
	rv = sc_pkcs15_wrap(fw_data->p15_card, skey->prv_p15obj, targetKeyObj->prv_p15obj, flags,
		pData, &len, pMechanism->pParameter, pMechanism->ulParameterLen);

	if (pulDataLen) {
		*pulDataLen = len;
	}

	sc_unlock(p11card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_UnwrapKey");

	return CKR_OK;
}


/*
 *  Secret key objects, currently used only to retrieve derived session key
 */
struct sc_pkcs11_object_ops pkcs15_skey_ops = {
	pkcs15_skey_release,
	pkcs15_skey_set_attribute,
	pkcs15_skey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	pkcs15_skey_destroy,
	NULL,	/* get_size */
	NULL,	/* sign */
	pkcs15_skey_unwrap,
	NULL,	/* decrypt */
	NULL,	/* derive */
	NULL,	/* can_do */
	NULL,	/* init_params */
	pkcs15_skey_wrap /* wrap_key */
};

/*
 * get_attribute helpers
 */
static CK_RV
get_bignum(sc_pkcs15_bignum_t *bn, CK_ATTRIBUTE_PTR attr)
{
	check_attribute_buffer(attr, bn->len);
	memcpy(attr->pValue, bn->data, bn->len);
	return CKR_OK;
}

static CK_RV
get_bignum_bits(sc_pkcs15_bignum_t *bn, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG	bits, mask;

	if (!bn || !bn->len || !bn->data)
		return CKR_DEVICE_ERROR;

	bits = bn->len * 8;
	for (mask = 0x80; mask; mask >>= 1, bits--)
		if (bn->data[0] & mask)
			break;

	check_attribute_buffer(attr, sizeof(bits));
	*(CK_ULONG *) attr->pValue = bits;
	return CKR_OK;
}

static CK_RV
get_modulus(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return get_bignum(&key->u.rsa.modulus, attr);
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_modulus_bits(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return get_bignum_bits(&key->u.rsa.modulus, attr);
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_public_exponent(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return get_bignum(&key->u.rsa.exponent, attr);
	}

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_ec_pubkey_params(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	struct sc_ec_parameters *ecp;

	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	if (key->alg_id == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	switch (key->algorithm) {
	case SC_ALGORITHM_EC:
		/* TODO parms should not be in two places */
		/* ec_params may be in key->alg_id or in key->u.ec */
		if (key->u.ec.params.der.value) {
			check_attribute_buffer(attr,key->u.ec.params.der.len);
			memcpy(attr->pValue, key->u.ec.params.der.value, key->u.ec.params.der.len);
			return CKR_OK;
		}

		ecp = (struct sc_ec_parameters *) key->alg_id->params;
		if (ecp && ecp->der.value && ecp->der.len)   {
			check_attribute_buffer(attr, ecp->der.len);
			memcpy(attr->pValue, ecp->der.value, ecp->der.len);
			return CKR_OK;
		}
	}

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_ec_pubkey_point(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	unsigned char *value = NULL;
	size_t value_len = 0;
	int rc;

	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	switch (key->algorithm) {
	case SC_ALGORITHM_EC:
		rc = sc_pkcs15_encode_pubkey_ec(context, &key->u.ec, &value, &value_len);
		if (rc != SC_SUCCESS)
			return sc_to_cryptoki_error(rc, NULL);

		if (attr->pValue == NULL_PTR) {
			attr->ulValueLen = value_len;
			free(value);
			return CKR_OK;
		}
		if (attr->ulValueLen < value_len) {
			attr->ulValueLen = value_len;
			free(value);
			return CKR_BUFFER_TOO_SMALL;
		}
		attr->ulValueLen = value_len;

		memcpy(attr->pValue, value, value_len);
		free(value);
		return CKR_OK;
	}

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_gostr3410_params(const u8 *params, size_t params_len, CK_ATTRIBUTE_PTR attr)
{
	size_t i;

	if (!params || params_len == sizeof(int))
		return CKR_ATTRIBUTE_TYPE_INVALID;

	for (i = 0; i < sizeof(gostr3410_param_oid)/sizeof(gostr3410_param_oid[0]); ++i) {
		if (gostr3410_param_oid[i].oid_id == ((int*)params)[0]) {
			check_attribute_buffer(attr, gostr3410_param_oid[i].encoded_oid_size);
			memcpy(attr->pValue, gostr3410_param_oid[i].encoded_oid,
					gostr3410_param_oid[i].encoded_oid_size);
			return CKR_OK;
		}
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

/*
 * Map pkcs15 usage bits to pkcs11 usage attributes.
 *
 * It's not totally clear to me whether SC_PKCS15_PRKEY_USAGE_NONREPUDIATION should
 * be treated as being equivalent with CKA_SIGN or not...
 */
static CK_RV
get_usage_bit(unsigned int usage, CK_ATTRIBUTE_PTR attr)
{
	static struct {
		CK_ATTRIBUTE_TYPE type;
		unsigned int	flag;
	} flag_mapping[] = {
		{ CKA_ENCRYPT,		SC_PKCS15_PRKEY_USAGE_ENCRYPT },
		{ CKA_DECRYPT,		SC_PKCS15_PRKEY_USAGE_DECRYPT },
		{ CKA_SIGN,		SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_NONREPUDIATION },
		{ CKA_SIGN_RECOVER,	SC_PKCS15_PRKEY_USAGE_SIGNRECOVER },
		{ CKA_WRAP,		SC_PKCS15_PRKEY_USAGE_WRAP },
		{ CKA_UNWRAP,		SC_PKCS15_PRKEY_USAGE_UNWRAP },
		{ CKA_VERIFY,		SC_PKCS15_PRKEY_USAGE_VERIFY },
		{ CKA_VERIFY_RECOVER,	SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER },
		{ CKA_DERIVE,		SC_PKCS15_PRKEY_USAGE_DERIVE },
		{ CKA_OPENSC_NON_REPUDIATION, SC_PKCS15_PRKEY_USAGE_NONREPUDIATION },
		{ 0, 0 }
	};
	unsigned int mask = 0, j;

	for (j = 0; (mask = flag_mapping[j].flag) != 0; j++) {
		if (flag_mapping[j].type == attr->type)
			break;
	}
	if (mask == 0)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	check_attribute_buffer(attr, sizeof(CK_BBOOL));
	*(CK_BBOOL*)attr->pValue = (usage & mask)? TRUE : FALSE;

	return CKR_OK;
}


static CK_RV
register_gost_mechanisms(struct sc_pkcs11_card *p11card, int flags)
{
	CK_MECHANISM_INFO mech_info;
	sc_pkcs11_mechanism_type_t *mt;
	CK_RV rc;

	mech_info.flags = CKF_HW | CKF_SIGN | CKF_DECRYPT;
#ifdef ENABLE_OPENSSL
	/* That practise definitely conflicts with CKF_HW -- andre 2010-11-28 */
	mech_info.flags |= CKF_VERIFY;
#endif
	mech_info.ulMinKeySize = SC_PKCS15_GOSTR3410_KEYSIZE;
	mech_info.ulMaxKeySize = SC_PKCS15_GOSTR3410_KEYSIZE;

	if (flags & SC_ALGORITHM_GOSTR3410_HASH_NONE) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_GOSTR3410,
				&mech_info, CKK_GOSTR3410, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}
	if (flags & SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_GOSTR3410_WITH_GOSTR3411,
				&mech_info, CKK_GOSTR3410, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}
	if (flags & SC_ALGORITHM_ONBOARD_KEY_GEN) {
		mech_info.flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
		mt = sc_pkcs11_new_fw_mechanism(CKM_GOSTR3410_KEY_PAIR_GEN,
				&mech_info, CKK_GOSTR3410, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}

	return CKR_OK;
}


static CK_RV register_ec_mechanisms(struct sc_pkcs11_card *p11card, int flags,
		unsigned long ext_flags, CK_ULONG min_key_size, CK_ULONG max_key_size)
{
	CK_MECHANISM_INFO mech_info;
	sc_pkcs11_mechanism_type_t *mt;
	CK_FLAGS ec_flags = 0;
	CK_RV rc;

	if (ext_flags & SC_ALGORITHM_EXT_EC_F_P)
		ec_flags |= CKF_EC_F_P;
	if (ext_flags & SC_ALGORITHM_EXT_EC_F_2M)
		ec_flags |= CKF_EC_F_2M;
	if (ext_flags & SC_ALGORITHM_EXT_EC_ECPARAMETERS)
		ec_flags |= CKF_EC_ECPARAMETERS;
	if (ext_flags & SC_ALGORITHM_EXT_EC_NAMEDCURVE)
		ec_flags |= CKF_EC_NAMEDCURVE;
	if (ext_flags & SC_ALGORITHM_EXT_EC_UNCOMPRESES)
		ec_flags |= CKF_EC_UNCOMPRESS;
	if (ext_flags & SC_ALGORITHM_EXT_EC_COMPRESS)
		ec_flags |= CKF_EC_COMPRESS;

	mech_info.flags = CKF_HW | CKF_SIGN; /* check for more */
	mech_info.flags |= ec_flags;
	mech_info.ulMinKeySize = min_key_size;
	mech_info.ulMaxKeySize = max_key_size;

	if(flags & SC_ALGORITHM_ECDSA_HASH_NONE) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_ECDSA, &mech_info, CKK_EC, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}

#ifdef ENABLE_OPENSSL
	if(flags & SC_ALGORITHM_ECDSA_HASH_SHA1) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_ECDSA_SHA1, &mech_info, CKK_EC, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}
#endif

	/* ADD ECDH mechanisms */
	/* The PIV uses curves where CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE produce the same results */
	if(flags & SC_ALGORITHM_ECDH_CDH_RAW) {
		mech_info.flags &= ~CKF_SIGN;
		mech_info.flags |= CKF_DERIVE;

		mt = sc_pkcs11_new_fw_mechanism(CKM_ECDH1_COFACTOR_DERIVE, &mech_info, CKK_EC, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

		mt = sc_pkcs11_new_fw_mechanism(CKM_ECDH1_DERIVE, &mech_info, CKK_EC, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}

	if (flags & SC_ALGORITHM_ONBOARD_KEY_GEN) {
		mech_info.flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
		mech_info.flags |= ec_flags;
		mt = sc_pkcs11_new_fw_mechanism(CKM_EC_KEY_PAIR_GEN, &mech_info, CKK_EC, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}

	return CKR_OK;
}

static int sc_pkcs11_register_aes_mechanisms(struct sc_pkcs11_card *p11card, int flags,
		CK_ULONG min_key_size, CK_ULONG max_key_size)
{
	int rc;
	CK_MECHANISM_INFO mech_info;
	sc_pkcs11_mechanism_type_t *mt;
	sc_card_t* card = p11card->card;
	memset(&mech_info, 0, sizeof(mech_info));
	mech_info.flags = CKF_ENCRYPT | CKF_DECRYPT;
	mech_info.ulMinKeySize = min_key_size;
	mech_info.ulMaxKeySize = max_key_size;

	if ((card->caps & SC_CARD_CAP_UNWRAP_KEY) == SC_CARD_CAP_UNWRAP_KEY)
		mech_info.flags |= CKF_UNWRAP;
	if ((card->caps & SC_CARD_CAP_WRAP_KEY) == SC_CARD_CAP_WRAP_KEY)
		mech_info.flags |= CKF_WRAP;

	mt = sc_pkcs11_new_fw_mechanism(CKM_AES_ECB, &mech_info, CKK_AES, NULL, NULL);
	if (!mt)
		return CKR_HOST_MEMORY;
	rc = sc_pkcs11_register_mechanism(p11card, mt);
	if (rc != CKR_OK)
			return rc;

	mt = sc_pkcs11_new_fw_mechanism(CKM_AES_CBC, &mech_info, CKK_AES, NULL, NULL);
	if (!mt)
		return CKR_HOST_MEMORY;
	rc = sc_pkcs11_register_mechanism(p11card, mt);
	if (rc != CKR_OK)
			return rc;

	mt = sc_pkcs11_new_fw_mechanism(CKM_AES_CBC_PAD, &mech_info, CKK_AES, NULL, NULL);
	if (!mt)
		return CKR_HOST_MEMORY;
	rc = sc_pkcs11_register_mechanism(p11card, mt);
	if (rc != CKR_OK)
			return rc;

	return CKR_OK;
}

/*
 * Mechanism handling
 * FIXME: We should consult the card's algorithm list to
 * find out what operations it supports
 */
static CK_RV
register_mechanisms(struct sc_pkcs11_card *p11card)
{
	sc_card_t *card = p11card->card;
	sc_algorithm_info_t *alg_info;
	CK_MECHANISM_INFO mech_info;
	CK_ULONG ec_min_key_size, ec_max_key_size,
		aes_min_key_size, aes_max_key_size;
	unsigned long ec_ext_flags;
	sc_pkcs11_mechanism_type_t *mt;
	unsigned int num;
	int rsa_flags = 0, ec_flags = 0, gostr_flags = 0, aes_flags = 0;
	CK_RV rc;

	/* Register generic mechanisms */
	sc_pkcs11_register_generic_mechanisms(p11card);

	mech_info.flags = CKF_HW | CKF_SIGN | CKF_DECRYPT;
#ifdef ENABLE_OPENSSL
	/* That practise definitely conflicts with CKF_HW -- andre 2010-11-28 */
	mech_info.flags |= CKF_VERIFY;
#endif
	if ((card->caps & SC_CARD_CAP_UNWRAP_KEY) == SC_CARD_CAP_UNWRAP_KEY)
		mech_info.flags |= CKF_UNWRAP;
	if ((card->caps & SC_CARD_CAP_WRAP_KEY) == SC_CARD_CAP_WRAP_KEY)
		mech_info.flags |= CKF_WRAP;

	mech_info.ulMinKeySize = ~0;
	mech_info.ulMaxKeySize = 0;
	ec_min_key_size = ~0;
	ec_max_key_size = 0;
	aes_min_key_size = ~0;
	aes_max_key_size = 0;

	ec_ext_flags = 0;

	/* For now, we just OR all the algorithm specific
	 * flags, based on the assumption that cards don't
	 * support different modes for different key *sizes*. */
	num = card->algorithm_count;
	alg_info = card->algorithms;
	while (num--) {
		switch (alg_info->algorithm) {
			case SC_ALGORITHM_RSA:
				if (alg_info->key_length < mech_info.ulMinKeySize)
					mech_info.ulMinKeySize = alg_info->key_length;
				if (alg_info->key_length > mech_info.ulMaxKeySize)
					mech_info.ulMaxKeySize = alg_info->key_length;
				rsa_flags |= alg_info->flags;
				break;
			case SC_ALGORITHM_EC:
				if (alg_info->key_length < ec_min_key_size)
					ec_min_key_size = alg_info->key_length;
				if (alg_info->key_length > ec_max_key_size)
					ec_max_key_size = alg_info->key_length;
				ec_flags |= alg_info->flags;
				ec_ext_flags |= alg_info->u._ec.ext_flags;
				break;
			case SC_ALGORITHM_GOSTR3410:
				gostr_flags |= alg_info->flags;
				break;
			case SC_ALGORITHM_AES:
				aes_flags |= alg_info->flags;
				if (alg_info->key_length < aes_min_key_size)
					aes_min_key_size = alg_info->key_length;
				if (alg_info->key_length > aes_max_key_size)
					aes_max_key_size = alg_info->key_length;
				break;
		}
		alg_info++;
	}

	if (ec_flags & SC_ALGORITHM_ECDSA_RAW) {
		rc = register_ec_mechanisms(p11card, ec_flags, ec_ext_flags, ec_min_key_size, ec_max_key_size);
		if (rc != CKR_OK)
			return rc;
	}

	if (gostr_flags & (SC_ALGORITHM_GOSTR3410_RAW
				| SC_ALGORITHM_GOSTR3410_HASH_NONE
				| SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411)) {
		if (gostr_flags & SC_ALGORITHM_GOSTR3410_RAW)
			gostr_flags |= SC_ALGORITHM_GOSTR3410_HASH_NONE;
		rc = register_gost_mechanisms(p11card, gostr_flags);
		if (rc != CKR_OK)
			return rc;
	}

	/* Check if we support raw RSA */
	if (rsa_flags & SC_ALGORITHM_RSA_RAW) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_X_509, &mech_info, CKK_RSA, NULL, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

		/* We support PKCS1 padding in software */
		/* either the card supports it or OpenSC does */
		rsa_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
#ifdef ENABLE_OPENSSL
		rsa_flags |= SC_ALGORITHM_RSA_PAD_PSS;
#endif
	}

	if (rsa_flags & SC_ALGORITHM_RSA_PAD_ISO9796) {
		/* Supported in hardware only, if the card driver declares it. */
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_9796, &mech_info, CKK_RSA, NULL, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}

#ifdef ENABLE_OPENSSL
	/* all our software hashes are in OpenSSL */
	/* Only if card did not list the hashes, will we
	 * help it a little, by adding all the OpenSSL hashes
	 * that have PKCS#11 mechanisms.
	 */
	if (!(rsa_flags & (SC_ALGORITHM_RSA_HASHES & ~SC_ALGORITHM_RSA_HASH_NONE))) {
		rsa_flags |= SC_ALGORITHM_RSA_HASHES;
	}
#endif

	/* No need to Check for PKCS1  We support it in software and turned it on above so always added it */
	if (rsa_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS, &mech_info, CKK_RSA, NULL, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

#ifdef ENABLE_OPENSSL
		/* sc_pkcs11_register_sign_and_hash_mechanism expects software hash */
		/* All hashes are in OpenSSL
		 * Either the card set the hashes or we helped it above */

		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA1_RSA_PKCS, CKM_SHA_1, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA224) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA224_RSA_PKCS, CKM_SHA224, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA256_RSA_PKCS, CKM_SHA256, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA384) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA384_RSA_PKCS, CKM_SHA384, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA512) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA512_RSA_PKCS, CKM_SHA512, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_MD5) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_MD5_RSA_PKCS, CKM_MD5, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_RIPEMD160) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_RIPEMD160_RSA_PKCS, CKM_RIPEMD160, mt);
			if (rc != CKR_OK)
				return rc;
		}
#endif /* ENABLE_OPENSSL */
	}

	if (rsa_flags & SC_ALGORITHM_RSA_PAD_PSS) {
		mech_info.flags &= ~(CKF_DECRYPT|CKF_ENCRYPT);
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS_PSS, &mech_info, CKK_RSA, NULL, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA224) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA224_RSA_PKCS_PSS, CKM_SHA224, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA384) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA512) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card,
				CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512, mt);
			if (rc != CKR_OK)
				return rc;
		}
	}

	if (rsa_flags & SC_ALGORITHM_ONBOARD_KEY_GEN) {
		mech_info.flags = CKF_GENERATE_KEY_PAIR;
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, &mech_info, CKK_RSA, NULL, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}

	if (aes_max_key_size > 0) {
		rc = sc_pkcs11_register_aes_mechanisms(p11card, aes_flags, aes_min_key_size, aes_max_key_size);
		if (rc != CKR_OK)
			return rc;
	}


	return CKR_OK;
}


static int
lock_card(struct pkcs15_fw_data *fw_data)
{
	int	rc;

	if ((rc = sc_lock(fw_data->p15_card->card)) < 0)
		sc_log(context, "Failed to lock card (%d)", rc);
	else
		fw_data->locked++;

	return rc;
}


static int
unlock_card(struct pkcs15_fw_data *fw_data)
{
	while (fw_data->locked) {
		sc_unlock(fw_data->p15_card->card);
		fw_data->locked--;
	}
	return 0;
}


static int
reselect_app_df(sc_pkcs15_card_t *p15card)
{
	int r = SC_SUCCESS;

	if (p15card->file_app != NULL) {
		/* if the application df (of the pkcs15 application) is specified select it */
		sc_path_t *tpath = &p15card->file_app->path;
		sc_log(p15card->card->ctx, "reselect application df");
		r = sc_select_file(p15card->card, tpath, NULL);
	}
	return r;
}
