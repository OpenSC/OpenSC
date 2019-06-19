/*
 * pkcs15-sc-hsm.c : PKCS#15 emulation for write support
 *
 * Copyright (C) 2012 Andreas Schwier, CardContact, Minden, Germany
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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include "../libopensc/opensc.h"
#include "../libopensc/cardctl.h"
#include "../libopensc/log.h"
#include "../libopensc/pkcs15.h"
#include "../libopensc/cards.h"
#include "../libopensc/card-sc-hsm.h"
#include "../libopensc/asn1.h"
#include "../libopensc/pkcs15.h"

#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"

#include "pkcs15-init.h"
#include "profile.h"



static u8 pubexp[] = { 0x01, 0x00, 0x01 };



static int sc_hsm_delete_ef(sc_pkcs15_card_t *p15card, u8 prefix, u8 id)
{
	sc_card_t *card = p15card->card;
	sc_path_t path;
	u8 fid[2];
	int r;

	fid[0] = prefix;
	fid[1] = id;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, -1);

	r = sc_delete_file(card, &path);
	LOG_TEST_RET(card->ctx, r, "Could not delete file");

	LOG_FUNC_RETURN(card->ctx, r);
}



static int sc_hsm_update_ef(sc_pkcs15_card_t *p15card, u8 prefix, u8 id, int erase, u8 *buf, size_t buflen)
{
	sc_card_t *card = p15card->card;
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 fid[2];
	int r;

	fid[0] = prefix;
	fid[1] = id;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, -1);

	r = sc_select_file(card, &path, NULL);

	if ((r == SC_SUCCESS) && erase) {
		r = sc_delete_file(card, &path);
		LOG_TEST_RET(card->ctx, r, "Could not delete file");
		r = SC_ERROR_FILE_NOT_FOUND;
	}

	if (r == SC_ERROR_FILE_NOT_FOUND) {
		file = sc_file_new();
		file->id = (path.value[0] << 8) | path.value[1];
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = (size_t) 0;
		file->status = SC_FILE_STATUS_ACTIVATED;
		r = sc_create_file(card, file);
		sc_file_free(file);
		LOG_TEST_RET(card->ctx, r, "Could not create file");
	}

	r = sc_update_binary(card, 0, buf, buflen, 0);
	LOG_FUNC_RETURN(card->ctx, r);
}



static int sc_hsm_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj)
{
	// Keys are automatically generated in GENERATE ASYMMETRIC KEY PAIR command
	LOG_FUNC_CALLED(p15card->card->ctx);
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}



static int sc_hsm_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	LOG_FUNC_CALLED(p15card->card->ctx);
	LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_NOT_SUPPORTED);
}



static int sc_hsm_determine_free_id(struct sc_pkcs15_card *p15card, u8 range)
{
	struct sc_card *card = p15card->card;
	u8 filelist[MAX_EXT_APDU_LENGTH];
	int filelistlength, i, j;

	LOG_FUNC_CALLED(p15card->card->ctx);

	filelistlength = sc_list_files(card, filelist, sizeof(filelist));
	LOG_TEST_RET(card->ctx, filelistlength, "Could not enumerate file and key identifier");

	for (j = 0; j < 256; j++) {
		for (i = 0; i < filelistlength; i += 2) {
			if ((filelist[i] == range) && (filelist[i + 1] == j)) {
				break;
			}
		}
		if (i >= filelistlength) {
			LOG_FUNC_RETURN(p15card->card->ctx, j);
		}
	}
	LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_NOT_ENOUGH_MEMORY);
}



static int sc_hsm_encode_gakp_rsa(struct sc_pkcs15_card *p15card, sc_cvc_t *cvc, int keysize) {
	struct sc_object_id rsa15withSHA256 = { { 0,4,0,127,0,7,2,2,2,1,2,-1 } };

	LOG_FUNC_CALLED(p15card->card->ctx);

	cvc->coefficientAorExponentlen = sizeof(pubexp);
	cvc->coefficientAorExponent = malloc(sizeof(pubexp));
	if (!cvc->coefficientAorExponent) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc->coefficientAorExponent, pubexp, sizeof(pubexp));

	cvc->pukoid = rsa15withSHA256;
	cvc->modulusSize = keysize;

	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}



static int sc_hsm_encode_gakp_ec(struct sc_pkcs15_card *p15card, sc_cvc_t *cvc, struct sc_pkcs15_prkey_info *key_info) {
	struct sc_object_id ecdsaWithSHA256 = { { 0,4,0,127,0,7,2,2,2,2,3,-1 } };
	struct sc_ec_parameters *ecparams = (struct sc_ec_parameters *)key_info->params.data;
	struct ec_curve *curve = NULL;
	u8 *curveoid;
	int curveoidlen,r;

	LOG_FUNC_CALLED(p15card->card->ctx);

	curveoid = ecparams->der.value;
	if ((ecparams->der.len < 3) || (*curveoid++ != 0x06)) {
		sc_log(p15card->card->ctx, "EC_PARAMS does not contain curve object identifier");
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_INVALID_DATA);
	}

	curveoidlen = *curveoid++;

	r = sc_pkcs15emu_sc_hsm_get_curve(&curve, curveoid, curveoidlen);
	LOG_TEST_RET(p15card->card->ctx, r, "Unsupported named curve");

	cvc->primeOrModuluslen = curve->prime.len;
	cvc->primeOrModulus = malloc(cvc->primeOrModuluslen);
	if (!cvc->primeOrModulus) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc->primeOrModulus, curve->prime.value, cvc->primeOrModuluslen);

	cvc->coefficientAorExponentlen = curve->coefficientA.len;
	cvc->coefficientAorExponent = malloc(cvc->coefficientAorExponentlen);
	if (!cvc->coefficientAorExponent) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc->coefficientAorExponent, curve->coefficientA.value, cvc->coefficientAorExponentlen);

	cvc->coefficientBlen = curve->coefficientB.len;
	cvc->coefficientB = malloc(cvc->coefficientBlen);
	if (!cvc->coefficientB) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc->coefficientB, curve->coefficientB.value, cvc->coefficientBlen);

	cvc->basePointGlen = curve->basePointG.len;
	cvc->basePointG = malloc(cvc->basePointGlen);
	if (!cvc->basePointG) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc->basePointG, curve->basePointG.value, cvc->basePointGlen);

	cvc->orderlen = curve->order.len;
	cvc->order = malloc(cvc->orderlen);
	if (!cvc->order) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc->order, curve->order.value, cvc->orderlen);

	cvc->cofactorlen = curve->coFactor.len;
	cvc->cofactor = malloc(cvc->cofactorlen);
	if (!cvc->cofactor) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc->cofactor, curve->coFactor.value, cvc->cofactorlen);

	cvc->pukoid = ecdsaWithSHA256;

	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}



static int sc_hsm_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
															struct sc_pkcs15_object *object,
															struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_card *card = p15card->card;
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	sc_cardctl_sc_hsm_keygen_info_t sc_hsm_keyinfo;
	sc_cvc_t cvc;
	u8 *cvcbin, *cvcpo;
	unsigned int cla,tag;
	size_t taglen, cvclen;
	int r;

	LOG_FUNC_CALLED(p15card->card->ctx);

	key_info->key_reference = sc_hsm_determine_free_id(p15card, KEY_PREFIX);
	LOG_TEST_RET(card->ctx, key_info->key_reference, "Could not determine key reference");

	memset(&cvc, 0, sizeof(cvc));

	strlcpy(cvc.car, "UTCA00001", sizeof cvc.car);
	strlcpy(cvc.chr, priv->serialno, sizeof cvc.chr);
	strlcat(cvc.chr, "00001", sizeof cvc.chr);

	switch(object->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		r = sc_hsm_encode_gakp_rsa(p15card, &cvc, key_info->modulus_length);
		break;
	case SC_PKCS15_TYPE_PRKEY_EC:
		r = sc_hsm_encode_gakp_ec(p15card, &cvc, key_info);
		break;
	default:
		r = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}
	LOG_TEST_RET(p15card->card->ctx, r, "Could not encode GAKP cdata");

	r = sc_pkcs15emu_sc_hsm_encode_cvc(p15card, &cvc, &cvcbin, &cvclen);
	sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
	LOG_TEST_RET(p15card->card->ctx, r, "Could not encode GAKP cdata");


	cvcpo = cvcbin;
	sc_asn1_read_tag((const u8 **)&cvcpo, cvclen, &cla, &tag, &taglen);
	sc_asn1_read_tag((const u8 **)&cvcpo, cvclen, &cla, &tag, &taglen);

	sc_hsm_keyinfo.key_id = key_info->key_reference;
	sc_hsm_keyinfo.auth_key_id = 0;
	sc_hsm_keyinfo.gakprequest = cvcpo;
	sc_hsm_keyinfo.gakprequest_len = taglen;
	sc_hsm_keyinfo.gakpresponse = NULL;
	sc_hsm_keyinfo.gakpresponse_len = 0;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_GENERATE_KEY, &sc_hsm_keyinfo);
	if (r < 0)
		goto out;


	cvcpo = sc_hsm_keyinfo.gakpresponse;
	cvclen = sc_hsm_keyinfo.gakpresponse_len;

	r = sc_pkcs15emu_sc_hsm_decode_cvc(p15card, (const u8 **)&cvcpo, &cvclen, &cvc);
	if (r < 0) {
		sc_log(p15card->card->ctx, "Could not decode GAKP rdata");
		r = SC_ERROR_OBJECT_NOT_VALID;
		goto out;
	}

	r = sc_hsm_update_ef(p15card, EE_CERTIFICATE_PREFIX, key_info->key_reference, 1, sc_hsm_keyinfo.gakpresponse, sc_hsm_keyinfo.gakpresponse_len);
	if (r < 0) {
		sc_log(p15card->card->ctx, "Could not save certificate signing request");
		goto out;
	}

	if (pubkey != NULL) {
		r = sc_pkcs15emu_sc_hsm_get_public_key(p15card->card->ctx, &cvc, pubkey);
	}

	out:

	sc_pkcs15emu_sc_hsm_free_cvc(&cvc);

	if (cvcbin) {
		free(cvcbin);
	}
	if (sc_hsm_keyinfo.gakpresponse) {
		free(sc_hsm_keyinfo.gakpresponse);
	}
	LOG_FUNC_RETURN(p15card->card->ctx, r);
}



/*
 * Certificates with a related private key are stored in the fid range CE00 - CEFF. The
 * second byte in the fid matches the key id.
 * Certificates without a related private key (e.g. CA certificates) are stored in the fid range
 * CA00 - CAFF. The second byte is a free selected id.
 */
static int sc_hsm_emu_store_cert(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data)

{
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	struct sc_pkcs15_object *prkey;
	sc_path_t path;
	u8 id[2];
	int r;

	r = sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PRKEY, &cert_info->id , &prkey);

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		r = sc_hsm_determine_free_id(p15card, CA_CERTIFICATE_PREFIX);
		LOG_TEST_RET(p15card->card->ctx, r, "Out of identifier to store certificate description");

		id[0] = CA_CERTIFICATE_PREFIX;
		id[1] = r;
	} else {
		LOG_TEST_RET(p15card->card->ctx, r, "Error locating matching private key");

		id[0] = EE_CERTIFICATE_PREFIX;
		id[1] = ((struct sc_pkcs15_prkey_info *)prkey->data)->key_reference;
	}

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, id, 2, 0, -1);
	cert_info->path = path;

	r = sc_hsm_update_ef(p15card, id[0], id[1], 1, data->value, data->len);
	return r;
}



static int sc_hsm_emu_delete_cert(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object)

{
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;

	return sc_hsm_delete_ef(p15card, cert_info->path.value[0], cert_info->path.value[1]);
}



static int sc_hsm_emu_store_binary(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data)

{
	struct sc_pkcs15_data_info *data_info = (struct sc_pkcs15_data_info *) object->data;
	sc_path_t path;
	u8 id[2];
	int r;

	r = sc_hsm_determine_free_id(p15card, DCOD_PREFIX);
	LOG_TEST_RET(p15card->card->ctx, r, "Out of identifier to store data description");

	if (object->flags & SC_PKCS15_CO_FLAG_PRIVATE) {
		id[0] = PROT_DATA_PREFIX;
	} else {
		id[0] = DATA_PREFIX;
	}
	id[1] = r;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, id, 2, 0, -1);
	data_info->path = path;

	r = sc_hsm_update_ef(p15card, id[0], id[1], 1, data->value, data->len);
	return r;
}



static int sc_hsm_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)

{
	struct sc_context *ctx = p15card->card->ctx;
	int r;

	LOG_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
	case SC_PKCS15_TYPE_PUBKEY:
		r = SC_SUCCESS;
		break;
	case SC_PKCS15_TYPE_CERT:
		r = sc_hsm_emu_store_cert(p15card, profile, object, data);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		r = sc_hsm_emu_store_binary(p15card, profile, object, data);
		break;
	default:
		r = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, r);
}



static int sc_hsm_emu_delete_object(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, const struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	int r;

	LOG_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		r = sc_hsm_delete_ef(p15card, KEY_PREFIX, ((struct sc_pkcs15_prkey_info *)object->data)->key_reference);
		break;
	case SC_PKCS15_TYPE_CERT:
		r = sc_hsm_emu_delete_cert(p15card, profile, object);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		r = sc_delete_file(p15card->card, path);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		r = SC_SUCCESS;
		break;
	default:
		r = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, r);
}



static int sc_hsm_emu_update_prkd(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	u8 *buf;
	size_t buflen;
	int r;

	// Don't save AID in PRKD
	key_info->path.aid.len = 0;

	r = sc_pkcs15_encode_prkdf_entry(p15card->card->ctx, object, &buf, &buflen);
	LOG_TEST_RET(p15card->card->ctx, r, "Error encoding PRKD entry");

	r = sc_hsm_update_ef(p15card, PRKD_PREFIX, key_info->key_reference, 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_update_dcod(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_pkcs15_data_info *data_info = (struct sc_pkcs15_data_info *) object->data;
	u8 *buf;
	size_t buflen;
	int r;

	r = sc_pkcs15_encode_dodf_entry(p15card->card->ctx, object, &buf, &buflen);
	LOG_TEST_RET(p15card->card->ctx, r, "Error encoding DCOD entry");

	r = sc_hsm_update_ef(p15card, DCOD_PREFIX, data_info->path.value[data_info->path.len - 1], 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_update_cd(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	u8 *buf;
	size_t buflen;
	int r;

	if ((cert_info->path.len < 2) ||
		((cert_info->path.value[cert_info->path.len - 2]) != CA_CERTIFICATE_PREFIX)) {
		// Certificates associated with stored private keys don't get a separate CD entry
		return SC_SUCCESS;
	}

	r = sc_pkcs15_encode_cdf_entry(p15card->card->ctx, object, &buf, &buflen);
	LOG_TEST_RET(p15card->card->ctx, r, "Error encoding CD entry");

	r = sc_hsm_update_ef(p15card, CD_PREFIX, cert_info->path.value[cert_info->path.len - 1], 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_delete_cd(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;

	if ((cert_info->path.len < 2) ||
		((cert_info->path.value[cert_info->path.len - 2]) != CA_CERTIFICATE_PREFIX)) {
		// Certificates associated with stored private keys don't get a separate CD entry
		return SC_SUCCESS;
	}

	return sc_hsm_delete_ef(p15card, CD_PREFIX, cert_info->path.value[cert_info->path.len - 1]);
}



static int sc_hsm_emu_update_any_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	SC_FUNC_CALLED(ctx, 1);
	switch(op)   {
	case SC_AC_OP_ERASE:
		sc_log(ctx, "Update DF; erase object('%s',type:%X)", object->label, object->type);
		switch(object->type & SC_PKCS15_TYPE_CLASS_MASK) {
		case SC_PKCS15_TYPE_PRKEY:
			rv = sc_hsm_delete_ef(p15card, PRKD_PREFIX, ((struct sc_pkcs15_prkey_info *)object->data)->key_reference);
			break;
		case SC_PKCS15_TYPE_PUBKEY:
			rv = SC_SUCCESS;
			break;
		case SC_PKCS15_TYPE_CERT:
			rv = sc_hsm_emu_delete_cd(profile, p15card, object);
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			rv = sc_hsm_delete_ef(p15card, DCOD_PREFIX, ((struct sc_pkcs15_data_info *)object->data)->path.value[1]);
			break;
		}
		break;
	case SC_AC_OP_UPDATE:
	case SC_AC_OP_CREATE:
		sc_log(ctx, "Update DF; create object('%s',type:%X)", object->label, object->type);
		switch(object->type & SC_PKCS15_TYPE_CLASS_MASK) {
		case SC_PKCS15_TYPE_PUBKEY:
			rv = SC_SUCCESS;
			break;
		case SC_PKCS15_TYPE_PRKEY:
			rv = sc_hsm_emu_update_prkd(profile, p15card, object);
			break;
		case SC_PKCS15_TYPE_CERT:
			rv = sc_hsm_emu_update_cd(profile, p15card, object);
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			rv = sc_hsm_emu_update_dcod(profile, p15card, object);
			break;
		}
		break;
	}
	SC_FUNC_RETURN(ctx, 1, rv);
}



static struct sc_pkcs15init_operations
sc_pkcs15init_sc_hsm_operations = {
	NULL, 						/* erase_card */
	NULL,						/* init_card  */
	NULL,						/* create_dir */
	NULL,						/* create_domain */
	NULL,						/* select_pin_reference */
	NULL,						/* create_pin */
	NULL,						/* select key reference */
	sc_hsm_create_key,
	sc_hsm_store_key,
	sc_hsm_generate_key,
	NULL,						/* encode private key */
	NULL,						/* encode public key */
	NULL,						/* finalize_card */
	sc_hsm_emu_delete_object,	/* delete object */
	NULL,						/* pkcs15init emulation update_dir */
	sc_hsm_emu_update_any_df,	/* pkcs15init emulation update_any_df */
	NULL,						/* pkcs15init emulation update_tokeninfo */
	NULL,						/* pkcs15init emulation write_info */
	sc_hsm_emu_store_data,
	NULL,						/* sanity_check */
};


struct sc_pkcs15init_operations *
sc_pkcs15init_get_sc_hsm_ops(void)
{
	return &sc_pkcs15init_sc_hsm_operations;
}

