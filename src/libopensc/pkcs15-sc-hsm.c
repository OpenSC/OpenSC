/*
 * pkcs15-sc-hsm.c : Initialize PKCS#15 emulation
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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"
#include "common/compat_strlcpy.h"

#include "card-sc-hsm.h"


extern struct sc_aid sc_hsm_aid;


void sc_hsm_set_serialnr(sc_card_t *card, char *serial);



#define C_ASN1_CVC_PUBKEY_SIZE 10
static const struct sc_asn1_entry c_asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE] = {
	{ "publicKeyOID", SC_ASN1_OBJECT, SC_ASN1_UNI | SC_ASN1_OBJECT, 0, NULL, NULL },
	{ "primeOrModulus", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 1, SC_ASN1_ALLOC, NULL, NULL },
	{ "coefficientAorExponent", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 2,  SC_ASN1_ALLOC, NULL, NULL },
	{ "coefficientB", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "basePointG", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "order", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "publicPoint", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 6, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "cofactor", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 7, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "modulusSize", SC_ASN1_INTEGER, SC_ASN1_UNI | SC_ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_CVC_BODY_SIZE 5
static const struct sc_asn1_entry c_asn1_cvc_body[C_ASN1_CVC_BODY_SIZE] = {
	{ "certificateProfileIdentifier", SC_ASN1_INTEGER, SC_ASN1_APP | 0x1F29, 0, NULL, NULL },
	{ "certificationAuthorityReference", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "publicKey", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F49, 0, NULL, NULL },
	{ "certificateHolderReference", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 0x1F20, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_CVCERT_SIZE 3
static const struct sc_asn1_entry c_asn1_cvcert[C_ASN1_CVCERT_SIZE] = {
	{ "certificateBody", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F4E, 0, NULL, NULL },
	{ "signature", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F37, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_CVC_SIZE 2
static const struct sc_asn1_entry c_asn1_cvc[C_ASN1_CVC_SIZE] = {
	{ "certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_AUTHREQ_SIZE 4
static const struct sc_asn1_entry c_asn1_authreq[C_ASN1_AUTHREQ_SIZE] = {
	{ "certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ "outerCAR", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "signature", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F37, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_REQ_SIZE 2
static const struct sc_asn1_entry c_asn1_req[C_ASN1_REQ_SIZE] = {
	{ "authenticatedrequest", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 7, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};



/*
 * Decode a card verifiable certificate as defined in TR-03110.
 */
int sc_pkcs15emu_sc_hsm_decode_cvc(sc_pkcs15_card_t * p15card,
											const u8 ** buf, size_t *buflen,
											sc_cvc_t *cvc)
{
	sc_card_t *card = p15card->card;
	struct sc_asn1_entry asn1_req[C_ASN1_REQ_SIZE];
	struct sc_asn1_entry asn1_authreq[C_ASN1_AUTHREQ_SIZE];
	struct sc_asn1_entry asn1_cvc[C_ASN1_CVC_SIZE];
	struct sc_asn1_entry asn1_cvcert[C_ASN1_CVCERT_SIZE];
	struct sc_asn1_entry asn1_cvc_body[C_ASN1_CVC_BODY_SIZE];
	struct sc_asn1_entry asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE];
	unsigned int cla,tag;
	size_t taglen;
	size_t lenchr = sizeof(cvc->chr);
	size_t lencar = sizeof(cvc->car);
	size_t lenoutercar = sizeof(cvc->outer_car);
	const u8 *tbuf;
	int r;

	memset(cvc, 0, sizeof(cvc));
	sc_copy_asn1_entry(c_asn1_req, asn1_req);
	sc_copy_asn1_entry(c_asn1_authreq, asn1_authreq);
	sc_copy_asn1_entry(c_asn1_cvc, asn1_cvc);
	sc_copy_asn1_entry(c_asn1_cvcert, asn1_cvcert);
	sc_copy_asn1_entry(c_asn1_cvc_body, asn1_cvc_body);
	sc_copy_asn1_entry(c_asn1_cvc_pubkey, asn1_cvc_pubkey);

	sc_format_asn1_entry(asn1_cvc_pubkey    , &cvc->pukoid, NULL, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 1, &cvc->primeOrModulus, &cvc->primeOrModuluslen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 2, &cvc->coefficientAorExponent, &cvc->coefficientAorExponentlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 3, &cvc->coefficientB, &cvc->coefficientBlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 4, &cvc->basePointG, &cvc->basePointGlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 5, &cvc->order, &cvc->orderlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 6, &cvc->publicPoint, &cvc->publicPointlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 7, &cvc->cofactor, &cvc->cofactorlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 8, &cvc->modulusSize, NULL, 0);

	sc_format_asn1_entry(asn1_cvc_body    , &cvc->cpi, NULL, 0);
	sc_format_asn1_entry(asn1_cvc_body + 1, &cvc->car, &lencar, 0);
	sc_format_asn1_entry(asn1_cvc_body + 2, &asn1_cvc_pubkey, NULL, 0);
	sc_format_asn1_entry(asn1_cvc_body + 3, &cvc->chr, &lenchr, 0);

	sc_format_asn1_entry(asn1_cvcert    , &asn1_cvc_body, NULL, 0);
	sc_format_asn1_entry(asn1_cvcert + 1, &cvc->signature, &cvc->signatureLen, 0);

	sc_format_asn1_entry(asn1_cvc , &asn1_cvcert, NULL, 0);

	sc_format_asn1_entry(asn1_authreq    , &asn1_cvcert, NULL, 0);
	sc_format_asn1_entry(asn1_authreq + 1, &cvc->outer_car, &lenoutercar, 0);
	sc_format_asn1_entry(asn1_authreq + 2, &cvc->outerSignature, &cvc->outerSignatureLen, 0);

	sc_format_asn1_entry(asn1_req , &asn1_authreq, NULL, 0);

//	sc_asn1_print_tags(*buf, *buflen);

	tbuf = *buf;
	r = sc_asn1_read_tag(&tbuf, *buflen, &cla, &tag, &taglen);
	LOG_TEST_RET(card->ctx, r, "Could not decode card verifiable certificate");

	// Determine if we deal with an authenticated request, plain request or certificate
	if ((cla == (SC_ASN1_TAG_APPLICATION|SC_ASN1_TAG_CONSTRUCTED)) && (tag == 7)) {
		r = sc_asn1_decode(card->ctx, asn1_req, *buf, *buflen, buf, buflen);
	} else {
		r = sc_asn1_decode(card->ctx, asn1_cvc, *buf, *buflen, buf, buflen);
	}

	LOG_TEST_RET(card->ctx, r, "Could not decode card verifiable certificate");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



/*
 * Encode a card verifiable certificate as defined in TR-03110.
 */
int sc_pkcs15emu_sc_hsm_encode_cvc(sc_pkcs15_card_t * p15card,
		sc_cvc_t *cvc,
		u8 ** buf, size_t *buflen)
{
	sc_card_t *card = p15card->card;
	struct sc_asn1_entry asn1_cvc[C_ASN1_CVC_SIZE];
	struct sc_asn1_entry asn1_cvcert[C_ASN1_CVCERT_SIZE];
	struct sc_asn1_entry asn1_cvc_body[C_ASN1_CVC_BODY_SIZE];
	struct sc_asn1_entry asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE];
	unsigned int cla,tag;
	size_t taglen;
	size_t lenchr;
	size_t lencar;
	int r;

	sc_copy_asn1_entry(c_asn1_cvc, asn1_cvc);
	sc_copy_asn1_entry(c_asn1_cvcert, asn1_cvcert);
	sc_copy_asn1_entry(c_asn1_cvc_body, asn1_cvc_body);
	sc_copy_asn1_entry(c_asn1_cvc_pubkey, asn1_cvc_pubkey);

	asn1_cvc_pubkey[1].flags = SC_ASN1_OPTIONAL;
	asn1_cvcert[1].flags = SC_ASN1_OPTIONAL;

	sc_format_asn1_entry(asn1_cvc_pubkey    , &cvc->pukoid, NULL, 1);
	if (cvc->primeOrModulus && (cvc->primeOrModuluslen > 0)) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 1, cvc->primeOrModulus, &cvc->primeOrModuluslen, 1);
	}
	sc_format_asn1_entry(asn1_cvc_pubkey + 2, cvc->coefficientAorExponent, &cvc->coefficientAorExponentlen, 1);
	if (cvc->coefficientB && (cvc->coefficientBlen > 0)) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 3, cvc->coefficientB, &cvc->coefficientBlen, 1);
		sc_format_asn1_entry(asn1_cvc_pubkey + 4, cvc->basePointG, &cvc->basePointGlen, 1);
		sc_format_asn1_entry(asn1_cvc_pubkey + 5, cvc->order, &cvc->orderlen, 1);
		if (cvc->publicPoint && (cvc->publicPointlen > 0)) {
			sc_format_asn1_entry(asn1_cvc_pubkey + 6, cvc->publicPoint, &cvc->publicPointlen, 1);
		}
		sc_format_asn1_entry(asn1_cvc_pubkey + 7, cvc->cofactor, &cvc->cofactorlen, 1);
	}
	if (cvc->modulusSize > 0) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 8, &cvc->modulusSize, NULL, 1);
	}

	sc_format_asn1_entry(asn1_cvc_body    , &cvc->cpi, NULL, 1);
	lencar = strlen(cvc->car);
	sc_format_asn1_entry(asn1_cvc_body + 1, &cvc->car, &lencar, 1);
	sc_format_asn1_entry(asn1_cvc_body + 2, &asn1_cvc_pubkey, NULL, 1);
	lenchr = strlen(cvc->chr);
	sc_format_asn1_entry(asn1_cvc_body + 3, &cvc->chr, &lenchr, 1);

	sc_format_asn1_entry(asn1_cvcert    , &asn1_cvc_body, NULL, 1);
	if (cvc->signature && (cvc->signatureLen > 0)) {
		sc_format_asn1_entry(asn1_cvcert + 1, cvc->signature, &cvc->signatureLen, 1);
	}

	sc_format_asn1_entry(asn1_cvc , &asn1_cvcert, NULL, 1);

	r = sc_asn1_encode(card->ctx, asn1_cvc, buf, buflen);
	LOG_TEST_RET(card->ctx, r, "Could not encode card verifiable certificate");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



void sc_pkcs15emu_sc_hsm_free_cvc(sc_cvc_t *cvc)
{
	if (cvc->signature) {
		free(cvc->signature);
	}
	if (cvc->primeOrModulus) {
		free(cvc->primeOrModulus);
	}
	if (cvc->coefficientAorExponent) {
		free(cvc->coefficientAorExponent);
	}
	if (cvc->coefficientB) {
		free(cvc->coefficientB);
	}
	if (cvc->basePointG) {
		free(cvc->basePointG);
	}
	if (cvc->order) {
		free(cvc->order);
	}
	if (cvc->publicPoint) {
		free(cvc->publicPoint);
	}
	if (cvc->cofactor) {
		free(cvc->cofactor);
	}
}



/*
 * Add a key and the key description in PKCS#15 format to the framework
 */
static int sc_pkcs15emu_sc_hsm_add_prkd(sc_pkcs15_card_t * p15card, u8 keyid) {

	sc_card_t *card = p15card->card;
	sc_pkcs15_cert_info_t cert_info;
	sc_pkcs15_object_t cert_obj;
	struct sc_pkcs15_object prkd;
	sc_pkcs15_prkey_info_t *key_info;
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 fid[2];
	u8 efbin[512];
	u8 *ptr;
	size_t len;
	int r, i;

	fid[0] = PRKD_PREFIX;
	fid[1] = keyid;

	/* Try to select a related EF containing the PKCS#15 description of the key */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, &file);

	if (r != SC_SUCCESS) {
		return SC_SUCCESS;
	}

	sc_file_free(file);
	r = sc_read_binary(p15card->card, 0, efbin, sizeof(efbin), 0);
	LOG_TEST_RET(card->ctx, r, "Could not read EF.PRKD");

	memset(&prkd, 0, sizeof(prkd));
	ptr = efbin;
	len = r;

	r = sc_pkcs15_decode_prkdf_entry(p15card, &prkd, (const u8 **)&ptr, &len);
	LOG_TEST_RET(card->ctx, r, "Could not decode EF.PRKD");

	/* All keys require user PIN authentication */
	prkd.auth_id.len = 1;
	prkd.auth_id.value[0] = 1;

	/*
	 * Set private key flag as all keys are private anyway
	 */
	prkd.flags |= SC_PKCS15_CO_FLAG_PRIVATE;

	key_info = (sc_pkcs15_prkey_info_t *)prkd.data;
	key_info->key_reference = keyid;

	if (prkd.type == SC_PKCS15_TYPE_PRKEY_RSA) {
		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkd, key_info);
	} else {
		r = sc_pkcs15emu_add_ec_prkey(p15card, &prkd, key_info);
	}

	LOG_TEST_RET(card->ctx, r, "Could not add private key to framework");

	/* Check if we also have a certificate for the private key */
	fid[0] = EE_CERTIFICATE_PREFIX;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, &file);

	if (r != SC_SUCCESS) {
		return SC_SUCCESS;
	}

	sc_file_free(file);

	memset(&cert_info, 0, sizeof(cert_info));
	memset(&cert_obj, 0, sizeof(cert_obj));

	cert_info.id = key_info->id;
	cert_info.path = path;
	cert_info.path.count = -1;

	strlcpy(cert_obj.label, prkd.label, sizeof(cert_obj.label));
	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	LOG_TEST_RET(card->ctx, r, "Could not add certificate");

	return SC_SUCCESS;
}



/*
 * Add a data object and description in PKCS#15 format to the framework
 */
static int sc_pkcs15emu_sc_hsm_add_dcod(sc_pkcs15_card_t * p15card, u8 id) {

	sc_card_t *card = p15card->card;
	sc_pkcs15_data_info_t *data_info;
	sc_pkcs15_object_t data_obj;
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 fid[2];
	u8 efbin[512];
	const u8 *ptr;
	size_t len;
	int r, i;

	fid[0] = DCOD_PREFIX;
	fid[1] = id;

	/* Try to select a related EF containing the PKCS#15 description of the data */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, &file);

	if (r != SC_SUCCESS) {
		return SC_SUCCESS;
	}

	sc_file_free(file);
	r = sc_read_binary(p15card->card, 0, efbin, sizeof(efbin), 0);
	LOG_TEST_RET(card->ctx, r, "Could not read EF.DCOD");

	memset(&data_obj, 0, sizeof(data_obj));
	ptr = efbin;
	len = r;

	r = sc_pkcs15_decode_dodf_entry(p15card, &data_obj, &ptr, &len);
	LOG_TEST_RET(card->ctx, r, "Could not decode EF.DCOD");

	data_info = (sc_pkcs15_data_info_t *)data_obj.data;

	r = sc_pkcs15emu_add_data_object(p15card, &data_obj, data_info);

	LOG_TEST_RET(card->ctx, r, "Could not add data object to framework");

	return SC_SUCCESS;
}



/*
 * Add a unrelated certificate object and description in PKCS#15 format to the framework
 */
static int sc_pkcs15emu_sc_hsm_add_cd(sc_pkcs15_card_t * p15card, u8 id) {

	sc_card_t *card = p15card->card;
	sc_pkcs15_cert_info_t *cert_info;
	sc_pkcs15_object_t obj;
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 fid[2];
	u8 efbin[512];
	const u8 *ptr;
	size_t len;
	int r, i;

	fid[0] = CD_PREFIX;
	fid[1] = id;

	/* Try to select a related EF containing the PKCS#15 description of the data */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, &file);

	if (r != SC_SUCCESS) {
		return SC_SUCCESS;
	}

	sc_file_free(file);
	r = sc_read_binary(p15card->card, 0, efbin, sizeof(efbin), 0);
	LOG_TEST_RET(card->ctx, r, "Could not read EF.DCOD");

	memset(&obj, 0, sizeof(obj));
	ptr = efbin;
	len = r;

	r = sc_pkcs15_decode_cdf_entry(p15card, &obj, &ptr, &len);
	LOG_TEST_RET(card->ctx, r, "Could not decode EF.CD");

	cert_info = (sc_pkcs15_cert_info_t *)obj.data;

	r = sc_pkcs15emu_add_x509_cert(p15card, &obj, cert_info);

	LOG_TEST_RET(card->ctx, r, "Could not add data object to framework");

	return SC_SUCCESS;
}



/*
 * Initialize PKCS#15 emulation with user PIN, private keys, certificate and data objects
 *
 */
static int sc_pkcs15emu_sc_hsm_init (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 filelist[MAX_EXT_APDU_LENGTH];
	int filelistlength;
	int r, i;
	sc_cvc_t devcert;
	struct sc_app_info *appinfo;
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;
	u8 fid[2];
	u8 efbin[512];
	u8 *ptr;
	size_t len;

	LOG_FUNC_CALLED(card->ctx);

	p15card->tokeninfo->label = strdup("SmartCard-HSM");
	p15card->tokeninfo->manufacturer_id = strdup("CardContact");

	appinfo = calloc(1, sizeof(struct sc_app_info));

	if (appinfo == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	appinfo->label = strdup(p15card->tokeninfo->label);
	appinfo->aid = sc_hsm_aid;

	appinfo->ddo.aid = sc_hsm_aid;
	p15card->app = appinfo;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, sc_hsm_aid.value, sc_hsm_aid.len, 0, 0);
	r = sc_select_file(card, &path, &file);
	LOG_TEST_RET(card->ctx, r, "Could not select SmartCard-HSM application");
	sc_file_free(file);

	// Read device certificate to determine serial number
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, "\x2F\x02", 2, 0, 0);
	r = sc_select_file(card, &path, &file);
	LOG_TEST_RET(card->ctx, r, "Could not select EF.C_DevAut");
	sc_file_free(file);

	r = sc_read_binary(p15card->card, 0, efbin, sizeof(efbin), 0);
	LOG_TEST_RET(card->ctx, r, "Could not read EF.C_DevAut");

	ptr = efbin;
	len = r;
	r = sc_pkcs15emu_sc_hsm_decode_cvc(p15card, (const u8 **)&ptr, &len, &devcert);
	LOG_TEST_RET(card->ctx, r, "Could not decode EF.C_DevAut");

	len = strlen(devcert.chr);		// Strip last 5 digit sequence number from CHR
	assert(len >= 8);
	len -= 5;

	p15card->tokeninfo->serial_number = calloc(len + 1, 1);
	if (p15card->tokeninfo->serial_number == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	memcpy(p15card->tokeninfo->serial_number, devcert.chr, len);
	*(p15card->tokeninfo->serial_number + len) = 0;

	sc_hsm_set_serialnr(card, p15card->tokeninfo->serial_number);

	sc_pkcs15emu_sc_hsm_free_cvc(&devcert);


	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	pin_info.auth_id.len = 1;
	pin_info.auth_id.value[0] = 1;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = 0x81;
	pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_LOCAL|SC_PKCS15_PIN_FLAG_INITIALIZED|SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED|SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length = 4;
	pin_info.attrs.pin.stored_length = 0;
	pin_info.attrs.pin.max_length = 16;
	pin_info.attrs.pin.pad_char = '\0';
	pin_info.tries_left = 3;
	pin_info.max_tries = 3;

	strlcpy(pin_obj.label, "UserPIN", sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE|SC_PKCS15_CO_FLAG_MODIFIABLE;

	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	if (r < 0)
		LOG_FUNC_RETURN(card->ctx, r);

	filelistlength = sc_list_files(card, filelist, sizeof(filelist));
	LOG_TEST_RET(card->ctx, filelistlength, "Could not enumerate file and key identifier");

	for (i = 0; i < filelistlength; i += 2) {
		switch(filelist[i]) {
		case KEY_PREFIX:
			r = sc_pkcs15emu_sc_hsm_add_prkd(p15card, filelist[i + 1]);
			break;
		case DCOD_PREFIX:
			r = sc_pkcs15emu_sc_hsm_add_dcod(p15card, filelist[i + 1]);
			break;
		case CD_PREFIX:
			r = sc_pkcs15emu_sc_hsm_add_cd(p15card, filelist[i + 1]);
			break;
		}
		LOG_TEST_RET(card->ctx, r, "Error adding elements to framework");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



int sc_pkcs15emu_sc_hsm_init_ex(sc_pkcs15_card_t *p15card,
				sc_pkcs15emu_opt_t *opts)
{
	if (opts && (opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)) {
		return sc_pkcs15emu_sc_hsm_init(p15card);
	} else {
		if (p15card->card->type != SC_CARD_TYPE_SC_HSM) {
			return SC_ERROR_WRONG_CARD;
		}
		return sc_pkcs15emu_sc_hsm_init(p15card);
	}
}
