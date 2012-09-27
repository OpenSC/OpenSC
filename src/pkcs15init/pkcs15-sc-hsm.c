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

#include "pkcs15-init.h"
#include "profile.h"



static u8 pubexp[] = { 0x01, 0x00, 0x01 };



#define C_ASN1_EC_POINTQ_SIZE 2
static struct sc_asn1_entry c_asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE] = {
	{ "ecpointQ", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};



struct ec_curve {
	const struct sc_lv_data oid;
	const struct sc_lv_data prime;
	const struct sc_lv_data coefficientA;
	const struct sc_lv_data coefficientB;
	const struct sc_lv_data basePointG;
	const struct sc_lv_data order;
	const struct sc_lv_data coFactor;
};



static struct ec_curve curves[] = {
		{
				{ "\x2A\x86\x48\xCE\x3D\x03\x01\x01", 8},	// secp192r1 aka prime192r1
				{ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 24},
				{ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 24},
				{ "\x64\x21\x05\x19\xE5\x9C\x80\xE7\x0F\xA7\xE9\xAB\x72\x24\x30\x49\xFE\xB8\xDE\xEC\xC1\x46\xB9\xB1", 24},
				{ "\x04\x18\x8D\xA8\x0E\xB0\x30\x90\xF6\x7C\xBF\x20\xEB\x43\xA1\x88\x00\xF4\xFF\x0A\xFD\x82\xFF\x10\x12\x07\x19\x2B\x95\xFF\xC8\xDA\x78\x63\x10\x11\xED\x6B\x24\xCD\xD5\x73\xF9\x77\xA1\x1E\x79\x48\x11", 49},
				{ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x99\xDE\xF8\x36\x14\x6B\xC9\xB1\xB4\xD2\x28\x31", 24},
				{ "\x01", 1}
		},
		{
				{ "\x2A\x86\x48\xCE\x3D\x03\x01\x07", 8},	// secp256r1 aka prime256r1
				{ "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 32},
				{ "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32},
				{ "\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B", 32},
				{ "\x04\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5", 65},
				{ "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51", 32},
				{ "\x01", 1}
		},
		{
				{ "\x2B\x24\x03\x03\x02\x08\x01\x01\x03", 9},	// brainpoolP192r1
				{ "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x30\x93\xD1\x8D\xB7\x8F\xCE\x47\x6D\xE1\xA8\x62\x97", 24},
				{ "\x6A\x91\x17\x40\x76\xB1\xE0\xE1\x9C\x39\xC0\x31\xFE\x86\x85\xC1\xCA\xE0\x40\xE5\xC6\x9A\x28\xEF", 24},
				{ "\x46\x9A\x28\xEF\x7C\x28\xCC\xA3\xDC\x72\x1D\x04\x4F\x44\x96\xBC\xCA\x7E\xF4\x14\x6F\xBF\x25\xC9", 24},
				{ "\x04\xC0\xA0\x64\x7E\xAA\xB6\xA4\x87\x53\xB0\x33\xC5\x6C\xB0\xF0\x90\x0A\x2F\x5C\x48\x53\x37\x5F\xD6\x14\xB6\x90\x86\x6A\xBD\x5B\xB8\x8B\x5F\x48\x28\xC1\x49\x00\x02\xE6\x77\x3F\xA2\xFA\x29\x9B\x8F", 49},
				{ "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x2F\x9E\x9E\x91\x6B\x5B\xE8\xF1\x02\x9A\xC4\xAC\xC1", 24},
				{ "\x01", 1}
		},
		{
				{ "\x2B\x24\x03\x03\x02\x08\x01\x01\x05", 9},	// brainpoolP224r1
				{ "\xD7\xC1\x34\xAA\x26\x43\x66\x86\x2A\x18\x30\x25\x75\xD1\xD7\x87\xB0\x9F\x07\x57\x97\xDA\x89\xF5\x7E\xC8\xC0\xFF", 28},
				{ "\x68\xA5\xE6\x2C\xA9\xCE\x6C\x1C\x29\x98\x03\xA6\xC1\x53\x0B\x51\x4E\x18\x2A\xD8\xB0\x04\x2A\x59\xCA\xD2\x9F\x43", 28},
				{ "\x25\x80\xF6\x3C\xCF\xE4\x41\x38\x87\x07\x13\xB1\xA9\x23\x69\xE3\x3E\x21\x35\xD2\x66\xDB\xB3\x72\x38\x6C\x40\x0B", 28},
				{ "\x04\x0D\x90\x29\xAD\x2C\x7E\x5C\xF4\x34\x08\x23\xB2\xA8\x7D\xC6\x8C\x9E\x4C\xE3\x17\x4C\x1E\x6E\xFD\xEE\x12\xC0\x7D\x58\xAA\x56\xF7\x72\xC0\x72\x6F\x24\xC6\xB8\x9E\x4E\xCD\xAC\x24\x35\x4B\x9E\x99\xCA\xA3\xF6\xD3\x76\x14\x02\xCD", 57},
				{ "\xD7\xC1\x34\xAA\x26\x43\x66\x86\x2A\x18\x30\x25\x75\xD0\xFB\x98\xD1\x16\xBC\x4B\x6D\xDE\xBC\xA3\xA5\xA7\x93\x9F", 28},
				{ "\x01", 1}
		},
		{
				{ "\x2B\x24\x03\x03\x02\x08\x01\x01\x07", 9},	// brainpoolP256r1
				{ "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x77", 32},
				{ "\x7D\x5A\x09\x75\xFC\x2C\x30\x57\xEE\xF6\x75\x30\x41\x7A\xFF\xE7\xFB\x80\x55\xC1\x26\xDC\x5C\x6C\xE9\x4A\x4B\x44\xF3\x30\xB5\xD9", 32},
				{ "\x26\xDC\x5C\x6C\xE9\x4A\x4B\x44\xF3\x30\xB5\xD9\xBB\xD7\x7C\xBF\x95\x84\x16\x29\x5C\xF7\xE1\xCE\x6B\xCC\xDC\x18\xFF\x8C\x07\xB6", 32},
				{ "\x04\x8B\xD2\xAE\xB9\xCB\x7E\x57\xCB\x2C\x4B\x48\x2F\xFC\x81\xB7\xAF\xB9\xDE\x27\xE1\xE3\xBD\x23\xC2\x3A\x44\x53\xBD\x9A\xCE\x32\x62\x54\x7E\xF8\x35\xC3\xDA\xC4\xFD\x97\xF8\x46\x1A\x14\x61\x1D\xC9\xC2\x77\x45\x13\x2D\xED\x8E\x54\x5C\x1D\x54\xC7\x2F\x04\x69\x97", 65},
				{ "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x71\x8C\x39\x7A\xA3\xB5\x61\xA6\xF7\x90\x1E\x0E\x82\x97\x48\x56\xA7", 32},
				{ "\x01", 1}
		},
		{
				{ "\x2B\x24\x03\x03\x02\x08\x01\x01\x09", 9},	// brainpoolP320r1
				{ "\xD3\x5E\x47\x20\x36\xBC\x4F\xB7\xE1\x3C\x78\x5E\xD2\x01\xE0\x65\xF9\x8F\xCF\xA6\xF6\xF4\x0D\xEF\x4F\x92\xB9\xEC\x78\x93\xEC\x28\xFC\xD4\x12\xB1\xF1\xB3\x2E\x27", 40},
				{ "\x3E\xE3\x0B\x56\x8F\xBA\xB0\xF8\x83\xCC\xEB\xD4\x6D\x3F\x3B\xB8\xA2\xA7\x35\x13\xF5\xEB\x79\xDA\x66\x19\x0E\xB0\x85\xFF\xA9\xF4\x92\xF3\x75\xA9\x7D\x86\x0E\xB4", 40},
				{ "\x52\x08\x83\x94\x9D\xFD\xBC\x42\xD3\xAD\x19\x86\x40\x68\x8A\x6F\xE1\x3F\x41\x34\x95\x54\xB4\x9A\xCC\x31\xDC\xCD\x88\x45\x39\x81\x6F\x5E\xB4\xAC\x8F\xB1\xF1\xA6", 40},
				{ "\x04\x43\xBD\x7E\x9A\xFB\x53\xD8\xB8\x52\x89\xBC\xC4\x8E\xE5\xBF\xE6\xF2\x01\x37\xD1\x0A\x08\x7E\xB6\xE7\x87\x1E\x2A\x10\xA5\x99\xC7\x10\xAF\x8D\x0D\x39\xE2\x06\x11\x14\xFD\xD0\x55\x45\xEC\x1C\xC8\xAB\x40\x93\x24\x7F\x77\x27\x5E\x07\x43\xFF\xED\x11\x71\x82\xEA\xA9\xC7\x78\x77\xAA\xAC\x6A\xC7\xD3\x52\x45\xD1\x69\x2E\x8E\xE1", 81},
				{ "\xD3\x5E\x47\x20\x36\xBC\x4F\xB7\xE1\x3C\x78\x5E\xD2\x01\xE0\x65\xF9\x8F\xCF\xA5\xB6\x8F\x12\xA3\x2D\x48\x2E\xC7\xEE\x86\x58\xE9\x86\x91\x55\x5B\x44\xC5\x93\x11", 40},
				{ "\x01", 1}
		},
		{
				{ NULL, 0}
		}
};



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
	sc_file_t newfile;
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
		LOG_TEST_RET(card->ctx, r, "Could not creat file");
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



static int sc_hsm_get_curve(struct sc_pkcs15_card *p15card, struct ec_curve **curve, u8 *oid, size_t oidlen) {
	int i;

	LOG_FUNC_CALLED(p15card->card->ctx);
	for (i = 0; curves[i].oid.value; i++) {
		if ((curves[i].oid.len == oidlen) && !memcmp(curves[i].oid.value, oid, oidlen)) {
			*curve = &curves[i];
			return SC_SUCCESS;
		}
	}
	sc_log(p15card->card->ctx, "Unknown curve");
	LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_INVALID_DATA);
}



static int sc_hsm_encode_gakp_ec(struct sc_pkcs15_card *p15card, sc_cvc_t *cvc, struct sc_pkcs15_prkey_info *key_info) {
	struct sc_object_id ecdsaWithSHA256 = { { 0,4,0,127,0,7,2,2,2,2,3,-1 } };
	/*
	u8 prime[] =        { 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
	u8 coefficientA[] = { 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC };
	u8 coefficientB[] = { 0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,0xB3,0xEB,0xBD,0x55,0x76,0x98,0x86,0xBC,0x65,0x1D,0x06,0xB0,0xCC,0x53,0xB0,0xF6,0x3B,0xCE,0x3C,0x3E,0x27,0xD2,0x60,0x4B };
	u8 basePointG[] =   { 0x04,0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96,0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5 };
	u8 order[] =        { 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51 };
	u8 coFactor[] =     { 0x01 };
	*/
	struct sc_pkcs15_ec_parameters *ecparams = (struct sc_pkcs15_ec_parameters *)key_info->params.data;
	struct ec_curve *curve;
	u8 *curveoid;
	int curveoidlen;
	int r;

	LOG_FUNC_CALLED(p15card->card->ctx);

	curveoid = ecparams->der.value;
	if ((ecparams->der.len < 3) || (*curveoid++ != 0x06)) {
		sc_log(p15card->card->ctx, "EC_PARAMS does not contain curve object identifier");
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_INVALID_DATA);
	}

	curveoidlen = *curveoid++;

	r = sc_hsm_get_curve(p15card, &curve, curveoid, curveoidlen);

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



static int sc_hsm_decode_gakp_rsa(struct sc_pkcs15_card *p15card,
									sc_cvc_t *cvc,
									struct sc_pkcs15_prkey_info *key_info,
									struct sc_pkcs15_pubkey *pubkey)
{
	u8 *buf;
	size_t buflen;
	int r;

	LOG_FUNC_CALLED(p15card->card->ctx);

	if (((key_info->modulus_length + 7) / 8) != cvc->primeOrModuluslen) {
		sc_log(p15card->card->ctx, "Modulus size in request does not match generated public key");
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len	= cvc->primeOrModuluslen;
	pubkey->u.rsa.modulus.data	= malloc(pubkey->u.rsa.modulus.len);
	pubkey->u.rsa.exponent.len	= sizeof(pubexp);
	pubkey->u.rsa.exponent.data	= malloc(pubkey->u.rsa.exponent.len);
	if (!pubkey->u.rsa.modulus.data || !pubkey->u.rsa.exponent.data) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(pubkey->u.rsa.exponent.data, pubexp, pubkey->u.rsa.exponent.len);
	memcpy(pubkey->u.rsa.modulus.data, cvc->primeOrModulus, pubkey->u.rsa.modulus.len);

	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}



static int sc_hsm_decode_gakp_ec(struct sc_pkcs15_card *p15card,
									sc_cvc_t *cvc,
									struct sc_pkcs15_prkey_info *key_info,
									struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_asn1_entry asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE];
	struct sc_pkcs15_ec_parameters *ecparams = (struct sc_pkcs15_ec_parameters *)(key_info->params.data);
	struct sc_ec_params *ecp;
	u8 *buf;
	size_t buflen;
	int r;

	LOG_FUNC_CALLED(p15card->card->ctx);

	pubkey->algorithm = SC_ALGORITHM_EC;
	pubkey->u.ec.params.named_curve = strdup(ecparams->named_curve);
	sc_pkcs15_fix_ec_parameters(p15card->card->ctx, &pubkey->u.ec.params);

	ecp = calloc(1, sizeof(struct sc_ec_params));
	if (!ecp) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	ecp->der = malloc(ecparams->der.len);
	if (!ecp->der) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	ecp->der_len = ecparams->der.len;
	memcpy(ecp->der, ecparams->der.value, ecp->der_len);

	pubkey->alg_id = (struct sc_algorithm_id *)calloc(1, sizeof(struct sc_algorithm_id));
	if (!pubkey->alg_id) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	pubkey->alg_id->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->params = ecp;

	sc_copy_asn1_entry(c_asn1_ec_pointQ, asn1_ec_pointQ);
	sc_format_asn1_entry(asn1_ec_pointQ + 0, cvc->publicPoint, &cvc->publicPointlen, 1);

	r = sc_asn1_encode(p15card->card->ctx, asn1_ec_pointQ, &pubkey->u.ec.ecpointQ.value, &pubkey->u.ec.ecpointQ.len);
	LOG_TEST_RET(p15card->card->ctx, r, "ASN.1 encoding failed");

	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}



static int sc_hsm_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
															struct sc_pkcs15_object *object,
															struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
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

	strcpy(cvc.car, "UTCA00001");
	strcpy(cvc.chr, "UTTM00001");

	switch(object->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		r = sc_hsm_encode_gakp_rsa(p15card, &cvc, key_info->modulus_length);
		break;
	case SC_PKCS15_TYPE_PRKEY_EC:
		r = sc_hsm_encode_gakp_ec(p15card, &cvc, key_info);
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_IMPLEMENTED);
		break;
	}

	r = sc_pkcs15emu_sc_hsm_encode_cvc(p15card, &cvc, &cvcbin, &cvclen);
	sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
	LOG_TEST_RET(p15card->card->ctx, r, "Could not encode GAKP cdata");


	cvcpo = cvcbin;
	sc_asn1_read_tag(&cvcpo, cvclen, &cla, &tag, &taglen);
	sc_asn1_read_tag(&cvcpo, cvclen, &cla, &tag, &taglen);

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

	if (pubkey != NULL) {
		switch(object->type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			r = sc_hsm_decode_gakp_rsa(p15card, &cvc, key_info, pubkey);
			break;
		case SC_PKCS15_TYPE_PRKEY_EC:
			r = sc_hsm_decode_gakp_ec(p15card, &cvc, key_info, pubkey);
			break;
		}
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
	struct sc_context *ctx = p15card->card->ctx;
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
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	struct sc_pkcs15_object *prkey;
	int r;

	r = sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PRKEY, &cert_info->id , &prkey);

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		r = sc_hsm_delete_ef(p15card, CA_CERTIFICATE_PREFIX, cert_info->path.value[1]);
	} else {
		LOG_TEST_RET(p15card->card->ctx, r, "Error locating matching private key");
		r = sc_hsm_delete_ef(p15card, EE_CERTIFICATE_PREFIX, ((struct sc_pkcs15_prkey_info *)prkey->data)->key_reference);
	}
	return r;
}



static int sc_hsm_emu_store_binary(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data)

{
	struct sc_context *ctx = p15card->card->ctx;
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
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	u8 *buf;
	size_t buflen;
	int r;

	r = sc_pkcs15_encode_prkdf_entry(p15card->card->ctx, object, &buf, &buflen);
	LOG_TEST_RET(p15card->card->ctx, r, "Error encoding PRKD entry");

	r = sc_hsm_update_ef(p15card, PRKD_PREFIX, key_info->key_reference, 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_update_dcod(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *data_info = (struct sc_pkcs15_data_info *) object->data;
	u8 *buf;
	size_t buflen;
	int r;

	r = sc_pkcs15_encode_dodf_entry(p15card->card->ctx, object, &buf, &buflen);
	LOG_TEST_RET(p15card->card->ctx, r, "Error encoding DCOD entry");

	r = sc_hsm_update_ef(p15card, DCOD_PREFIX, data_info->path.value[1], 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_update_cd(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
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

	r = sc_hsm_update_ef(p15card, CD_PREFIX, cert_info->path.value[1], 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_delete_cd(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	u8 *buf;
	size_t buflen;
	int r;

	if ((cert_info->path.len < 2) ||
		((cert_info->path.value[cert_info->path.len - 2]) != CA_CERTIFICATE_PREFIX)) {
		// Certificates associated with stored private keys don't get a separate CD entry
		return SC_SUCCESS;
	}

	return sc_hsm_delete_ef(p15card, CD_PREFIX, ((struct sc_pkcs15_data_info *)object->data)->path.value[1]);
}



static int sc_hsm_emu_update_any_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	SC_FUNC_CALLED(ctx, 1);
	switch(op)   {
	case SC_AC_OP_ERASE:
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update DF; erase object('%s',type:%X)", object->label, object->type);
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
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update DF; create object('%s',type:%X)", object->label, object->type);
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
	NULL,						/* store_key */
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

