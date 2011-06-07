/*
 * pkcs15.c: PKCS #15 general functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include <stdio.h>
#include <assert.h>

#include "cardctl.h"
#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"

static const struct sc_asn1_entry c_asn1_twlabel[] = {
	{ "twlabel", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_algorithm_info[7] = {
	{ "reference",		SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,	0, NULL, NULL },
	{ "algorithmPKCS#11",	SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,	0, NULL, NULL },
	{ "parameters",		SC_ASN1_NULL,		SC_ASN1_TAG_NULL,	0, NULL, NULL },
	{ "supportedOperations",SC_ASN1_BIT_FIELD,	SC_ASN1_TAG_BIT_STRING,	0, NULL, NULL },
	{ "objId",		SC_ASN1_OBJECT,		SC_ASN1_TAG_OBJECT,	SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algRef",		SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,	SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

/*
 * in src/libopensc/types.h SC_MAX_SUPPORTED_ALGORITHMS  defined as 8
 */
static const struct sc_asn1_entry c_asn1_supported_algorithms[SC_MAX_SUPPORTED_ALGORITHMS + 1] = {
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_toki[] = {
	{ "version",        SC_ASN1_INTEGER,      SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "serialNumber",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "manufacturerID", SC_ASN1_UTF8STRING,   SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "label",	    SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
	/* XXX the Taiwanese ID card erroneously uses explicit tagging */
	{ "label-tw",       SC_ASN1_STRUCT,       SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "tokenflags",	    SC_ASN1_BIT_FIELD,    SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
	{ "seInfo",	    SC_ASN1_SE_INFO,	  SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "recordInfo",	    SC_ASN1_STRUCT,       SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "supportedAlgorithms", SC_ASN1_STRUCT,  SC_ASN1_CONS | SC_ASN1_CTX | 2, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "issuerId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "holderId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "lastUpdate",     SC_ASN1_GENERALIZEDTIME, SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "preferredLanguage", SC_ASN1_PRINTABLESTRING, SC_ASN1_TAG_PRINTABLESTRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_tokeninfo[] = {
	{ "TokenInfo", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15_parse_tokeninfo(sc_context_t *ctx,
	sc_pkcs15_tokeninfo_t *ti, const u8 *buf, size_t blen)
{
	int r;
	size_t ii;
	u8 serial[128];
	size_t serial_len = sizeof(serial);
	u8 mnfid[SC_PKCS15_MAX_LABEL_SIZE];
	size_t mnfid_len  = sizeof(mnfid);
	u8 label[SC_PKCS15_MAX_LABEL_SIZE];
	size_t label_len = sizeof(label);
	u8 last_update[32];
	size_t lupdate_len = sizeof(last_update) - 1;
	size_t flags_len   = sizeof(ti->flags);
	struct sc_asn1_entry asn1_toki[14], asn1_tokeninfo[3], asn1_twlabel[3];
	u8 preferred_language[3];
	size_t lang_length = sizeof(preferred_language);
	struct sc_asn1_entry asn1_supported_algorithms[SC_MAX_SUPPORTED_ALGORITHMS + 1],
			     asn1_algo_infos[SC_MAX_SUPPORTED_ALGORITHMS][7];
	size_t reference_len = sizeof(ti->supported_algos[0].reference);
	size_t mechanism_len = sizeof(ti->supported_algos[0].mechanism);
	size_t operations_len = sizeof(ti->supported_algos[0].operations);
	size_t algo_ref_len = sizeof(ti->supported_algos[0].algo_ref);

	memset(last_update, 0, sizeof(last_update));
	sc_copy_asn1_entry(c_asn1_twlabel, asn1_twlabel);
	sc_copy_asn1_entry(c_asn1_toki, asn1_toki);
	sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
	sc_format_asn1_entry(asn1_twlabel, label, &label_len, 0);
	
	for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS; ii++)
		sc_copy_asn1_entry(c_asn1_algorithm_info, asn1_algo_infos[ii]);
	sc_copy_asn1_entry(c_asn1_supported_algorithms, asn1_supported_algorithms);

	for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS; ii++)   {
		sc_format_asn1_entry(asn1_algo_infos[ii] + 0, &ti->supported_algos[ii].reference, &reference_len, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 1, &ti->supported_algos[ii].mechanism, &mechanism_len, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 2, NULL, NULL, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 3, &ti->supported_algos[ii].operations, &operations_len, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 4, &ti->supported_algos[ii].algo_id, NULL, 1);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 5, &ti->supported_algos[ii].algo_ref, &algo_ref_len, 0);
		sc_format_asn1_entry(asn1_supported_algorithms + ii, asn1_algo_infos[ii], NULL, 0);
	}

	sc_format_asn1_entry(asn1_toki + 0, &ti->version, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 1, serial, &serial_len, 0);
	sc_format_asn1_entry(asn1_toki + 2, mnfid, &mnfid_len, 0);
	sc_format_asn1_entry(asn1_toki + 3, label, &label_len, 0);
	sc_format_asn1_entry(asn1_toki + 4, asn1_twlabel, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 5, &ti->flags, &flags_len, 0);
	sc_format_asn1_entry(asn1_toki + 6, &ti->seInfo, &ti->num_seInfo, 0);
	sc_format_asn1_entry(asn1_toki + 7, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 8, asn1_supported_algorithms, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 9, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 10, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 11, last_update, &lupdate_len, 0);
	sc_format_asn1_entry(asn1_toki + 12, preferred_language, &lang_length, 0);
	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 0);
	
	r = sc_asn1_decode(ctx, asn1_tokeninfo, buf, blen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of EF(TokenInfo) failed");

	if (asn1_toki[1].flags & SC_ASN1_PRESENT)   {
		ti->serial_number = malloc(serial_len * 2 + 1);
		if (ti->serial_number == NULL)
			return SC_ERROR_OUT_OF_MEMORY;

		ti->serial_number[0] = 0;
		for (ii = 0; ii < serial_len; ii++) {
			char byte[3];

			sprintf(byte, "%02X", serial[ii]);
			strcat(ti->serial_number, byte);
		}
	}

	if (ti->manufacturer_id == NULL) {
		if (asn1_toki[2].flags & SC_ASN1_PRESENT)
			ti->manufacturer_id = strdup((char *) mnfid);
		else
			ti->manufacturer_id = strdup("(unknown)");
		if (ti->manufacturer_id == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	if (ti->label == NULL) {
		if (asn1_toki[3].flags & SC_ASN1_PRESENT ||
		    asn1_toki[4].flags & SC_ASN1_PRESENT)
			ti->label = strdup((char *) label);
		else
			ti->label = strdup("(unknown)");
		if (ti->label == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	if (asn1_toki[11].flags & SC_ASN1_PRESENT) {
		ti->last_update = strdup((char *)last_update);
		if (ti->last_update == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	if (asn1_toki[12].flags & SC_ASN1_PRESENT) {
		preferred_language[2] = 0;
		ti->preferred_language = strdup((char *)preferred_language);
		if (ti->preferred_language == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	return SC_SUCCESS;
}

int sc_pkcs15_encode_tokeninfo(sc_context_t *ctx,
			       sc_pkcs15_tokeninfo_t *ti,
			       u8 **buf, size_t *buflen)
{
	int r;
	size_t serial_len, mnfid_len, label_len, flags_len, last_upd_len;
	
	struct sc_asn1_entry asn1_toki[14], asn1_tokeninfo[2];

	sc_copy_asn1_entry(c_asn1_toki, asn1_toki);
	sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
	sc_format_asn1_entry(asn1_toki + 0, &ti->version, NULL, 1);
	if (ti->serial_number != NULL) {
		u8 serial[128];
		serial_len = 0;
		if (strlen(ti->serial_number)/2 > sizeof(serial))
			return SC_ERROR_BUFFER_TOO_SMALL;
		serial_len = sizeof(serial);
		if (sc_hex_to_bin(ti->serial_number, serial, &serial_len) < 0)
			return SC_ERROR_INVALID_ARGUMENTS;
		sc_format_asn1_entry(asn1_toki + 1, serial, &serial_len, 1);
	} else
		sc_format_asn1_entry(asn1_toki + 1, NULL, NULL, 0);
	if (ti->manufacturer_id != NULL) {
		mnfid_len = strlen(ti->manufacturer_id);
		sc_format_asn1_entry(asn1_toki + 2, ti->manufacturer_id, &mnfid_len, 1);
	} else
		sc_format_asn1_entry(asn1_toki + 2, NULL, NULL, 0);
	if (ti->label != NULL) {
		label_len = strlen(ti->label);
		sc_format_asn1_entry(asn1_toki + 3, ti->label, &label_len, 1);
	} else
		sc_format_asn1_entry(asn1_toki + 3, NULL, NULL, 0);
	if (ti->flags) {
		flags_len = sizeof(ti->flags);
		sc_format_asn1_entry(asn1_toki + 5, &ti->flags, &flags_len, 1);
	} else
		sc_format_asn1_entry(asn1_toki + 5, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 6, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 7, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 8, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 9, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 10, NULL, NULL, 0);
	if (ti->last_update != NULL) {
		last_upd_len = strlen(ti->last_update);
		sc_format_asn1_entry(asn1_toki + 11, ti->last_update, &last_upd_len, 1);
	} else
		sc_format_asn1_entry(asn1_toki + 11, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 12, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 1);

	r = sc_asn1_encode(ctx, asn1_tokeninfo, buf, buflen);
	LOG_TEST_RET(ctx, r, "sc_asn1_encode() failed");

	return SC_SUCCESS;
}

static const struct sc_asn1_entry c_asn1_ddo[] = {
	{ "oid",	   SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "odfPath",	   SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "tokenInfoPath", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "unusedPath",    SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
/* According to PKCS#15 v1.1 here is the place for the future extensions.
 * The following data are used when ODF record points to the xDF files in a different application. 
 */
	{ "ddoIIN",	   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x02, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "ddoAID",	   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x0F, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static void fix_authentic_ddo(struct sc_pkcs15_card *p15card)
{
	/* AuthentIC v3.2 card has invalid ODF and tokenInfo paths encoded into DDO.
	 * Cleanup this attributes -- default values must be OK.
	 */
	if (p15card->card->type == SC_CARD_TYPE_OBERTHUR_AUTHENTIC_3_2)   {
        	if (p15card->file_odf != NULL) {
			sc_file_free(p15card->file_odf);
			p15card->file_odf = NULL;
		}
	        if (p15card->file_tokeninfo != NULL) {
			sc_file_free(p15card->file_tokeninfo);
			p15card->file_tokeninfo = NULL;
		}
	}
}


static void fix_starcos_pkcs15_card(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;

	/* set special flags based on card meta data */
	if (strcmp(p15card->card->driver->short_name,"cardos") == 0) {

		/* D-Trust cards (D-TRUST, D-SIGN) */
		if (strstr(p15card->tokeninfo->label,"D-TRUST") != NULL
			|| strstr(p15card->tokeninfo->label,"D-SIGN") != NULL) {

			/* D-TRUST Card 2.0 2cc (standard cards, which always add
			 * SHA1 prefix itself */
			if (strstr(p15card->tokeninfo->label, "2cc") != NULL) {
				p15card->card->caps |= SC_CARD_CAP_ONLY_RAW_HASH_STRIPPED;
				sc_log(ctx, "D-TRUST 2cc card detected, only SHA1 works with this card");
				/* XXX: add detection when other hash than SHA1 is used with
				 *      such a card, as this produces invalid signatures.
				 */
			}

			/* D-SIGN multicard 2.0 2ca (cards working with all types of hashes
			 * and no addition of prefix) */
			else if (strstr(p15card->tokeninfo->label, "2ca") != NULL) {
				p15card->card->caps |= SC_CARD_CAP_ONLY_RAW_HASH;
				sc_log(ctx, "D-TRUST 2ca card detected");
			}

			/* XXX: probably there are more D-Trust card in the wild,
			 *      which also need these flags to produce valid signatures
			 */
		}
	}
}

static int parse_ddo(struct sc_pkcs15_card *p15card, const u8 * buf, size_t buflen)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_asn1_entry asn1_ddo[7];
	sc_path_t odf_path, ti_path, us_path;
	struct sc_iid iid;
	struct sc_aid aid;
	int r;

	LOG_FUNC_CALLED(ctx);

	iid.len = sizeof(iid.value);
	aid.len = sizeof(aid.value);

	sc_copy_asn1_entry(c_asn1_ddo, asn1_ddo);
	sc_format_asn1_entry(asn1_ddo + 1, &odf_path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 2, &ti_path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 3, &us_path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 4, iid.value, &iid.len, 0);
	sc_format_asn1_entry(asn1_ddo + 5, aid.value, &aid.len, 0);

	r = sc_asn1_decode(ctx, asn1_ddo, buf, buflen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "DDO parsing failed");

	if (asn1_ddo[1].flags & SC_ASN1_PRESENT) {
		p15card->file_odf = sc_file_new();
		if (p15card->file_odf == NULL)
			goto mem_err;
		p15card->file_odf->path = odf_path;
	}
	if (asn1_ddo[2].flags & SC_ASN1_PRESENT) {
		p15card->file_tokeninfo = sc_file_new();
		if (p15card->file_tokeninfo == NULL)
			goto mem_err;
		p15card->file_tokeninfo->path = ti_path;
	}
	if (asn1_ddo[3].flags & SC_ASN1_PRESENT) {
		p15card->file_unusedspace = sc_file_new();
		if (p15card->file_unusedspace == NULL)
			goto mem_err;
		p15card->file_unusedspace->path = us_path;
	}
	if (asn1_ddo[4].flags & SC_ASN1_PRESENT) {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "DDO.IID '%s'", sc_dump_hex(iid.value, iid.len));
		memcpy(&p15card->app->ddo.iid, &iid, sizeof(struct sc_iid));
	}
	if (asn1_ddo[5].flags & SC_ASN1_PRESENT) {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "DDO.AID '%s'", sc_dump_hex(aid.value, aid.len));
		memcpy(&p15card->app->ddo.aid, &aid, sizeof(struct sc_aid));
	}

	fix_authentic_ddo(p15card);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
mem_err:
	if (p15card->file_odf != NULL) {
		sc_file_free(p15card->file_odf);
		p15card->file_odf = NULL;
	}
	if (p15card->file_tokeninfo != NULL) {
		sc_file_free(p15card->file_tokeninfo);
		p15card->file_tokeninfo = NULL;
	}
	if (p15card->file_unusedspace != NULL) {
		sc_file_free(p15card->file_unusedspace);
		p15card->file_unusedspace = NULL;
	}
	LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
}

#if 0
static int encode_ddo(struct sc_pkcs15_card *p15card, u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_ddo[5];
	int r;
	size_t label_len;
	
	sc_copy_asn1_entry(c_asn1_ddo, asn1_ddo);

	sc_format_asn1_entry(asn1_ddo + 1, &card->file_odf.path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 2, &card->file_tokeninfo.path, NULL, 0);

	r = sc_asn1_encode(ctx, asn1_dir, buf, buflen);
	if (r) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "sc_asn1_encode() failed: %s",
		      sc_strerror(r));
		return r;
	}
	return 0;
}
#endif

static const struct sc_asn1_entry c_asn1_odf[] = {
	{ "privateKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "publicKeys",		 SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "trustedPublicKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "secretKeys",	 	 SC_ASN1_STRUCT, SC_ASN1_CTX | 3 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "certificates",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "usefulCertificates",  SC_ASN1_STRUCT, SC_ASN1_CTX | 6 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "dataObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "authObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const unsigned int odf_indexes[] = {
	SC_PKCS15_PRKDF,
	SC_PKCS15_PUKDF,
	SC_PKCS15_PUKDF_TRUSTED,
	SC_PKCS15_SKDF,
	SC_PKCS15_CDF,
	SC_PKCS15_CDF_TRUSTED,
	SC_PKCS15_CDF_USEFUL,
	SC_PKCS15_DODF,
	SC_PKCS15_AODF,
};

static int parse_odf(const u8 * buf, size_t buflen, struct sc_pkcs15_card *p15card)
{
	const u8 *p = buf;
	size_t left = buflen;
	int r, i, type;
	sc_path_t path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_odf[10];
	
	sc_copy_asn1_entry(c_asn1_odf, asn1_odf);
	for (i = 0; asn1_odf[i].name != NULL; i++)
		sc_format_asn1_entry(asn1_odf + i, asn1_obj_or_path, NULL, 0);
	while (left > 0) {
		r = sc_asn1_decode_choice(p15card->card->ctx, asn1_odf, p, left, &p, &left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r < 0)
			return r;
		type = r;
		r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &path);
		if (r < 0)
			return r;
		r = sc_pkcs15_add_df(p15card, odf_indexes[type], &path);
		if (r)
			return r;
	}
	return 0;
}

int sc_pkcs15_encode_odf(sc_context_t *ctx,
			 struct sc_pkcs15_card *p15card,
			 u8 **buf, size_t *buflen)
{
	sc_path_t path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry *asn1_paths = NULL;
	struct sc_asn1_entry *asn1_odf = NULL;
	int df_count = 0, r, c = 0;
	const int nr_indexes = sizeof(odf_indexes)/sizeof(odf_indexes[0]);
	struct sc_pkcs15_df *df;
	
	df = p15card->df_list;
	while (df != NULL) {
		df_count++;
		df = df->next;
	};
	if (df_count == 0)
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "No DF's found.");

	asn1_odf = malloc(sizeof(struct sc_asn1_entry) * (df_count + 1));
	if (asn1_odf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	asn1_paths = malloc(sizeof(struct sc_asn1_entry) * (df_count * 2));
	if (asn1_paths == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	for (df = p15card->df_list; df != NULL; df = df->next) {
		int j, type = -1;

		for (j = 0; j < nr_indexes; j++)
			if (odf_indexes[j] == df->type) {
				type = j;
				break;
			}
		if (type == -1) {
			sc_log(ctx, "Unsupported DF type.");
			continue;
		}
		asn1_odf[c] = c_asn1_odf[type];
		sc_format_asn1_entry(asn1_odf + c, asn1_paths + 2*c, NULL, 1);
		sc_copy_asn1_entry(asn1_obj_or_path, asn1_paths + 2*c);
		sc_format_asn1_entry(asn1_paths + 2*c, &df->path, NULL, 1);
		c++;
	}
	asn1_odf[c].name = NULL;
	r = sc_asn1_encode(ctx, asn1_odf, buf, buflen);
err:
	if (asn1_paths != NULL)
		free(asn1_paths);
	if (asn1_odf != NULL)
		free(asn1_odf);
	return r;
}

struct sc_pkcs15_card * sc_pkcs15_card_new(void)
{
	struct sc_pkcs15_card *p15card;
	
	p15card = calloc(1, sizeof(struct sc_pkcs15_card));
	if (p15card == NULL)
		return NULL;

	p15card->tokeninfo = calloc(1, sizeof(struct sc_pkcs15_tokeninfo));
	if (p15card->tokeninfo == NULL) {
		free(p15card);
		return NULL;
	}

	p15card->magic = SC_PKCS15_CARD_MAGIC;
	return p15card;
}

void sc_pkcs15_card_free(struct sc_pkcs15_card *p15card)
{
	size_t i;

	if (p15card == NULL)
		return;
	assert(p15card->magic == SC_PKCS15_CARD_MAGIC);

	if (p15card->ops.clear)
		p15card->ops.clear(p15card);

	while (p15card->obj_list)   {
		struct sc_pkcs15_object *obj = p15card->obj_list;

		sc_pkcs15_remove_object(p15card, obj);
		sc_pkcs15_free_object(obj);
	}
	while (p15card->df_list)
		sc_pkcs15_remove_df(p15card, p15card->df_list);
	while (p15card->unusedspace_list)
		sc_pkcs15_remove_unusedspace(p15card, p15card->unusedspace_list);
	p15card->unusedspace_read = 0;
	if (p15card->file_app != NULL)
		sc_file_free(p15card->file_app);
	if (p15card->file_tokeninfo != NULL)
		sc_file_free(p15card->file_tokeninfo);
	if (p15card->file_odf != NULL)
		sc_file_free(p15card->file_odf);
	if (p15card->file_unusedspace != NULL)
		sc_file_free(p15card->file_unusedspace);
	p15card->magic = 0;
	if (p15card->tokeninfo->label != NULL)
		free(p15card->tokeninfo->label);
	if (p15card->tokeninfo->serial_number != NULL)
		free(p15card->tokeninfo->serial_number);
	if (p15card->tokeninfo->manufacturer_id != NULL)
		free(p15card->tokeninfo->manufacturer_id);
	if (p15card->tokeninfo->last_update != NULL)
		free(p15card->tokeninfo->last_update);
	if (p15card->tokeninfo->preferred_language != NULL)
		free(p15card->tokeninfo->preferred_language);
	if (p15card->tokeninfo->seInfo != NULL) {
		for (i = 0; i < p15card->tokeninfo->num_seInfo; i++)
			free(p15card->tokeninfo->seInfo[i]);
		free(p15card->tokeninfo->seInfo);
	}
	free(p15card->tokeninfo);
	if (p15card->app)   {
		if (p15card->app->label)
			free(p15card->app->label);
		if (p15card->app->ddo.value)
			free(p15card->app->ddo.value);
		free(p15card->app);
	}
	free(p15card);
}

void sc_pkcs15_card_clear(sc_pkcs15_card_t *p15card)
{
	if (p15card == NULL)
		return;

	if (p15card->ops.clear)
		p15card->ops.clear(p15card);

	p15card->flags = 0;
	p15card->tokeninfo->version = 0;
	p15card->tokeninfo->flags   = 0;
	while (p15card->obj_list)   {
		struct sc_pkcs15_object *obj = p15card->obj_list;

		sc_pkcs15_remove_object(p15card, obj);
		sc_pkcs15_free_object(obj);
	}
	p15card->obj_list = NULL;
	while (p15card->df_list != NULL)
		sc_pkcs15_remove_df(p15card, p15card->df_list);
	p15card->df_list = NULL;
	if (p15card->file_app != NULL) {
		sc_file_free(p15card->file_app);
		p15card->file_app = NULL;
	}
	if (p15card->file_tokeninfo != NULL) {
		sc_file_free(p15card->file_tokeninfo);
		p15card->file_tokeninfo = NULL;
	}
	if (p15card->file_odf != NULL) {
		sc_file_free(p15card->file_odf);
		p15card->file_odf = NULL;
	}
	if (p15card->file_unusedspace != NULL) {
		sc_file_free(p15card->file_unusedspace);
		p15card->file_unusedspace = NULL;
	}
	if (p15card->tokeninfo->label != NULL) {
		free(p15card->tokeninfo->label);
		p15card->tokeninfo->label = NULL;
	}
	if (p15card->tokeninfo->serial_number != NULL) {
		free(p15card->tokeninfo->serial_number);
		p15card->tokeninfo->serial_number = NULL;
	}
	if (p15card->tokeninfo->manufacturer_id != NULL) {
		free(p15card->tokeninfo->manufacturer_id);
		p15card->tokeninfo->manufacturer_id = NULL;
	}
	if (p15card->tokeninfo->last_update != NULL) {
		free(p15card->tokeninfo->last_update);
		p15card->tokeninfo->last_update = NULL;
	}
	if (p15card->tokeninfo->preferred_language != NULL) {
		free(p15card->tokeninfo->preferred_language);
		p15card->tokeninfo->preferred_language = NULL;
	}
	if (p15card->tokeninfo->seInfo != NULL) {
		size_t i;
		for (i = 0; i < p15card->tokeninfo->num_seInfo; i++)
			free(p15card->tokeninfo->seInfo[i]);
		free(p15card->tokeninfo->seInfo);
		p15card->tokeninfo->seInfo     = NULL;
		p15card->tokeninfo->num_seInfo = 0;
	}
}

struct sc_app_info * sc_find_app(struct sc_card *card, struct sc_aid *aid)
{
	int ii;

	if (card->app_count <= 0)
		return NULL;

	if (!aid || !aid->len)
		return card->app[0];
		
	for (ii=0; ii < card->app_count; ii++) {
		if (card->app[ii]->aid.len != aid->len)
			continue;
		if (memcmp(card->app[ii]->aid.value, aid->value, aid->len))
			continue;
		return card->app[ii];
	}
	return NULL;
}

static struct sc_app_info *sc_dup_app_info(const struct sc_app_info *info)
{
	struct sc_app_info *out = calloc(1, sizeof(struct sc_app_info));

	if (!out)
		return NULL;

	memcpy(out, info, sizeof(struct sc_app_info));

	if (info->label) {
		out->label = strdup(info->label);
		if (!out->label)
			return NULL;
	} else
		out->label = NULL;

	out->ddo.value = malloc(info->ddo.len);
	if (!out->ddo.value)
		return NULL;
	memcpy(out->ddo.value, info->ddo.value, info->ddo.len);

	return out;
}

static int sc_pkcs15_bind_internal(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	sc_path_t tmppath;
	sc_card_t    *card = p15card->card;
	sc_context_t *ctx  = card->ctx;
	sc_pkcs15_tokeninfo_t tokeninfo;
	sc_pkcs15_df_t *df;
	const sc_app_info_t *info = NULL;
	unsigned char *buf = NULL;
	size_t len;
	int    err, ok = 0;

	LOG_FUNC_CALLED(ctx);
	/* Enumerate apps now */
	if (card->app_count < 0) {
		err = sc_enum_apps(card);
		if (err != SC_ERROR_FILE_NOT_FOUND)
			LOG_TEST_RET(ctx, err, "unable to enumerate apps");
	}
	p15card->file_app = sc_file_new();
	if (p15card->file_app == NULL) {
		err = SC_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	sc_format_path("3F005015", &p15card->file_app->path);

	info = sc_find_app(card, aid);
	if (info)   {
		sc_log(ctx, "bind to application('%s',aid:'%s')",  info->label, 
				sc_dump_hex(info->aid.value, info->aid.len));
		p15card->app = sc_dup_app_info(info);
		if (!p15card->app)   {
			err = SC_ERROR_OUT_OF_MEMORY;
			goto end;
		}

		if (info->path.len)
			p15card->file_app->path = info->path;

		if (info->ddo.value && info->ddo.len)
			parse_ddo(p15card, info->ddo.value, info->ddo.len);

	}
	else if (aid)   {
		sc_log(ctx, "Application(aid:'%s') not found", sc_dump_hex(aid->value, aid->len));
		err = SC_ERROR_INVALID_ARGUMENTS;
		goto end;
	}
	sc_log(ctx, "application path '%s'", sc_print_path(&p15card->file_app->path));

	/* Check if pkcs15 directory exists */
	err = sc_select_file(card, &p15card->file_app->path, NULL);

	/* If the above test failed on cards without EF(DIR),
	 * try to continue read ODF from 3F005031. -aet
	 */
	if ((err == SC_ERROR_FILE_NOT_FOUND) && (card->app_count < 1)) {
		sc_format_path("3F00", &p15card->file_app->path);
		err = SC_SUCCESS;
	}
	if (err < 0)
		goto end;

	if (p15card->file_odf == NULL) {
		/* check if an ODF is present; we don't know yet whether we have a pkcs15 card */
		sc_format_path("5031", &tmppath);
		err = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &tmppath);
		if (err != SC_SUCCESS)   {
			sc_log(ctx, "Cannot make absolute path to EF(ODF); error:%i", err);
			goto end;
		}
		sc_log(ctx, "absolute path to EF(ODF) %s", sc_print_path(&tmppath));
		err = sc_select_file(card, &tmppath, &p15card->file_odf);
	} 
	else {
		tmppath = p15card->file_odf->path;
		sc_file_free(p15card->file_odf);
		p15card->file_odf = NULL;
		err = sc_select_file(card, &tmppath, &p15card->file_odf);
	}

	if (err != SC_SUCCESS) {
		sc_log(ctx, "EF(ODF) not found in '%s'", sc_print_path(&tmppath));
		goto end;
	}

	len = p15card->file_odf->size;
	if (!len) {
		sc_log(ctx, "EF(ODF) is empty");
		goto end;
	}
	buf = malloc(len);
	if(buf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	err = sc_read_binary(card, 0, buf, len, 0);
	if (err < 0)
		goto end;
	if (err < 2) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto end;
	}
	len = err;
	if (parse_odf(buf, len, p15card)) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		sc_log(ctx, "Unable to parse ODF");
		goto end;
	}
	free(buf);
	buf = NULL;

	sc_log(ctx, "The following DFs were found:");
	for (df = p15card->df_list; df; df = df->next)
		sc_log(ctx, "  DF type %u, path %s, index %u, count %d", df->type, 
				sc_print_path(&df->path), df->path.index, df->path.count);

	if (p15card->file_tokeninfo == NULL) {
		sc_format_path("5032", &tmppath);
		err = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &tmppath);
		if (err != SC_SUCCESS)   {
			sc_log(ctx, "Cannot make absolute path to EF(TokenInfo); error:%i", err);
			goto end;
		}
		sc_log(ctx, "absolute path to EF(TokenInfo) %s", sc_print_path(&tmppath));
	} 
	else {
		tmppath = p15card->file_tokeninfo->path;
		sc_file_free(p15card->file_tokeninfo);
		p15card->file_tokeninfo = NULL;
	}
	err = sc_select_file(card, &tmppath, &p15card->file_tokeninfo);
	if (err)
		goto end;

	if ((len = p15card->file_tokeninfo->size) == 0) {
		sc_log(ctx, "EF(TokenInfo) is empty");
		goto end;
	}
	buf = malloc(len);
	if(buf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	err = sc_read_binary(card, 0, buf, len, 0);
	if (err < 0)
		goto end;
	if (err <= 2) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto end;
	}

	memset(&tokeninfo, 0, sizeof(tokeninfo));
	err = sc_pkcs15_parse_tokeninfo(ctx, &tokeninfo, buf, (size_t)err);
	if (err != SC_SUCCESS)
		goto end;

	*(p15card->tokeninfo) = tokeninfo;

	if (!p15card->tokeninfo->serial_number && card->serialnr.len)   {
		char *serial = calloc(1, card->serialnr.len*2 + 1);
		size_t ii;
		
		for(ii=0;ii<card->serialnr.len;ii++)
			sprintf(serial + ii*2, "%02X", *(card->serialnr.value + ii));

		p15card->tokeninfo->serial_number = serial;
		sc_log(ctx, "p15card->tokeninfo->serial_number %s", p15card->tokeninfo->serial_number);
	}

	ok = 1;
end:
	if(buf != NULL)
		free(buf);
	if (!ok) {
		sc_pkcs15_card_clear(p15card);
		return err;
	}

	return SC_SUCCESS;
}

int sc_pkcs15_bind(sc_card_t *card, struct sc_aid *aid, struct sc_pkcs15_card **p15card_out)
{
	struct sc_pkcs15_card *p15card = NULL;
	sc_context_t *ctx = card->ctx;
	scconf_block *conf_block = NULL;
	int r, emu_first, enable_emu;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "application(aid:'%s')", aid ? sc_dump_hex(aid->value, aid->len) : "empty");

	assert(p15card_out != NULL);
	p15card = sc_pkcs15_card_new();
	if (p15card == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	p15card->card = card;
	p15card->opts.use_file_cache = 0;
	p15card->opts.use_pin_cache = 1;
	p15card->opts.pin_cache_counter = 10;

	conf_block = sc_get_conf_block(ctx, "framework", "pkcs15", 1);

	if (conf_block) {
		p15card->opts.use_file_cache = scconf_get_bool(conf_block, "use_file_caching", p15card->opts.use_file_cache);
		p15card->opts.use_pin_cache = scconf_get_bool(conf_block, "use_pin_caching", p15card->opts.use_pin_cache);
		p15card->opts.pin_cache_counter = scconf_get_int(conf_block, "pin_cache_counter", p15card->opts.pin_cache_counter);
	}
	sc_log(ctx, "PKCS#15 options: use_file_cache=%d use_pin_cache=%d pin_cache_counter=%d",
	         p15card->opts.use_file_cache, p15card->opts.use_pin_cache, p15card->opts.pin_cache_counter);

	r = sc_lock(card);
	if (r) {
		sc_log(ctx, "sc_lock() failed: %s", sc_strerror(r));
		sc_pkcs15_card_free(p15card);
		LOG_FUNC_RETURN(ctx, r);
	}

	enable_emu = scconf_get_bool(conf_block, "enable_pkcs15_emulation", 1);
	if (enable_emu) {
		emu_first = scconf_get_bool(conf_block, "try_emulation_first", 0);
		if (emu_first || sc_pkcs15_is_emulation_only(card)) {
			r = sc_pkcs15_bind_synthetic(p15card);
			if (r == SC_SUCCESS)
				goto done;
			r = sc_pkcs15_bind_internal(p15card, aid);
			if (r < 0)
				goto error;
		} else {
			r = sc_pkcs15_bind_internal(p15card, aid);
			if (r == SC_SUCCESS)
				goto done;
			r = sc_pkcs15_bind_synthetic(p15card);
			if (r < 0)
				goto error;
		}
	} else {
		r = sc_pkcs15_bind_internal(p15card, aid);
		if (r < 0)
			goto error;
	}
done:
	fix_starcos_pkcs15_card(p15card);

	*p15card_out = p15card;
	sc_unlock(card);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
error:
	sc_unlock(card);
	sc_pkcs15_card_free(p15card);
	LOG_FUNC_RETURN(ctx, r);
}

int sc_pkcs15_unbind(struct sc_pkcs15_card *p15card)
{
	assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
	LOG_FUNC_CALLED(p15card->card->ctx);
	if (p15card->dll_handle)
		sc_dlclose(p15card->dll_handle);
	sc_pkcs15_pincache_clear(p15card);
	sc_pkcs15_card_free(p15card);
	return 0;
}

static int
__sc_pkcs15_search_objects(sc_pkcs15_card_t *p15card,
			unsigned int class_mask, unsigned int type,
			int (*func)(sc_pkcs15_object_t *, void *),
			void *func_arg,
			sc_pkcs15_object_t **ret, size_t ret_size)
{
	sc_pkcs15_object_t *obj;
	sc_pkcs15_df_t	*df;
	unsigned int	df_mask = 0;
	size_t		match_count = 0;
	int		r = 0;

	if (type)
		class_mask |= SC_PKCS15_TYPE_TO_CLASS(type);

	/* Make sure the class mask we have makes sense */
	if (class_mask == 0
	 || (class_mask & ~(SC_PKCS15_SEARCH_CLASS_PRKEY |
			    SC_PKCS15_SEARCH_CLASS_PUBKEY |
			    SC_PKCS15_SEARCH_CLASS_CERT |
			    SC_PKCS15_SEARCH_CLASS_DATA |
			    SC_PKCS15_SEARCH_CLASS_AUTH))) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (class_mask & SC_PKCS15_SEARCH_CLASS_PRKEY)
		df_mask |= (1 << SC_PKCS15_PRKDF);
	if (class_mask & SC_PKCS15_SEARCH_CLASS_PUBKEY)
		df_mask |= (1 << SC_PKCS15_PUKDF) | (1 << SC_PKCS15_PUKDF_TRUSTED);
	if (class_mask & SC_PKCS15_SEARCH_CLASS_CERT)
		df_mask |= (1 << SC_PKCS15_CDF) | (1 << SC_PKCS15_CDF_TRUSTED) | (1 << SC_PKCS15_CDF_USEFUL);
	if (class_mask & SC_PKCS15_SEARCH_CLASS_DATA)
		df_mask |= (1 << SC_PKCS15_DODF);
	if (class_mask & SC_PKCS15_SEARCH_CLASS_AUTH)
		df_mask |= (1 << SC_PKCS15_AODF);

	/* Make sure all the DFs we want to search have been
	 * enumerated. */
	for (df = p15card->df_list; df != NULL; df = df->next) {
		if (!(df_mask & (1 << df->type)))
			continue;
		if (df->enumerated)
			continue;
		/* Enumerate the DF's, so p15card->obj_list is
		 * populated. */
		r = sc_pkcs15_parse_df(p15card, df);
	}

	/* And now loop over all objects */
	for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
		/* Check object type */
		if (!(class_mask & SC_PKCS15_TYPE_TO_CLASS(obj->type)))
			continue;
		if (type != 0
		 && obj->type != type
		 && (obj->type & SC_PKCS15_TYPE_CLASS_MASK) != type)
			continue;

		/* Potential candidate, apply search function */
		if (func != NULL && func(obj, func_arg) <= 0)
			continue;
		/* Okay, we have a match. */
		match_count++;
		if (!ret || ret_size <= 0)
			continue;
		ret[match_count-1] = obj;
		if (ret_size <= match_count)
			break;
	}

	return match_count;
}

int sc_pkcs15_get_objects(struct sc_pkcs15_card *p15card, unsigned int type,
			  struct sc_pkcs15_object **ret, size_t ret_size)
{
	return sc_pkcs15_get_objects_cond(p15card, type, NULL, NULL, ret, ret_size);
}

static int compare_obj_id(struct sc_pkcs15_object *obj, const sc_pkcs15_id_t *id)
{
	void *data = obj->data;
	
	switch (obj->type) {
	case SC_PKCS15_TYPE_CERT_X509:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_cert_info *) data)->id, id);
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_DSA:
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PRKEY_EC:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_prkey_info *) data)->id, id);
	case SC_PKCS15_TYPE_PUBKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_DSA:
	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PUBKEY_EC:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_pubkey_info *) data)->id, id);
	case SC_PKCS15_TYPE_AUTH_PIN:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_auth_info *) data)->auth_id, id);
	case SC_PKCS15_TYPE_DATA_OBJECT:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_data_info *) data)->id, id);
	}
	return 0;
}

static int sc_obj_app_oid(struct sc_pkcs15_object *obj, const struct sc_object_id *app_oid)
{
	if (obj->type & SC_PKCS15_TYPE_DATA_OBJECT)
		return sc_compare_oid(&((struct sc_pkcs15_data_info *) obj->data)->app_oid, app_oid);
	return 0;
}

static int compare_obj_usage(sc_pkcs15_object_t *obj, unsigned int mask, unsigned int value)
{
	void		*data = obj->data;
	unsigned int	usage;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_DSA:
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PRKEY_EC:
		usage = ((struct sc_pkcs15_prkey_info *) data)->usage;
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_DSA:
	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PUBKEY_EC:
		usage = ((struct sc_pkcs15_pubkey_info *) data)->usage;
		break;
	default:
		return 0;
	}
	return (usage & mask & value) != 0;
}

static int compare_obj_flags(sc_pkcs15_object_t *obj, unsigned int mask, unsigned int value)
{
	struct sc_pkcs15_auth_info *auth_info;
	unsigned int	flags;

	switch (obj->type) {
	case SC_PKCS15_TYPE_AUTH_PIN:
		auth_info = (struct sc_pkcs15_auth_info *) obj->data;
		if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			return 0;
		flags = auth_info->attrs.pin.flags;
		break;
	default:
		return 0;
	}
	return !((flags ^ value) & mask);
}

static int compare_obj_reference(sc_pkcs15_object_t *obj, int value)
{
	struct sc_pkcs15_auth_info *auth_info;
	void		*data = obj->data;
	int		reference;

	switch (obj->type) {
	case SC_PKCS15_TYPE_AUTH_PIN:
		auth_info = (struct sc_pkcs15_auth_info *) obj->data;
		if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			return 0;
		reference = auth_info->attrs.pin.reference;
		break;
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_DSA:
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PRKEY_EC:
		reference = ((struct sc_pkcs15_prkey_info *) data)->key_reference;
		break;
	default:
		return 0;
	}
	return reference == value;
}

static int compare_obj_path(sc_pkcs15_object_t *obj, const sc_path_t *path)
{
	void *data = obj->data;
	
	switch (obj->type) {
	case SC_PKCS15_TYPE_CERT_X509:
		return sc_compare_path(&((struct sc_pkcs15_cert_info *) data)->path, path);
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_DSA:
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PRKEY_EC:
		return sc_compare_path(&((struct sc_pkcs15_prkey_info *) data)->path, path);
	case SC_PKCS15_TYPE_PUBKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_DSA:
	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PUBKEY_EC:
		return sc_compare_path(&((struct sc_pkcs15_pubkey_info *) data)->path, path);
	case SC_PKCS15_TYPE_AUTH_PIN:
		return sc_compare_path(&((struct sc_pkcs15_auth_info *) data)->path, path);
	case SC_PKCS15_TYPE_DATA_OBJECT:
		return sc_compare_path(&((struct sc_pkcs15_data_info *) data)->path, path);
	}
	return 0;
}

static int compare_obj_data_name(sc_pkcs15_object_t *obj, const char *app_label, const char *label)
{
	struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) obj->data;

	if (obj->type != SC_PKCS15_TYPE_DATA_OBJECT)
		return 0;
	
	return !strcmp(cinfo->app_label, app_label) &&
		!strcmp(obj->label, label);
}

static int compare_obj_key(struct sc_pkcs15_object *obj, void *arg)
{
	struct sc_pkcs15_search_key *sk = (struct sc_pkcs15_search_key *) arg;

	if (sk->id && !compare_obj_id(obj, sk->id))
		return 0;
	if (sk->app_oid && !sc_obj_app_oid(obj, sk->app_oid))
		return 0;
	if (sk->usage_mask && !compare_obj_usage(obj, sk->usage_mask, sk->usage_value))
		return 0;
	if (sk->flags_mask && !compare_obj_flags(obj, sk->flags_mask, sk->flags_value))
		return 0;
	if (sk->match_reference && !compare_obj_reference(obj, sk->reference))
		return 0;
	if (sk->path && !compare_obj_path(obj, sk->path))
		return 0;
	if (
		sk->app_label && sk->label &&
		!compare_obj_data_name(obj, sk->app_label, sk->label)
	) {
		return 0;
	}

	return 1;
}

static int find_by_key(struct sc_pkcs15_card *p15card,
		       unsigned int type, struct sc_pkcs15_search_key *sk,
		       struct sc_pkcs15_object **out)
{
	int r;
	
	r = sc_pkcs15_get_objects_cond(p15card, type, compare_obj_key, sk, out, 1);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_OBJECT_NOT_FOUND;
	return 0;
}

int
sc_pkcs15_search_objects(sc_pkcs15_card_t *p15card, sc_pkcs15_search_key_t *sk,
			sc_pkcs15_object_t **ret, size_t ret_size)
{
	return __sc_pkcs15_search_objects(p15card,
			sk->class_mask, sk->type,
			compare_obj_key, sk,
			ret, ret_size);
}

int sc_pkcs15_get_objects_cond(struct sc_pkcs15_card *p15card, unsigned int type,
			       int (* func)(struct sc_pkcs15_object *, void *),
			       void *func_arg,
			       struct sc_pkcs15_object **ret, size_t ret_size)
{
	return __sc_pkcs15_search_objects(p15card, 0, type,
			func, func_arg, ret, ret_size);
}

int sc_pkcs15_find_object_by_id(sc_pkcs15_card_t *p15card,
				unsigned int type, const sc_pkcs15_id_t *id,
				sc_pkcs15_object_t **out)
{
	sc_pkcs15_search_key_t sk;
	int	r;

	memset(&sk, 0, sizeof(sk));
	sk.id = id;

	r = __sc_pkcs15_search_objects(p15card, 0, type, compare_obj_key, &sk, out, 1);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_OBJECT_NOT_FOUND;
	return 0;
}

int sc_pkcs15_find_cert_by_id(struct sc_pkcs15_card *p15card,
			      const struct sc_pkcs15_id *id,
			      struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_CERT, id, out);
}

int sc_pkcs15_find_prkey_by_id(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_id *id,
			       struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PRKEY, id, out);
}

int sc_pkcs15_find_pubkey_by_id(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_id *id,
				struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PUBKEY, id, out);
}

int sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *p15card,
			     const struct sc_pkcs15_id *id,
			     struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_AUTH_PIN, id, out);
}

int sc_pkcs15_find_pin_by_reference(struct sc_pkcs15_card *p15card,
				const sc_path_t *path, int reference,
				struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.match_reference = 1;
	sk.reference = reference;
	sk.path = path;

	return find_by_key(p15card, SC_PKCS15_TYPE_AUTH_PIN, &sk, out);
}

int sc_pkcs15_find_pin_by_type_and_reference(struct sc_pkcs15_card *p15card,
				const sc_path_t *path,
				unsigned auth_method, int reference,
				struct sc_pkcs15_object **out)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *auth_objs[0x10];
	size_t nn_objs, ii;
	int r;

	/* Get all existing pkcs15 AUTH objects */
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, auth_objs, 0x10);
	LOG_TEST_RET(ctx, r, "Get PKCS#15 AUTH objects error");
	nn_objs = r;

	for (ii=0; ii<nn_objs; ii++)   {
		struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *)auth_objs[ii]->data;

		if (auth_info->auth_method != auth_method)
			continue;
		if (auth_info->auth_type == SC_PKCS15_PIN_AUTH_TYPE_PIN)
			if (auth_info->attrs.pin.reference != reference)
				continue;

		if (path && !sc_compare_path(&auth_info->path, path))
			continue;

		if (out)
			*out = auth_objs[ii];

		return SC_SUCCESS;
	}

	return SC_ERROR_OBJECT_NOT_FOUND;
}

int sc_pkcs15_find_data_object_by_id(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_id *id,
				struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_DATA_OBJECT, id, out);
}

int sc_pkcs15_find_data_object_by_app_oid(struct sc_pkcs15_card *p15card,
				const struct sc_object_id *app_oid,
				struct sc_pkcs15_object **out)
{
	sc_pkcs15_search_key_t sk;
	int	r;

	memset(&sk, 0, sizeof(sk));
	sk.app_oid = app_oid;

	r = __sc_pkcs15_search_objects(p15card, 0, SC_PKCS15_TYPE_DATA_OBJECT,
				compare_obj_key, &sk,
				out, 1);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_OBJECT_NOT_FOUND;
	return 0;
}

int sc_pkcs15_find_data_object_by_name(struct sc_pkcs15_card *p15card,
				const char *app_label,
				const char *label,
				struct sc_pkcs15_object **out)
{
	sc_pkcs15_search_key_t sk;
	int	r;

	memset(&sk, 0, sizeof(sk));
	sk.app_label = app_label;
	sk.label = label;

	r = __sc_pkcs15_search_objects(p15card, 0, SC_PKCS15_TYPE_DATA_OBJECT,
				compare_obj_key, &sk,
				out, 1);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_OBJECT_NOT_FOUND;
	return 0;
}

int sc_pkcs15_find_prkey_by_id_usage(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_id *id,
			       unsigned int usage,
			       struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.usage_mask = sk.usage_value = usage;
	sk.id = id;

	return find_by_key(p15card, SC_PKCS15_TYPE_PRKEY, &sk, out);
}

int sc_pkcs15_find_prkey_by_reference(sc_pkcs15_card_t *p15card,
				const sc_path_t *path,
				int reference,
				struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.match_reference = 1;
	sk.reference = reference;
	sk.path = path;

	return find_by_key(p15card, SC_PKCS15_TYPE_PRKEY, &sk, out);
}

int sc_pkcs15_find_so_pin(struct sc_pkcs15_card *p15card,
			struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.flags_mask = sk.flags_value = SC_PKCS15_PIN_FLAG_SO_PIN;
	
	return find_by_key(p15card, SC_PKCS15_TYPE_AUTH_PIN, &sk, out);
}

int sc_pkcs15_add_object(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_object *p = p15card->obj_list;

	obj->next = obj->prev = NULL;
	if (p15card->obj_list == NULL) {
		p15card->obj_list = obj;
		return 0;
	}
	while (p->next != NULL)
 		p = p->next;
	p->next = obj;
	obj->prev = p;

	return 0;
}

void sc_pkcs15_remove_object(struct sc_pkcs15_card *p15card,
			     struct sc_pkcs15_object *obj)
{
	if (!obj)
		return;

	if (obj->prev == NULL)
		p15card->obj_list = obj->next;
	else
		obj->prev->next = obj->next;
	if (obj->next != NULL)
		obj->next->prev = obj->prev;
}

void sc_pkcs15_free_object(struct sc_pkcs15_object *obj)
{
	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		sc_pkcs15_free_prkey_info((sc_pkcs15_prkey_info_t *)obj->data);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		sc_pkcs15_free_pubkey_info((sc_pkcs15_pubkey_info_t *)obj->data);
		break;
	case SC_PKCS15_TYPE_CERT:
		sc_pkcs15_free_cert_info((sc_pkcs15_cert_info_t *)obj->data);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		sc_pkcs15_free_data_info((sc_pkcs15_data_info_t *)obj->data);
		break;
	case SC_PKCS15_TYPE_AUTH:
		sc_pkcs15_free_auth_info((sc_pkcs15_auth_info_t *)obj->data);
		break;
	default:
		free(obj->data);
	}

	sc_pkcs15_free_object_content(obj);

	free(obj);
}

int sc_pkcs15_add_df(struct sc_pkcs15_card *p15card, unsigned int type, const sc_path_t *path)
{
	struct sc_pkcs15_df *p, *newdf;
	
	newdf = calloc(1, sizeof(struct sc_pkcs15_df));
	if (newdf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	newdf->path = *path;
	newdf->type = type;

	if (p15card->df_list == NULL) {
		p15card->df_list = newdf;
		return 0;
	}

	p = p15card->df_list;
	while (p->next != NULL)
 		p = p->next;
	p->next = newdf;
	newdf->prev = p;

	return 0;
}

void sc_pkcs15_remove_df(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_df *obj)
{
	if (obj->prev == NULL)
		p15card->df_list = obj->next;
	else
		obj->prev->next = obj->next;
	if (obj->next != NULL)
		obj->next->prev = obj->prev;
	free(obj);
}

int sc_pkcs15_encode_df(sc_context_t *ctx,
			struct sc_pkcs15_card *p15card,
			struct sc_pkcs15_df *df,
			u8 **buf_out, size_t *bufsize_out)
{
	u8 *buf = NULL, *tmp = NULL;
	size_t bufsize = 0, tmpsize;
	const struct sc_pkcs15_object *obj;
	int (* func)(sc_context_t *, const struct sc_pkcs15_object *nobj,
		     u8 **nbuf, size_t *nbufsize) = NULL;
	int r;

	assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_encode_prkdf_entry;
		break;
	case SC_PKCS15_PUKDF:
	case SC_PKCS15_PUKDF_TRUSTED:
		func = sc_pkcs15_encode_pukdf_entry;
		break;
	case SC_PKCS15_CDF:
	case SC_PKCS15_CDF_TRUSTED:
	case SC_PKCS15_CDF_USEFUL:
		func = sc_pkcs15_encode_cdf_entry;
		break;
	case SC_PKCS15_DODF:
		func = sc_pkcs15_encode_dodf_entry;
		break;
	case SC_PKCS15_AODF:
		func = sc_pkcs15_encode_aodf_entry;
		break;
	}
	if (func == NULL) {
		sc_log(ctx, "unknown DF type: %d", df->type);
		*buf_out = NULL;
		*bufsize_out = 0;
		return 0;
	}
	for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
		if (obj->df != df)
			continue;
		r = func(ctx, obj, &tmp, &tmpsize);
		if (r) {
			free(tmp);
			free(buf);
			return r;
		}
		buf = (u8 *) realloc(buf, bufsize + tmpsize);
		memcpy(buf + bufsize, tmp, tmpsize);
		free(tmp);
		bufsize += tmpsize;
	}
	*buf_out = buf;
	*bufsize_out = bufsize;
	
	return 0;	
}

int sc_pkcs15_parse_df(struct sc_pkcs15_card *p15card,
		       struct sc_pkcs15_df *df)
{
	sc_context_t *ctx = p15card->card->ctx;
	u8 *buf;
	const u8 *p;
	size_t bufsize;
	int r;
	struct sc_pkcs15_object *obj = NULL;
	int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
		     const u8 **nbuf, size_t *nbufsize) = NULL;

	sc_log(ctx, "called; path=%s, type=%d, enum=%d", 
			sc_print_path(&df->path), df->type, df->enumerated);

	if (p15card->ops.parse_df)   {
		r = p15card->ops.parse_df(p15card, df);
		LOG_FUNC_RETURN(ctx, r);
	}

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_decode_prkdf_entry;
		break;
	case SC_PKCS15_PUKDF:
		func = sc_pkcs15_decode_pukdf_entry;
		break;
	case SC_PKCS15_CDF:
	case SC_PKCS15_CDF_TRUSTED:
	case SC_PKCS15_CDF_USEFUL:
		func = sc_pkcs15_decode_cdf_entry;
		break;
	case SC_PKCS15_DODF:
		func = sc_pkcs15_decode_dodf_entry;
		break;
	case SC_PKCS15_AODF:
		func = sc_pkcs15_decode_aodf_entry;
		break;
	}
	if (func == NULL) {
		sc_log(ctx, "unknown DF type: %d", df->type);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	r = sc_pkcs15_read_file(p15card, &df->path, &buf, &bufsize);
	LOG_TEST_RET(ctx, r, "pkcs15 read file failed");

	p = buf;
	sc_log(ctx, "bufsize %i; first tag 0x%X", bufsize, *p);
	while (bufsize && *p != 0x00) {
		
		obj = calloc(1, sizeof(struct sc_pkcs15_object));
		if (obj == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto ret;
		}
		r = func(p15card, obj, &p, &bufsize);
		sc_log(ctx, "rv %i", r);
		if (r) {
			free(obj);
			if (r == SC_ERROR_ASN1_END_OF_CONTENTS) {
				r = 0;
				break;
			}
			sc_log(ctx, "%s: Error decoding DF entry", sc_strerror(r));
			goto ret;
		}

		obj->df = df;
		r = sc_pkcs15_add_object(p15card, obj);
		if (r) {
			if (obj->data)
				free(obj->data);
			free(obj);
			sc_log(ctx, "%s: Error adding object", sc_strerror(r));
			goto ret;
		}
	};

	if (r > 0)
		r = 0;
ret:
	df->enumerated = 1;
	free(buf);
	LOG_FUNC_RETURN(ctx, r);
}

int sc_pkcs15_add_unusedspace(struct sc_pkcs15_card *p15card,
		     const sc_path_t *path, const sc_pkcs15_id_t *auth_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_pkcs15_unusedspace_t *p = p15card->unusedspace_list, *new_unusedspace;

	if (path->count == -1) {
		char pbuf[SC_MAX_PATH_STRING_SIZE];

		int r = sc_path_print(pbuf, sizeof(pbuf), path);
		if (r != SC_SUCCESS)
			pbuf[0] = '\0';

		sc_log(ctx, "No offset and length present in path %s", pbuf);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	new_unusedspace = calloc(1, sizeof(sc_pkcs15_unusedspace_t));
	if (new_unusedspace == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	new_unusedspace->path = *path;
	if (auth_id != NULL)
		new_unusedspace->auth_id = *auth_id;

	if (p15card->unusedspace_list == NULL) {
		p15card->unusedspace_list = new_unusedspace;
		return 0;
	}
	while (p->next != NULL)
 		p = p->next;
	p->next = new_unusedspace;
	new_unusedspace->prev = p;

	return 0;
}

void sc_pkcs15_remove_unusedspace(struct sc_pkcs15_card *p15card,
			 sc_pkcs15_unusedspace_t *unusedspace)
{
	if (unusedspace->prev == NULL)
		p15card->unusedspace_list = unusedspace->next;
	else
		unusedspace->prev->next = unusedspace->next;
	if (unusedspace->next != NULL)
		unusedspace->next->prev = unusedspace->prev;
	free(unusedspace);
}

int sc_pkcs15_encode_unusedspace(sc_context_t *ctx,
			 struct sc_pkcs15_card *p15card,
			 u8 **buf, size_t *buflen)
{
	sc_path_t dummy_path;
	static const struct sc_asn1_entry c_asn1_unusedspace[] = {
		{ "UnusedSpace", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	static const struct sc_asn1_entry c_asn1_unusedspace_values[] = {
		{ "path", SC_ASN1_PATH,	SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ "authId", SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry *asn1_unusedspace = NULL;
	struct sc_asn1_entry *asn1_values = NULL;
	int unusedspace_count = 0, r, c = 0;
	sc_pkcs15_unusedspace_t *unusedspace;

	sc_format_path("3F00", &dummy_path);
	dummy_path.index = dummy_path.count = 0;

	unusedspace = p15card->unusedspace_list;
	for ( ; unusedspace != NULL; unusedspace = unusedspace->next)
		unusedspace_count++;
	if (unusedspace_count == 0) {
		/* The standard says there has to be at least 1 entry,
		 * so we use a path with a length of 0 bytes */
		r = sc_pkcs15_add_unusedspace(p15card, &dummy_path, NULL);
		if (r)
			return r;
		unusedspace_count = 1;
	}

	asn1_unusedspace = (struct sc_asn1_entry *)
		malloc(sizeof(struct sc_asn1_entry) * (unusedspace_count + 1));
	if (asn1_unusedspace == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	asn1_values = (struct sc_asn1_entry *)
		malloc(sizeof(struct sc_asn1_entry) * (unusedspace_count * 3));
	if (asn1_values == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	for (unusedspace = p15card->unusedspace_list; unusedspace != NULL; unusedspace = unusedspace->next) {
		sc_copy_asn1_entry(c_asn1_unusedspace, asn1_unusedspace + c);
		sc_format_asn1_entry(asn1_unusedspace + c, asn1_values + 3*c, NULL, 1);
		sc_copy_asn1_entry(c_asn1_unusedspace_values, asn1_values + 3*c);
		sc_format_asn1_entry(asn1_values + 3*c, &unusedspace->path, NULL, 1);
		sc_format_asn1_entry(asn1_values + 3*c+1, &unusedspace->auth_id, NULL, unusedspace->auth_id.len);
		c++;
	}
	asn1_unusedspace[c].name = NULL;

	r = sc_asn1_encode(ctx, asn1_unusedspace, buf, buflen);

err:
	if (asn1_values != NULL)
		free(asn1_values);
	if (asn1_unusedspace != NULL)
		free(asn1_unusedspace);

	/* If we added the dummy entry, remove it now */
	if (unusedspace_count == 1 && sc_compare_path(&p15card->unusedspace_list->path, &dummy_path))
		sc_pkcs15_remove_unusedspace(p15card, p15card->unusedspace_list);

	return r;
}

int sc_pkcs15_parse_unusedspace(const u8 * buf, size_t buflen, struct sc_pkcs15_card *p15card)
{
	const u8 *p = buf;
	size_t left = buflen;
	int r;
	sc_path_t path, dummy_path;
	sc_pkcs15_id_t auth_id;
	struct sc_asn1_entry asn1_unusedspace[] = {
		{ "UnusedSpace", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_unusedspace_values[] = {
		{ "path", SC_ASN1_PATH,	SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ "authId", SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};

	/* Clean the list if already present */
	while (p15card->unusedspace_list)
		sc_pkcs15_remove_unusedspace(p15card, p15card->unusedspace_list);

	sc_format_path("3F00", &dummy_path);
	dummy_path.index = dummy_path.count = 0;

	sc_format_asn1_entry(asn1_unusedspace, asn1_unusedspace_values, NULL, 1);
	sc_format_asn1_entry(asn1_unusedspace_values, &path, NULL, 1);
	sc_format_asn1_entry(asn1_unusedspace_values+1, &auth_id, NULL, 0);

	while (left > 0) {
		memset(&auth_id, 0, sizeof(auth_id));
		r = sc_asn1_decode(p15card->card->ctx, asn1_unusedspace, p, left, &p, &left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r < 0)
			return r;
		/* If the path length is 0, it's a dummy path then don't add it.
		 * If the path length isn't included (-1) then it's against the standard
		 *   but we'll just ignore it instead of returning an error. */
		if (path.count > 0) {
			r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &path);
			if (r < 0)
				return r;
			r = sc_pkcs15_add_unusedspace(p15card, &path, &auth_id);
			if (r)
				return r;
		}
	}

	p15card->unusedspace_read = 1;

	return 0;
}

int sc_pkcs15_read_file(struct sc_pkcs15_card *p15card,
			const sc_path_t *in_path,
			u8 **buf, size_t *buflen)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_file_t *file = NULL;
	u8	*data = NULL;
	size_t	len = 0, offset = 0;
	int	r;

	assert(p15card != NULL && in_path != NULL && buf != NULL);

	sc_log(ctx, "called; path=%s, index=%u, count=%d", sc_print_path(in_path), 
			in_path->index, in_path->count);

	r = -1; /* file state: not in cache */
	if (p15card->opts.use_file_cache) {
		r = sc_pkcs15_read_cached_file(p15card, in_path, &data, &len);
	}
	if (r) {
		r = sc_lock(p15card->card);
		LOG_TEST_RET(ctx, r, "sc_lock() failed");
		r = sc_select_file(p15card->card, in_path, &file);
		if (r)
			goto fail_unlock;

		/* Handle the case where the ASN.1 Path object specified
		 * index and length values */
		if (in_path->count < 0) {
			len = file->size;
			offset = 0;
		} 
		else {
			offset = in_path->index;
			len = in_path->count;
			/* Make sure we're within proper bounds */
			if (offset >= file->size || offset + len > file->size) {
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				goto fail_unlock;
			}
		}
		data = malloc(len);
		if (data == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto fail_unlock;
		}

		if (file->ef_structure == SC_FILE_EF_LINEAR_VARIABLE_TLV) {
			int i;
			size_t l, record_len;
			unsigned char *head;

			head = data;
			for (i=1;  ; i++) {
				l = len - (head - data);
				if (l > 256) { l = 256; }
				r = sc_read_record(p15card->card, i, head, l, SC_RECORD_BY_REC_NR);
				if (r == SC_ERROR_RECORD_NOT_FOUND)
					break;
				if (r < 0) {
					free(data);
					goto fail_unlock;
				}
				if (r < 2)
					break;
				record_len = head[1];
				if (record_len != 0xff) {
					memmove(head,head+2,r-2);
					head += (r-2);
				} else {
					if (r < 4)
						break;
					memmove(head,head+4,r-4);
					head += (r-4);
				}
			}
			len = head-data;
		} else {
			r = sc_read_binary(p15card->card, offset, data, len, 0);
			if (r < 0) {
				free(data);
				goto fail_unlock;
			}
			/* sc_read_binary may return less than requested */
			len = r;
		}
		sc_unlock(p15card->card);

		sc_file_free(file);
	}
	*buf = data;
	*buflen = len;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);

fail_unlock:
	if (file)
		sc_file_free(file);
	sc_unlock(p15card->card);
	LOG_FUNC_RETURN(ctx, r);
}

int sc_pkcs15_compare_id(const struct sc_pkcs15_id *id1,
			 const struct sc_pkcs15_id *id2)
{
	assert(id1 != NULL && id2 != NULL);
	if (id1->len != id2->len)
		return 0;
	return memcmp(id1->value, id2->value, id1->len) == 0;
}

void sc_pkcs15_format_id(const char *str, struct sc_pkcs15_id *id)
{
	size_t len = sizeof(id->value);

	if (sc_hex_to_bin(str, id->value, &len) >= 0)
		id->len = len;
}

const char *sc_pkcs15_print_id(const struct sc_pkcs15_id *id)
{
	static char buffer[256];

	sc_bin_to_hex(id->value, id->len, buffer, sizeof(buffer), '\0');
	return buffer;
}

int sc_pkcs15_hex_string_to_id(const char *in, struct sc_pkcs15_id *out)
{
	out->len = sizeof(out->value);
	return sc_hex_to_bin(in, out->value, &out->len);
}

int sc_pkcs15_make_absolute_path(const sc_path_t *parent, sc_path_t *child)
{
	/* nothing to do if child has valid 'aid' */
	if (child->aid.len)
		return SC_SUCCESS;

	if (parent->aid.len)   {
		sc_path_t ppath;

		/* child inherits parent's 'aid' */
		child->aid = parent->aid;
		if (!parent->len)
			return SC_SUCCESS;

		/* parent has valid 'path' -- concatenate it with the child's one */
		memcpy(&ppath, parent, sizeof(sc_path_t));
		ppath.aid.len = 0;
		ppath.type = SC_PATH_TYPE_FROM_CURRENT;
		return sc_concatenate_path(child, &ppath, child);

	}
	else if (parent->type == SC_PATH_TYPE_DF_NAME)   {
		/* child inherits parent's 'DF NAME' as 'aid' */
		if (parent->len > sizeof(child->aid.value))
			return SC_ERROR_WRONG_LENGTH;

		memcpy(child->aid.value, parent->value, parent->len);
		child->aid.len = parent->len;

		return SC_SUCCESS;
	}

	/* a 0 length path stays a 0 length path */
	if (child->len == 0)
		return SC_SUCCESS;
	
	if (sc_compare_path_prefix(sc_get_mf_path(), child))
		return SC_SUCCESS;

	return sc_concatenate_path(child, parent, child);
}

void sc_pkcs15_free_object_content(struct sc_pkcs15_object *obj)
{
	if (obj->content.value && obj->content.len)   {
		sc_mem_clear(obj->content.value, obj->content.len);
		free(obj->content.value);
	}
	obj->content.value = NULL;
	obj->content.len = 0;
}

int sc_pkcs15_allocate_object_content(struct sc_pkcs15_object *obj,
		const unsigned char *value, size_t len)
{
	unsigned char *tmp_buf;

	if (!obj)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (!value || !len)   {
		sc_pkcs15_free_object_content(obj);
		return SC_SUCCESS;
	}

	/* Need to pass by temporary variable,
	 * because 'value' and 'content.value' pointers can be the sames.
	 */
	tmp_buf = (unsigned char *)sc_mem_alloc_secure(len);
	if (!tmp_buf)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(tmp_buf, value, len);

	sc_pkcs15_free_object_content(obj);

	obj->content.value = tmp_buf;
	obj->content.len = len;

	return SC_SUCCESS;
}

struct sc_supported_algo_info *
sc_pkcs15_get_supported_algo(struct sc_pkcs15_card *p15card,
		unsigned operation, unsigned mechanism)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_supported_algo_info *info = NULL;
	int ii;
	
	for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS && p15card->tokeninfo->supported_algos[ii].reference; ii++)
		if ((p15card->tokeninfo->supported_algos[ii].operations & operation) 
				&& (p15card->tokeninfo->supported_algos[ii].mechanism == mechanism))
			break;
	
	if (ii < SC_MAX_SUPPORTED_ALGORITHMS && p15card->tokeninfo->supported_algos[ii].reference)   {
        	info = &p15card->tokeninfo->supported_algos[ii];
        	sc_log(ctx, "found supported algorithm (ref:%X,mech:%X,ops:%X,algo_ref:%X)", 
				info->reference, info->mechanism, info->operations, info->algo_ref); 
	}
	
	return info;
}


int 
sc_pkcs15_add_supported_algo_ref(struct sc_pkcs15_object *obj, 
		struct sc_supported_algo_info *algo)
{
	unsigned int ii, *algo_refs = NULL;

	if (!algo)
		return SC_SUCCESS;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		algo_refs = ((struct sc_pkcs15_prkey_info *)obj->data)->algo_refs;
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		algo_refs = ((struct sc_pkcs15_pubkey_info *)obj->data)->algo_refs;
		break;
	}
	if (!algo_refs)
		return SC_ERROR_NOT_SUPPORTED;

	for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS && *(algo_refs + ii);ii++)
		if (*(algo_refs + ii) == algo->reference)
			return SC_SUCCESS;

	for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS;ii++)   {
		if (*(algo_refs + ii) == 0)   {
			*(algo_refs + ii) = algo->reference;
			return SC_SUCCESS;
		}
	}

	return SC_ERROR_TOO_MANY_OBJECTS;
}


int 
sc_pkcs15_get_object_id(const struct sc_pkcs15_object *obj, struct sc_pkcs15_id *out)
{
	if (!obj || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	switch (obj->type) {
	case SC_PKCS15_TYPE_CERT_X509:
		*out = ((struct sc_pkcs15_cert_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_DSA:
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PRKEY_EC:
		*out = ((struct sc_pkcs15_prkey_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_DSA:
	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
	case SC_PKCS15_TYPE_PUBKEY_EC:
		*out = ((struct sc_pkcs15_pubkey_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_AUTH_PIN:
		*out = ((struct sc_pkcs15_auth_info *) obj->data)->auth_id;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		*out = ((struct sc_pkcs15_data_info *) obj->data)->id;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	return SC_SUCCESS;
}

/*
 * Simplified GUID serializing.
 * Ex. {3F2504E0-4F89-11D3-9A0C-0305E82C3301}
 *
 * There is no variant, version number and other special meaning fields
 *  that are described in RFC-4122 .
 */
static int
sc_pkcs15_serialize_guid(unsigned char *in, size_t in_size, 
		char *out, size_t out_size)
{
	int ii, jj, offs = 0;

	if (in_size < 16)
		return SC_ERROR_BUFFER_TOO_SMALL;
	if (out_size < 39) 
		return SC_ERROR_BUFFER_TOO_SMALL;

	strcpy(out, "{");
	for (ii=0; ii<4; ii++)
		sprintf(out + strlen(out), "%02x", *(in + offs++));
	for (jj=0; jj<3; jj++)   {
		strcat(out, "-");
		for (ii=0; ii<2; ii++)
			sprintf(out + strlen(out), "%02x", *(in + offs++));
	}
	strcat(out, "-");
	for (ii=0; ii<6; ii++)
		sprintf(out + strlen(out), "%02x", *(in + offs++));
	strcat(out, "}");

	return SC_SUCCESS;
}

int 
sc_pkcs15_get_guid(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_object *obj,
		                char *out, size_t out_size)
{
	struct sc_serial_number serialnr;
	struct sc_pkcs15_id  id;
	unsigned char guid_bin[SC_PKCS15_MAX_ID_SIZE + SC_MAX_SERIALNR];
	int rv;

	if (p15card->ops.get_guid)
		return p15card->ops.get_guid(p15card, obj, out, out_size);

	rv = sc_pkcs15_get_object_id(obj, &id);
	if (rv)
		return rv;

	rv = sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &serialnr);                                        
	if (rv)
		return rv;

	memset(guid_bin, 0, sizeof(guid_bin));
	memcpy(guid_bin, id.value, id.len);
	memcpy(guid_bin + id.len, serialnr.value, serialnr.len);

	return sc_pkcs15_serialize_guid(guid_bin, id.len + serialnr.len, out, out_size);
}

void sc_pkcs15_free_key_params(struct sc_pkcs15_key_params *params)   
{
	if (!params)
		return;
	if (params->data && params->free_params)
		params->free_params(params->data);
	else if (params->data)
		free(params->data);

	params->data = NULL;
}

