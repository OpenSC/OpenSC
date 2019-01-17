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
#include <ctype.h>

#include "cardctl.h"
#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"
#include "common/libscdl.h"

#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

static const struct sc_asn1_entry c_asn1_twlabel[] = {
	{ "twlabel", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_algorithm_info[7] = {
	{ "reference",		SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,	0, NULL, NULL },
	{ "algorithmPKCS#11",	SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,	0, NULL, NULL },
	{ "parameters",		SC_ASN1_CHOICE,		0,			0, NULL, NULL },
	{ "supportedOperations",SC_ASN1_BIT_FIELD,	SC_ASN1_TAG_BIT_STRING,	0, NULL, NULL },
	{ "objId",		SC_ASN1_OBJECT,		SC_ASN1_TAG_OBJECT,	SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algRef",		SC_ASN1_INTEGER,	SC_ASN1_TAG_INTEGER,	SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_algorithm_info_parameters[3] = {
	{ "PKCS15RSAParameters",SC_ASN1_NULL,		SC_ASN1_TAG_NULL,	0, NULL, NULL },
	{ "PKCS15ECParameters",	SC_ASN1_OBJECT,		SC_ASN1_TAG_OBJECT,	0, NULL, NULL },
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

#define C_ASN1_LAST_UPDATE_SIZE 3
static const struct sc_asn1_entry c_asn1_last_update[C_ASN1_LAST_UPDATE_SIZE] = {
	{ "generalizedTime",	SC_ASN1_GENERALIZEDTIME, SC_ASN1_TAG_GENERALIZEDTIME,	SC_ASN1_OPTIONAL, NULL, NULL },
	{ "referencedTime",	SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS,	SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PROFILE_INDICATION_SIZE 3
static const struct sc_asn1_entry c_asn1_profile_indication[C_ASN1_PROFILE_INDICATION_SIZE] = {
	{ "profileOID",		SC_ASN1_OBJECT,		SC_ASN1_TAG_OBJECT,     SC_ASN1_OPTIONAL, NULL, NULL },
	{ "profileName",	SC_ASN1_UTF8STRING,	SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_TOKI_ATTRS_SIZE 15
static const struct sc_asn1_entry c_asn1_toki_attrs[C_ASN1_TOKI_ATTRS_SIZE] = {
	{ "version",	    SC_ASN1_INTEGER,		SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "serialNumber",   SC_ASN1_OCTET_STRING,	SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "manufacturerID", SC_ASN1_UTF8STRING,		SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "label",	    SC_ASN1_UTF8STRING,		SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
	/* XXX the Taiwanese ID card erroneously uses explicit tagging */
	{ "label-tw",       SC_ASN1_STRUCT,		SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "tokenflags",	    SC_ASN1_BIT_FIELD,		SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
	{ "seInfo",	    SC_ASN1_SE_INFO,		SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "recordInfo",	    SC_ASN1_STRUCT,		SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "supportedAlgorithms", SC_ASN1_STRUCT,	SC_ASN1_CONS | SC_ASN1_CTX | 2, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "issuerId",       SC_ASN1_UTF8STRING,		SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "holderId",       SC_ASN1_UTF8STRING,		SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "lastUpdate",     SC_ASN1_STRUCT,		SC_ASN1_CONS | SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "preferredLanguage", SC_ASN1_PRINTABLESTRING,	SC_ASN1_TAG_PRINTABLESTRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "profileIndication", SC_ASN1_STRUCT,		SC_ASN1_CONS | SC_ASN1_CTX | 6, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_tokeninfo[] = {
	{ "TokenInfo", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static void sc_pkcs15_free_unusedspace(struct sc_pkcs15_card *);
static void sc_pkcs15_remove_dfs(struct sc_pkcs15_card *);
static void sc_pkcs15_remove_objects(struct sc_pkcs15_card *);
static int sc_pkcs15_aux_get_md_guid(struct sc_pkcs15_card *, const struct sc_pkcs15_object *,
		unsigned, unsigned char *, size_t *);

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
	u8 last_update[32], profile_indication[SC_PKCS15_MAX_LABEL_SIZE];
	size_t lupdate_len = sizeof(last_update) - 1, pi_len = sizeof(profile_indication) - 1;
	size_t flags_len   = sizeof(ti->flags);
	u8 preferred_language[3];
	size_t lang_length = sizeof(preferred_language);
	struct sc_asn1_entry asn1_supported_algorithms[SC_MAX_SUPPORTED_ALGORITHMS + 1],
			asn1_algo_infos[SC_MAX_SUPPORTED_ALGORITHMS][7],
			asn1_algo_infos_parameters[SC_MAX_SUPPORTED_ALGORITHMS][3];
	size_t reference_len = sizeof(ti->supported_algos[0].reference);
	size_t mechanism_len = sizeof(ti->supported_algos[0].mechanism);
	size_t parameter_len = sizeof(ti->supported_algos[0].parameters);
	size_t operations_len = sizeof(ti->supported_algos[0].operations);
	size_t algo_ref_len = sizeof(ti->supported_algos[0].algo_ref);

	struct sc_asn1_entry asn1_last_update[C_ASN1_LAST_UPDATE_SIZE];
	struct sc_asn1_entry asn1_profile_indication[C_ASN1_PROFILE_INDICATION_SIZE];
	struct sc_asn1_entry asn1_toki_attrs[C_ASN1_TOKI_ATTRS_SIZE], asn1_tokeninfo[3], asn1_twlabel[3];

	memset(last_update, 0, sizeof(last_update));
	sc_copy_asn1_entry(c_asn1_twlabel, asn1_twlabel);
	sc_copy_asn1_entry(c_asn1_toki_attrs, asn1_toki_attrs);
	sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
	sc_copy_asn1_entry(c_asn1_last_update, asn1_last_update);
	sc_format_asn1_entry(asn1_twlabel, label, &label_len, 0);
	sc_copy_asn1_entry(c_asn1_profile_indication, asn1_profile_indication);

	for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS; ii++) {
		sc_copy_asn1_entry(c_asn1_algorithm_info, asn1_algo_infos[ii]);
		sc_copy_asn1_entry(c_asn1_algorithm_info_parameters,
			asn1_algo_infos_parameters[ii]);
	}
	sc_copy_asn1_entry(c_asn1_supported_algorithms, asn1_supported_algorithms);

	for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS; ii++)   {
		sc_format_asn1_entry(asn1_algo_infos[ii] + 0, &ti->supported_algos[ii].reference, &reference_len, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 1, &ti->supported_algos[ii].mechanism, &mechanism_len, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 2,
			asn1_algo_infos_parameters[ii], NULL, 0);
		sc_format_asn1_entry(asn1_algo_infos_parameters[ii] + 0,
			NULL, NULL, 0);
		sc_format_asn1_entry(asn1_algo_infos_parameters[ii] + 1,
			&ti->supported_algos[ii].parameters, &parameter_len, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 3, &ti->supported_algos[ii].operations, &operations_len, 0);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 4, &ti->supported_algos[ii].algo_id, NULL, 1);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 5, &ti->supported_algos[ii].algo_ref, &algo_ref_len, 0);
		sc_format_asn1_entry(asn1_supported_algorithms + ii, asn1_algo_infos[ii], NULL, 0);
	}

	sc_format_asn1_entry(asn1_last_update + 0, last_update, &lupdate_len, 0);
	sc_format_asn1_entry(asn1_last_update + 1, &ti->last_update.path, NULL, 0);

	sc_format_asn1_entry(asn1_profile_indication + 0, &ti->profile_indication.oid, NULL, 0);
	sc_format_asn1_entry(asn1_profile_indication + 1, profile_indication, &pi_len, 0);

	sc_format_asn1_entry(asn1_toki_attrs + 0, &ti->version, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 1, serial, &serial_len, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 2, mnfid, &mnfid_len, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 3, label, &label_len, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 4, asn1_twlabel, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 5, &ti->flags, &flags_len, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 6, &ti->seInfo, &ti->num_seInfo, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 7, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 8, asn1_supported_algorithms, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 9, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 10, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 11, asn1_last_update, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 12, preferred_language, &lang_length, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 13, asn1_profile_indication, NULL, 0);
	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki_attrs, NULL, 0);

	r = sc_asn1_decode(ctx, asn1_tokeninfo, buf, blen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of EF(TokenInfo) failed");

	if (asn1_toki_attrs[1].flags & SC_ASN1_PRESENT && serial_len > 0)   {
		ti->serial_number = malloc(serial_len * 2 + 1);
		if (ti->serial_number == NULL)
			return SC_ERROR_OUT_OF_MEMORY;

		ti->serial_number[0] = 0;
		for (ii = 0; ii < serial_len; ii++) {
			char byte[3];

			sprintf(byte, "%02X", serial[ii]);
			strcat(ti->serial_number, byte);
		}
		sc_log(ctx, "TokenInfo.serialNunmber '%s'", ti->serial_number);
	}

	if (ti->manufacturer_id == NULL) {
		if (asn1_toki_attrs[2].flags & SC_ASN1_PRESENT)
			ti->manufacturer_id = strdup((char *) mnfid);
		else
			ti->manufacturer_id = strdup("(unknown)");
		if (ti->manufacturer_id == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	if (ti->label == NULL) {
		if (asn1_toki_attrs[3].flags & SC_ASN1_PRESENT ||
		    asn1_toki_attrs[4].flags & SC_ASN1_PRESENT)
			ti->label = strdup((char *) label);
		else
			ti->label = strdup("(unknown)");
		if (ti->label == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	if (asn1_toki_attrs[11].flags & SC_ASN1_PRESENT) {
		if (asn1_last_update[0].flags & SC_ASN1_PRESENT)   {
			sc_log(ctx, "LastUpdate.generalizedTime present");
			ti->last_update.gtime = strdup((char *)last_update);
			if (ti->last_update.gtime == NULL)
				return SC_ERROR_OUT_OF_MEMORY;
		}
		else if (asn1_last_update[1].flags & SC_ASN1_PRESENT)  {
			sc_log(ctx, "LastUpdate.referencedTime present");
		}
	}
	if (asn1_toki_attrs[12].flags & SC_ASN1_PRESENT) {
		preferred_language[2] = 0;
		ti->preferred_language = strdup((char *)preferred_language);
		if (ti->preferred_language == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	}

	sc_init_oid(&ti->profile_indication.oid);
	if (asn1_toki_attrs[13].flags & SC_ASN1_PRESENT) {
		if (asn1_profile_indication[0].flags & SC_ASN1_PRESENT)   {
			sc_log(ctx, "ProfileIndication.oid present");
		}
		else if (asn1_profile_indication[1].flags & SC_ASN1_PRESENT)  {
			sc_log(ctx, "ProfileIndication.name present");
			ti->profile_indication.name = strdup((char *)profile_indication);
			if (ti->profile_indication.name == NULL)
				return SC_ERROR_OUT_OF_MEMORY;
		}
	}

	sc_log(ctx, "LastUpdate.path '%s'", sc_print_path(&ti->last_update.path));
	sc_log(ctx, "ProfileIndication.name '%s'",  ti->profile_indication.name);
	return SC_SUCCESS;
}


int
sc_pkcs15_encode_tokeninfo(sc_context_t *ctx, sc_pkcs15_tokeninfo_t *ti,
		u8 **buf, size_t *buflen)
{
	int r, ii;
	size_t serial_len, mnfid_len, label_len, flags_len, last_upd_len, pi_len;

	struct sc_asn1_entry asn1_toki_attrs[C_ASN1_TOKI_ATTRS_SIZE];
	struct sc_asn1_entry asn1_tokeninfo[2];
	struct sc_asn1_entry asn1_supported_algorithms[SC_MAX_SUPPORTED_ALGORITHMS + 1],
			asn1_algo_infos[SC_MAX_SUPPORTED_ALGORITHMS][7],
			asn1_algo_infos_parameters[SC_MAX_SUPPORTED_ALGORITHMS][3];
	size_t reference_len = sizeof(ti->supported_algos[0].reference);
	size_t mechanism_len = sizeof(ti->supported_algos[0].mechanism);
	size_t parameter_len = sizeof(ti->supported_algos[0].parameters);
	size_t operations_len = sizeof(ti->supported_algos[0].operations);
	size_t algo_ref_len = sizeof(ti->supported_algos[0].algo_ref);
	struct sc_asn1_entry asn1_last_update[C_ASN1_LAST_UPDATE_SIZE];
	struct sc_asn1_entry asn1_profile_indication[C_ASN1_PROFILE_INDICATION_SIZE];

	sc_copy_asn1_entry(c_asn1_toki_attrs, asn1_toki_attrs);
	sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
	sc_copy_asn1_entry(c_asn1_last_update, asn1_last_update);
	sc_copy_asn1_entry(c_asn1_profile_indication, asn1_profile_indication);

	for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS && ti->supported_algos[ii].reference; ii++) {
		sc_copy_asn1_entry(c_asn1_algorithm_info, asn1_algo_infos[ii]);
		sc_copy_asn1_entry(c_asn1_algorithm_info_parameters,
			asn1_algo_infos_parameters[ii]);
	}
	sc_copy_asn1_entry(c_asn1_supported_algorithms, asn1_supported_algorithms);

	for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS && ti->supported_algos[ii].reference; ii++)   {
		sc_format_asn1_entry(asn1_algo_infos[ii] + 0, &ti->supported_algos[ii].reference, &reference_len, 1);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 1, &ti->supported_algos[ii].mechanism, &mechanism_len, 1);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 2,
			asn1_algo_infos_parameters[ii], NULL, 1);
		if (!ti->supported_algos[ii].parameters)	{
			sc_format_asn1_entry(asn1_algo_infos_parameters[ii] + 0,
				NULL, NULL, 1);
		}
		else {
			sc_format_asn1_entry(asn1_algo_infos_parameters[ii] + 1,
				&ti->supported_algos[ii].parameters, &parameter_len, 0);
		}
		sc_format_asn1_entry(asn1_algo_infos[ii] + 3, &ti->supported_algos[ii].operations, &operations_len, 1);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 4, &ti->supported_algos[ii].algo_id, NULL, 1);
		sc_format_asn1_entry(asn1_algo_infos[ii] + 5, &ti->supported_algos[ii].algo_ref, &algo_ref_len, 1);
		sc_format_asn1_entry(asn1_supported_algorithms + ii, asn1_algo_infos[ii], NULL, 1);
	}

	sc_format_asn1_entry(asn1_toki_attrs + 0, &ti->version, NULL, 1);
	if (ti->serial_number != NULL) {
		u8 serial[128];
		serial_len = 0;
		if (strlen(ti->serial_number)/2 > sizeof(serial))
			return SC_ERROR_BUFFER_TOO_SMALL;
		serial_len = sizeof(serial);
		if (sc_hex_to_bin(ti->serial_number, serial, &serial_len) < 0)
			return SC_ERROR_INVALID_ARGUMENTS;
		sc_format_asn1_entry(asn1_toki_attrs + 1, serial, &serial_len, 1);
	}
	else   {
		sc_format_asn1_entry(asn1_toki_attrs + 1, NULL, NULL, 0);
	}

	if (ti->manufacturer_id != NULL) {
		mnfid_len = strlen(ti->manufacturer_id);
		sc_format_asn1_entry(asn1_toki_attrs + 2, ti->manufacturer_id, &mnfid_len, 1);
	}
	else    {
		sc_format_asn1_entry(asn1_toki_attrs + 2, NULL, NULL, 0);
	}

	if (ti->label != NULL) {
		label_len = strlen(ti->label);
		sc_format_asn1_entry(asn1_toki_attrs + 3, ti->label, &label_len, 1);
	}
	else   {
		sc_format_asn1_entry(asn1_toki_attrs + 3, NULL, NULL, 0);
	}

	if (ti->flags) {
		flags_len = sizeof(ti->flags);
		sc_format_asn1_entry(asn1_toki_attrs + 5, &ti->flags, &flags_len, 1);
	}
	else   {
		sc_format_asn1_entry(asn1_toki_attrs + 5, NULL, NULL, 0);
	}

	if (ti->num_seInfo)
		sc_format_asn1_entry(asn1_toki_attrs + 6, ti->seInfo, &ti->num_seInfo, 1);
	else
		sc_format_asn1_entry(asn1_toki_attrs + 6, NULL, NULL, 0);

	sc_format_asn1_entry(asn1_toki_attrs + 7, NULL, NULL, 0);

	if (ti->supported_algos[0].reference)
		sc_format_asn1_entry(asn1_toki_attrs + 8, asn1_supported_algorithms, NULL, 1);
	else
		sc_format_asn1_entry(asn1_toki_attrs + 8, NULL, NULL, 0);

	sc_format_asn1_entry(asn1_toki_attrs + 9, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_toki_attrs + 10, NULL, NULL, 0);

	if (ti->last_update.path.len) {
		sc_format_asn1_entry(asn1_last_update + 0, &ti->last_update.path, NULL, 1);
		sc_format_asn1_entry(asn1_toki_attrs + 11, asn1_last_update, NULL, 1);
	}
	else if (ti->last_update.gtime != NULL) {
		last_upd_len = strlen(ti->last_update.gtime);
		sc_format_asn1_entry(asn1_last_update + 0, ti->last_update.gtime, &last_upd_len, 1);
		sc_format_asn1_entry(asn1_toki_attrs + 11, asn1_last_update, NULL, 1);
	}
	else   {
		sc_format_asn1_entry(asn1_toki_attrs + 11, NULL, NULL, 0);
	}
	sc_format_asn1_entry(asn1_toki_attrs + 12, NULL, NULL, 0);

	if (sc_valid_oid(&ti->profile_indication.oid))   {
		sc_format_asn1_entry(asn1_profile_indication + 0, &ti->profile_indication.oid, NULL, 1);
		sc_format_asn1_entry(asn1_toki_attrs + 13, asn1_profile_indication, NULL, 1);
	}
	else if (ti->profile_indication.name)   {
		pi_len = strlen(ti->profile_indication.name);
		sc_format_asn1_entry(asn1_profile_indication + 1, ti->profile_indication.name, &pi_len, 1);
		sc_format_asn1_entry(asn1_toki_attrs + 13, asn1_profile_indication, NULL, 1);
	}
	else    {
		sc_format_asn1_entry(asn1_toki_attrs + 13, NULL, NULL, 0);
	}

	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki_attrs, NULL, 1);

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

static void
fix_authentic_ddo(struct sc_pkcs15_card *p15card)
{
	/* AuthentIC v3.2 card has invalid ODF and tokenInfo paths encoded into DDO.
	 * Cleanup this attributes -- default values must be OK.
	 */
	if (p15card->card->type == SC_CARD_TYPE_OBERTHUR_AUTHENTIC_3_2)   {
		sc_file_free(p15card->file_odf);
		p15card->file_odf = NULL;
		sc_file_free(p15card->file_tokeninfo);
		p15card->file_tokeninfo = NULL;
	}
}

static int
parse_ddo(struct sc_pkcs15_card *p15card, const u8 * buf, size_t buflen)
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
	sc_file_free(p15card->file_odf);
	p15card->file_odf = NULL;
	sc_file_free(p15card->file_tokeninfo);
	p15card->file_tokeninfo = NULL;
	sc_file_free(p15card->file_unusedspace);
	p15card->file_unusedspace = NULL;
	LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
}


char *
sc_pkcs15_get_lastupdate(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx  = p15card->card->ctx;
	struct sc_file *file = NULL;
	struct sc_asn1_entry asn1_last_update[C_ASN1_LAST_UPDATE_SIZE];
	unsigned char *content, last_update[32];
	size_t lupdate_len = sizeof(last_update) - 1;
	int r, content_len;
	size_t size;

	if (p15card->tokeninfo->last_update.gtime)
		goto done;

	if (!p15card->tokeninfo->last_update.path.len)
		return NULL;

	r = sc_select_file(p15card->card, &p15card->tokeninfo->last_update.path, &file);
	if (r < 0)
		return NULL;

	size = file->size ? file->size : 1024;

	content = calloc(size, 1);
	if (!content)
		return NULL;

	r = sc_read_binary(p15card->card, 0, content, size, 0);
	if (r < 0)
		return NULL;
	content_len = r;

	sc_file_free(file);

	sc_copy_asn1_entry(c_asn1_last_update, asn1_last_update);
	sc_format_asn1_entry(asn1_last_update + 0, last_update, &lupdate_len, 0);

	r = sc_asn1_decode(ctx, asn1_last_update, content, content_len, NULL, NULL);
	free(content);
	if (r < 0)
		return NULL;

	p15card->tokeninfo->last_update.gtime = strdup((char *)last_update);
	if (!p15card->tokeninfo->last_update.gtime)
		return NULL;
done:
	sc_log(ctx, "lastUpdate.gtime '%s'", p15card->tokeninfo->last_update.gtime);
	return p15card->tokeninfo->last_update.gtime;
}


static const struct sc_asn1_entry c_asn1_odf[] = {
	{ "privateKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "publicKeys",		 SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "trustedPublicKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "secretKeys",		 SC_ASN1_STRUCT, SC_ASN1_CTX | 3 | SC_ASN1_CONS, 0, NULL, NULL },
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


static int
parse_odf(const unsigned char * buf, size_t buflen, struct sc_pkcs15_card *p15card)
{
	const unsigned char *p = buf;
	size_t left = buflen;
	int r, i, type;
	struct sc_path path;
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


int
sc_pkcs15_encode_odf(struct sc_context *ctx, struct sc_pkcs15_card *p15card,
			 unsigned char **buf, size_t *buflen)
{
	struct sc_path path;
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


struct sc_pkcs15_card *
sc_pkcs15_card_new(void)
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


struct sc_pkcs15_tokeninfo *
sc_pkcs15_tokeninfo_new(void)
{
	struct sc_pkcs15_tokeninfo *tokeninfo;

	tokeninfo = calloc(1, sizeof(struct sc_pkcs15_tokeninfo));
	if (tokeninfo == NULL) {
		return NULL;
	}

	sc_init_oid(&tokeninfo->profile_indication.oid);

	return tokeninfo;
}


void
sc_pkcs15_free_tokeninfo(struct sc_pkcs15_tokeninfo *tokeninfo)
{
	if (!tokeninfo)
		return;

	if (tokeninfo->label != NULL)
		free(tokeninfo->label);
	if (tokeninfo->serial_number != NULL)
		free(tokeninfo->serial_number);
	if (tokeninfo->manufacturer_id != NULL)
		free(tokeninfo->manufacturer_id);
	if (tokeninfo->last_update.gtime != NULL)
		free(tokeninfo->last_update.gtime);
	if (tokeninfo->preferred_language != NULL)
		free(tokeninfo->preferred_language);
	if (tokeninfo->profile_indication.name != NULL)
		free(tokeninfo->profile_indication.name);
	if (tokeninfo->seInfo != NULL) {
		unsigned i;
		for (i = 0; i < tokeninfo->num_seInfo; i++)
			free(tokeninfo->seInfo[i]);
		free(tokeninfo->seInfo);
	}
	free(tokeninfo);
}


void
sc_pkcs15_free_app(struct sc_pkcs15_card *p15card)
{
	if (p15card && p15card->app) {
		free(p15card->app->label);
		free(p15card->app->ddo.value);
		free(p15card->app);
		p15card->app = NULL;
	}
}


void
sc_pkcs15_card_free(struct sc_pkcs15_card *p15card)
{
	if (p15card == NULL || p15card->magic != SC_PKCS15_CARD_MAGIC)
		return;

	if (p15card->ops.clear)
		p15card->ops.clear(p15card);

	/* For more complicated MD data a dedicated release procedure
	 * has to be implemented. */
	if (p15card->md_data)
		free(p15card->md_data);

	sc_pkcs15_remove_objects(p15card);
	sc_pkcs15_remove_dfs(p15card);
	sc_pkcs15_free_unusedspace(p15card);
	p15card->unusedspace_read = 0;

	sc_file_free(p15card->file_app);
	sc_file_free(p15card->file_tokeninfo);
	sc_file_free(p15card->file_odf);
	sc_file_free(p15card->file_unusedspace);

	p15card->magic = 0;
	sc_pkcs15_free_tokeninfo(p15card->tokeninfo);
	sc_pkcs15_free_app(p15card);
	free(p15card);
}


void
sc_pkcs15_card_clear(struct sc_pkcs15_card *p15card)
{
	if (p15card == NULL)
		return;

	if (p15card->ops.clear)
		p15card->ops.clear(p15card);

	p15card->flags = 0;
	p15card->tokeninfo->version = 0;
	p15card->tokeninfo->flags   = 0;

	sc_pkcs15_remove_objects(p15card);
	sc_pkcs15_remove_dfs(p15card);

	p15card->df_list = NULL;
	sc_file_free(p15card->file_app);
	p15card->file_app = NULL;
	sc_file_free(p15card->file_tokeninfo);
	p15card->file_tokeninfo = NULL;
	sc_file_free(p15card->file_odf);
	p15card->file_odf = NULL;
	sc_file_free(p15card->file_unusedspace);
	p15card->file_unusedspace = NULL;
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
	if (p15card->tokeninfo->last_update.gtime != NULL) {
		free(p15card->tokeninfo->last_update.gtime);
		p15card->tokeninfo->last_update.gtime = NULL;
	}
	if (p15card->tokeninfo->preferred_language != NULL) {
		free(p15card->tokeninfo->preferred_language);
		p15card->tokeninfo->preferred_language = NULL;
	}
	if (p15card->tokeninfo->profile_indication.name != NULL)   {
		free(p15card->tokeninfo->profile_indication.name);
		p15card->tokeninfo->profile_indication.name = NULL;
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


struct sc_app_info *
sc_find_app(struct sc_card *card, struct sc_aid *aid)
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


static struct sc_app_info *
sc_dup_app_info(const struct sc_app_info *info)
{
	struct sc_app_info *out = calloc(1, sizeof(struct sc_app_info));

	if (!out)
		return NULL;

	memcpy(out, info, sizeof(struct sc_app_info));

	if (info->label) {
		out->label = strdup(info->label);
		if (!out->label) {
			free(out);
			return NULL;
		}
	} else
		out->label = NULL;

	out->ddo.value = malloc(info->ddo.len);
	if (!out->ddo.value) {
		free(out->label);
		free(out);
		return NULL;
	}
	memcpy(out->ddo.value, info->ddo.value, info->ddo.len);

	return out;
}


struct sc_app_info *
sc_pkcs15_get_application_by_type(struct sc_card * card, char *app_type)
{
	struct sc_app_info *out = NULL;
	scconf_block *conf_block = NULL;
	int i, rv;

	if (!card)
		return NULL;

	if (card->app_count < 0)   {
		rv = sc_enum_apps(card);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			return NULL;
	}

	conf_block = sc_get_conf_block(card->ctx, "framework", "pkcs15", 1);
	if (!conf_block)
		return NULL;

	for (i = 0; i < card->app_count; i++)   {
		struct sc_app_info *app_info = card->app[i];
		scconf_block **blocks = NULL;
		char str_path[SC_MAX_AID_STRING_SIZE];

		sc_bin_to_hex(app_info->aid.value, app_info->aid.len, str_path, sizeof(str_path), 0);
		blocks = scconf_find_blocks(card->ctx->conf, conf_block, "application", str_path);
		if (blocks)   {
			if (blocks[0])   {
				char *type = (char *)scconf_get_str(blocks[0], "type", app_type);
				if (!strcmp(type, app_type))   {
					out = app_info;
					free(blocks);
					break;
				}
			}
			free(blocks);
		}
	}

	return out;
}


int
sc_pkcs15_bind_internal(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	struct sc_path tmppath;
	struct sc_card    *card = p15card->card;
	struct sc_context *ctx  = card->ctx;
	struct sc_pkcs15_tokeninfo tokeninfo;
	struct sc_pkcs15_df *df;
	const struct sc_app_info *info = NULL;
	unsigned char *buf = NULL;
	size_t len;
	int    err, ok = 0;

	LOG_FUNC_CALLED(ctx);
	/* Enumerate apps now */
	if (card->app_count < 0) {
		err = sc_enum_apps(card);
		if (err != SC_SUCCESS)
			sc_log(ctx, "unable to enumerate apps: %s", sc_strerror(err));
	}
	p15card->file_app = sc_file_new();
	if (p15card->file_app == NULL) {
		err = SC_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	sc_format_path("3F005015", &p15card->file_app->path);

	info = sc_find_app(card, aid);
	if (info)   {
		sc_log(ctx, "bind to application('%s',aid:'%s')", info->label, sc_dump_hex(info->aid.value, info->aid.len));
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
		sc_log(ctx, "Application '%s' not found", sc_dump_hex(aid->value, aid->len));
		err = SC_ERROR_INVALID_ARGUMENTS;
		goto end;
	}
	sc_log(ctx, "application path '%s'", sc_print_path(&p15card->file_app->path));

	/* Check if pkcs15 directory exists */
	err = sc_select_file(card, &p15card->file_app->path, NULL);

	/* If the above test failed on cards without EF(DIR),
	 * try to continue read ODF from 3F005031. -aet
	 */
	if ((err != SC_SUCCESS) && (card->app_count < 1)) {
		sc_format_path("3F00", &p15card->file_app->path);
		err = SC_SUCCESS;
	}

	if (err < 0)   {
		sc_log (ctx, "Cannot select application path");
		goto end;
	}

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
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	err = -1; /* file state: not in cache */
	if (p15card->opts.use_file_cache) {
		err = sc_pkcs15_read_cached_file(p15card, &tmppath, &buf, &len);
		if (err == SC_SUCCESS)
			err = len;
	}
	if (err < 0) {
		err = sc_read_binary(card, 0, buf, len, 0);
		if (err < 2) {
			if (err < 0) {
				sc_log(ctx, "read EF(ODF) file error: %s", sc_strerror(err));
			} else {
				err = SC_ERROR_PKCS15_APP_NOT_FOUND;
				sc_log(ctx, "Invalid content of EF(ODF): %s", sc_strerror(err));
			}
			goto end;
		}
		/* sc_read_binary may return less than requested */
		len = err;

		if (p15card->opts.use_file_cache) {
			sc_pkcs15_cache_file(p15card, &tmppath, buf, len);
		}
	}

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
	if (err)   {
		sc_log(ctx, "cannot select EF(TokenInfo) file: %s", sc_strerror(err));
		goto end;
	}

	len = p15card->file_tokeninfo->size;
	if (!len) {
		sc_log(ctx, "EF(TokenInfo) is empty");
		goto end;
	}
	buf = malloc(len);
	if(buf == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	err = -1; /* file state: not in cache */
	if (p15card->opts.use_file_cache) {
		err = sc_pkcs15_read_cached_file(p15card, &tmppath, &buf, &len);
		if (err == SC_SUCCESS)
			err = len;
	}
	if (err < 0) {
		err = sc_read_binary(card, 0, buf, len, 0);
		if (err <= 2) {
			if (err < 0)   {
				sc_log(ctx, "read EF(TokenInfo) file error: %s", sc_strerror(err));
			} else {
				err = SC_ERROR_PKCS15_APP_NOT_FOUND;
				sc_log(ctx, "Invalid content of EF(TokenInfo): %s", sc_strerror(err));
			}
			goto end;
		}
		/* sc_read_binary may return less than requested */
		len = err;

		if (p15card->opts.use_file_cache) {
			sc_pkcs15_cache_file(p15card, &tmppath, buf, len);
		}
	}

	memset(&tokeninfo, 0, sizeof(tokeninfo));
	err = sc_pkcs15_parse_tokeninfo(ctx, &tokeninfo, buf, (size_t)err);
	if (err != SC_SUCCESS)   {
		sc_log(ctx, "cannot parse TokenInfo content: %s", sc_strerror(err));
		goto end;
	}

	*(p15card->tokeninfo) = tokeninfo;

	if (!p15card->tokeninfo->serial_number && 0 == card->serialnr.len) {
		sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &card->serialnr);
	}

	if (!p15card->tokeninfo->serial_number && card->serialnr.len)   {
		char *serial = calloc(1, card->serialnr.len*2 + 1);
		size_t ii;
		if (!serial) {
			err = SC_ERROR_OUT_OF_MEMORY;
			goto end;
		}

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
		if (err == SC_ERROR_FILE_NOT_FOUND)
			err = SC_ERROR_WRONG_CARD;
		LOG_FUNC_RETURN(ctx, err);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15_bind(struct sc_card *card, struct sc_aid *aid,
		struct sc_pkcs15_card **p15card_out)
{
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_context *ctx = card->ctx;
	scconf_block *conf_block = NULL;
	int r, emu_first, enable_emu;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "application(aid:'%s')", aid ? sc_dump_hex(aid->value, aid->len) : "empty");

	if (p15card_out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p15card = sc_pkcs15_card_new();
	if (p15card == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	p15card->card = card;
	p15card->opts.use_file_cache = 0;
	p15card->opts.use_pin_cache = 1;
	p15card->opts.pin_cache_counter = 10;
	p15card->opts.pin_cache_ignore_user_consent = 0;

	conf_block = sc_get_conf_block(ctx, "framework", "pkcs15", 1);

	if (conf_block) {
		p15card->opts.use_file_cache = scconf_get_bool(conf_block, "use_file_caching", p15card->opts.use_file_cache);
		p15card->opts.use_pin_cache = scconf_get_bool(conf_block, "use_pin_caching", p15card->opts.use_pin_cache);
		p15card->opts.pin_cache_counter = scconf_get_int(conf_block, "pin_cache_counter", p15card->opts.pin_cache_counter);
		p15card->opts.pin_cache_ignore_user_consent =  scconf_get_bool(conf_block, "pin_cache_ignore_user_consent",
				p15card->opts.pin_cache_ignore_user_consent);
	}
	sc_log(ctx, "PKCS#15 options: use_file_cache=%d use_pin_cache=%d pin_cache_counter=%d pin_cache_ignore_user_consent=%d",
			p15card->opts.use_file_cache, p15card->opts.use_pin_cache,p15card->opts.pin_cache_counter,
			p15card->opts.pin_cache_ignore_user_consent);

	r = sc_lock(card);
	if (r) {
		sc_log(ctx, "sc_lock() failed: %s", sc_strerror(r));
		sc_pkcs15_card_free(p15card);
		LOG_FUNC_RETURN(ctx, r);
	}

	enable_emu = scconf_get_bool(conf_block, "enable_pkcs15_emulation", 1);
	if (enable_emu) {
		sc_log(ctx, "PKCS#15 emulation enabled");
		emu_first = scconf_get_bool(conf_block, "try_emulation_first", 0);
		if (emu_first || sc_pkcs15_is_emulation_only(card)) {
			r = sc_pkcs15_bind_synthetic(p15card, aid);
			if (r == SC_SUCCESS)
				goto done;
			r = sc_pkcs15_bind_internal(p15card, aid);
			if (r < 0)
				goto error;
		} else {
			r = sc_pkcs15_bind_internal(p15card, aid);
			if (r == SC_SUCCESS)
				goto done;
			r = sc_pkcs15_bind_synthetic(p15card, aid);
			if (r < 0)
				goto error;
		}
	}
	else {
		r = sc_pkcs15_bind_internal(p15card, aid);
		if (r < 0)
			goto error;
	}
done:
	*p15card_out = p15card;
	sc_unlock(card);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
error:
	sc_unlock(card);
	sc_pkcs15_card_free(p15card);
	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15_unbind(struct sc_pkcs15_card *p15card)
{
	if (p15card == NULL || p15card->magic != SC_PKCS15_CARD_MAGIC) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	LOG_FUNC_CALLED(p15card->card->ctx);
	if (p15card->dll_handle)
		sc_dlclose(p15card->dll_handle);
	sc_pkcs15_pincache_clear(p15card);
	sc_pkcs15_card_free(p15card);
	return 0;
}


static int
__sc_pkcs15_search_objects(struct sc_pkcs15_card *p15card, unsigned int class_mask, unsigned int type,
			int (*func)(sc_pkcs15_object_t *, void *), void *func_arg,
			sc_pkcs15_object_t **ret, size_t ret_size)
{
	struct sc_pkcs15_object *obj = NULL;
	struct sc_pkcs15_df	*df = NULL;
	unsigned int	df_mask = 0;
	size_t		match_count = 0;
	int r;

	if (type)
		class_mask |= SC_PKCS15_TYPE_TO_CLASS(type);

	/* Make sure the class mask we have makes sense */
	if (class_mask == 0
	 || (class_mask & ~(SC_PKCS15_SEARCH_CLASS_PRKEY |
			    SC_PKCS15_SEARCH_CLASS_PUBKEY |
			    SC_PKCS15_SEARCH_CLASS_SKEY |
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
	if (class_mask & SC_PKCS15_SEARCH_CLASS_SKEY)
		df_mask |= (1 << SC_PKCS15_SKDF);

	/* Make sure all the DFs we want to search have been
	 * enumerated. */
	for (df = p15card->df_list; df != NULL; df = df->next) {
		if (!(df_mask & (1 << df->type)))   {
			continue;
		}
		if (df->enumerated)
			continue;
		/* Enumerate the DF's, so p15card->obj_list is populated. */
		if (p15card->ops.parse_df)
			r = p15card->ops.parse_df(p15card, df);
		else
			r = sc_pkcs15_parse_df(p15card, df);
		if (r != SC_SUCCESS)
			continue;
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


int
sc_pkcs15_get_objects(struct sc_pkcs15_card *p15card, unsigned int type,
		struct sc_pkcs15_object **ret, size_t ret_size)
{
	return sc_pkcs15_get_objects_cond(p15card, type, NULL, NULL, ret, ret_size);
}


static int
compare_obj_id(struct sc_pkcs15_object *obj, const struct sc_pkcs15_id *id)
{
	void *data = obj->data;

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_CERT:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_cert_info *) data)->id, id);
	case SC_PKCS15_TYPE_PRKEY:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_prkey_info *) data)->id, id);
	case SC_PKCS15_TYPE_PUBKEY:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_pubkey_info *) data)->id, id);
	case SC_PKCS15_TYPE_SKEY:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_skey_info *) data)->id, id);
	case SC_PKCS15_TYPE_AUTH:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_auth_info *) data)->auth_id, id);
	case SC_PKCS15_TYPE_DATA_OBJECT:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_data_info *) data)->id, id);
	}
	return 0;
}


static int
sc_obj_app_oid(struct sc_pkcs15_object *obj, const struct sc_object_id *app_oid)
{
	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_DATA_OBJECT)
		return sc_compare_oid(&((struct sc_pkcs15_data_info *) obj->data)->app_oid, app_oid);
	return 0;
}


static int
compare_obj_usage(struct sc_pkcs15_object *obj, unsigned int mask, unsigned int value)
{
	void		*data = obj->data;
	unsigned int	usage;

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		usage = ((struct sc_pkcs15_prkey_info *) data)->usage;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		usage = ((struct sc_pkcs15_pubkey_info *) data)->usage;
		break;
	default:
		return 0;
	}
	return (usage & mask & value) != 0;
}


static int
compare_obj_flags(struct sc_pkcs15_object *obj, unsigned int mask, unsigned int value)
{
	struct sc_pkcs15_auth_info *auth_info;
	unsigned int	flags;

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
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


static int
compare_obj_reference(struct sc_pkcs15_object *obj, int value)
{
	struct sc_pkcs15_auth_info *auth_info;
	void		*data = obj->data;
	int		reference;

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		auth_info = (struct sc_pkcs15_auth_info *) obj->data;
		if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			return 0;
		reference = auth_info->attrs.pin.reference;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		reference = ((struct sc_pkcs15_prkey_info *) data)->key_reference;
		break;
	default:
		return 0;
	}
	return reference == value;
}


static int
compare_obj_path(struct sc_pkcs15_object *obj, const struct sc_path *path)
{
	void *data = obj->data;

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		return sc_compare_path(&((struct sc_pkcs15_prkey_info *) data)->path, path);
	case SC_PKCS15_TYPE_PUBKEY:
		return sc_compare_path(&((struct sc_pkcs15_pubkey_info *) data)->path, path);
	case SC_PKCS15_TYPE_SKEY:
		return sc_compare_path(&((struct sc_pkcs15_skey_info *) data)->path, path);
	case SC_PKCS15_TYPE_CERT:
		return sc_compare_path(&((struct sc_pkcs15_cert_info *) data)->path, path);
	case SC_PKCS15_TYPE_AUTH:
		return sc_compare_path(&((struct sc_pkcs15_auth_info *) data)->path, path);
	case SC_PKCS15_TYPE_DATA_OBJECT:
		return sc_compare_path(&((struct sc_pkcs15_data_info *) data)->path, path);
	}
	return 0;
}


static int
compare_obj_data_name(struct sc_pkcs15_object *obj, const char *app_label, const char *label)
{
	struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) obj->data;

	if (obj->type != SC_PKCS15_TYPE_DATA_OBJECT)
		return 0;

	return !strncmp(cinfo->app_label, app_label, sizeof cinfo->app_label) &&
		!strncmp(obj->label, label, sizeof obj->label);
}


static int
compare_obj_key(struct sc_pkcs15_object *obj, void *arg)
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


static int
find_by_key(struct sc_pkcs15_card *p15card, unsigned int type, struct sc_pkcs15_search_key *sk,
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
sc_pkcs15_search_objects(struct sc_pkcs15_card *p15card, struct sc_pkcs15_search_key *sk,
			struct sc_pkcs15_object **ret, size_t ret_size)
{
	return __sc_pkcs15_search_objects(p15card,
			sk->class_mask, sk->type,
			compare_obj_key, sk,
			ret, ret_size);
}


int
sc_pkcs15_get_objects_cond(struct sc_pkcs15_card *p15card, unsigned int type,
		int (* func)(struct sc_pkcs15_object *, void *),
		void *func_arg, struct sc_pkcs15_object **ret, size_t ret_size)
{
	return __sc_pkcs15_search_objects(p15card, 0, type,
			func, func_arg, ret, ret_size);
}


int sc_pkcs15_find_object_by_id(struct sc_pkcs15_card *p15card,
				unsigned int type, const struct sc_pkcs15_id *id,
				struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;
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


int
sc_pkcs15_find_cert_by_id(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_CERT, id, out);
}


int
sc_pkcs15_find_prkey_by_id(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PRKEY, id, out);
}


int
sc_pkcs15_find_pubkey_by_id(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PUBKEY, id, out);
}


int
sc_pkcs15_find_skey_by_id(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_SKEY, id, out);
}


int
sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_AUTH, id, out);
}


int
sc_pkcs15_find_pin_by_reference(struct sc_pkcs15_card *p15card, const sc_path_t *path, int reference,
		struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.match_reference = 1;
	sk.reference = reference;
	sk.path = path;

	return find_by_key(p15card, SC_PKCS15_TYPE_AUTH_PIN, &sk, out);
}


int
sc_pkcs15_find_pin_by_type_and_reference(struct sc_pkcs15_card *p15card, const struct sc_path *path,
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


int
sc_pkcs15_find_so_pin(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.flags_mask = sk.flags_value = SC_PKCS15_PIN_FLAG_SO_PIN;

	return find_by_key(p15card, SC_PKCS15_TYPE_AUTH_PIN, &sk, out);
}


int
sc_pkcs15_find_pin_by_flags(struct sc_pkcs15_card *p15card,
		unsigned flags, unsigned mask, int *index,
		struct sc_pkcs15_object **out)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *auths[SC_PKCS15_MAX_PINS];
	int r, i, num, idx = 0;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Find PIN flags:0x%X, mask:0x%X, index:%i", flags, mask, index ? *index : -1);
	if (index)
		idx = *index;
	/* Get authentication PKCS#15 objects that are present in the given application */
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, auths, SC_PKCS15_MAX_PINS);
	if (r < 0)
		return r;
	num = r;

	for (i=idx; i<num; i++)   {
		struct sc_pkcs15_auth_info *pin_info = (struct sc_pkcs15_auth_info *)(*(auths + i))->data;

		if (!pin_info || pin_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			continue;

		if ((pin_info->attrs.pin.flags & mask) != flags)
			continue;

		if (out)
			*out = *(auths + i);
		if (index)
			*index = i;

		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);
}


int
sc_pkcs15_find_data_object_by_id(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		struct sc_pkcs15_object **out)
{
	return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_DATA_OBJECT, id, out);
}


int
sc_pkcs15_find_data_object_by_app_oid(struct sc_pkcs15_card *p15card, const struct sc_object_id *app_oid,
		struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;
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


int
sc_pkcs15_find_data_object_by_name(struct sc_pkcs15_card *p15card, const char *app_label, const char *label,
		struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;
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


int
sc_pkcs15_find_prkey_by_id_usage(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		unsigned int usage, struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.usage_mask = sk.usage_value = usage;
	sk.id = id;

	return find_by_key(p15card, SC_PKCS15_TYPE_PRKEY, &sk, out);
}


int
sc_pkcs15_find_prkey_by_reference(struct sc_pkcs15_card *p15card, const struct sc_path *path,
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


int
sc_pkcs15_add_object(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_object *p = p15card->obj_list;

	if (!obj)
		return 0;
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


void
sc_pkcs15_remove_object(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj)
{
	if (!obj)
		return;
	else if (obj->prev == NULL)
		p15card->obj_list = obj->next;
	else
		obj->prev->next = obj->next;
	if (obj->next != NULL)
		obj->next->prev = obj->prev;
}


static void
sc_pkcs15_remove_objects(struct sc_pkcs15_card *p15card)
{
	struct sc_pkcs15_object *cur = NULL, *next = NULL;

	if (!p15card || !p15card->obj_list)
		return;
	for (cur = p15card->obj_list; cur; cur = next)   {
		next = cur->next;
		sc_pkcs15_free_object(cur);
	}

	p15card->obj_list = NULL;
}


void
sc_pkcs15_free_object(struct sc_pkcs15_object *obj)
{
	if (!obj)
		return;
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


int
sc_pkcs15_add_df(struct sc_pkcs15_card *p15card, unsigned int type, const sc_path_t *path)
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


static void
sc_pkcs15_remove_dfs(struct sc_pkcs15_card *p15card)
{
	struct sc_pkcs15_df *cur = NULL, *next = NULL;

	if (!p15card || !p15card->df_list)
		return;

	for (cur = p15card->df_list; cur; cur = next)   {
		next = cur->next;
		free(cur);
	}

	p15card->df_list = NULL;
}


int
sc_pkcs15_encode_df(struct sc_context *ctx, struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df,
		unsigned char **buf_out, size_t *bufsize_out)
{
	unsigned char *buf = NULL, *tmp = NULL, *p;
	size_t bufsize = 0, tmpsize;
	const struct sc_pkcs15_object *obj;
	int (* func)(struct sc_context *, const struct sc_pkcs15_object *nobj,
		     unsigned char **nbuf, size_t *nbufsize) = NULL;
	int r;

	if (p15card == NULL || p15card->magic != SC_PKCS15_CARD_MAGIC) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_encode_prkdf_entry;
		break;
	case SC_PKCS15_PUKDF:
	case SC_PKCS15_PUKDF_TRUSTED:
		func = sc_pkcs15_encode_pukdf_entry;
		break;
	case SC_PKCS15_SKDF:
		func = sc_pkcs15_encode_skdf_entry;
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
		if (!tmpsize)
			continue;
		p = (u8 *) realloc(buf, bufsize + tmpsize);
		if (!p) {
			free(tmp);
			free(buf);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		buf = p;
		memcpy(buf + bufsize, tmp, tmpsize);
		free(tmp);
		bufsize += tmpsize;
	}
	*buf_out = buf;
	*bufsize_out = bufsize;

	return 0;
}


int
sc_pkcs15_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char *buf;
	const unsigned char *p;
	size_t bufsize;
	int r;
	struct sc_pkcs15_object *obj = NULL;
	int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
		     const u8 **nbuf, size_t *nbufsize) = NULL;

	sc_log(ctx, "called; path=%s, type=%d, enum=%d", sc_print_path(&df->path), df->type, df->enumerated);

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_decode_prkdf_entry;
		break;
	case SC_PKCS15_PUKDF:
		func = sc_pkcs15_decode_pukdf_entry;
		break;
	case SC_PKCS15_SKDF:
		func = sc_pkcs15_decode_skdf_entry;
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
	while (bufsize && *p != 0x00) {

		obj = calloc(1, sizeof(struct sc_pkcs15_object));
		if (obj == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto ret;
		}
		r = func(p15card, obj, &p, &bufsize);
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


int
sc_pkcs15_add_unusedspace(struct sc_pkcs15_card *p15card, const struct sc_path *path,
		const struct sc_pkcs15_id *auth_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_unusedspace *p = p15card->unusedspace_list, *new_unusedspace;

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


void
sc_pkcs15_remove_unusedspace(struct sc_pkcs15_card *p15card, struct sc_pkcs15_unusedspace *unusedspace)
{
	if (!unusedspace)
		return;

	if (!unusedspace->prev)
		p15card->unusedspace_list = unusedspace->next;
	else
		unusedspace->prev->next = unusedspace->next;

	if (unusedspace->next)
		unusedspace->next->prev = unusedspace->prev;

	free(unusedspace);
}


static void
sc_pkcs15_free_unusedspace(struct sc_pkcs15_card *p15card)
{
	struct sc_pkcs15_unusedspace *cur = NULL, *next = NULL;

	if (!p15card || !p15card->unusedspace_list)
		return;
	for (cur = p15card->unusedspace_list; cur; cur = next)   {
		next = cur->next;
		free(cur);
	}

	p15card->unusedspace_list = NULL;
}


int
sc_pkcs15_encode_unusedspace(struct sc_context *ctx, struct sc_pkcs15_card *p15card,
			 unsigned char **buf, size_t *buflen)
{
	struct sc_path dummy_path;
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
	struct sc_pkcs15_unusedspace *unusedspace = NULL;

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
		sc_format_asn1_entry(asn1_values + 3*c+1, &unusedspace->auth_id, NULL,
			   unusedspace->auth_id.len > 0 ? 1 : 0);
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


int
sc_pkcs15_parse_unusedspace(const unsigned char *buf, size_t buflen, struct sc_pkcs15_card *p15card)
{
	const unsigned char *p = buf;
	size_t left = buflen;
	int r;
	struct sc_path path, dummy_path;
	struct sc_pkcs15_id auth_id;
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
	sc_pkcs15_free_unusedspace(p15card);

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


int
sc_pkcs15_read_file(struct sc_pkcs15_card *p15card, const struct sc_path *in_path,
		unsigned char **buf, size_t *buflen)
{
	struct sc_context *ctx;
	struct sc_file *file = NULL;
	unsigned char *data = NULL;
	size_t	len = 0, offset = 0;
	int	r;

	if (p15card == NULL || p15card->card == NULL || in_path == NULL || buf == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "path=%s, index=%u, count=%d", sc_print_path(in_path), in_path->index, in_path->count);

	r = -1; /* file state: not in cache */
	if (p15card->opts.use_file_cache) {
		r = sc_pkcs15_read_cached_file(p15card, in_path, &data, &len);

		if (!r && in_path->aid.len > 0 && in_path->len >= 2)   {
			struct sc_path parent = *in_path;

			parent.len -= 2;
			parent.type = SC_PATH_TYPE_PATH;
			r = sc_select_file(p15card->card, &parent, NULL);
		}
	}

	if (r) {
		r = sc_lock(p15card->card);
		if (r)
			goto fail;
		r = sc_select_file(p15card->card, in_path, &file);
		if (r)
			goto fail_unlock;

		/* Handle the case where the ASN.1 Path object specified
		 * index and length values */
		if (in_path->count < 0) {
			if (file->size)
				len = file->size;
			else
				len = 1024;
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
			unsigned char *head = data;

			for (i=1;  ; i++) {
				l = len - (head - data);
				if (l > 256) { l = 256; }
				r = sc_read_record(p15card->card, i, head, l, SC_RECORD_BY_REC_NR);
				if (r == SC_ERROR_RECORD_NOT_FOUND)
					break;
				if (r < 0) {
					goto fail_unlock;
				}
				if (r < 2)
					break;
				record_len = head[1];
				if (record_len != 0xff) {
					memmove(head,head+2,r-2);
					head += (r-2);
				}
				else {
					if (r < 4)
						break;
					memmove(head,head+4,r-4);
					head += (r-4);
				}
			}
			len = head-data;
		}
		else {
			r = sc_read_binary(p15card->card, offset, data, len, 0);
			if (r < 0) {
				goto fail_unlock;
			}
			/* sc_read_binary may return less than requested */
			len = r;
		}
		sc_unlock(p15card->card);

		sc_file_free(file);

		if (len && p15card->opts.use_file_cache) {
			sc_pkcs15_cache_file(p15card, in_path, data, len);
		}
	}
	*buf = data;
	*buflen = len;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);

fail_unlock:
	sc_unlock(p15card->card);
fail:
	free(data);
	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15_compare_id(const struct sc_pkcs15_id *id1, const struct sc_pkcs15_id *id2)
{
	if (id1 == NULL || id2 == NULL)
		return 0;
	if (id1->len != id2->len)
		return 0;
	return memcmp(id1->value, id2->value, id1->len) == 0;
}


void
sc_pkcs15_format_id(const char *str, struct sc_pkcs15_id *id)
{
	size_t len;

	if (!id)
		return;
	len = sizeof(id->value);

	if (sc_hex_to_bin(str, id->value, &len) != SC_SUCCESS)
		id->len = 0;
	else
		id->len = len;
}


const char *
sc_pkcs15_print_id(const struct sc_pkcs15_id *id)
{
	static char buffer[256];

	sc_bin_to_hex(id->value, id->len, buffer, sizeof(buffer), '\0');
	return buffer;
}


int
sc_pkcs15_hex_string_to_id(const char *in, struct sc_pkcs15_id *out)
{
	out->len = sizeof(out->value);
	return sc_hex_to_bin(in, out->value, &out->len);
}


int
sc_pkcs15_make_absolute_path(const struct sc_path *parent, struct sc_path *child)
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
		if (SC_PKCS15_TYPE_AUTH & obj->type
			|| SC_PKCS15_TYPE_SKEY & obj->type
			|| SC_PKCS15_TYPE_PRKEY & obj->type) {
			/* clean everything that potentially contains a secret */
			sc_mem_clear(obj->content.value, obj->content.len);
			sc_mem_secure_free(obj->content.value, obj->content.len);
		} else {
			free(obj->content.value);
		}
	}
	obj->content.value = NULL;
	obj->content.len = 0;
}


int
sc_pkcs15_allocate_object_content(struct sc_context *ctx, struct sc_pkcs15_object *obj,
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
	if (SC_PKCS15_TYPE_AUTH & obj->type
			|| SC_PKCS15_TYPE_SKEY & obj->type
			|| SC_PKCS15_TYPE_PRKEY & obj->type) {
		tmp_buf = sc_mem_secure_alloc(len);
	} else {
		tmp_buf = malloc(len);
	}
	if (!tmp_buf)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(tmp_buf, value, len);

	sc_pkcs15_free_object_content(obj);

	obj->content.value = tmp_buf;
	obj->content.len = len;

	return SC_SUCCESS;
}


struct sc_supported_algo_info *
sc_pkcs15_get_supported_algo(struct sc_pkcs15_card *p15card, unsigned operation, unsigned mechanism)
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

struct sc_supported_algo_info *
sc_pkcs15_get_specific_supported_algo(struct sc_pkcs15_card *p15card, unsigned operation, unsigned mechanism, const struct sc_object_id *algo_oid)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_supported_algo_info *info = NULL;
	int ii;

	if (algo_oid == NULL)
		return NULL;

	for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS && p15card->tokeninfo->supported_algos[ii].reference; ii++)
		if ((p15card->tokeninfo->supported_algos[ii].operations & operation)
				&& (p15card->tokeninfo->supported_algos[ii].mechanism == mechanism)
				&& sc_compare_oid(algo_oid, &p15card->tokeninfo->supported_algos[ii].algo_id) == 1)
			break;

	if (ii < SC_MAX_SUPPORTED_ALGORITHMS && p15card->tokeninfo->supported_algos[ii].reference)   {
		info = &p15card->tokeninfo->supported_algos[ii];
		sc_log(ctx, "found supported algorithm (ref:%X,mech:%X,ops:%X,algo_ref:%X)",
				info->reference, info->mechanism, info->operations, info->algo_ref);
	}

	return info;
}

int
sc_pkcs15_get_generalized_time(struct sc_context *ctx, char **out)
{
#ifdef HAVE_GETTIMEOFDAY
	struct timeval tv;
#endif
	struct tm tm;
	time_t t;

	if (!ctx || !out)
		return SC_ERROR_INVALID_ARGUMENTS;
	*out = NULL;

#ifdef HAVE_GETTIMEOFDAY
	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
#else
	t = time(NULL);
#endif

#ifdef _WIN32
	if (0 != gmtime_s(&tm, &t))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
#else
	if (NULL == gmtime_r(&t, &tm))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
#endif

	*out = calloc(1, 16);
	if (*out == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "memory failure");

	/* print time in generalized time format */
	if (!strftime(*out, 16, "%Y%m%d%H%M%SZ", &tm)) {
		free(*out);
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "strftime failed");
	}

	return SC_SUCCESS;
}


int
sc_pkcs15_add_supported_algo_ref(struct sc_pkcs15_object *obj, struct sc_supported_algo_info *algo)
{
	unsigned int ii, *algo_refs = NULL;

	if (!algo)
		return SC_SUCCESS;

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		algo_refs = ((struct sc_pkcs15_prkey_info *)obj->data)->algo_refs;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		algo_refs = ((struct sc_pkcs15_pubkey_info *)obj->data)->algo_refs;
		break;
	case SC_PKCS15_TYPE_SKEY:
		algo_refs = ((struct sc_pkcs15_skey_info *)obj->data)->algo_refs;
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

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_CERT:
		*out = ((struct sc_pkcs15_cert_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		*out = ((struct sc_pkcs15_prkey_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		*out = ((struct sc_pkcs15_pubkey_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_SKEY:
		*out = ((struct sc_pkcs15_skey_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_AUTH:
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
int
sc_pkcs15_serialize_guid(unsigned char *in, size_t in_size, unsigned flags,
		char *out, size_t out_size)
{
	int ii, jj, offs = 0;

	if (in_size < 16)
		return SC_ERROR_BUFFER_TOO_SMALL;
	if (out_size < 39)
		return SC_ERROR_BUFFER_TOO_SMALL;

	*out = '\0';
	if (!flags)
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
	if (!flags)
		strcat(out, "}");

	return SC_SUCCESS;
}


int
sc_pkcs15_get_object_guid(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_object *obj,
		unsigned flags, unsigned char *out, size_t *out_size)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_serial_number serialnr;
	struct sc_pkcs15_id  id;
	unsigned char guid_bin[SC_PKCS15_MAX_ID_SIZE + SC_MAX_SERIALNR];
	int rv, guid_bin_size;

	LOG_FUNC_CALLED(ctx);
	if(!out || !out_size)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (p15card->ops.get_guid)   {
		rv = p15card->ops.get_guid(p15card, obj, out, out_size);
		LOG_FUNC_RETURN(ctx, rv);
	}

	rv = sc_pkcs15_aux_get_md_guid(p15card, obj, flags, out, out_size);
	if (rv == SC_SUCCESS)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	else if (rv != SC_ERROR_NOT_SUPPORTED)
		LOG_TEST_RET(ctx, rv, "Failed to get alternative object GUID");

	memset(out, 0, *out_size);

	rv = sc_pkcs15_get_object_id(obj, &id);
	LOG_TEST_RET(ctx, rv, "Cannot get object's ID");

	if (p15card->tokeninfo && p15card->tokeninfo->serial_number)   {
		/* The serial from EF(TokenInfo) is preferred because of the
		 * "--serial" parameter of pkcs15-init. */
		serialnr.len = SC_MAX_SERIALNR;
		rv = sc_hex_to_bin(p15card->tokeninfo->serial_number, serialnr.value, &serialnr.len);
		if (rv) {
			/* Fallback in case hex_to_bin fails due to unexpected characters */
			serialnr.len = strlen(p15card->tokeninfo->serial_number);
			if (serialnr.len > SC_MAX_SERIALNR)
				serialnr.len = SC_MAX_SERIALNR;

			memcpy(serialnr.value, p15card->tokeninfo->serial_number, serialnr.len);
		}
	} else if (p15card->card->serialnr.len)   {
		serialnr = p15card->card->serialnr;
	} else   {
		rv = sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &serialnr);
		LOG_TEST_RET(ctx, rv, "'GET_SERIALNR' CTL failed and other serial numbers not present");
	}

	memset(guid_bin, 0, sizeof(guid_bin));
	memcpy(guid_bin, id.value, id.len);
	memcpy(guid_bin + id.len, serialnr.value, serialnr.len);
	guid_bin_size = id.len + serialnr.len;

	/*
	 * If OpenSSL is available (SHA1), then rather use the hash of the data
	 * - this also protects against data being too short
	 */
#ifdef ENABLE_OPENSSL
	SHA1(guid_bin, guid_bin_size, guid_bin);
	guid_bin_size = SHA_DIGEST_LENGTH;
#else
	/* If guid_bin has a size larger than 16 bytes
	 * force the remaining bytes up to 16 bytes to be zero
	 * so sc_pkcs15_serialize_guid won't fail because the size is less than 16
	 */
	if (guid_bin_size < 16)
		guid_bin_size = 16;
#endif

	rv = sc_pkcs15_serialize_guid(guid_bin, guid_bin_size, flags, (char *)out, *out_size);
	LOG_TEST_RET(ctx, rv, "Serialize GUID error");

	*out_size = strlen((char *)out);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_pkcs15_aux_get_md_guid(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_object *obj,
		unsigned flags,
		unsigned char *out, size_t *out_size)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if(!out || !out_size)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_PRKEY)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	prkey_info = (struct sc_pkcs15_prkey_info *)obj->data;
	if (!prkey_info->aux_data || prkey_info->aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	rv = sc_aux_data_get_md_guid(ctx, prkey_info->aux_data, flags, out, out_size);
	LOG_FUNC_RETURN(ctx, rv);
}


void
sc_pkcs15_free_key_params(struct sc_pkcs15_key_params *params)
{
	if (!params)
		return;
	if (params->data && params->free_params)
		params->free_params(params->data);
	else if (params->data)
		free(params->data);

	params->data = NULL;
}

