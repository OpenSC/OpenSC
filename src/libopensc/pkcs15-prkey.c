/*
 * pkcs15-prkey.c: PKCS #15 private key functions
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "sc-internal.h"
#include "opensc-pkcs15.h"
#include "sc-asn1.h"
#include "sc-log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

void sc_pkcs15_print_prkey_info(const struct sc_pkcs15_prkey_info *prkey)
{
	int i;
	printf("Private RSA Key [%s]\n", prkey->com_attr.label);
	printf("\tFlags       : %X\n", prkey->com_attr.flags);
	printf("\tUsage       : %X\n", prkey->usage);
	printf("\tAccessFlags : %X\n", prkey->access_flags);
	printf("\tModLength   : %d\n", prkey->modulus_length);
	printf("\tKey ref     : %d\n", prkey->key_reference);
	printf("\tFile ID     : ");
	for (i = 0; i < prkey->file_id.len; i++)
		printf("%02X", prkey->file_id.value[i]);
	printf("\n");
	printf("\tAuth ID     : ");
	sc_pkcs15_print_id(&prkey->com_attr.auth_id);
	printf("\n");
	printf("\tID          : ");
	sc_pkcs15_print_id(&prkey->id);
	printf("\n");
}

static const struct sc_asn1_entry c_asn1_com_key_attr[] = {
	{ "iD",		 SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, NULL },
	{ "usage",	 SC_ASN1_BIT_STRING, ASN1_BIT_STRING, 0, NULL },
	{ "native",	 SC_ASN1_BOOLEAN, ASN1_BOOLEAN, SC_ASN1_OPTIONAL, NULL },
	{ "accessFlags", SC_ASN1_BIT_STRING, ASN1_BIT_STRING, SC_ASN1_OPTIONAL, NULL },
	{ "keyReference",SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_com_prkey_attr[] = {
        /* FIXME */
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_rsakey_attr[] = {
	{ "value",	   SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ "modulusLength", SC_ASN1_INTEGER, ASN1_INTEGER, 0, NULL },
	{ "keyInfo",	   SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_type_attr[] = {
	{ "privateRSAKeyAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_prkey[] = {
	{ "privateRSAKey", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};		

static int parse_rsa_prkey_info(struct sc_context *ctx,
				struct sc_pkcs15_prkey_info *prkey,
				const u8 **buf, size_t *buflen)
{
	int r;
	int usage_len = sizeof(prkey->usage);
	int af_len = sizeof(prkey->access_flags);
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[1];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_type_attr[2];
	struct sc_asn1_entry asn1_prkey[2];

	struct sc_asn1_pkcs15_object prkey_obj = { &prkey->com_attr, asn1_com_key_attr,
						   asn1_com_prkey_attr, asn1_type_attr };

        sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);
        sc_copy_asn1_entry(c_asn1_type_attr, asn1_type_attr);
        sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
        sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
        sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_prkey + 0, &prkey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_type_attr + 0, asn1_rsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, &prkey->file_id, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &prkey->modulus_length, NULL, 0);

	sc_format_asn1_entry(asn1_com_key_attr + 0, &prkey->id, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &prkey->usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &prkey->native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &prkey->access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &prkey->key_reference, NULL, 0);

        /* Fill in defaults */
	prkey->key_reference = -1;
	prkey->native = 1;

	r = sc_asn1_decode(ctx, asn1_prkey, *buf, *buflen, buf, buflen);

	return r;
}

int sc_pkcs15_encode_prkdf_entry(struct sc_context *ctx,
				 const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[1];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_type_attr[2];
	struct sc_asn1_entry asn1_prkey[2];
	struct sc_pkcs15_prkey_info *prkey =
                (struct sc_pkcs15_prkey_info *) obj->data;
	struct sc_asn1_pkcs15_object prkey_obj = { &prkey->com_attr, asn1_com_key_attr,
						   asn1_com_prkey_attr, asn1_type_attr };
	int r;
	int af_len, usage_len;

        sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);
        sc_copy_asn1_entry(c_asn1_type_attr, asn1_type_attr);
        sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
        sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
        sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_prkey + 0, &prkey_obj, NULL, 1);

	sc_format_asn1_entry(asn1_type_attr + 0, asn1_rsakey_attr, NULL, 1);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, &prkey->file_id, NULL, 1);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &prkey->modulus_length, NULL, 1);

	sc_format_asn1_entry(asn1_com_key_attr + 0, &prkey->id, NULL, 1);
	usage_len = sc_count_bit_string_size(&prkey->usage, sizeof(prkey->usage));
	sc_format_asn1_entry(asn1_com_key_attr + 1, &prkey->usage, &usage_len, 1);
	if (prkey->native == 0)
		sc_format_asn1_entry(asn1_com_key_attr + 2, &prkey->native, NULL, 1);
	if (prkey->access_flags) {
		af_len = sc_count_bit_string_size(&prkey->access_flags, sizeof(prkey->access_flags));
		sc_format_asn1_entry(asn1_com_key_attr + 3, &prkey->access_flags, &af_len, 1);
	}
	if (prkey->key_reference >= 0)
		sc_format_asn1_entry(asn1_com_key_attr + 4, &prkey->key_reference, NULL, 1);
	r = sc_asn1_encode(ctx, asn1_prkey, buf, buflen);

	return r;
}


static int get_prkeys_from_file(struct sc_pkcs15_card *p15card,
				struct sc_pkcs15_df *df,
				int file_nr)
{
	int r;
	size_t bytes_left;
	u8 buf[2048];
	const u8 *p = buf;
	struct sc_file *file = df->file[file_nr];

	r = sc_select_file(p15card->card, &file->path, file);
	if (r)
		return r;
	if (file->size > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = sc_read_binary(p15card->card, 0, buf, file->size, 0);
	if (r < 0)
		return r;
	bytes_left = r;
	do {
		struct sc_pkcs15_prkey_info info;

		memset(&info, 0, sizeof(info));
		r = parse_rsa_prkey_info(p15card->card->ctx,
					 &info, &p, &bytes_left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r)
			return r;
		r = sc_pkcs15_add_object(p15card->card->ctx, df, file_nr,
					 SC_PKCS15_TYPE_PRKEY_RSA,
					 &info, sizeof(info));
		if (r)
			return r;
		if (p15card->prkey_count >= SC_PKCS15_MAX_PRKEYS)
			break;
		p15card->prkey_info[p15card->prkey_count] = info;
		p15card->prkey_count++;
	} while (bytes_left);

	return 0;
}


int sc_pkcs15_enum_private_keys(struct sc_pkcs15_card *card)
{
	int r, i, j;
	struct sc_context *ctx = card->card->ctx;
	const int df_types[] = {
		SC_PKCS15_PRKDF
	};
	const int nr_types = sizeof(df_types)/sizeof(df_types[0]);

	assert(card != NULL);
	SC_FUNC_CALLED(ctx, 1);
	if (card->prkey_count)
		return card->prkey_count;	/* already enumerated */
	r = sc_lock(card->card);
	SC_TEST_RET(card->card->ctx, r, "sc_lock() failed");
	for (j = 0; r == 0 && j < nr_types; j++) {
		int type = df_types[j];
		
		for (i = 0; r == 0 && i < card->df[type].count; i++) {
			r = get_prkeys_from_file(card, &card->df[type], i);
			if (r != 0)
                                break;
		}
		if (r != 0)
			break;
	}
	sc_unlock(card->card);
	if (r != 0)
		return r;
	return card->prkey_count;
}

int sc_pkcs15_find_prkey_by_id(struct sc_pkcs15_card *card,
				    const struct sc_pkcs15_id *id,
				    struct sc_pkcs15_prkey_info **key_out)
{
	int r, i;
	
	r = sc_pkcs15_enum_private_keys(card);
	if (r < 0)
		return r;
	for (i = 0; i < card->prkey_count; i++) {
		struct sc_pkcs15_prkey_info *key = &card->prkey_info[i];
		if (sc_pkcs15_compare_id(&key->id, id) == 1) {
			*key_out = key;
			return 0;
		}
	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}
