/*
 * sc-pkcs15-prkey.c: PKCS#15 private key functions
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

#include "opensc.h"
#include "opensc-pkcs15.h"
#include "sc-asn1.h"
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

static int parse_rsa_prkey_info(struct sc_context *ctx,
				struct sc_pkcs15_prkey_info *prkey,
				const u8 **buf, int *buflen)
{
	int r;
	int usage_len = sizeof(prkey->usage);
	int af_len = sizeof(prkey->access_flags);
	struct sc_asn1_struct asn1_com_key_attr[] = {
		{ "iD",		 SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, &prkey->id, NULL },
		{ "usage",	 SC_ASN1_BIT_STRING, ASN1_BIT_STRING, 0, &prkey->usage, &usage_len },
		{ "native",	 SC_ASN1_BOOLEAN, ASN1_BOOLEAN, SC_ASN1_OPTIONAL, &prkey->native },
		{ "accessFlags", SC_ASN1_BIT_STRING, ASN1_BIT_STRING, SC_ASN1_OPTIONAL, &prkey->access_flags, &af_len },
		{ "keyReference",SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, &prkey->key_reference },
		{ NULL }
	};
	struct sc_asn1_struct asn1_com_prkey_attr[] = {
		{ NULL }
	};
	struct sc_asn1_struct asn1_rsakey_attr[] = {
		{ "value",	   SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, 0, &prkey->file_id },
		{ "modulusLength", SC_ASN1_INTEGER, ASN1_INTEGER, 0, &prkey->modulus_length },
		{ "keyInfo",	   SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL },
		{ NULL }
	};
	struct sc_asn1_struct asn1_type_attr[] = {
		{ "publicRSAKeyAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, asn1_rsakey_attr },
		{ NULL }
	};

	struct sc_pkcs15_object prkey_obj = { &prkey->com_attr, asn1_com_key_attr,
					      asn1_com_prkey_attr, asn1_type_attr };
	struct sc_asn1_struct asn1_prkey[] = {
		{ "privateRSAKey", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, &prkey_obj },
		{ NULL }
	};		

	prkey->key_reference = -1;
	prkey->native = 1;

	r = sc_asn1_parse(ctx, asn1_prkey, *buf, *buflen, buf, buflen);

	return r;
}

static int get_prkeys_from_file(struct sc_pkcs15_card *card,
				struct sc_file *file)
{
	int r, bytes_left;
	u8 buf[2048];
	const u8 *p = buf;

	r = sc_select_file(card->card, &file->path, file);
	if (r)
		return r;
	if (file->size > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = sc_read_binary(card->card, 0, buf, file->size);
	if (r < 0)
		return r;
	bytes_left = r;
	do {
		struct sc_pkcs15_prkey_info tmp;

		r = parse_rsa_prkey_info(card->card->ctx,
					 &tmp, &p, &bytes_left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r)
			return r;
		if (card->prkey_count >= SC_PKCS15_MAX_PRKEYS)
			return SC_ERROR_TOO_MANY_OBJECTS;
		card->prkey_info[card->prkey_count] = tmp;
		card->prkey_count++;
	} while (bytes_left);

	return 0;
}


int sc_pkcs15_enum_private_keys(struct sc_pkcs15_card *card)
{
	int r, i;
	assert(card != NULL);

	if (card->prkey_count)
		return card->prkey_count;	/* already enumerated */
	for (i = 0; i < 1; i++) {
		r = get_prkeys_from_file(card, &card->file_prkdf);
		if (r != 0)
			return r;
	}
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
