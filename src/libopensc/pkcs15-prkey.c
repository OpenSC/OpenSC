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

#include "sc.h"
#include "sc-pkcs15.h"
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
	printf("\tID          : ");
	sc_pkcs15_print_id(&prkey->id);
	printf("\n");
}

static int parse_prkey_info(const u8 * buf,
			    int buflen, struct sc_pkcs15_prkey_info *prkey)
{
	const u8 *tag, *p;
	int taglen, left;

	tag = sc_asn1_skip_tag(&buf, &buflen, 0x30, &taglen);	/* SEQUENCE */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	sc_pkcs15_parse_common_object_attr(&prkey->com_attr, tag, taglen);

	p = sc_asn1_skip_tag(&buf, &buflen, 0x30, &left);	/* SEQUENCE */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;

	tag = sc_asn1_skip_tag(&p, &left, 0x04, &taglen);	/* OCTET STRING */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	memcpy(prkey->id.value, tag, taglen);
	prkey->id.len = taglen;

	tag = sc_asn1_skip_tag(&p, &left, 0x03, &taglen);	/* BIT STRING */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	sc_asn1_decode_bit_string(tag, taglen, &prkey->usage,
				  sizeof(prkey->usage));

	tag = sc_asn1_skip_tag(&p, &left, 0x01, &taglen);	/* BOOLEAN */
	if (tag != NULL) {
		/* FIXME */
	}

	tag = sc_asn1_skip_tag(&p, &left, 0x03, &taglen);	/* BIT STRING */
	if (tag != NULL) {
		sc_asn1_decode_bit_string(tag, taglen,
					  &prkey->access_flags,
					  sizeof(prkey->access_flags));
	} else
		prkey->access_flags = 0;

	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);	/* INTEGER */
	if (tag != NULL && taglen) {
		prkey->key_reference = tag[0];
	} else
		prkey->key_reference = -1;


	/* FIXME */
	p = sc_asn1_find_tag(buf, buflen, 0xA1, &left);
	if (p == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	p = sc_asn1_verify_tag(p, left, 0x30, &left);	/* SEQUENCE 1 */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;

	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);	/* SEQUENCE 2 */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	tag = sc_asn1_verify_tag(tag, taglen, 0x04, &taglen);	/* OCTET STRING */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	memcpy(prkey->file_id.value, tag, taglen);
	prkey->file_id.len = taglen;

	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);	/* INTEGER */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	sc_asn1_decode_integer(tag, taglen, &prkey->modulus_length);

	return 0;
}

int sc_pkcs15_enum_private_keys(struct sc_pkcs15_card *card)
{
	int r, left, taglen;
	const u8 *p, *tag;
	u8 buf[1024];

	assert(card != NULL);

	card->prkey_count = 0;
	r = sc_select_file(card->card, &card->file_prkdf,
			   &card->file_prkdf.path, SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;
	r = sc_read_binary(card->card, 0, buf, card->file_prkdf.size);
	if (r < 0)
		return r;
	left = r;
	p = buf;
	while ((tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen)) != NULL) {
		struct sc_pkcs15_prkey_info *prkey =
		    &card->prkey_info[card->prkey_count];

		if (parse_prkey_info(tag, taglen, prkey))
			break;
		card->prkey_count++;
	}
	return card->prkey_count;
}
