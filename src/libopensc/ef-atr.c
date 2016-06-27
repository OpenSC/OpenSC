/*
 * ef-atr.c: Stuff for handling EF(ATR)
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "iso7816.h"

static int
sc_parse_ef_atr_content(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	const unsigned char *tag = NULL;
	size_t taglen;
	struct sc_ef_atr ef_atr;

	LOG_FUNC_CALLED(ctx);

	memset(&ef_atr, 0, sizeof(struct sc_ef_atr));

	tag = sc_asn1_find_tag(ctx, buf, buflen, ISO7816_TAG_II_CARD_SERVICE, &taglen);
	if (tag && taglen >= 1)   {
		ef_atr.card_service = *tag;
		sc_log(ctx, "EF.ATR: card service 0x%X", ef_atr.card_service);
	}

	tag = sc_asn1_find_tag(ctx, buf, buflen, ISO7816_TAG_II_PRE_ISSUING, &taglen);
	if (tag) {
		size_t len = taglen > sizeof(ef_atr.pre_issuing) ? sizeof(ef_atr.pre_issuing) : taglen;

		memcpy(ef_atr.pre_issuing, tag, len);
		ef_atr.pre_issuing_len = len;

		sc_log(ctx, "EF.ATR: Pre-Issuing data '%s'", sc_dump_hex(ef_atr.pre_issuing, ef_atr.pre_issuing_len));
	}

	tag = sc_asn1_find_tag(ctx, buf, buflen, ISO7816_TAG_II_CARD_CAPABILITIES, &taglen);
	if (tag && taglen >= 3) {
		ef_atr.df_selection =  *(tag + 0);
		ef_atr.unit_size = *(tag + 1);
		ef_atr.card_capabilities = *(tag + 2);
		sc_log(ctx, "EF.ATR: DF selection %X, unit_size %X, card caps %X", 
				ef_atr.df_selection, ef_atr.unit_size, ef_atr.card_capabilities);
	}

	if (ef_atr.card_capabilities & ISO7816_CAP_EXTENDED_LENGTH_INFO) {
		/* Extended Length Information in EF.ATR/INFO */
		tag = sc_asn1_find_tag(ctx, buf, buflen, ISO7816_TAG_II_EXTENDED_LENGTH, &taglen);
		if (tag && taglen >= 8) {
			/* The command- and response-APDU size limitations are defined by
			 * two integers, each nested in a DO'02'.
			 * We skip parsing the nested DOs and jump directly to the numbers */
			ef_atr.max_command_apdu = bebytes2ushort(tag + 2);
			ef_atr.max_response_apdu = bebytes2ushort(tag + 6);
			sc_log(ctx, "EF.ATR: Biggest command APDU %u bytes, response APDU %u", 
					(unsigned long) ef_atr.max_command_apdu,
					(unsigned long) ef_atr.max_response_apdu);
		}
	}

	tag = sc_asn1_find_tag(ctx, buf, buflen, ISO7816_TAG_II_AID, &taglen);
	if (tag) {
		if (taglen > sizeof(ef_atr.aid.value))
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid MF AID size");
		memcpy(ef_atr.aid.value, tag, taglen);
		ef_atr.aid.len = taglen;
		sc_log(ctx, "EF.ATR: AID '%s'", sc_dump_hex(ef_atr.aid.value, ef_atr.aid.len));
	}

	/* IAS/ECC specific issuer data: contains the max send/recv buffer sizes in plain and SM modes */
	tag = sc_asn1_find_tag(ctx, buf, buflen, IASECC_TAG_II_IO_BUFFER_SIZES, &taglen);
	if (tag) {
		size_t len = taglen > sizeof(ef_atr.issuer_data) ? sizeof(ef_atr.issuer_data) : taglen;

		memcpy(ef_atr.issuer_data, tag, len);
		ef_atr.issuer_data_len = len;

		sc_log(ctx, "EF.ATR: Issuer data '%s'", sc_dump_hex(ef_atr.issuer_data, ef_atr.issuer_data_len));
	}

	tag = sc_asn1_find_tag(ctx, buf, buflen, ISO7816_TAG_II_ALLOCATION_SCHEME, &taglen);
	if (tag)   {
		sc_log(ctx, "EF.ATR: DER encoded OID %s", sc_dump_hex(tag, taglen));
		tag = sc_asn1_find_tag(ctx, tag, taglen, SC_ASN1_TAG_OBJECT, &taglen);
		if (tag)   {
			sc_log(ctx, "EF.ATR: OID %s", sc_dump_hex(tag, taglen));
			if(sc_asn1_decode_object_id(tag, taglen, &ef_atr.allocation_oid))
				LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ASN1_OBJECT);
		}
	}

	tag = sc_asn1_find_tag(ctx, buf, buflen, ISO7816_TAG_II_STATUS_SW, &taglen);
	if (tag && taglen == 2)   {
		ef_atr.status = *(tag + 0) * 0x100 + *(tag + 1);
		sc_log(ctx, "EF.ATR: status word 0x%X", ef_atr.status);
	}

	if (!card->ef_atr)
		card->ef_atr = calloc(1, sizeof(struct sc_ef_atr));

	if (!card->ef_atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(card->ef_atr, &ef_atr, sizeof(struct sc_ef_atr));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int sc_parse_ef_atr(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	struct sc_file *file;
	int rv;
	unsigned char *buf = NULL;
	size_t size;

	LOG_FUNC_CALLED(ctx);

	sc_format_path("3F002F01", &path);
	rv = sc_select_file(card, &path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select EF(ATR) file");

	if (file->size) {
		size = file->size;
	} else {
		size = 1024;
	}
	buf = malloc(size);
	if (!buf)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Memory allocation error");
	rv = sc_read_binary(card, 0, buf, size, 0);
	LOG_TEST_RET(ctx, rv, "Cannot read EF(ATR) file");
	
	rv = sc_parse_ef_atr_content(card, buf, rv);
	LOG_TEST_RET(ctx, rv, "EF(ATR) parse error");

	free(buf);
	sc_file_free(file);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

void sc_free_ef_atr(sc_card_t *card)
{
	if (card->ef_atr)
		free(card->ef_atr);
	card->ef_atr = NULL;
}
