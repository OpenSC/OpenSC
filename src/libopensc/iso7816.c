/*
 * sc-iso7816-4.c: Functions specified by the ISO 7816-4 standard
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
#include "sc-asn1.h"
#include "sc-log.h"

#include <assert.h>
#include <ctype.h>

static int iso7816_read_binary(struct sc_card *card,
			       unsigned int idx, u8 *buf, size_t count)
{
	struct sc_apdu apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, 2, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, 2, apdu.resplen);
}

static void process_fci(struct sc_context *ctx, struct sc_file *file,
			const u8 *buf, int buflen)
{
	int taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	if (ctx->debug >= 3)
		debug(ctx, "processing FCI bytes\n");
	tag = sc_asn1_find_tag(p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		if (ctx->debug >= 3)
			debug(ctx, "  file identifier: 0x%02X%02X\n", tag[0],
			       tag[1]);
	}
	tag = sc_asn1_find_tag(p, len, 0x81, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		if (ctx->debug >= 3)
			debug(ctx, "  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	tag = sc_asn1_find_tag(p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			if (ctx->debug >= 3)
				debug(ctx, "  shareable: %s\n",
				       (byte & 0x40) ? "yes" : "no");
			file->type = (byte >> 3) & 7;
			file->ef_structure = byte & 0x07;
			if (ctx->debug >= 3) {
				switch ((byte >> 3) & 7) {
				case 0:
					type = "working EF";
					break;
				case 1:
					type = "internal EF";
					break;
				case 7:
					type = "DF";
					break;
				default:
					type = "unknown";
					break;
				}
				debug(ctx, "  type: %s\n", type);
				debug(ctx, "  EF structure: %d\n",
				       byte & 0x07);
			}
		}
	}
	tag = sc_asn1_find_tag(p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char name[17];
		int i;

		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		for (i = 0; i < taglen; i++) {
			if (isalnum(tag[i]) || ispunct(tag[i])
			    || isspace(tag[i]))
				name[i] = tag[i];
			else
				name[i] = '?';
		}
		name[taglen] = 0;
		if (ctx->debug >= 3)
			debug(ctx, "File name: %s\n", name);
	}
	tag = sc_asn1_find_tag(p, len, 0x85, &taglen);
	if (tag != NULL && taglen && taglen <= SC_MAX_PROP_ATTR_SIZE) {
		memcpy(file->prop_attr, tag, taglen);
		file->prop_attr_len = taglen;
	} else
		file->prop_attr_len = 0;
	tag = sc_asn1_find_tag(p, len, 0x86, &taglen);
	if (tag != NULL && taglen && taglen <= SC_MAX_SEC_ATTR_SIZE) {
		memcpy(file->sec_attr, tag, taglen);
		file->sec_attr_len = taglen;
	} else
		file->sec_attr_len = 0;
	file->magic = SC_FILE_MAGIC;
}

static int iso7816_select_file(struct sc_card *card,
			       const struct sc_path *in_path,
			       struct sc_file *file)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	char buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;

	assert(card != NULL && in_path != NULL);
	ctx = card->ctx;
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0, 0);
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);
	
	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
			if (pathlen == 2) {	/* only 3F00 supplied */
				apdu.p1 = 0;
				break;
			}
			path += 2;
			pathlen -= 2;
		}
		break;
	default:
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.p2 = 0;		/* record */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file != NULL) {
		memset(file, 0, sizeof(*file));
		memcpy(&file->path.value, path, pathlen);
		file->path.len = pathlen;
	}
	if (file == NULL || sc_file_valid(file))
		apdu.no_response = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	
	if (apdu.no_response) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, 2, 0);
		SC_FUNC_RETURN(card->ctx, 2, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2));
	}

	r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, 2, r);

	switch (apdu.resp[0]) {
	case 0x6F:
		if (file != NULL && apdu.resp[1] <= apdu.resplen)
			process_fci(card->ctx, file, apdu.resp+2, apdu.resp[1]);
		break;
	case 0x00:	/* proprietary coding */
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_REPLY);
	default:
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_REPLY);
	}
	return 0;
}

static int iso7816_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{
	int r;
	struct sc_apdu apdu;
	u8 buf[10];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
		       0x84, 0x00, 0x00);
	apdu.le = 8;
	apdu.resp = buf;
	apdu.resplen = 8;	/* include SW's */

	while (len > 0) {
		int n = len > 8 ? 8 : len;
		
		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.resplen != 8)
			return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
		memcpy(rnd, apdu.resp, n);
		len -= n;
		rnd += n;
	}	
	return 0;
}

static struct sc_card_operations iso_ops = {
	read_binary: NULL
};

static const struct sc_card_driver iso_driver = {
	name: "ISO 7816-x reference driver",
	ops: &iso_ops
};

const struct sc_card_driver * sc_get_iso7816_driver(void)
{
	if (iso_ops.read_binary == NULL) {
		memset(&iso_ops, 0, sizeof(iso_ops));
		iso_ops.read_binary = iso7816_read_binary;
		iso_ops.select_file = iso7816_select_file;
		iso_ops.get_challenge = iso7816_get_challenge;
	}
	return &iso_driver;
}
