/*
 * iso7816.c: Functions specified by the ISO 7816 standard
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
#include "sc-asn1.h"
#include "sc-log.h"

#include <assert.h>
#include <ctype.h>

static int iso7816_read_binary(struct sc_card *card,
			       unsigned int idx, u8 *buf, size_t count,
			       unsigned long flags)
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

	SC_FUNC_RETURN(card->ctx, 3, apdu.resplen);
}

static int iso7816_read_record(struct sc_card *card,
			       unsigned int rec_nr, u8 *buf, size_t count,
			       unsigned long flags)
{
	struct sc_apdu apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB2, rec_nr, 0);
	apdu.p2 = (flags & SC_READ_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_READ_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;
	
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, 2, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, 3, apdu.resplen);
}

static int iso7816_write_binary(struct sc_card *card,
				unsigned int idx, const u8 *buf,
				size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	if (count > SC_APDU_CHOP_SIZE) {
		error(card->ctx, "Too large buffer supplied\n");
		return SC_ERROR_CMD_TOO_LONG;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, 3, count);
}

static int iso7816_update_binary(struct sc_card *card,
				 unsigned int idx, const u8 *buf,
				size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	if (count > SC_APDU_CHOP_SIZE) {
		error(card->ctx, "Too large buffer supplied\n");
		return SC_ERROR_CMD_TOO_LONG;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD6,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, 3, count);
}

static unsigned int byte_to_acl(u8 byte)
{
	switch (byte >> 4) {
	case 0:
		return SC_AC_NONE;
	case 1:
		return SC_AC_CHV1;
	case 2:
		return SC_AC_CHV2;
	case 4:
		return SC_AC_TERM;
	case 15:
		return SC_AC_NEVER;
	}
	return SC_AC_UNKNOWN;
}

static void parse_sec_attr(struct sc_file *file, const u8 *buf, size_t len)
{
	/* FIXME: confirm if this is specified in the ISO 7816-9 standard */
	int i;
	
	if (len < 6)
		return;
	for (i = 0; i < 6; i++)
		file->acl[i] = byte_to_acl(buf[i]);
}

static void process_fci(struct sc_context *ctx, struct sc_file *file,
		       const u8 *buf, size_t buflen)
{
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	if (ctx->debug >= 3)
		debug(ctx, "processing FCI bytes\n");
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		if (ctx->debug >= 3)
			debug(ctx, "  file identifier: 0x%02X%02X\n", tag[0],
			       tag[1]);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		if (ctx->debug >= 3)
			debug(ctx, "  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			if (ctx->debug >= 3)
				debug(ctx, "  shareable: %s\n",
				       (byte & 0x40) ? "yes" : "no");
			file->ef_structure = byte & 0x07;
			switch ((byte >> 3) & 7) {
			case 0:
				type = "working EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				break;
			case 1:
				type = "internal EF";
				file->type = SC_FILE_TYPE_INTERNAL_EF;
				break;
			case 7:
				type = "DF";
				file->type = SC_FILE_TYPE_DF;
				break;
			default:
				type = "unknown";
				break;
			}
			if (ctx->debug >= 3) {
				debug(ctx, "  type: %s\n", type);
				debug(ctx, "  EF structure: %d\n",
				       byte & 0x07);
			}
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x84, &taglen);
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
	tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
	if (tag != NULL && taglen && taglen <= SC_MAX_PROP_ATTR_SIZE) {
		memcpy(file->prop_attr, tag, taglen);
		file->prop_attr_len = taglen;
	} else
		file->prop_attr_len = 0;
	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen && taglen <= SC_MAX_PROP_ATTR_SIZE) {
		memcpy(file->prop_attr, tag, taglen);
		file->prop_attr_len = taglen;
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen && taglen <= SC_MAX_SEC_ATTR_SIZE)
		parse_sec_attr(file, tag, taglen);
	else
		file->sec_attr_len = 0;
	file->magic = SC_FILE_MAGIC;
}

static int iso7816_select_file(struct sc_card *card,
			       const struct sc_path *in_path,
			       struct sc_file *file)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
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
	apdu.p2 = 0;		/* first record */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file != NULL) {
		int i;
		/* initialize file to default values */
		memset(file, 0, sizeof(struct sc_file));  
		for (i = 0; i < SC_MAX_AC_OPS; i++)
			file->acl[i] = SC_AC_UNKNOWN;
		file->path = *in_path;
	}
	if (file == NULL)
		apdu.resplen = 0;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (file == NULL) {
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

static u8 acl_to_byte(unsigned int acl)
{
	switch (acl) {
	case SC_AC_NONE:
		return 0x00;
	case SC_AC_CHV1:
		return 0x01;
	case SC_AC_CHV2:
		return 0x02;
	case SC_AC_TERM:
		return 0x04;
	case SC_AC_NEVER:
		return 0x0F;
	}
	return 0x00;
}

static int construct_fci(const struct sc_file *file, u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];
	int i;
	
	*p++ = 0x6F;
	p++;
	
	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x81, buf, 2, p, 16, &p);
	buf[0] = file->shareable ? 0x40 : 0;
	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		buf[0] |= 0x08;
		break;
	case SC_FILE_TYPE_DF:
		buf[0] |= 0x38;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
	buf[0] |= file->ef_structure & 7;
	sc_asn1_put_tag(0x82, buf, 1, p, 16, &p);
	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, 16, &p);
	/* 0x84 = DF name */
	if (file->prop_attr_len) {
		memcpy(buf, file->prop_attr, file->prop_attr_len);
		sc_asn1_put_tag(0x85, buf, file->prop_attr_len, p, 18, &p);
	}
	if (file->sec_attr_len) {
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		sc_asn1_put_tag(0x86, buf, file->sec_attr_len, p, 18, &p);
	} else {
		int idx[6];
		if (file->type == SC_FILE_TYPE_DF) {
			const int df_idx[6] = {
				SC_AC_OP_SELECT, SC_AC_OP_LOCK, SC_AC_OP_DELETE,
				SC_AC_OP_CREATE, SC_AC_OP_REHABILITATE,
				SC_AC_OP_INVALIDATE
			};
			for (i = 0; i < 6; i++)
				idx[i] = df_idx[i];
		} else {
			const int ef_idx[6] = {
				SC_AC_OP_READ, SC_AC_OP_UPDATE, SC_AC_OP_WRITE,
				SC_AC_OP_ERASE, SC_AC_OP_REHABILITATE,
				SC_AC_OP_INVALIDATE
			};
			for (i = 0; i < 6; i++)
				idx[i] = ef_idx[i];
		}
		for (i = 0; i < 6; i++)
			buf[i] = acl_to_byte(file->acl[idx[i]]);
		sc_asn1_put_tag(0x86, buf, 6, p, 18, &p);
	}
	out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}

static int iso7816_create_file(struct sc_card *card, struct sc_file *file)
{
	int r;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;

	len = SC_MAX_APDU_BUFFER_SIZE;
	r = construct_fci(file, sbuf, &len);
	SC_TEST_RET(card->ctx, r, "construct_fci() failed");
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

static int iso7816_delete_file(struct sc_card *card, const struct sc_path *path)
{
	int r;
	u8 sbuf[2];
	struct sc_apdu apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2) {
		error(card->ctx, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	sbuf[0] = path->value[0];
	sbuf[1] = path->value[1];
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

static int iso7816_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xAA, 0, 0);
	apdu.resp = buf;
	apdu.resplen = buflen;
	apdu.le = 0;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	return apdu.resplen;
}

static int iso7816_verify(struct sc_card *card, unsigned int type, int ref,
			  const u8 *pin, size_t pinlen, int *tries_left)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;
	
	if (pinlen >= SC_MAX_APDU_BUFFER_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	switch (type) {
	case SC_AC_CHV1:
	case SC_AC_CHV2:
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, ref);
	memcpy(sbuf, pin, pinlen);
	apdu.lc = pinlen;
	apdu.datalen = pinlen;
	apdu.data = sbuf;
	apdu.resplen = 0;
	
	r = sc_transmit_apdu(card, &apdu);
	memset(sbuf, 0, pinlen);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x63) {
		if ((apdu.sw2 & 0xF0) == 0xC0 && tries_left != NULL)
			*tries_left = apdu.sw2 & 0x0F;
		return SC_ERROR_PIN_CODE_INCORRECT;
	}
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

static int iso7816_set_security_env(struct sc_card *card,
				    const struct sc_security_env *env,
				    int se_num)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;

	assert(card != NULL && env != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x81;
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
		*p++ = 0x81;
		*p++ = env->file_ref.len;
		memcpy(p, env->file_ref.value, env->file_ref.len);
		p += env->file_ref.len;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		*p++ = env->key_ref_len;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;
	if (se_num > 0) {
		r = sc_lock(card);
		SC_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_perror(card->ctx, r, "APDU transmit failed");
			goto err;
		}
		r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_perror(card->ctx, r, "Card returned error");
			goto err;
		}
	}
	if (se_num <= 0)
		return 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num);
	r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}

static int iso7816_restore_security_env(struct sc_card *card, int se_num)
{
	struct sc_apdu apdu;
	int r;
	u8 rbuf[MAX_BUFFER_SIZE];
	
	assert(card != NULL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0xF3, se_num);
	apdu.resplen = sizeof(rbuf) > 250 ? 250 : sizeof(rbuf);
	apdu.resp = rbuf;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

static int iso7816_compute_signature(struct sc_card *card,
				     const u8 * data, size_t datalen,
				     u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[MAX_BUFFER_SIZE];
	u8 sbuf[MAX_BUFFER_SIZE];

	assert(card != NULL && data != NULL && out != NULL);
	if (datalen > 255)
		SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x9E,
		       0x9A);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf); /* FIXME */

	memcpy(sbuf, data, datalen);
	apdu.data = sbuf;
	apdu.lc = datalen;
	apdu.datalen = datalen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		int len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, 4, len);
	}
	SC_FUNC_RETURN(card->ctx, 4, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2));
}

static int iso7816_change_reference_data(struct sc_card *card, unsigned int type,
					 int ref, const u8 *old, size_t oldlen,
					 const u8 *new, size_t newlen,
					 int *tries_left)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r, p1 = 0, len = oldlen + newlen;

	if (len >= SC_MAX_APDU_BUFFER_SIZE)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	switch (type) {
	case SC_AC_CHV1:
	case SC_AC_CHV2:
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (oldlen == 0)
		p1 = 1;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, p1, ref);
	memcpy(sbuf, old, oldlen);
	memcpy(sbuf + oldlen, new, newlen);
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;
	apdu.resplen = 0;
	
	r = sc_transmit_apdu(card, &apdu);
	memset(sbuf, 0, len);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0) {
		if (tries_left != NULL)
			*tries_left = apdu.sw2 & 0x0F;
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_PIN_CODE_INCORRECT);
	}
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

static int iso7816_reset_retry_counter(struct sc_card *card, unsigned int type, int ref,
				       const u8 *puk, size_t puklen, const u8 *new,
				       size_t newlen)
{
	struct sc_apdu apdu;
	u8 sbuf[MAX_BUFFER_SIZE];
	int r, p1 = 0, len = puklen + newlen;

	if (len >= MAX_BUFFER_SIZE)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	switch (type) {
	case SC_AC_CHV1:
	case SC_AC_CHV2:
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (puklen == 0) {
		if (newlen == 0)
			p1 = 3;
		else
			p1 = 2;
	} else {
		if (newlen == 0)
			p1 = 1;
		else
			p1 = 0;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2C, p1, ref);
	memcpy(sbuf, puk, puklen);
	memcpy(sbuf + puklen, new, newlen);
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;
	apdu.resplen = 0;

	r = sc_transmit_apdu(card, &apdu);
	memset(sbuf, 0, len);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

static struct sc_card_operations iso_ops = {
	NULL,
};

static const struct sc_card_driver iso_driver = {
	NULL,
	"ISO 7816 reference driver",
	"iso7816",
	&iso_ops
};

static int no_match(struct sc_card *card)
{
	return 0;
}

const struct sc_card_driver * sc_get_iso7816_driver(void)
{
	if (iso_ops.match_card == NULL) {
		memset(&iso_ops, 0, sizeof(iso_ops));
		iso_ops.match_card    = no_match;
		iso_ops.read_binary   = iso7816_read_binary;
		iso_ops.read_record   = iso7816_read_record;
		iso_ops.write_binary  = iso7816_write_binary;
		iso_ops.update_binary = iso7816_update_binary;
		iso_ops.select_file   = iso7816_select_file;
		iso_ops.get_challenge = iso7816_get_challenge;
		iso_ops.create_file   = iso7816_create_file;
		iso_ops.delete_file   = iso7816_delete_file;
		iso_ops.list_files    = iso7816_list_files;
		iso_ops.verify	      = iso7816_verify;
		iso_ops.set_security_env	= iso7816_set_security_env;
		iso_ops.restore_security_env	= iso7816_restore_security_env;
		iso_ops.compute_signature	= iso7816_compute_signature;
		iso_ops.reset_retry_counter     = iso7816_reset_retry_counter;
                iso_ops.change_reference_data   = iso7816_change_reference_data;
	}
	return &iso_driver;
}
