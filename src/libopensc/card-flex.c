/*
 * card-flex.c: Support for Schlumberger cards
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
#include "sc-log.h"
#include <stdlib.h>

static const char *flex_atrs[] = {
	"3B:95:94:40:FF:63:01:01:02:01", /* Cryptoflex 16k */
	"3B:85:40:20:68:01:01:05:01",    /* Cryptoflex 8k */
	"3B:19:14:55:90:01:02:02:00:05:04:B0",
	NULL
};

struct flex_private_data {
	int rsa_key_ref;
};

static struct sc_card_operations flex_ops;
static const struct sc_card_driver flex_drv = {
	NULL,
	"Schlumberger Multiflex/Cryptoflex",
	"slb",
	&flex_ops
};

static int flex_finish(struct sc_card *card)
{
	free(card->ops_data);
	return 0;
}

static int flex_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; flex_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = flex_atrs[i];

		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != card->atr_len)
			continue;
		if (memcmp(card->atr, defatr, len) != 0)
			continue;
		match = i;
		break;
	}
	if (match == -1)
		return 0;

	return 1;
}

static int flex_init(struct sc_card *card)
{
	card->ops_data = malloc(sizeof(struct flex_private_data));;
	if (card->ops_data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	card->cla = 0xC0;

	return 0;
}

static unsigned int ac_to_acl(u8 nibble)
{
	unsigned int acl_table[16] = {
		/* 0 */ SC_AC_NONE, SC_AC_CHV1, SC_AC_CHV2, SC_AC_PRO,
		/* 4 */ SC_AC_AUT, SC_AC_UNKNOWN, SC_AC_CHV1 | SC_AC_PRO,
		/* 7 */ SC_AC_CHV2 | SC_AC_PRO, SC_AC_CHV1 | SC_AC_AUT,
		/* 9 */ SC_AC_CHV2 | SC_AC_AUT, SC_AC_UNKNOWN, SC_AC_UNKNOWN,
		/* c */	SC_AC_UNKNOWN, SC_AC_UNKNOWN, SC_AC_UNKNOWN,
		/* f */ SC_AC_NEVER };
	return acl_table[nibble & 0x0F];
}

static int parse_flex_sf_reply(struct sc_context *ctx, const u8 *buf, int buflen,
			       struct sc_file *file)
{
	const u8 *p = buf + 2;
	u8 b1, b2;
        int left;
	
	if (buflen < 14)
		return -1;
	b1 = *p++;
	b2 = *p++;
	file->size = (b1 << 8) + b2;
	b1 = *p++;
	b2 = *p++;
	file->id = (b1 << 8) + b2;
	switch (*p) {
	case 0x01:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		break;
	case 0x02:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_LINEAR_FIXED;
		break;
	case 0x04:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_LINEAR_VARIABLE;
		break;
	case 0x06:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_CYCLIC;
		break;
	case 0x38:
		file->type = SC_FILE_TYPE_DF;
		break;
	default:
		error(ctx, "invalid file type: 0x%02X\n", *p);
                return SC_ERROR_UNKNOWN_REPLY;
	}
        p += 2;
	if (file->type == SC_FILE_TYPE_DF) {
		file->acl[SC_AC_OP_LIST_FILES] = ac_to_acl(p[0] >> 4);
		file->acl[SC_AC_OP_DELETE] = ac_to_acl(p[1] >> 4);
		file->acl[SC_AC_OP_CREATE] = ac_to_acl(p[1] & 0x0F);
	} else { /* EF */
		file->acl[SC_AC_OP_READ] = ac_to_acl(p[0] >> 4);
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			file->acl[SC_AC_OP_UPDATE] = ac_to_acl(p[0] & 0x0F);
			break;
		case SC_FILE_EF_LINEAR_FIXED:
		case SC_FILE_EF_LINEAR_VARIABLE:
			file->acl[SC_AC_OP_UPDATE] = ac_to_acl(p[0] & 0x0F);
			break;
		case SC_FILE_EF_CYCLIC:
#if 0
			/* FIXME */
			file->acl[SC_AC_OP_DECREASE] = ac_to_acl(p[0] & 0x0F);
#endif
			break;
		}
	}
	file->acl[SC_AC_OP_REHABILITATE] = ac_to_acl(p[2] >> 4);
	file->acl[SC_AC_OP_INVALIDATE] = ac_to_acl(p[2] & 0x0F);
	p += 3; /* skip ACs */
	if (*p++)
		file->status = SC_FILE_STATUS_ACTIVATED;
	else
                file->status = SC_FILE_STATUS_INVALIDATED;
        left = *p++;
	/* FIXME: CODEME */
	file->magic = SC_FILE_MAGIC;

	return 0;
}

static int check_path(struct sc_card *card, const u8 **pathptr, size_t *pathlen,
		      int need_info)
{
	const u8 *curptr = card->cache.current_path.value;
	const u8 *ptr = *pathptr;
	size_t curlen = card->cache.current_path.len;
	size_t len = *pathlen;

	if (curlen < 2)
		return 0;
	if (len < 2)
		return 0;
	if (memcmp(ptr, "\x3F\x00", 2) != 0) {
		/* Skip the MF id */
		curptr += 2;
		curlen -= 2;
	}
	if (len == curlen && memcmp(ptr, curptr, len) == 0) {
		if (need_info)
			return 0;
		*pathptr = ptr + len;
		*pathlen = 0;
		return 1;
	}
	if (curlen < len && memcmp(ptr, curptr, curlen) == 0) {
		*pathptr = ptr + curlen;
		*pathlen = len - curlen;
		return 1;
	}
	/* FIXME: Build additional logic */
	return 0;
}

void cache_path(struct sc_card *card, const struct sc_path *path)
{
	struct sc_path *curpath = &card->cache.current_path;
	
	switch (path->type) {
	case SC_PATH_TYPE_FILE_ID:
		if (path->value[0] == 0x3F && path->value[1] == 0x00)
			sc_format_path("3F00", curpath);
		else {
			if (curpath->len + 2 > SC_MAX_PATH_SIZE) {
				curpath->len = 0;
				return;
			}
			memcpy(curpath->value + curpath->len, path->value, 2);
			curpath->len += 2;
		}
		break;
	case SC_PATH_TYPE_PATH:
		curpath->len = 0;
		if (path->value[0] != 0x3F || path->value[1] != 0)
			sc_format_path("3F00", curpath);
		if (curpath->len + path->len > SC_MAX_PATH_SIZE) {
			curpath->len = 0;
			return;
		}
		memcpy(curpath->value + curpath->len, path->value, path->len);
		curpath->len += path->len;
		break;
	case SC_PATH_TYPE_DF_NAME:
		/* All bets are off */
		curpath->len = 0;
		break;
	}
}

static int select_file_id(struct sc_card *card, const u8 *buf, size_t buflen,
			  u8 p1, struct sc_file *file)
{
	int r, i;
	struct sc_apdu apdu;
        u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, p1, 0);
	apdu.resp = rbuf;
        apdu.resplen = sizeof(rbuf);
	apdu.datalen = buflen;
        apdu.data = buf;
	apdu.lc = buflen;

	/* No need to get file information, if file is NULL. */
	if (file == NULL)
                apdu.resplen = 0;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	if (file == NULL)
                return 0;

	if (apdu.resplen < 14)
		return SC_ERROR_UNKNOWN_REPLY;
	if (apdu.resp[0] == 0x6F) {
		error(card->ctx, "unsupported: card returned FCI\n");
		return SC_ERROR_UNKNOWN_REPLY; /* FIXME */
	}

	memset(file, 0, sizeof(struct sc_file));
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		file->acl[i] = SC_AC_UNKNOWN;

	return parse_flex_sf_reply(card->ctx, apdu.resp, apdu.resplen, file);

}

static int flex_select_file(struct sc_card *card, const struct sc_path *path,
			     struct sc_file *file)
{
	int r;
	const u8 *pathptr = path->value;
	size_t pathlen = path->len;
	int locked = 0, magic_done;
	u8 p1 = 0;

	SC_FUNC_CALLED(card->ctx, 3);
	switch (path->type) {
	case SC_PATH_TYPE_PATH:
		if ((pathlen & 1) != 0) /* not divisible by 2 */
			return SC_ERROR_INVALID_ARGUMENTS;
		magic_done = check_path(card, &pathptr, &pathlen, file != NULL);
		if (pathlen == 0)
			return 0;
		if (pathlen != 2 || memcmp(pathptr, "\x3F\x00", 2) != 0) {
			locked = 1;
			r = sc_lock(card);
			SC_TEST_RET(card->ctx, r, "sc_lock() failed");
			if (!magic_done && memcmp(pathptr, "\x3F\x00", 2) != 0) {
				r = select_file_id(card, (const u8 *) "\x3F\x00", 2, 0, NULL);
				if (r)
					sc_unlock(card);
				SC_TEST_RET(card->ctx, r, "Unable to select Master File (MF)");
			}
			while (pathlen > 2) {
				r = select_file_id(card, pathptr, 2, 0, NULL);
				if (r)
					sc_unlock(card);
				SC_TEST_RET(card->ctx, r, "Unable to select DF");
				pathptr += 2;
				pathlen -= 2;
			}
		}
                break;
	case SC_PATH_TYPE_DF_NAME:
		p1 = 0x04;
		break;
	case SC_PATH_TYPE_FILE_ID:
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
                break;
	}
	r = select_file_id(card, pathptr, pathlen, p1, file);
	if (locked)
		sc_unlock(card);
	if (r)
		return r;
	cache_path(card, path);
	return 0;
}

static int flex_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	u8 rbuf[4];
	int r;
	size_t count = 0;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA8, 0, 0);
	apdu.cla = 0xF0;
	apdu.le = 4;
	apdu.resplen = 4;
	apdu.resp = rbuf;
	while (buflen > 2) {
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return r;
		if (apdu.sw1 == 0x6A && apdu.sw2 == 0x82)
			break;
		r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
		if (r)
			return r;
		if (apdu.resplen != 4) {
			error(card->ctx, "expected 4 bytes, got %d.\n", apdu.resplen);
			return SC_ERROR_ILLEGAL_RESPONSE;
		}
		memcpy(buf, rbuf + 2, 2);
		buf += 2;
		count += 2;
		buflen -= 2;
	}
	return count;
}

static int flex_delete_file(struct sc_card *card, const struct sc_path *path)
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
	apdu.cla = 0xF0;	/* Override CLA byte */
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

static int acl_to_ac(unsigned int acl)
{
	int i;
	unsigned int acl_table[16] = {
		/* 0 */ SC_AC_NONE, SC_AC_CHV1, SC_AC_CHV2, SC_AC_PRO,
		/* 4 */ SC_AC_AUT, SC_AC_UNKNOWN, SC_AC_CHV1 | SC_AC_PRO,
		/* 7 */ SC_AC_CHV2 | SC_AC_PRO, SC_AC_CHV1 | SC_AC_AUT,
		/* 9 */ SC_AC_CHV2 | SC_AC_AUT, SC_AC_UNKNOWN, SC_AC_UNKNOWN,
		/* c */	SC_AC_UNKNOWN, SC_AC_UNKNOWN, SC_AC_UNKNOWN,
		/* f */ SC_AC_NEVER };
	if (acl == SC_AC_NEVER)
		return 0x0f;
	else if (acl == SC_AC_UNKNOWN)
		return -1;
	acl &= ~SC_AC_KEY_NUM_MASK;
	for (i = 0; i < sizeof(acl_table)/sizeof(acl_table[0]); i++)
		if (acl == acl_table[i])
			return i;
	return -1;
}

static int acl_to_keynum(unsigned int acl)
{
	if (!(acl & SC_AC_AUT))
		return 0;
	switch (acl & SC_AC_KEY_NUM_MASK) {
	case SC_AC_KEY_NUM_0:
		return 0x00;
	case SC_AC_KEY_NUM_1:
		return 0x01;
	case SC_AC_KEY_NUM_2:
		return 0x02;
	}
	return 0;
}

static int encode_file_structure(struct sc_card *card, const struct sc_file *file,
				 u8 *buf, size_t *buflen)
{
	u8 *p = buf;
	int r, i;
	int ops[6];

	p[0] = 0xFF;
	p[1] = 0xFF;
	p[2] = file->size >> 8;
	p[3] = file->size & 0xFF;
	p[4] = file->id >> 8;
	p[5] = file->id & 0xFF;
	if (file->type == SC_FILE_TYPE_DF)
		p[6] = 0x38;
	else
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			p[6] = 0x01;
			break;
		case SC_FILE_EF_LINEAR_FIXED:
			p[6] = 0x02;
			break;
		case SC_FILE_EF_LINEAR_VARIABLE:
			p[6] = 0x04;
			break;
		case SC_FILE_EF_CYCLIC:
			p[6] = 0x06;
			break;
		default:
			error(card->ctx, "Invalid EF structure\n");
			return -1;
		}
	p[7] = 0xFF;	/* allow Decrease and Increase */
	for (i = 0; i < 6; i++)
		ops[i] = -1;
	if (file->type == SC_FILE_TYPE_DF) {
		ops[0] = SC_AC_OP_LIST_FILES;
		ops[2] = SC_AC_OP_DELETE;
		ops[3] = SC_AC_OP_CREATE;
	} else {
		ops[0] = SC_AC_OP_READ;
		ops[1] = SC_AC_OP_UPDATE;
		ops[2] = SC_AC_OP_READ;
		ops[3] = SC_AC_OP_UPDATE;
		ops[4] = SC_AC_OP_REHABILITATE;
		ops[5] = SC_AC_OP_INVALIDATE;
	}
	p[8] = p[9] = p[10] = 0;
	p[13] = p[14] = p[15] = 0; /* Key numbers */
	for (i = 0; i < 6; i++) {
		if (ops[i] == -1)
			continue;
		r = acl_to_ac(file->acl[ops[i]]);
		SC_TEST_RET(card->ctx, r, "Invalid ACL value");
		/* Do some magic to get the nibbles right */
		p[8 + i/2] |= (r & 0x0F) << (((i+1) % 2) * 4);
		r = acl_to_keynum(file->acl[ops[i]]);
		p[13 + i/2] |= (r & 0x0F) << (((i+1) % 2) * 4);
	}
	p[11] = (file->status & SC_FILE_STATUS_INVALIDATED) ? 0x00 : 0x01;
	if (file->type != SC_FILE_TYPE_DF &&
	    (file->ef_structure == SC_FILE_EF_LINEAR_FIXED ||
	     file->ef_structure == SC_FILE_EF_CYCLIC))
		p[12] = 0x04;
	else
		p[12] = 0x03;
	if (p[12] == 0x04) {
		p[16] = file->record_length;
		*buflen = 17;
	} else
		*buflen = 16;

	return 0;
}

static int flex_create_file(struct sc_card *card, struct sc_file *file)
{
	u8 sbuf[18];
	size_t sendlen;
	int r, rec_nr;
	struct sc_apdu apdu;
	
	r = encode_file_structure(card, file, sbuf, &sendlen);
	if (r) {
		error(card->ctx, "File structure encoding failed.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (file->type != SC_FILE_TYPE_DF && file->ef_structure != SC_FILE_EF_TRANSPARENT)
		rec_nr = file->record_count;
	else
		rec_nr = 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, rec_nr);
	apdu.cla = 0xF0;
	apdu.data = sbuf;
	apdu.datalen = sendlen;
	apdu.lc = sendlen;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");
	if (card->cache_valid) {
		u8 file_id[2];
		
		file_id[0] = file->id >> 8;
		file_id[1] = file->id & 0xFF;
		if (card->cache.current_path.len != 0)
			sc_append_path_id(&card->cache.current_path, file_id, 2);
	}		
	return 0;
}

static int flex_set_security_env(struct sc_card *card,
				 const struct sc_security_env *env,
				 int se_num)   
{
	struct flex_private_data *prv = (struct flex_private_data *) card->ops_data;

	if (env->operation != SC_SEC_OPERATION_SIGN) {
		error(card->ctx, "Invalid crypto operation supplied.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->key_ref_len != 1 ||
		    (env->key_ref[0] != 0 && env->key_ref[0] != 1)) {
			error(card->ctx, "Invalid key reference supplied.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		prv->rsa_key_ref = env->key_ref[0];
	}
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		error(card->ctx, "Algorithm reference not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
		if (memcmp(env->file_ref.value, "\x00\x12", 2) != 0) {
			error(card->ctx, "File reference is not 0012.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
	return 0;
}

static int flex_restore_security_env(struct sc_card *card, int se_num)
{
	return 0;
}

static int flex_compute_signature(struct sc_card *card, const u8 *data,
				  size_t data_len, u8 * out, size_t outlen)
{
	struct flex_private_data *prv = (struct flex_private_data *) card->ops_data;
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int i, r;
	
	if (data_len != 64 && data_len != 96 && data_len != 128) {
		error(card->ctx, "Illegal input length: %d\n", data_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (outlen < data_len) {
		error(card->ctx, "Output buffer too small.\n");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x88, 0x00, prv->rsa_key_ref);
	apdu.lc = data_len;
	apdu.datalen = data_len;
	for (i = 0; i < data_len; i++)
		sbuf[i] = data[data_len-1-i];
	apdu.data = sbuf;
	apdu.resplen = outlen > sizeof(sbuf) ? sizeof(sbuf) : outlen;
	apdu.resp = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");
	for (i = 0; i < apdu.resplen; i++)
		out[i] = sbuf[apdu.resplen-1-i];
	return apdu.resplen;
}

static int flex_verify(struct sc_card *card, unsigned int type, int ref,
		       const u8 *buf, size_t buflen, int *tries_left)
{
        struct sc_apdu apdu;
        u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
        int r;
        int cla, ins;

	if (buflen >= SC_MAX_APDU_BUFFER_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	switch (type) {
	case SC_AC_CHV1:
	case SC_AC_CHV2:
		cla = 0xC0;
		ins = 0x20;
		break;
	case SC_AC_AUT:
		cla = 0xF0;
		ins = 0x2A;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
        }
        sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, ins, 0, ref);
        memcpy(sbuf, buf, buflen);
	apdu.cla = cla;
        apdu.lc = buflen;
        apdu.datalen = buflen;
        apdu.data = sbuf;
	apdu.resplen = 0;
	r = sc_transmit_apdu(card, &apdu);
	memset(sbuf, 0, buflen);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
        if (apdu.sw1 == 0x63)
		return SC_ERROR_PIN_CODE_INCORRECT;   
        return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}              

static const struct sc_card_driver * sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	flex_ops = *iso_drv->ops;
	flex_ops.match_card = flex_match_card;
	flex_ops.init = flex_init;
        flex_ops.finish = flex_finish;
	flex_ops.select_file = flex_select_file;
	flex_ops.list_files = flex_list_files;
	flex_ops.delete_file = flex_delete_file;
	flex_ops.create_file = flex_create_file;
	flex_ops.verify = flex_verify;
	flex_ops.set_security_env = flex_set_security_env;
	flex_ops.restore_security_env = flex_restore_security_env;
	flex_ops.compute_signature = flex_compute_signature;
        return &flex_drv;
}

#if 1
const struct sc_card_driver * sc_get_flex_driver(void)
{
	return sc_get_driver();
}
#endif
