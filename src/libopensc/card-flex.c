/*
 * card-flex.c: Support for Schlumberger cards
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

#include "internal.h"
#include "cardctl.h"
#include <stdlib.h>
#include <string.h>

#define TYPE_UNKNOWN		0x0000
#define TYPE_CRYPTOFLEX		0x0100
#define TYPE_MULTIFLEX		0x0200
#define TYPE_CYBERFLEX		0x0300
#define FLAG_KEYGEN		0x0001
#define FLAG_FULL_DES		0x0002	/* whatever that means */

#define TYPE_MASK		0xFF00

#define IS_CYBERFLEX(card)	((DRV_DATA(card)->card_type & TYPE_MASK) == TYPE_CYBERFLEX)

/* We may want to change sc_atr_table to hold the string representation
 * of the ATR instead */
static struct {
	const char *		atr;
	int			type;
	const char *		name;
} flex_atrs[] = {
      /* Cryptoflex */
      {	"3B:95:15:40:FF:68:01:02:02:04",       /* 8k */
	TYPE_CRYPTOFLEX,
	"Cryptoflex 8K" },
      {	"3B:85:40:20:68:01:01:05:01",          /* 8k */
	TYPE_CRYPTOFLEX,
	"Cryptoflex 8K" },
      {	"3B:95:94:40:FF:63:01:01:02:01",       /* 16k */
	TYPE_CRYPTOFLEX|FLAG_KEYGEN,
	"Cryptoflex 16K" },
      { "3B:95:18:40:FF:64:02:01:01:02",       /* 32K v4 */
	TYPE_CRYPTOFLEX|FLAG_KEYGEN,
	"Cryptoflex 32K v4" },
      {	"3B:95:18:40:FF:62:01:02:01:04",       /* 32K e-gate */
	TYPE_CRYPTOFLEX|FLAG_KEYGEN,
	"Cryptoflex 32K e-gate" },
      {	"3B:95:18:40:FF:62:04:01:01:05",       /* 32K e-gate v4 */
	TYPE_CRYPTOFLEX|FLAG_KEYGEN,
	"Cryptoflex 32K e-gate v4" },
      {	"3B:E2:00:00:40:20:49:06",
	TYPE_CRYPTOFLEX,
	"Cryptoflex" },
      {	"3B:E2:00:00:40:20:49:05",             /* + full DES option */
	TYPE_CRYPTOFLEX|FLAG_FULL_DES,
	"Cryptoflex" },
      {	"3B:E2:00:00:40:20:49:07",             /* + Key Generation */
	TYPE_CRYPTOFLEX|FLAG_KEYGEN,
	"Cryptoflex" },
      {	"3B:85:40:20:68:01:01:03:05",          /* + Key Generation */
	TYPE_CRYPTOFLEX|FLAG_KEYGEN,
	"Cryptoflex" },

      /* Multiflex */
      {	"3B:02:14:50",                         /* 3K */
	TYPE_MULTIFLEX,
	"Multiflex 3K" },
      {	"3B:19:14:55:90:01:02:01:00:05:04:B0", /* 4K */
	TYPE_MULTIFLEX,
	"Multiflex 4K" },
      {	"3B:32:15:00:06:80",                   /* 8K */
	TYPE_MULTIFLEX,
	"Multiflex 8K" },
      {	"3B:32:15:00:06:95",                   /* 8K + full DES option */
	TYPE_MULTIFLEX,
	"Multiflex 8K" },
      {	"3B:19:14:59:01:01:0F:01:00:05:08:B0", /* 8K */
	TYPE_MULTIFLEX,
	"Multiflex 8K" },
      {	"3B:19:14:55:90:01:01:01:00:05:08:B0", /* 8K */
	TYPE_MULTIFLEX,
	"Multiflex 8K" },

      /* Cyberflex Access */
      {	"3B:16:94:81:10:06:01:81:3F",          /* Crypto */
	TYPE_CYBERFLEX,
	"Cyberflex Access" },
      {	"3B:16:94:81:10:06:01:81:2F",          /* Aug. Crypto */
	TYPE_CYBERFLEX,
	"Cyberflex Access" },

      { NULL, TYPE_UNKNOWN }
};

struct flex_private_data {
	int	card_type;
	int	rsa_key_ref;

	/* Support card variations without having to
	 * do the if (DRV_DATA(card)->card_type ...) thing
	 * all the time */
	u8	aak_key_ref;
};

#define DRV_DATA(card)	((struct flex_private_data *) (card)->drv_data)

static struct sc_card_operations cryptoflex_ops;
static struct sc_card_operations cyberflex_ops;
static struct sc_card_operations *iso_ops;
static struct sc_card_driver cryptoflex_drv = {
	"Schlumberger Multiflex/Cryptoflex",
	"flex",
	&cryptoflex_ops
};
static struct sc_card_driver cyberflex_drv = {
	"Schlumberger Cyberflex",
	"cyberflex",
	&cyberflex_ops
};

static int flex_finish(struct sc_card *card)
{
	free(card->drv_data);
	return 0;
}

static int flex_identify_card(struct sc_card *card)
{
	int i;

	for (i = 0; flex_atrs[i].atr != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = flex_atrs[i].atr;

		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != card->atr_len)
			continue;
		if (memcmp(card->atr, defatr, len) == 0)
			break;
	}

	return i;
}

static int cryptoflex_match_card(struct sc_card *card)
{
	int	idx;

	idx = flex_identify_card(card);

	switch (flex_atrs[idx].type & TYPE_MASK) {
	case TYPE_CRYPTOFLEX:
	case TYPE_MULTIFLEX:
		return 1;
	}
	return 0;
}

static int cyberflex_match_card(struct sc_card *card)
{
	int	idx;

	idx = flex_identify_card(card);

	switch (flex_atrs[idx].type & TYPE_MASK) {
	case TYPE_CYBERFLEX:
		return 1;
	}
	return 0;
}

static int flex_init(struct sc_card *card)
{
	struct flex_private_data *data;
	int idx;

	if (!(data = (struct flex_private_data *) malloc(sizeof(*data))))
		return SC_ERROR_OUT_OF_MEMORY;

	idx = flex_identify_card(card);
	data->card_type = flex_atrs[idx].type;
	data->aak_key_ref = 1;

	card->name = flex_atrs[idx].name;
	card->drv_data = data;
	card->cla = 0xC0;

	/* Override Cryptoflex defaults for specific card types */
	switch (data->card_type & TYPE_MASK) {
	case TYPE_CYBERFLEX:
		card->cla = 0x00;
		data->aak_key_ref = 0;
		break;
	}

	/* FIXME: Card type detection */
	if (1) {
		unsigned long flags;
		
		flags = SC_ALGORITHM_RSA_RAW;
		flags |= SC_ALGORITHM_RSA_HASH_NONE;
		if (data->card_type & FLAG_KEYGEN)
			flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

		_sc_card_add_rsa_alg(card, 512, flags, 0);
		_sc_card_add_rsa_alg(card, 768, flags, 0);
		_sc_card_add_rsa_alg(card, 1024, flags, 0);
		_sc_card_add_rsa_alg(card, 2048, flags, 0);
	}

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG;

	return 0;
}

static void
add_acl_entry(sc_card_t *card, sc_file_t *file, unsigned int op, u8 nibble)
{
	struct flex_private_data *prv = DRV_DATA(card);

	switch (nibble) {
	case 0:
		sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE);
		break;
	case 1:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, 1);
		break;
	case 2:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, 2);
		break;
	case 3:
		sc_file_add_acl_entry(file, op, SC_AC_PRO, SC_AC_KEY_REF_NONE);
		break;
	case 4:
		/* Assume the key is the AAK */
		sc_file_add_acl_entry(file, op, SC_AC_AUT, prv->aak_key_ref);
		break;
	case 6:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, 1);
		sc_file_add_acl_entry(file, op, SC_AC_PRO, SC_AC_KEY_REF_NONE);
		break;
	case 7:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, 2);
		sc_file_add_acl_entry(file, op, SC_AC_PRO, SC_AC_KEY_REF_NONE);
		break;
	case 8:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, 1);
		/* Assume the key is the AAK */
		sc_file_add_acl_entry(file, op, SC_AC_AUT, prv->aak_key_ref);
		break;
	case 9:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, 2);
		/* Assume the key is the AAK */
		sc_file_add_acl_entry(file, op, SC_AC_AUT, prv->aak_key_ref);
		break;
	case 15:
		sc_file_add_acl_entry(file, op, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		break;
	default:
		sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
		break;
	}
}

static int
cryptoflex_get_ac_keys(struct sc_card *card, struct sc_file *file)
{
#if 0
	struct sc_apdu apdu;
	u8 rbuf[3];
	int r;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xC4, 0x00, 0x00);
	apdu.cla = 0xF0 /* 0x00 for Cyberflex */;
	apdu.le = 3;
	apdu.resplen = 3;
	apdu.resp = rbuf;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 && apdu.sw2 != 0x00)
		return 0;
	sc_debug(card->ctx, "AC Keys: %02X %02X %02X\n", rbuf[0], rbuf[1], rbuf[2]);
#endif
	return 0;
}

static int
cryptoflex_process_file_attrs(sc_card_t *card, sc_file_t *file,
			const u8 *buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	const u8 *p = buf + 2;
	u8 b1, b2;
        int left, is_mf = 0;
	
	if (buflen < 14)
		return -1;
	b1 = *p++;
	b2 = *p++;
	file->size = (b1 << 8) + b2;
	b1 = *p++;
	b2 = *p++;
	file->id = (b1 << 8) + b2;
	if (file->id == 0x3F00)
		is_mf = 1;
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
		sc_error(ctx, "invalid file type: 0x%02X\n", *p);
                return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
        p += 2;
	if (file->type == SC_FILE_TYPE_DF) {
		add_acl_entry(card, file, SC_AC_OP_LIST_FILES, (u8)(p[0] >> 4));
		add_acl_entry(card, file, SC_AC_OP_DELETE, (u8)(p[1] >> 4));
		add_acl_entry(card, file, SC_AC_OP_CREATE, (u8)(p[1] & 0x0F));
	} else { /* EF */
		add_acl_entry(card, file, SC_AC_OP_READ, (u8)(p[0] >> 4));
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, (u8)(p[0] & 0x0F));
			break;
		case SC_FILE_EF_LINEAR_FIXED:
		case SC_FILE_EF_LINEAR_VARIABLE:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, (u8)(p[0] & 0x0F));
			break;
		case SC_FILE_EF_CYCLIC:
#if 0
			/* FIXME */
			file->acl[SC_AC_OP_DECREASE] = ac_to_acl(p[0] & 0x0F);
#endif
			break;
		}
	}
	if (file->type != SC_FILE_TYPE_DF || is_mf) {
		add_acl_entry(card, file, SC_AC_OP_REHABILITATE, (u8)(p[2] >> 4));
		add_acl_entry(card, file, SC_AC_OP_INVALIDATE, (u8)(p[2] & 0x0F));
	}
	p += 3;
	if (*p++)
		file->status = SC_FILE_STATUS_ACTIVATED;
	else
                file->status = SC_FILE_STATUS_INVALIDATED;
        left = *p++;

	return cryptoflex_get_ac_keys(card, file);
}

static int
cyberflex_process_file_attrs(sc_card_t *card, sc_file_t *file,
			const u8 *buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	const u8 *p = buf + 2;
	const u8 *pos;
	u8 b1, b2;
	int left, is_mf = 0;

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
		is_mf = 1;
		break;
	case 0x02:
		file->type = SC_FILE_TYPE_DF;
		break;
	case 0x04:
		file->type = SC_FILE_TYPE_WORKING_EF;
		break;
	default:
		sc_error(ctx, "invalid file type: 0x%02X\n", *p);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
  
	if (is_mf) {
		sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_AUT, 0);
		sc_file_add_acl_entry(file, SC_AC_OP_DELETE, SC_AC_AUT, 0);
		sc_file_add_acl_entry(file, SC_AC_OP_CREATE, SC_AC_AUT, 0);
	} else {
		p += 2;
    
		if (file->type == SC_FILE_TYPE_DF) {
			add_acl_entry(card, file, SC_AC_OP_LIST_FILES, (u8)(p[0] >> 4));
			add_acl_entry(card, file, SC_AC_OP_DELETE, (u8)(p[1] >> 4));
			add_acl_entry(card, file, SC_AC_OP_CREATE, (u8)(p[1] & 0x0F));
		} else { /* EF */
			add_acl_entry(card, file, SC_AC_OP_READ, (u8)(p[0] >> 4));
      
		}
	}
	if (file->type != SC_FILE_TYPE_DF) {
		add_acl_entry(card, file, SC_AC_OP_REHABILITATE, (u8)(p[2] >> 4));
		add_acl_entry(card, file, SC_AC_OP_INVALIDATE, (u8)(p[2] & 0x0F));
	}
	pos = p;
	p += 3;
	if (*p++)
		file->status = SC_FILE_STATUS_ACTIVATED;
	else
		file->status = SC_FILE_STATUS_INVALIDATED;
	left = *p++;
	if (0 == is_mf) {
		*p++;
		switch (*p) {
		case  0x00:
			file->ef_structure = SC_FILE_EF_TRANSPARENT;
			break;
		case  0x01:
			file->ef_structure = SC_FILE_EF_LINEAR_FIXED;
			break;
		case  0x02:
			file->ef_structure = SC_FILE_EF_LINEAR_VARIABLE;
			break;
		case  0x03:
			file->ef_structure = SC_FILE_EF_CYCLIC;
			break;
		case  0x04:
#if 0
			file->ef_structure = SC_FILE_EF_PROGRAM;
#endif
			break;
		default:
			sc_error(ctx, "invalid file type: 0x%02X\n", *p);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;          
		}
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, (u8)(pos[0] & 0x0F));
			break;
		case SC_FILE_EF_LINEAR_FIXED:
		case SC_FILE_EF_LINEAR_VARIABLE:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, (u8)(pos[0] & 0x0F));
			break;
		case SC_FILE_EF_CYCLIC:
#if 0
			/* FIXME */
			file->acl[SC_AC_OP_DECREASE] = ac_to_acl(pos[0] & 0x0F);
#endif
			break;
		}
	}
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

void cache_path(struct sc_card *card, const struct sc_path *path, int result)
{
	struct sc_path *curpath = &card->cache.current_path;
	
	if (result < 0) {
		curpath->len = 0;
		return;
	}

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
			  u8 p1, struct sc_file **file_out)
{
	int r;
	struct sc_apdu apdu;
        u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
        struct sc_file *file;

	if (card->ctx->debug >= 4) {
		char	string[32];

		sc_bin_to_hex(buf, buflen, string, sizeof(string), 0);
		sc_debug(card->ctx, "called, p1=%u, path=%s\n", p1, string);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, p1, 0);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.datalen = buflen;
	apdu.data = buf;
	apdu.lc = buflen;
	apdu.le = 252;

	/* No need to get file information, if file is NULL. */
	if (file_out == NULL) {
		apdu.cse = SC_APDU_CASE_3_SHORT;
		apdu.le = 0;
	}
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	if (file_out == NULL)
                return 0;

	if (apdu.resplen < 14)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (apdu.resp[0] == 0x6F) {
		sc_error(card->ctx, "unsupported: card returned FCI\n");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED; /* FIXME */
	}
	file = sc_file_new();
	if (file == NULL)
		SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);

	/* We abuse process_fci here even though it's not the real FCI. */
	r = card->ops->process_fci(card, file, apdu.resp, apdu.resplen);
	if (r) {
                sc_file_free(file);
		return r;
	}

	*file_out = file;
        return 0;
}

static int flex_select_file(struct sc_card *card, const struct sc_path *path,
			     struct sc_file **file_out)
{
	int r;
	const u8 *pathptr = path->value;
	size_t pathlen = path->len;
	int locked = 0, magic_done;
	u8 p1 = 0;

	if (card->ctx->debug >= 2)
		sc_debug(card->ctx, "called, cached path=%s\n", sc_print_path(&card->cache.current_path));

	switch (path->type) {
	case SC_PATH_TYPE_PATH:
		if ((pathlen & 1) != 0) /* not divisible by 2 */
			return SC_ERROR_INVALID_ARGUMENTS;
		magic_done = check_path(card, &pathptr, &pathlen, file_out != NULL);
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
	r = select_file_id(card, pathptr, pathlen, p1, file_out);
	if (locked)
		sc_unlock(card);
	cache_path(card, path, r);
	SC_FUNC_RETURN(card->ctx, 2, r);
	return r;
}

static int cryptoflex_list_files(struct sc_card *card, u8 *buf, size_t buflen)
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
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
			return r;
		if (apdu.resplen != 4) {
			sc_error(card->ctx, "expected 4 bytes, got %d.\n", apdu.resplen);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}
		memcpy(buf, rbuf + 2, 2);
		buf += 2;
		count += 2;
		buflen -= 2;
	}
	return count;
}

/*
 * The Cyberflex LIST FILES command is slightly different...
 */
static int cyberflex_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	u8 rbuf[6];
	int r;
	size_t count = 0, p2 = 0;
	
	while (buflen > 2) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA8, 0, ++p2);
		apdu.le = 6;
		apdu.resplen = 6;
		apdu.resp = rbuf;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return r;
		if (apdu.sw1 == 0x6A && apdu.sw2 == 0x83)
			break;
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
			return r;
		if (apdu.resplen != 6) {
			sc_error(card->ctx, "expected 6 bytes, got %d.\n", apdu.resplen);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}
		memcpy(buf, rbuf + 4, 2);
		buf += 2;
		count += 2;
		buflen -= 2;
	}
	return count;
}

static int flex_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_apdu apdu;
	int r;

	SC_FUNC_CALLED(card->ctx, 1);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2) {
		sc_error(card->ctx, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
	if (!IS_CYBERFLEX(card))
		apdu.cla = 0xF0;	/* Override CLA byte */
	apdu.data = path->value;
	apdu.lc = 2;
	apdu.datalen = 2;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int acl_to_ac_nibble(const struct sc_acl_entry *e)
{
	if (e == NULL)
		return -1;
	if (e->next != NULL)	/* FIXME */
		return -1;
	switch (e->method) {
	case SC_AC_NONE:
		return 0x00;
	case SC_AC_CHV:
		switch (e->key_ref) {
		case 1:
			return 0x01;
			break;
		case 2:
			return 0x02;
			break;
		}
		return -1;
	case SC_AC_PRO:
		return 0x03;
	case SC_AC_AUT:
		return 0x04;
	case SC_AC_NEVER:
		return 0x0f;
	}
	return -1;
}

static int acl_to_keynum_nibble(const struct sc_acl_entry *e)
{
	while (e != NULL && e->method != SC_AC_AUT)
		e = e->next;
	if (e == NULL || e->key_ref == SC_AC_KEY_REF_NONE)
		return 0;

        return e->key_ref & 0x0F;
}

static int
cryptoflex_construct_file_attrs(sc_card_t *card, const sc_file_t *file,
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
			sc_error(card->ctx, "Invalid EF structure\n");
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
		const struct sc_acl_entry *entry;
		if (ops[i] == -1)
			continue;
		entry = sc_file_get_acl_entry(file, ops[i]);
		r = acl_to_ac_nibble(entry);
		SC_TEST_RET(card->ctx, r, "Invalid ACL value");
		/* Do some magic to get the nibbles right */
		p[8 + i/2] |= (r & 0x0F) << (((i+1) % 2) * 4);
		r = acl_to_keynum_nibble(entry);
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

static int
cyberflex_construct_file_attrs(sc_card_t *card, const sc_file_t *file,
				 u8 *buf, size_t *buflen)
{
	u8 *p = buf;
	int i;
	size_t size = file->size;
	int ops[6];

	/* cyberflex wants input parameters length added */
	switch (file->type) {
	case SC_FILE_TYPE_DF:
		size += 24;
		break;
	case SC_FILE_TYPE_WORKING_EF:
	default:
		size += 16;
		break;
	}

	sc_debug(card->ctx, "Creating %02x:%02x, size %d %02x:%02x\n", 
		 file->id >> 8,  
		 file->id & 0xFF, 
		 size, 
		 size >> 8,  
		 size & 0xFF);

	p[0] = size >> 8;
	p[1] = size & 0xFF;
	p[2] = file->id >> 8;
	p[3] = file->id & 0xFF;
	if (file->type == SC_FILE_TYPE_DF)
		p[4] = 0x20;
	else
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			p[4] = 0x02;
			break;
		case SC_FILE_EF_LINEAR_FIXED:
			p[4] = 0x0C;
			break;
		case SC_FILE_EF_LINEAR_VARIABLE:
			p[4] = 0x19;
			break;
		case SC_FILE_EF_CYCLIC:
			p[4] = 0x1D;
			break;
		default:
			sc_error(card->ctx, "Invalid EF structure\n");
			return -1;
		}
	p[5] = 0x01;	/* status?? */
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
	p[6] = p[7] = 0;
	
	*buflen = 16;

	p[8] = p[9] = p[11] = 0xFF;
	p[10] = p[12] = p[13] = p[14] = p[15] = 0x00;
	return 0;
}

static int flex_create_file(struct sc_card *card, struct sc_file *file)
{
	u8 sbuf[18];
	size_t sendlen;
	int r, rec_nr;
	struct sc_apdu apdu;
	
	/* Build the file attrs. These are not the real FCI bytes
	 * in the standard sense, but its a convenient way of
	 * abstracting the Cryptoflex/Cyberflex differences */
	r = card->ops->construct_fci(card, file, sbuf, &sendlen);
	if (r) {
		sc_error(card->ctx, "File structure encoding failed.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (file->type != SC_FILE_TYPE_DF && file->ef_structure != SC_FILE_EF_TRANSPARENT)
		rec_nr = file->record_count;
	else
		rec_nr = 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, rec_nr);
	if (!IS_CYBERFLEX(card))
		apdu.cla = 0xF0;
	apdu.data = sbuf;
	apdu.datalen = sendlen;
	apdu.lc = sendlen;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
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
	struct flex_private_data *prv = (struct flex_private_data *) card->drv_data;

	if (env->operation != SC_SEC_OPERATION_SIGN &&
	    env->operation != SC_SEC_OPERATION_DECIPHER) {
		sc_error(card->ctx, "Invalid crypto operation supplied.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->algorithm != SC_ALGORITHM_RSA) {
		sc_error(card->ctx, "Invalid crypto algorithm supplied.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if ((env->algorithm_flags & SC_ALGORITHM_RSA_PADS) ||
	    (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES)) {
	    	sc_error(card->ctx, "Card supports only raw RSA.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->key_ref_len != 1 ||
		    (env->key_ref[0] != 0 && env->key_ref[0] != 1)) {
			sc_error(card->ctx, "Invalid key reference supplied.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		prv->rsa_key_ref = env->key_ref[0];
	}
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		sc_error(card->ctx, "Algorithm reference not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
		if (memcmp(env->file_ref.value, "\x00\x12", 2) != 0) {
			sc_error(card->ctx, "File reference is not 0012.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
	return 0;
}

static int flex_restore_security_env(struct sc_card *card, int se_num)
{
	return 0;
}

static int
cryptoflex_compute_signature(sc_card_t *card, const u8 *data,
				size_t data_len, u8 * out, size_t outlen)
{
	struct flex_private_data *prv = (struct flex_private_data *) card->drv_data;
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;
	size_t i;
	
	if (data_len != 64 && data_len != 96 && data_len != 128  && data_len != 256) {
		sc_error(card->ctx, "Illegal input length: %d\n", data_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (outlen < data_len) {
		sc_error(card->ctx, "Output buffer too small.\n");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x88, 0x00, prv->rsa_key_ref);

	/* This works around a problem with some PC/SC IFD drivers that don't grok
	 * lc=00 (Chaskiel M Grundman <cg2v@andrew.cmu.edu>) */
	if (data_len == 256) {
		apdu.cla=0x10;
		apdu.lc=1;
		apdu.datalen=1;
		apdu.data = sbuf;
		sbuf[0]=data[data_len-1];
		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, r, "Card returned error");
		data_len--;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x88, 0x00, prv->rsa_key_ref);
		apdu.cla=0x0;
	}

	apdu.lc = data_len;
	apdu.datalen = data_len;
	for (i = 0; i < data_len; i++)
		sbuf[i] = data[data_len-1-i];
	apdu.data = sbuf;
	apdu.resplen = outlen > sizeof(sbuf) ? sizeof(sbuf) : outlen;
	apdu.resp = sbuf;
	apdu.sensitive = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");
	for (i = 0; i < apdu.resplen; i++)
		out[i] = sbuf[apdu.resplen-1-i];
	return apdu.resplen;
}

static int
cyberflex_compute_signature(sc_card_t *card, const u8 *data,
		size_t data_len, u8 * out, size_t outlen)
{
	struct flex_private_data *prv = DRV_DATA(card);
	struct sc_apdu apdu;
	u8 alg_id, key_id;
	int r;
	
	switch (data_len) {
	case 64:  alg_id = 0xC4; break;
	case 96:  alg_id = 0xC6; break;
	case 128: alg_id = 0xC8; break;
	default:
		sc_error(card->ctx, "Illegal input length: %d\n", data_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	key_id = prv->rsa_key_ref + 1; /* Why? */

	if (outlen < data_len) {
		sc_error(card->ctx, "Output buffer too small.\n");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x88, alg_id, key_id);

	apdu.lc = data_len;
	apdu.datalen = data_len;
	apdu.data = data;
	apdu.resplen = outlen;
	apdu.resp = out;
	apdu.sensitive = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");
	return apdu.resplen;
}

static int flex_decipher(struct sc_card *card,
			    const u8 * crgram, size_t crgram_len,
			    u8 * out, size_t outlen)
{
	/* There seems to be no Decipher command, but an RSA signature
	 * is the same operation as an RSA decryption.
	 * Of course, the (PKCS#1) padding is different, but at least
	 * a Cryptoflex 32K e-gate doesn't seem to check this. */
	return card->ops->compute_signature(card, crgram, crgram_len, out, outlen);
}

/* Return the default AAK for this type of card */
static int flex_get_default_key(struct sc_card *card,
				struct sc_cardctl_default_key *data)
{
	struct flex_private_data *prv = DRV_DATA(card);
	const char *key;

	if (data->method != SC_AC_AUT || data->key_ref != prv->aak_key_ref)
		return SC_ERROR_NO_DEFAULT_KEY;

	/* These seem to be the default AAKs used by Schlumberger */
	switch (prv->card_type & TYPE_MASK) {
	case TYPE_CRYPTOFLEX:
		key = "2c:15:e5:26:e9:3e:8a:19";
		break;
	case TYPE_CYBERFLEX:
		key = "ad:9f:61:fe:fa:20:ce:63";
		break;
	default:
		return SC_ERROR_NO_DEFAULT_KEY;
	}

	return sc_hex_to_bin(key, data->key_data, &data->len);
}

/* Generate key on-card */
static int flex_generate_key(sc_card_t *card, struct sc_cardctl_cryptoflex_genkey_info *data)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r, p1, p2;
	
	switch (data->key_bits) {
	case  512:	p2 = 0x40; break;
	case  768:	p2 = 0x60; break;
	case 1024:	p2 = 0x80; break;
	case 2048:	p2 = 0x00; break;
	default:
		sc_error(card->ctx, "Illegal key length: %d\n", data->key_bits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	p1 = data->key_num;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x46, p1, p2);
	if (!IS_CYBERFLEX(card))
		apdu.cla = 0xF0;
	apdu.data = sbuf;
	apdu.datalen = 4;
	apdu.lc = 4;

	/* Little endian representation of exponent */
	sbuf[0] = data->exponent;
	sbuf[1] = data->exponent >> 8;
	sbuf[2] = data->exponent >> 16;
	sbuf[3] = data->exponent >> 24;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	data->pubkey_len = apdu.resplen;
	return 0;
}

static int flex_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return flex_get_default_key(card,
				(struct sc_cardctl_default_key *) ptr);
	case SC_CARDCTL_CRYPTOFLEX_GENERATE_KEY:
		return flex_generate_key(card,
				(struct sc_cardctl_cryptoflex_genkey_info *) ptr);
	}

	return SC_ERROR_NOT_SUPPORTED;
}

static int flex_build_verify_apdu(struct sc_card *card, struct sc_apdu *apdu,
				  struct sc_pin_cmd_data *data)
{
	static u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r, len;
	int cla = card->cla, ins;

	switch (data->pin_type) {
	case SC_AC_CHV:
		ins = 0x20;
		break;
	case SC_AC_AUT:
		/* AUT keys cannot be entered through terminal */
		if (data->flags & SC_PIN_CMD_USE_PINPAD)
			return SC_ERROR_INVALID_ARGUMENTS;
		/* Override CLA byte */
		if (!IS_CYBERFLEX(card))
			cla = 0xF0;
		ins = 0x2A;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
        }
	/* Copy the PIN, with padding */
	if ((r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, 1)) < 0)
		return r;
	len = r;

        sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, ins, 0, data->pin_reference);
	apdu->cla = cla;
	apdu->data = sbuf;
	apdu->datalen = len;
	apdu->lc = len;
	apdu->sensitive = 1;

	return 0;
}

static void flex_init_pin_info(struct sc_pin_cmd_pin *pin, unsigned int num)
{
	pin->encoding   = SC_PIN_ENCODING_ASCII;
	pin->max_length = 8;
	pin->pad_length = 8;
	pin->offset     = 5 + num * 8;
}

static int flex_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data,
			int *tries_left)
{
	sc_apdu_t apdu;
	int r;
	int old_cla = -1;

	/* Fix pin data */
	data->flags |= SC_PIN_CMD_NEED_PADDING;
	flex_init_pin_info(&data->pin1, 0);
	flex_init_pin_info(&data->pin2, 1);

	if (data->cmd == SC_PIN_CMD_VERIFY) {
		r = flex_build_verify_apdu(card, &apdu, data);
		if (r < 0)
			return r;
		data->apdu = &apdu;
	} else if (data->cmd == SC_PIN_CMD_CHANGE || data->cmd == SC_PIN_CMD_UNBLOCK) {
		if (data->pin_type != SC_AC_CHV)
			return SC_ERROR_INVALID_ARGUMENTS;
		old_cla = card->cla;
		if (!IS_CYBERFLEX(card))
			card->cla = 0xF0;
	}

	/* According to the Cryptoflex documentation, the card
	 * does not return the number of attempts left using
	 * the 63C0xx convention, hence we don't pass the
	 * tries_left pointer. */
	r = iso_ops->pin_cmd(card, data, NULL);
	if (old_cla != -1) 
		card->cla = old_cla;
	return r;
}

static int flex_logout(struct sc_card *card)
{
	struct	sc_apdu apdu;
	int	r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0x07, 0x00);
	apdu.cla = 0xF0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}


struct sc_card_driver * sc_get_cryptoflex_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	cryptoflex_ops = *iso_ops;
	cryptoflex_ops.match_card = cryptoflex_match_card;
	cryptoflex_ops.init = flex_init;
        cryptoflex_ops.finish = flex_finish;
	cryptoflex_ops.process_fci = cryptoflex_process_file_attrs;
	cryptoflex_ops.construct_fci = cryptoflex_construct_file_attrs;
	cryptoflex_ops.select_file = flex_select_file;
	cryptoflex_ops.list_files = cryptoflex_list_files;
	cryptoflex_ops.delete_file = flex_delete_file;
	cryptoflex_ops.create_file = flex_create_file;
	cryptoflex_ops.card_ctl = flex_card_ctl;
	cryptoflex_ops.set_security_env = flex_set_security_env;
	cryptoflex_ops.restore_security_env = flex_restore_security_env;
	cryptoflex_ops.compute_signature = cryptoflex_compute_signature;
	cryptoflex_ops.decipher = flex_decipher;
	cryptoflex_ops.pin_cmd = flex_pin_cmd;
	cryptoflex_ops.logout = flex_logout;
        return &cryptoflex_drv;
}

struct sc_card_driver * sc_get_cyberflex_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	cyberflex_ops = *iso_ops;
	cyberflex_ops.match_card = cyberflex_match_card;
	cyberflex_ops.init = flex_init;
        cyberflex_ops.finish = flex_finish;
	cyberflex_ops.process_fci = cyberflex_process_file_attrs;
	cyberflex_ops.construct_fci = cyberflex_construct_file_attrs;
	cyberflex_ops.select_file = flex_select_file;
	cyberflex_ops.list_files = cyberflex_list_files;
	cyberflex_ops.delete_file = flex_delete_file;
	cyberflex_ops.create_file = flex_create_file;
	cyberflex_ops.card_ctl = flex_card_ctl;
	cyberflex_ops.set_security_env = flex_set_security_env;
	cyberflex_ops.restore_security_env = flex_restore_security_env;
	cyberflex_ops.compute_signature = cyberflex_compute_signature;
	cyberflex_ops.decipher = flex_decipher;
	cyberflex_ops.pin_cmd = flex_pin_cmd;
	cyberflex_ops.logout = flex_logout;
        return &cyberflex_drv;
}
