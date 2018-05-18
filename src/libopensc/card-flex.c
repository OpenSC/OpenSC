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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "cardctl.h"

#define FLAG_KEYGEN		0x80000000
#define IS_CYBERFLEX(card)	(card->type == SC_CARD_TYPE_FLEX_CYBER)

static struct sc_atr_table flex_atrs[] = {
	/* Cryptoflex */
	/* 8k win2000 */
	{ "3b:95:15:40:20:68:01:02:00:00", NULL, "Cryptoflex 8K", SC_CARD_TYPE_FLEX_CRYPTO, 0, NULL },
	/* 8k */
	{ "3B:95:15:40:FF:68:01:02:02:01", NULL, "Cryptoflex 8K", SC_CARD_TYPE_FLEX_CRYPTO, 0, NULL },
	/* 8k */
	{ "3B:95:15:40:FF:68:01:02:02:04", NULL, "Cryptoflex 8K", SC_CARD_TYPE_FLEX_CRYPTO, 0, NULL },
	/* 8k */
	{ "3B:85:40:20:68:01:01:05:01", NULL, "Cryptoflex 8K", SC_CARD_TYPE_FLEX_CRYPTO, 0, NULL },
	/* 16k */
	{ "3B:95:94:40:FF:63:01:01:02:01", NULL, "Cryptoflex 16K", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },
	/* "16K+SS1" alias Cryptoflex 16 card with Standard Softmask V1 */
	/* (taken from Cryptoflex Card Programmers Guide 4.5 Page xviii) */
	/* last two bytes can be ignored - version of the softmask */
	{ "3B:95:15:40:FF:63:01:01:02:01", "FF:FF:FF:FF:FF:FF:FF:FF:00:00",
		"Cryptoflex 16K", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },
	/* 32K v4 */
	/* "32K+SS1" alias Cryptoflex 32 card with Standard Softmask V1 */
	/* (taken from Cryptoflex Card Programmers Guide 4.5 Page xviii) */
	/* last two bytes can be ignored - version of the softmask */
	{ "3B:95:18:40:FF:64:02:01:01:02","FF:FF:FF:FF:FF:FF:FF:FF:00:00",
		"Cryptoflex 32K v4", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },
	/* "32K+e-gate" alias Cryptoflex e-gate 32K card */
	/* (taken from Cryptoflex Card Programmers Guide 4.5 Page xviii) */
	/* last two bytes can be ignored - version of the softmask */
	{ "3B:95:18:40:FF:62:01:01:00:00", "FF:FF:FF:FF:FF:FF:FF:FF:00:00",
		"Cryptoflex e-gate 32K", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },
	/* 32K e-gate */
	{ "3B:95:18:40:FF:62:01:02:01:04", NULL, "Cryptoflex 32K e-gate", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },
	/* 32K e-gate v4 */
	{ "3B:95:18:40:FF:62:04:01:01:05", NULL, "Cryptoflex 32K e-gate v4", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },

	/* new cryptoflex 32k card - atr looks very similar to old 8k card */
	{ "3b:95:15:40:ff:68:01:02:45:47", NULL, "Cryptoflex 32K", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },

	{ "3B:E2:00:00:40:20:49:06", NULL, "Cryptoflex", SC_CARD_TYPE_FLEX_CRYPTO, 0, NULL },
	/* + full DES option */
	{ "3B:E2:00:00:40:20:49:05", NULL, "Cryptoflex", SC_CARD_TYPE_FLEX_CRYPTO, 0, NULL },
	/* + Key Generation */
	{ "3B:E2:00:00:40:20:49:07", NULL, "Cryptoflex", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },
	/* + Key Generation */
	{ "3B:85:40:20:68:01:01:03:05", NULL, "Cryptoflex", SC_CARD_TYPE_FLEX_CRYPTO, FLAG_KEYGEN, NULL },

	/* Multiflex */
	/* 3K */
	{ "3B:02:14:50", NULL, "Multiflex 3K", SC_CARD_TYPE_FLEX_MULTI, 0, NULL },
	/* 4K */
	{ "3B:19:14:55:90:01:02:01:00:05:04:B0", NULL, "Multiflex 4K", SC_CARD_TYPE_FLEX_MULTI, 0, NULL },
	/* 8K */
	{ "3B:32:15:00:06:80", NULL, "Multiflex 8K", SC_CARD_TYPE_FLEX_MULTI, 0, NULL },
	/* 8K + full DES option */
	{ "3B:32:15:00:06:95", NULL, "Multiflex 8K", SC_CARD_TYPE_FLEX_MULTI, 0, NULL },
	/* 8K */
	{ "3B:19:14:59:01:01:0F:01:00:05:08:B0", NULL, "Multiflex 8K", SC_CARD_TYPE_FLEX_MULTI, 0, NULL },
	/* 8K */
	{ "3B:19:14:55:90:01:01:01:00:05:08:B0", NULL, "Multiflex 8K", SC_CARD_TYPE_FLEX_MULTI, 0, NULL },

	/* Cyberflex Access */
	/* Crypto */
	{ "3B:16:94:81:10:06:01:81:3F", NULL, "Cyberflex Access", SC_CARD_TYPE_FLEX_CYBER, 0, NULL },
	/* Aug. Crypto */
	{ "3B:16:94:81:10:06:01:81:2F", NULL, "Cyberflex Access", SC_CARD_TYPE_FLEX_CYBER, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

struct flex_private_data {
	int	rsa_key_ref;

	/* Support card variations without having to
	 * do the if (card->type ...) thing
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
	&cryptoflex_ops,
	NULL, 0, NULL
};
static struct sc_card_driver cyberflex_drv = {
	"Schlumberger Cyberflex",
	"cyberflex",
	&cyberflex_ops,
	NULL, 0, NULL
};

static int flex_finish(sc_card_t *card)
{
	free(card->drv_data);
	return 0;
}

static int cryptoflex_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, flex_atrs, NULL);
	if (i < 0)
		return 0;
	switch (flex_atrs[i].type) {
	case SC_CARD_TYPE_FLEX_CRYPTO:
	case SC_CARD_TYPE_FLEX_MULTI:
		card->name = flex_atrs[i].name;
		card->type = flex_atrs[i].type;
		card->flags = flex_atrs[i].flags;
		return 1;
	}
	return 0;
}

static int cyberflex_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, flex_atrs, NULL);
	if (i < 0)
		return 0;
	switch (flex_atrs[i].type) {
	case SC_CARD_TYPE_FLEX_CYBER:
		card->name = flex_atrs[i].name;
		card->type = flex_atrs[i].type;
		card->flags = flex_atrs[i].flags;
		return 1;
	}
	return 0;
}

static int flex_init(sc_card_t *card)
{
	struct flex_private_data *data;

	if (!(data = malloc(sizeof(*data))))
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = data;

	card->cla = 0xC0;
	data->aak_key_ref = 1;

	/* Override Cryptoflex defaults for specific card types */
	switch (card->type) {
	case SC_CARD_TYPE_FLEX_CYBER:
		card->cla = 0x00;
		data->aak_key_ref = 0;
		break;
	}

	/* FIXME: Card type detection */
	if (1) {
		unsigned long flags;
		
		flags = SC_ALGORITHM_RSA_RAW;
		flags |= SC_ALGORITHM_RSA_HASH_NONE;
		if (card->flags & FLAG_KEYGEN)
			flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

		_sc_card_add_rsa_alg(card, 512, flags, 0);
		_sc_card_add_rsa_alg(card, 768, flags, 0);
		_sc_card_add_rsa_alg(card, 1024, flags, 0);
		_sc_card_add_rsa_alg(card, 2048, flags, 0);
	}

	/* SCardTransmit failed: 8010002f
	 * this can be solved with a small delay. */
	msleep(100);

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
cryptoflex_get_ac_keys(sc_card_t *card, sc_file_t *file)
{
	return 0;
}

static int
cryptoflex_process_file_attrs(sc_card_t *card, sc_file_t *file,
			const u8 *buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	const u8 *p = buf + 2;
	u8 b1, b2;
	int is_mf = 0;
	
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
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "invalid file type: 0x%02X\n", *p);
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
			break;
		}
	}
	if (file->type != SC_FILE_TYPE_DF || is_mf) {
		add_acl_entry(card, file, SC_AC_OP_REHABILITATE, (u8)(p[2] >> 4));
		add_acl_entry(card, file, SC_AC_OP_INVALIDATE, (u8)(p[2] & 0x0F));
	}
	p += 3;
	if (*p)
		file->status = SC_FILE_STATUS_ACTIVATED;
	else
		file->status = SC_FILE_STATUS_INVALIDATED;

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
	int is_mf = 0;

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
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "invalid file type: 0x%02X\n", *p);
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
	p++;
	if (0 == is_mf) {
		p++;
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
			break;
		default:
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "invalid file type: 0x%02X\n", *p);
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
			break;
		}
	}
	return 0;
}

static int check_path(sc_card_t *card, const u8 **pathptr, size_t *pathlen,
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

static void cache_path(sc_card_t *card, const sc_path_t *path,
	int result)
{
	sc_path_t *curpath = &card->cache.current_path;
	
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

static int select_file_id(sc_card_t *card, const u8 *buf, size_t buflen,
			  u8 p1, sc_file_t **file_out)
{
	int r;
	sc_apdu_t apdu;
        u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
        sc_file_t *file;

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "called, p1=%u\n", p1);
	sc_debug_hex(card->ctx, SC_LOG_DEBUG_NORMAL, "path", buf, buflen);

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
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	if (file_out == NULL)
		return 0;

	if (apdu.resplen < 14)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (apdu.resp[0] == 0x6F) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unsupported: card returned FCI\n");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED; /* FIXME */
	}
	file = sc_file_new();
	if (file == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);

	/* We abuse process_fci here even though it's not the real FCI. */
	r = card->ops->process_fci(card, file, apdu.resp, apdu.resplen);
	if (r) {
		sc_file_free(file);
		return r;
	}

	*file_out = file;
	return 0;
}

static int flex_select_file(sc_card_t *card, const sc_path_t *path,
			     sc_file_t **file_out)
{
	int r;
	const u8 *pathptr = path->value;
	size_t pathlen = path->len;
	int locked = 0, magic_done;
	u8 p1 = 0;
	char pbuf[SC_MAX_PATH_STRING_SIZE];


	r = sc_path_print(pbuf, sizeof(pbuf), &card->cache.current_path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "called, cached path=%s\n", pbuf);

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
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "sc_lock() failed");
			if (!magic_done && memcmp(pathptr, "\x3F\x00", 2) != 0) {
				r = select_file_id(card, (const u8 *) "\x3F\x00", 2, 0, NULL);
				if (r)
					sc_unlock(card);
				SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Unable to select Master File (MF)");
			}
			while (pathlen > 2) {
				r = select_file_id(card, pathptr, 2, 0, NULL);
				if (r)
					sc_unlock(card);
				SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Unable to select DF");
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
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int cryptoflex_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
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
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "expected 4 bytes, got %"SC_FORMAT_LEN_SIZE_T"u.\n",
				 apdu.resplen);
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
static int cyberflex_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
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
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "expected 6 bytes, got %"SC_FORMAT_LEN_SIZE_T"u.\n",
				 apdu.resplen);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}
		memcpy(buf, rbuf + 4, 2);
		buf += 2;
		count += 2;
		buflen -= 2;
	}
	return count;
}

static int flex_delete_file(sc_card_t *card, const sc_path_t *path)
{
	sc_apdu_t apdu;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
	if (!IS_CYBERFLEX(card))
		apdu.cla = 0xF0;	/* Override CLA byte */
	apdu.data = path->value;
	apdu.lc = 2;
	apdu.datalen = 2;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int acl_to_ac_nibble(const sc_acl_entry_t *e)
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

static int acl_to_keynum_nibble(const sc_acl_entry_t *e)
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
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid EF structure\n");
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
		const sc_acl_entry_t *entry;
		if (ops[i] == -1)
			continue;
		entry = sc_file_get_acl_entry(file, ops[i]);
		r = acl_to_ac_nibble(entry);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Invalid ACL value");
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
	size_t size = file->size;

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

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "Creating %02x:%02x, size %"SC_FORMAT_LEN_SIZE_T"u %02"SC_FORMAT_LEN_SIZE_T"x:%02"SC_FORMAT_LEN_SIZE_T"x\n",
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
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid EF structure\n");
			return -1;
		}
	p[5] = 0x01;	/* status?? */
	p[6] = p[7] = 0;
	
	*buflen = 16;

	p[8] = p[9] = p[11] = 0xFF;
	p[10] = p[12] = p[13] = p[14] = p[15] = 0x00;
	return 0;
}

static int flex_create_file(sc_card_t *card, sc_file_t *file)
{
	u8 sbuf[18];
	size_t sendlen;
	int r, rec_nr;
	sc_apdu_t apdu;
	
	/* Build the file attrs. These are not the real FCI bytes
	 * in the standard sense, but its a convenient way of
	 * abstracting the Cryptoflex/Cyberflex differences */
	r = card->ops->construct_fci(card, file, sbuf, &sendlen);
	if (r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File structure encoding failed.\n");
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
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");
	if (card->cache.valid) {
		u8 file_id[2];
		
		file_id[0] = file->id >> 8;
		file_id[1] = file->id & 0xFF;
		if (card->cache.current_path.len != 0)
			sc_append_path_id(&card->cache.current_path, file_id, 2);
	}		
	return 0;
}

static int flex_set_security_env(sc_card_t *card,
				 const sc_security_env_t *env,
				 int se_num)   
{
	struct flex_private_data *prv = (struct flex_private_data *) card->drv_data;

	if (env->operation != SC_SEC_OPERATION_SIGN &&
	    env->operation != SC_SEC_OPERATION_DECIPHER) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid crypto operation supplied.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->algorithm != SC_ALGORITHM_RSA) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid crypto algorithm supplied.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if ((env->algorithm_flags & SC_ALGORITHM_RSA_PADS) ||
	    (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES)) {
	    	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Card supports only raw RSA.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->key_ref_len != 1 ||
		    (env->key_ref[0] != 0 && env->key_ref[0] != 1)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid key reference supplied.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		prv->rsa_key_ref = env->key_ref[0];
	}
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Algorithm reference not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
		if (memcmp(env->file_ref.value, "\x00\x12", 2) != 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File reference is not 0012.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
	return 0;
}

static int flex_restore_security_env(sc_card_t *card, int se_num)
{
	return 0;
}

static int
cryptoflex_compute_signature(sc_card_t *card, const u8 *data,
				size_t data_len, u8 * out, size_t outlen)
{
	struct flex_private_data *prv = (struct flex_private_data *) card->drv_data;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;
	size_t i, i2;
	
	if (data_len != 64 && data_len != 96 && data_len != 128  && data_len != 256) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			 "Illegal input length: %"SC_FORMAT_LEN_SIZE_T"u\n",
			 data_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (outlen < data_len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Output buffer too small.\n");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x00, prv->rsa_key_ref);

	/* This works around a problem with some PC/SC IFD drivers that don't grok
	 * lc=00 (Chaskiel M Grundman <cg2v@andrew.cmu.edu>) */
	if (data_len == 256) {
		apdu.cla=0x10;
		apdu.cse= SC_APDU_CASE_3_SHORT;
		apdu.lc=10;
		apdu.datalen=10;
		apdu.data = sbuf;
		for (i2 = 0; i2 < 10; i2++)
			sbuf[i2]=data[data_len-1-i2];
		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");
		data_len -= 10;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x00, prv->rsa_key_ref);
		apdu.cla=0x0;
	}

	apdu.lc = data_len;
	apdu.datalen = data_len;
	for (i = 0; i < data_len; i++)
		sbuf[i] = data[data_len-1-i];
	apdu.data = sbuf;
	apdu.resplen = outlen > sizeof(sbuf) ? sizeof(sbuf) : outlen;
	apdu.le      = apdu.resplen > 256 ? 256 : apdu.resplen;
	apdu.resp    = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");
	for (i = 0; i < apdu.resplen; i++)
		out[i] = sbuf[apdu.resplen-1-i];
	return apdu.resplen;
}

static int
cyberflex_compute_signature(sc_card_t *card, const u8 *data,
		size_t data_len, u8 * out, size_t outlen)
{
	struct flex_private_data *prv = DRV_DATA(card);
	sc_apdu_t apdu;
	u8 alg_id, key_id;
	int r;
	
	switch (data_len) {
	case 64:  alg_id = 0xC4; break;
	case 96:  alg_id = 0xC6; break;
	case 128: alg_id = 0xC8; break;
	default:
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			 "Illegal input length: %"SC_FORMAT_LEN_SIZE_T"u\n",
			 data_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	key_id = prv->rsa_key_ref + 1; /* Why? */

	if (outlen < data_len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Output buffer too small.\n");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x88, alg_id, key_id);

	apdu.lc = data_len;
	apdu.datalen = data_len;
	apdu.data = data;
	apdu.resplen = outlen;
	apdu.resp = out;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");
	return apdu.resplen;
}

static int flex_decipher(sc_card_t *card,
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
static int flex_get_default_key(sc_card_t *card,
				struct sc_cardctl_default_key *data)
{
	struct flex_private_data *prv = DRV_DATA(card);
	const char *key;

	if (data->method != SC_AC_AUT || data->key_ref != prv->aak_key_ref)
		return SC_ERROR_NO_DEFAULT_KEY;

	/* These seem to be the default AAKs used by Schlumberger */
	switch (card->type) {
	case SC_CARD_TYPE_FLEX_CRYPTO:
		key = "2c:15:e5:26:e9:3e:8a:19";
		break;
	case SC_CARD_TYPE_FLEX_CYBER:
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
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r, p1, p2;
	
	switch (data->key_bits) {
	case  512:	p2 = 0x40; break;
	case  768:	p2 = 0x60; break;
	case 1024:	p2 = 0x80; break;
	case 2048:	p2 = 0x00; break;
	default:
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Illegal key length: %d\n", data->key_bits);
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
	sbuf[0] = data->exponent & 0xFF;
	sbuf[1] = (data->exponent >> 8) & 0xFF;
	sbuf[2] = (data->exponent >> 16) & 0xFF;
	sbuf[3] = (data->exponent >> 24) & 0xFF;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	data->pubkey_len = apdu.resplen;
	return 0;
}

/* read the card serial number from the EF_gdo system file */
static int flex_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int       r;
	u8        buf[16];
	size_t    len;
	sc_path_t tpath;
	sc_file_t *tfile = NULL;

	if (!serial)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* see if we have cached serial number */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		return SC_SUCCESS;
	}
	/* read EF_ICCSN */
	sc_format_path("3F000002", &tpath);
	r = sc_select_file(card, &tpath, &tfile);
	if (r < 0)
		return r;
	len = tfile->size;
	sc_file_free(tfile);
	if (len != 8) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unexpected file length of EF_ICCSN (%lu)\n",
			(unsigned long) len);
		return SC_ERROR_INTERNAL;
	}
	r = sc_read_binary(card, 0, buf, len, 0);
	if (r < 0)
		return r;
	card->serialnr.len = len;	
	memcpy(card->serialnr.value, buf, len);

	memcpy(serial, &card->serialnr, sizeof(*serial));

	return SC_SUCCESS;
}

static int flex_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return flex_get_default_key(card,
				(struct sc_cardctl_default_key *) ptr);
	case SC_CARDCTL_CRYPTOFLEX_GENERATE_KEY:
		return flex_generate_key(card,
				(struct sc_cardctl_cryptoflex_genkey_info *) ptr);
	case SC_CARDCTL_GET_SERIALNR:
		return flex_get_serialnr(card, (sc_serial_number_t *) ptr);
	}

	return SC_ERROR_NOT_SUPPORTED;
}

static int flex_build_verify_apdu(sc_card_t *card, sc_apdu_t *apdu,
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

	return 0;
}

static void flex_init_pin_info(struct sc_pin_cmd_pin *pin, unsigned int num)
{
	pin->encoding   = SC_PIN_ENCODING_ASCII;
	pin->min_length = 4;
	pin->max_length = 8;
	pin->pad_length = 8;
	pin->offset     = 5 + num * 8;
}

static int flex_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
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

static int flex_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	int	r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0x07, 0x00);
	apdu.cla = 0xF0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
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
