/*
 * card-itacns.c: Support for Italian CNS
 *
 * Copyright (C) 2008-2010	Emanuele Pucciarelli <ep@acm.org>
 * Copyright (C) 2005  		ST Incard srl, Giuseppe Amato <giuseppe dot amato at st dot com>, <midori3@gmail.com>
 * Copyright (C) 2002  		Andreas Jellinghaus <aj@dungeon.inka.de>
 * Copyright (C) 2001  		Juha Yrjölä <juha.yrjola@iki.fi>
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

/*
 * Specifications for the development of this driver come from:
 * http://www.cnipa.gov.it/html/docs/CNS%20Functional%20Specification%201.1.5_11012010.pdf
 */

#include "internal.h"
#include "cardctl.h"
#include "itacns.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#define ITACNS_MAX_PAYLOAD 0xff

static const struct sc_card_operations *default_ops = NULL;

static struct sc_card_operations itacns_ops;
static struct sc_card_driver itacns_drv = {
	"Italian CNS",
	"itacns",
	&itacns_ops,
	NULL, 0, NULL
};

/*
 * Card matching
 */


/* List of ATR's for "hard" matching. */
static struct sc_atr_table itacns_atrs[] = {
	{ "3b:f4:18:00:ff:81:31:80:55:00:31:80:00:c7", NULL, NULL,
		SC_CARD_TYPE_ITACNS_CIE_V1, 0, NULL},
	{ NULL, NULL, NULL, 0, 0, NULL}
};

/* Output debug info */
#define matchdebug(idx, c) do { \
	sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, \
		"Matching %x against atr[%d] == %x", c, idx, atr[idx]); \
	} while(0);

/* Check that we are not looking at values beyond the ATR's length.
 * If we are, then the card does not match. */
#define itacns_atr_l(idx) do {if (idx >= card->atr.len) return 0;} while(0);

/* Match byte exactly and increment index. */
#define itacns_atr_match(idx, c) do { \
		itacns_atr_l(idx); \
		matchdebug(idx, c); \
		if (((u8)atr[idx]) != c) return 0; \
		idx++; \
	} while(0);

/* Match masked bits and increment index. */
#define itacns_atr_mmatch(idx, c, mask) do { \
		itacns_atr_l(idx); \
		if ((((u8)atr[idx]) & mask) != c) return 0; \
		idx ++; \
	} while(0);

/* Macro to access private driver data. */
#define DRVDATA(card) ((itacns_drv_data_t *) card->drv_data)


static int itacns_match_cns_card(sc_card_t *card, unsigned int i)
{
	unsigned char *atr = card->atr.value;
	sc_context_t *ctx;
	ctx = card->ctx;


	itacns_atr_match(i, 0x01); /* H7 */
	i += 2; /* H8, H9 */
	itacns_atr_match(i, 'C'); /* H10 */
	itacns_atr_match(i, 'N'); /* H11 */
	itacns_atr_match(i, 'S'); /* H12 */

	/* H13 */
	/* Version byte: h.l, h in the high nibble, l in the low nibble. */
	if(card->driver) {
		DRVDATA(card)->cns_version = atr[i];
	}
	/* Warn if the version is not 1.0. */
	if(atr[i] != 0x10) {
		char version[8];
		snprintf(version, sizeof(version), "%d.%d", (atr[i] >> 4) & 0x0f, atr[i] & 0x0f);
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "CNS card version %s; no official specifications "
			"are published. Proceeding anyway.\n", version);
	}
	i++;

	itacns_atr_match(i, 0x31); /* H14 */
	itacns_atr_match(i, 0x80); /* H15 */

	card->type = SC_CARD_TYPE_ITACNS_CNS;

	return 1;
}

static int itacns_match_cie_card(sc_card_t *card, unsigned int i)
{
	unsigned char *atr = card->atr.value;
	sc_context_t *ctx;
	ctx = card->ctx;

	itacns_atr_match(i, 0x02); /* H7 */
	itacns_atr_match(i, 'I'); /* H8 */
	itacns_atr_match(i, 'T'); /* H9 */
	itacns_atr_match(i, 'I'); /* H10 */
	itacns_atr_match(i, 'D'); /* H11 */
	itacns_atr_match(i, 0x20); /* H12 */
	itacns_atr_match(i, 0x20); /* H13 */
	itacns_atr_match(i, 0x31); /* H14 */
	itacns_atr_match(i, 0x80); /* H15 */

	card->type = SC_CARD_TYPE_ITACNS_CIE_V2;

	return 1;
}

static int itacns_match_card(sc_card_t *card)
{
	unsigned int i = 0;
	int r;
	unsigned char *atr = card->atr.value;
	int td1_idx;
	sc_context_t *ctx;
	ctx = card->ctx;

	/* Try table first */
	r = _sc_match_atr(card, itacns_atrs, &card->type);
	if(r >= 0) return 1;

	/* The ATR was not recognized; try to match it
	   according to the official specs. */

	/* Check ATR up to byte H6 */
	itacns_atr_match(i, 0x3b); /* TS */
	itacns_atr_mmatch(i, 0x8f, 0x8f); /* T0 */
	/* TA1, TB1, TC1 */
	if(atr[1] & 0x40) i++;
	if(atr[1] & 0x20) i++;
	if(atr[1] & 0x10) i++;
	/* TD1 */
	td1_idx = i;
	itacns_atr_mmatch(i, 0x81, 0x8f);
	/* TA2, TB2, TC2 */
	if(atr[td1_idx] & 0x40) i++;
	if(atr[td1_idx] & 0x20) i++;
	if(atr[td1_idx] & 0x10) i++;
	/* TD2 */
	itacns_atr_match(i, 0x31);
	i += 2; /* TA3, TB3 */
	itacns_atr_match(i, 0x00); /* H1 */
	itacns_atr_match(i, 0x6b); /* H2 */
	/* Store interesting data */
	if(card->driver) {
		DRVDATA(card)->ic_manufacturer_code = card->atr.value[i];
		DRVDATA(card)->mask_manufacturer_code = card->atr.value[i+1];
		DRVDATA(card)->os_version_h = card->atr.value[i+2];
		DRVDATA(card)->os_version_l = card->atr.value[i+3];
	}
	i += 4; /* H3, H4, H5, H6 */

	/* Check final part. */
	if (itacns_match_cns_card(card, i)) return 1;
	if (itacns_match_cie_card(card, i)) return 1;

	/* No card type was matched. */
	return 0;
}

/*
 * Initialization and termination
 */

static int itacns_init(sc_card_t *card)
{
	unsigned long	flags;

	SC_FUNC_CALLED(card->ctx, 1);

	card->name = "CNS card";
	card->cla = 0x00;

	card->drv_data = calloc(1, sizeof(itacns_drv_data_t));
	if (!card->drv_data)
		return SC_ERROR_OUT_OF_MEMORY;

	/* Match ATR again to find the card data. */
	itacns_match_card(card);

	/* Set up algorithm info. */
	flags = SC_ALGORITHM_NEED_USAGE
		| SC_ALGORITHM_RSA_RAW
		| SC_ALGORITHM_RSA_HASHES
		;
	_sc_card_add_rsa_alg(card, 1024, flags, 0);

	return SC_SUCCESS;
}

static int itacns_finish(struct sc_card *card)
{
	if(card->drv_data) {
		free(card->drv_data);
	}
	return 0;
}



/*
 * Restore the indicated SE
 */
static int itacns_restore_security_env(sc_card_t *card, int se_num)
{
	sc_apdu_t apdu;
	int	r;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

	SC_FUNC_CALLED(card->ctx, 1);

	/*
	 * The Italian CNS requires a 0-valued Lc byte at the end of the APDU
	 * (see paragraph 13.14 of the Functional Specification), but since
	 * it is invalid, we "cheat" and pretend it's a Le byte.
	 *
	 * For this workaround, we must allocate and supply a response buffer,
	 * even though we know it will not be used (we don't even check it).
	 */

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x22, 0xF3, se_num);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * Set the security context
 * Things get a little messy here. It seems you cannot do any
 * crypto without a security environment - but there isn't really
 * a way to specify the security environment in PKCS15.
 * What I'm doing here (for now) is to assume that for a key
 * object with ID 0xNN there is always a corresponding SE object
 * with the same ID.
 * XXX Need to find out how the Aladdin drivers do it.
 */
static int itacns_set_security_env(sc_card_t *card,
		    const sc_security_env_t *env, int se_num)
{
	sc_apdu_t apdu;
	u8	data[3];
	int	key_id, r;
	
	/* Do not complain about se_num; the argument is part of the API. */
	(void) se_num;

	assert(card != NULL && env != NULL);

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	 || env->key_ref_len != 1) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"No or invalid key reference\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	key_id = env->key_ref[0];

	/* CIE v1 cards need to restore security environment 0x30; all the others
	   so far want 0x03. */
	r = itacns_restore_security_env(card,
		(card->type == SC_CARD_TYPE_ITACNS_CIE_V1 ? 0x30 : 0x03));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF1, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	case SC_SEC_OPERATION_AUTHENTICATE:
		apdu.p2 = 0xA4;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		"Setting sec env for key_id=%d\n", key_id);

	data[0] = 0x83;
	data[1] = 0x01;
	data[2] = key_id;
	apdu.lc = apdu.datalen = 3;
	apdu.data = data;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * The 0x80 thing tells the card it's okay to search parent
 * directories as well for the referenced object.
 * This is necessary for some Italian CNS cards, and to be avoided
 * for others. Right now it seems that it is only needed with
 * cards by STIncard.
 */
static int
itacns_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
		 int *tries_left)
{
	data->flags |= SC_PIN_CMD_NEED_PADDING;
	/* Enable backtracking for STIncard cards. */
	if(DRVDATA(card)->mask_manufacturer_code == ITACNS_MASKMAN_STINCARD) {
		data->pin_reference |= 0x80;
	}

	/* FIXME: the following values depend on what pin length was
	 * used when creating the BS objects */
	if (data->pin1.max_length == 0)
		data->pin1.max_length = 8;
	if (data->pin2.max_length == 0)
		data->pin2.max_length = 8;
	return default_ops->pin_cmd(card, data, tries_left);
}

static int itacns_read_binary(sc_card_t *card,
			       unsigned int idx, u8 *buf, size_t count,
			       unsigned long flags)
{
	size_t already_read = 0;
	int requested;
	int r;
	while(1) {
		requested = count - already_read;
		if(requested > ITACNS_MAX_PAYLOAD)
			requested = ITACNS_MAX_PAYLOAD;
		r = default_ops->read_binary(card, idx+already_read,
			&buf[already_read], requested, flags);
		if(r < 0) return r;
		already_read += r;
		if (r == 0 || r < requested || already_read == count) {
			/* We have finished */
			return already_read;
		}
	}
}

static int itacns_list_files(sc_card_t *card, u8 *buf, size_t buflen) {
	struct sc_card_operations *list_ops;

	if (DRVDATA(card) && (DRVDATA(card)->mask_manufacturer_code
		== ITACNS_MASKMAN_SIEMENS)) {
		list_ops = sc_get_cardos_driver()->ops;
	} else {
		list_ops = sc_get_incrypto34_driver()->ops;
	}
	return list_ops->list_files(card, buf, buflen);
}

static void add_acl_entry(sc_file_t *file, int op, u8 byte)
{
	unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

	switch (byte) {
	case 0x00:
		method = SC_AC_NONE;
		break;
	case 0xFF:
	case 0x66:
		method = SC_AC_NEVER;
		break;
	default:
		if (byte > 0x1F) {
			method = SC_AC_UNKNOWN;
		} else {
			method = SC_AC_CHV;
			key_ref = byte;
		}
		break;
	}
	sc_file_add_acl_entry(file, op, method, key_ref);
}

static const int df_acl[9] = {
	-1,			/* LCYCLE (life cycle change) */
	SC_AC_OP_UPDATE,	/* UPDATE Objects */
	SC_AC_OP_WRITE,		/* APPEND Objects */

	SC_AC_OP_INVALIDATE,	/* DF */
	SC_AC_OP_REHABILITATE,	/* DF */
	SC_AC_OP_DELETE,	/* DF */

	SC_AC_OP_WRITE,		/* ADMIN DF */
	SC_AC_OP_CREATE,	/* Files */
	-1			/* Reserved */
};
static const int ef_acl[9] = {
	SC_AC_OP_READ,		/* Data */
	SC_AC_OP_UPDATE,	/* Data (write file content) */
	SC_AC_OP_WRITE,		/* */

	SC_AC_OP_INVALIDATE,	/* EF */
	SC_AC_OP_REHABILITATE,	/* EF */
	SC_AC_OP_ERASE,		/* (delete) EF */

	/* XXX: ADMIN should be an ACL type of its own, or mapped
	 * to erase */
	SC_AC_OP_ERASE,		/* ADMIN EF (modify meta information?) */
	-1,			/* INC (-> cylic fixed files) */
	-1			/* DEC */
};

static void parse_sec_attr(sc_file_t *file, const u8 *buf, size_t len)
{
	size_t i;
	const int *idx;

	idx = (file->type == SC_FILE_TYPE_DF) ?  df_acl : ef_acl;

	/* acl defaults to 0xFF if unspecified */
	for (i = 0; i < 9; i++) {
		if (idx[i] != -1) {
			add_acl_entry(file, idx[i],
				(u8)((i < len) ? buf[i] : 0xFF));
		}
	}
}

static int itacns_select_file(sc_card_t *card,
			      const sc_path_t *in_path,
			      sc_file_t **file)
{
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	r = default_ops->select_file(card, in_path, file);
	if (r >= 0 && file) {
		parse_sec_attr((*file), (*file)->sec_attr,
			(*file)->sec_attr_len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int itacns_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	sc_path_t path;
	sc_file_t *file;
	size_t    len;
	int r;
	u8        rbuf[256];

	if (!serial) return SC_ERROR_INVALID_ARGUMENTS;

	/* see if we have cached serial number */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		return SC_SUCCESS;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Reading EF_IDCarta.\n");

	sc_format_path("3F0010001003", &path);

	r = sc_select_file(card, &path, &file);
	if (r != SC_SUCCESS) {
		return SC_ERROR_WRONG_CARD;
	}
	len = file->size;

	//Returned file->size should be 16. 
	//We choose to not consider it as critical, because some cards 
	//do not return FCI/FCP templates that include the file size.
	//Notify abnormal length anyway.
	if (len != 16) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, 
				"Unexpected file length of EF_IDCarta (%lu)\n",
				(unsigned long) len);
	}

	r = sc_read_binary(card, 0, rbuf, 256, 0);
	if ( r != 16 ) {
		return SC_ERROR_WRONG_CARD;
	}

	/* cache serial number */
	memcpy(card->serialnr.value, rbuf, 16);
	card->serialnr.len = 16;
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));

	return SC_SUCCESS;
}

static int
itacns_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
		case SC_CARDCTL_GET_SERIALNR:
		return itacns_get_serialnr(card, ptr);
	}
	return SC_ERROR_NOT_SUPPORTED;
}

static struct sc_card_driver * sc_get_driver(void)
{
	if (!default_ops)
		default_ops = sc_get_iso7816_driver()->ops;
	itacns_ops = *default_ops;
	itacns_ops.match_card = itacns_match_card;
	itacns_ops.init = itacns_init;
	itacns_ops.finish = itacns_finish;
	itacns_ops.set_security_env = itacns_set_security_env;
	itacns_ops.restore_security_env = itacns_restore_security_env;
	itacns_ops.pin_cmd = itacns_pin_cmd;
	itacns_ops.read_binary = itacns_read_binary;
	itacns_ops.list_files = itacns_list_files;
	itacns_ops.select_file = itacns_select_file;
	itacns_ops.card_ctl = itacns_card_ctl;
	return &itacns_drv;
}

struct sc_card_driver * sc_get_itacns_driver(void)
{
	return sc_get_driver();
}
