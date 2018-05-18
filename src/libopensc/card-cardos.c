/*
 * card-cardos.c: Support for CardOS (from Siemens or Atos) based cards and
 * tokens (for example Aladdin eToken PRO, Eutron CryptoIdentity IT-SEC)
 *
 * Copyright (c) 2005  Nils Larsch <nils@larsch.net>
 * Copyright (C) 2002  Andreas Jellinghaus <aj@dungeon.inka.de>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations cardos_ops;
static struct sc_card_driver cardos_drv = {
	"Siemens CardOS",
	"cardos",
	&cardos_ops,
	NULL, 0, NULL
};

static struct sc_atr_table cardos_atrs[] = {
	/* 4.0 */
	{ "3b:e2:00:ff:c1:10:31:fe:55:c8:02:9c", NULL, NULL, SC_CARD_TYPE_CARDOS_GENERIC, 0, NULL },
	/* Italian eID card, postecert */
	{ "3b:e9:00:ff:c1:10:31:fe:55:00:64:05:00:c8:02:31:80:00:47", NULL, NULL, SC_CARD_TYPE_CARDOS_CIE_V1, 0, NULL },
	/* Italian eID card, infocamere */
	{ "3b:fb:98:00:ff:c1:10:31:fe:55:00:64:05:20:47:03:31:80:00:90:00:f3", NULL, NULL, SC_CARD_TYPE_CARDOS_GENERIC, 0, NULL },
	/* Another Italian InfocamereCard */
	{ "3b:fc:98:00:ff:c1:10:31:fe:55:c8:03:49:6e:66:6f:63:61:6d:65:72:65:28", NULL, NULL, SC_CARD_TYPE_CARDOS_GENERIC, 0, NULL },
	{ "3b:f4:98:00:ff:c1:10:31:fe:55:4d:34:63:76:b4", NULL, NULL, SC_CARD_TYPE_CARDOS_GENERIC, 0, NULL},
	/* cardos m4.2 and above */
	{ "3b:f2:18:00:ff:c1:0a:31:fe:55:c8:06:8a", "ff:ff:0f:ff:00:ff:00:ff:ff:00:00:00:00", NULL, SC_CARD_TYPE_CARDOS_M4_2, 0, NULL },
	/* CardOS 4.4 */
	{ "3b:d2:18:02:c1:0a:31:fe:58:c8:0d:51", NULL, NULL, SC_CARD_TYPE_CARDOS_M4_4, 0, NULL},
	/* CardOS v5.0 */
	{ "3b:d2:18:00:81:31:fe:58:c9:01:14", NULL, NULL, SC_CARD_TYPE_CARDOS_V5_0, 0, NULL},
	/* CardOS v5.3 */
	{ "3b:d2:18:00:81:31:fe:58:c9:02:17", NULL, NULL, SC_CARD_TYPE_CARDOS_V5_0, 0, NULL},
	{ "3b:d2:18:00:81:31:fe:58:c9:03:16", NULL, NULL, SC_CARD_TYPE_CARDOS_V5_0, 0, NULL},
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static unsigned int algorithm_ids_in_tokeninfo[SC_MAX_SUPPORTED_ALGORITHMS];
static unsigned int algorithm_ids_in_tokeninfo_count=0;

static int cardos_match_card(sc_card_t *card)
{
	unsigned char atr[SC_MAX_ATR_SIZE];
	int i;

	i = _sc_match_atr(card, cardos_atrs, &card->type);
	if (i < 0)
		return 0;

	memcpy(atr, card->atr.value, sizeof(atr));

	/* Do not change card type for CIE! */
	if (card->type == SC_CARD_TYPE_CARDOS_CIE_V1)
		return 1;
	if (card->type == SC_CARD_TYPE_CARDOS_M4_4)
		return 1;
	if (card->type == SC_CARD_TYPE_CARDOS_V5_0)
		return 1;
	if (card->type == SC_CARD_TYPE_CARDOS_M4_2) {
		int rv;
		sc_apdu_t apdu;
		u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
		/* first check some additional ATR bytes */
		if ((atr[4] != 0xff && atr[4] != 0x02) ||
		    (atr[6] != 0x10 && atr[6] != 0x0a) ||
		    (atr[9] != 0x55 && atr[9] != 0x58))
			return 0;
		/* get the os version using GET DATA and compare it with
		 * version in the ATR */
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "checking cardos version ...");
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x82);
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;
		apdu.lc = 0;
		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			return 0;
		if (apdu.resp[0] != atr[10] ||
		    apdu.resp[1] != atr[11])
			/* version mismatch */
			return 0;
		if (atr[11] <= 0x04) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "found cardos m4.01");
			card->type = SC_CARD_TYPE_CARDOS_M4_01;
		} else if (atr[11] == 0x08) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "found cardos v4.3b");
			card->type = SC_CARD_TYPE_CARDOS_M4_3;
		} else if (atr[11] == 0x09) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "found cardos v4.2b");
			card->type = SC_CARD_TYPE_CARDOS_M4_2B;
		} else if (atr[11] >= 0x0B) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "found cardos v4.2c or higher");
			card->type = SC_CARD_TYPE_CARDOS_M4_2C;
		} else {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "found cardos m4.2");
		}
	}
	return 1;
}

static int cardos_have_2048bit_package(sc_card_t *card)
{
	sc_apdu_t apdu;
        u8        rbuf[SC_MAX_APDU_BUFFER_SIZE];
        int       r;
	const u8  *p = rbuf, *q;
	size_t    len, tlen = 0, ilen = 0;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x88);
	apdu.resp    = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	if ((len = apdu.resplen) == 0)
		/* looks like no package has been installed  */
		return 0;

	while (len != 0) {
		p = sc_asn1_find_tag(card->ctx, p, len, 0xe1, &tlen);
		if (p == NULL)
			return 0;
		q = sc_asn1_find_tag(card->ctx, p, tlen, 0x01, &ilen);
		if (q == NULL || ilen != 4)
			return 0;
		if (q[0] == 0x1c)
			return 1;
		p   += tlen;
		len -= tlen + 2;
	}

	return 0;
}

static int cardos_init(sc_card_t *card)
{
	unsigned long	flags, rsa_2048 = 0;
	size_t data_field_length;
	sc_apdu_t apdu;
	u8 rbuf[2];

	card->name = "Atos CardOS";
	card->cla = 0x00;

	/* Set up algorithm info. */
	flags = SC_ALGORITHM_RSA_RAW
		| SC_ALGORITHM_RSA_HASH_NONE
		| SC_ALGORITHM_ONBOARD_KEY_GEN
		;
	if (card->type != SC_CARD_TYPE_CARDOS_V5_0)
		flags |= SC_ALGORITHM_NEED_USAGE;

	_sc_card_add_rsa_alg(card,  512, flags, 0);
	_sc_card_add_rsa_alg(card,  768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);

	if (card->type == SC_CARD_TYPE_CARDOS_M4_2) {
		int r = cardos_have_2048bit_package(card);
		if (r < 0)
			return r;
		if (r == 1)
			rsa_2048 = 1;
		card->caps |= SC_CARD_CAP_APDU_EXT;
	} else if (card->type == SC_CARD_TYPE_CARDOS_M4_3 
		|| card->type == SC_CARD_TYPE_CARDOS_M4_2B
		|| card->type == SC_CARD_TYPE_CARDOS_M4_2C
		|| card->type == SC_CARD_TYPE_CARDOS_M4_4
		|| card->type == SC_CARD_TYPE_CARDOS_V5_0) {
		rsa_2048 = 1;
		card->caps |= SC_CARD_CAP_APDU_EXT;
	}

	/* probe DATA FIELD LENGTH with GET DATA */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x8D);
	apdu.le = sizeof rbuf;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,
			sc_transmit_apdu(card, &apdu),
			"APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,
			sc_check_sw(card, apdu.sw1, apdu.sw2),
			"GET DATA command returned error");
	if (apdu.resplen != 2)
		return SC_ERROR_WRONG_LENGTH;
	data_field_length = ((rbuf[0] << 8) | rbuf[1]);

	/* strip the length of possible Lc and Le bytes */
	if (card->caps & SC_CARD_CAP_APDU_EXT)
		card->max_send_size = data_field_length - 6;
	else
		card->max_send_size = data_field_length - 3;
	/* strip the length of SW bytes */
	card->max_recv_size = data_field_length - 2;

	if (rsa_2048 == 1) {
		_sc_card_add_rsa_alg(card, 1280, flags, 0);
		_sc_card_add_rsa_alg(card, 1536, flags, 0);
		_sc_card_add_rsa_alg(card, 1792, flags, 0);
		_sc_card_add_rsa_alg(card, 2048, flags, 0);
	}

	if (card->type == SC_CARD_TYPE_CARDOS_V5_0) {
		/* Starting with CardOS 5, the card supports PIN query commands */
		card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;
	}

	return 0;
}

static const struct sc_card_error cardos_errors[] = {
/* some error inside the card */
/* i.e. nothing you can do */
{ 0x6581, SC_ERROR_MEMORY_FAILURE,	"EEPROM error; command aborted"}, 
{ 0x6fff, SC_ERROR_CARD_CMD_FAILED,	"internal assertion error"},
{ 0x6700, SC_ERROR_WRONG_LENGTH,	"LC invalid"}, 
{ 0x6985, SC_ERROR_CARD_CMD_FAILED,	"no random number available"}, 
{ 0x6f81, SC_ERROR_CARD_CMD_FAILED,	"file invalid, maybe checksum error"}, 
{ 0x6f82, SC_ERROR_CARD_CMD_FAILED,	"not enough memory in xram"}, 
{ 0x6f84, SC_ERROR_CARD_CMD_FAILED,	"general protection fault"}, 

/* the card doesn't know this combination of ins+cla+p1+p2 */
/* i.e. command will never work */
{ 0x6881, SC_ERROR_NO_CARD_SUPPORT,	"logical channel not supported"}, 
{ 0x6a86, SC_ERROR_INCORRECT_PARAMETERS,"p1/p2 invalid"}, 
{ 0x6d00, SC_ERROR_INS_NOT_SUPPORTED,	"ins invalid"}, 
{ 0x6e00, SC_ERROR_CLASS_NOT_SUPPORTED,	"class invalid (hi nibble)"}, 

/* known command, but incorrectly used */
/* i.e. command could work, but you need to change something */
{ 0x6981, SC_ERROR_CARD_CMD_FAILED,	"command cannot be used for file structure"}, 
{ 0x6a80, SC_ERROR_INCORRECT_PARAMETERS,"invalid parameters in data field"}, 
{ 0x6a81, SC_ERROR_NOT_SUPPORTED,	"function/mode not supported"}, 
{ 0x6a85, SC_ERROR_INCORRECT_PARAMETERS,"lc does not fit the tlv structure"}, 
{ 0x6986, SC_ERROR_INCORRECT_PARAMETERS,"no current ef selected"}, 
{ 0x6a87, SC_ERROR_INCORRECT_PARAMETERS,"lc does not fit p1/p2"}, 
{ 0x6c00, SC_ERROR_WRONG_LENGTH,	"le does not fit the data to be sent"}, 
{ 0x6f83, SC_ERROR_CARD_CMD_FAILED,	"command must not be used in transaction"}, 

/* (something) not found */
{ 0x6987, SC_ERROR_INCORRECT_PARAMETERS,"key object for sm not found"}, 
{ 0x6f86, SC_ERROR_CARD_CMD_FAILED,	"key object not found"}, 
{ 0x6a82, SC_ERROR_FILE_NOT_FOUND,	"file not found"}, 
{ 0x6a83, SC_ERROR_RECORD_NOT_FOUND,	"record not found"}, 
{ 0x6a88, SC_ERROR_CARD_CMD_FAILED,	"object not found"}, 

/* (something) invalid */
{ 0x6884, SC_ERROR_CARD_CMD_FAILED,	"chaining error"}, 
{ 0x6984, SC_ERROR_CARD_CMD_FAILED,	"bs object has invalid format"}, 
{ 0x6988, SC_ERROR_INCORRECT_PARAMETERS,"key object used for sm has invalid format"}, 

/* (something) deactivated */
{ 0x6283, SC_ERROR_CARD_CMD_FAILED,	"file is deactivated"	},
{ 0x6983, SC_ERROR_AUTH_METHOD_BLOCKED,	"bs object blocked"}, 

/* access denied */
{ 0x6300, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,"authentication failed"}, 
{ 0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,"required access right not granted"}, 

/* other errors */
{ 0x6a84, SC_ERROR_CARD_CMD_FAILED,	"not enough memory"}, 

/* command ok, execution failed */
{ 0x6f00, SC_ERROR_CARD_CMD_FAILED,	"technical error (see eToken developers guide)"}, 

/* no error, maybe a note */
{ 0x9000, SC_SUCCESS,		NULL}, 
{ 0x9001, SC_SUCCESS,		"success, but eeprom weakness detected"}, 
{ 0x9850, SC_SUCCESS,		"over/underflow using in/decrease"}
};

static int cardos_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
	const int err_count = sizeof(cardos_errors)/sizeof(cardos_errors[0]);
	int i;
			        
	for (i = 0; i < err_count; i++) {
		if (cardos_errors[i].SWs == ((sw1 << 8) | sw2)) {
			if ( cardos_errors[i].errorstr ) 
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "%s\n",
				 	cardos_errors[i].errorstr);
			return cardos_errors[i].errorno;
		}
	}

        sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
	return SC_ERROR_CARD_CMD_FAILED;
}

static int cardos_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
	u8        rbuf[256], offset = 0;
	const u8  *p = rbuf, *q;
	int       r;
	size_t    fids = 0, len;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* 0x16: DIRECTORY */
	/* 0x02: list both DF and EF */

get_next_part:
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x16, 0x02, offset);
	apdu.cla = 0x80;
	apdu.le = 256;
	apdu.resplen = 256;
	apdu.resp = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "DIRECTORY command returned error");

	if (apdu.resplen > 256) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "directory listing > 256 bytes, cutting");
	}

	len = apdu.resplen;
	while (len != 0) {
		size_t   tlen = 0, ilen = 0;
		/* is there a file information block (0x6f) ? */
		p = sc_asn1_find_tag(card->ctx, p, len, 0x6f, &tlen);
		if (p == NULL) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "directory tag missing");
			return SC_ERROR_INTERNAL;
		}
		if (tlen == 0)
			/* empty directory */
			break;
		q = sc_asn1_find_tag(card->ctx, p, tlen, 0x86, &ilen);
		if (q == NULL || ilen != 2) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "error parsing file id TLV object");
			return SC_ERROR_INTERNAL;
		}
		/* put file id in buf */
		if (buflen >= 2) {
			buf[fids++] = q[0];
			buf[fids++] = q[1];
			buflen -= 2;
		} else
			/* not enough space left in buffer => break */
			break;
		/* extract next offset */
		q = sc_asn1_find_tag(card->ctx, p, tlen, 0x8a, &ilen);
		if (q != NULL && ilen == 1) {
			offset = (u8)ilen;
			if (offset != 0)
				goto get_next_part;
		}
		len -= tlen + 2;
		p   += tlen;
	}

	r = fids;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static void add_acl_entry(sc_file_t *file, int op, u8 byte)
{
	unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

	switch (byte) {
	case 0x00:
		method = SC_AC_NONE;
		break;
	case 0xFF:
		method = SC_AC_NEVER;
		break;
	default:
		if (byte > 0x7F) {
			method = SC_AC_UNKNOWN;
		} else {
			method = SC_AC_CHV;
			key_ref = byte;
		}
		break;
	}
	sc_file_add_acl_entry(file, op, method, key_ref);
}

static int acl_to_byte(const sc_acl_entry_t *e)
{
	if (e != NULL) {
		switch (e->method) {
		case SC_AC_NONE:
			return 0x00;
		case SC_AC_NEVER:
			return 0xFF;
		case SC_AC_CHV:
		case SC_AC_TERM:
		case SC_AC_AUT:
			if (e->key_ref == SC_AC_KEY_REF_NONE)
				return -1;
			if (e->key_ref > 0x7F)
				return -1;
			return e->key_ref;
		}
	}
        return 0x00;
}

static const int df_acl[9] = {
	-1,			/* LCYCLE (life cycle change) */
	SC_AC_OP_UPDATE,	/* UPDATE Objects */
	-1,			/* APPEND Objects */

	SC_AC_OP_INVALIDATE,	/* DF */
	SC_AC_OP_REHABILITATE,	/* DF */
	SC_AC_OP_DELETE,	/* DF */

	SC_AC_OP_UPDATE,	/* ADMIN DF */
	SC_AC_OP_CREATE,	/* Files */
	-1			/* Reserved */
};
static const int ef_acl[9] = {
	SC_AC_OP_READ,		/* Data */
	SC_AC_OP_UPDATE,	/* Data (write file content) */
	SC_AC_OP_WRITE,		/* */

	SC_AC_OP_INVALIDATE,	/* EF */
	SC_AC_OP_REHABILITATE,	/* EF */
	SC_AC_OP_DELETE,	/* (delete) EF */

	/* XXX: ADMIN should be an ACL type of its own, or mapped
	 * to erase */
	SC_AC_OP_UPDATE,	/* ADMIN EF (modify meta information?) */
	-1,			/* INC (-> cylic fixed files) */
	-1			/* DEC */
};

static void parse_sec_attr(sc_file_t *file, const u8 *buf, size_t len)
{
	size_t i;
	const int *idx;

	idx = (file->type == SC_FILE_TYPE_DF) ?  df_acl : ef_acl;

	/* acl defaults to 0xFF if unspecified */
	for (i = 0; i < 9; i++)
		if (idx[i] != -1)
			add_acl_entry(file, idx[i], (u8)((i < len) ? buf[i] : 0xFF));
}

static int cardos_select_file(sc_card_t *card,
			      const sc_path_t *in_path,
			      sc_file_t **file)
{
	int r;
	
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	r = iso_ops->select_file(card, in_path, file);
	if (r >= 0 && file)
		parse_sec_attr((*file), (*file)->sec_attr, (*file)->sec_attr_len);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int cardos_acl_to_bytes(sc_card_t *card, const sc_file_t *file,
	u8 *buf, size_t *outlen)
{
	int       i, byte;
	const int *idx;

	if (buf == NULL || *outlen < 9)
		return SC_ERROR_INVALID_ARGUMENTS;

	idx = (file->type == SC_FILE_TYPE_DF) ?  df_acl : ef_acl;
	for (i = 0; i < 9; i++) {
		if (idx[i] < 0)
			byte = 0x00;
		else
			byte = acl_to_byte(sc_file_get_acl_entry(file, idx[i]));
		if (byte < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid ACL\n");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		buf[i] = byte;
	}
	*outlen = 9;

	return SC_SUCCESS;
}

static int cardos_set_file_attributes(sc_card_t *card, sc_file_t *file)
{
	int r;

	if (file->type_attr_len == 0) {
		u8 type[3];

		memset(type, 0, sizeof(type));
		type[0] = 0x00;
		switch (file->type) {
		case SC_FILE_TYPE_WORKING_EF:
			break;
		case SC_FILE_TYPE_DF:
			type[0] = 0x38;
			break;
		default:
			return SC_ERROR_NOT_SUPPORTED;
		}
		if (file->type != SC_FILE_TYPE_DF) {
			switch (file->ef_structure) {
			case SC_FILE_EF_LINEAR_FIXED_TLV:
			case SC_FILE_EF_LINEAR_VARIABLE:
			case SC_FILE_EF_CYCLIC_TLV:
				return SC_ERROR_NOT_SUPPORTED;
				/* No idea what this means, but it
				 * seems to be required for key
				 * generation. */
			case SC_FILE_EF_LINEAR_VARIABLE_TLV:
				type[1] = 0xff;
				/* fall through */
			default:
				type[0] |= file->ef_structure & 7;
				break;
			}
		}
		r = sc_file_set_type_attr(file, type, sizeof(type));
		if (r != SC_SUCCESS)
			return r;
	}
	if (file->prop_attr_len == 0) {
		u8 status[3];

		status[0] = 0x01;
		if (file->type == SC_FILE_TYPE_DF) {
			status[1] = (file->size >> 8) & 0xFF;
			status[2] = file->size & 0xFF;
		} else {
			status[1] = status[2] = 0x00; /* not used */
		}
		r = sc_file_set_prop_attr(file, status, sizeof(status));
		if (r != SC_SUCCESS)
			return r;
	}
	if (file->sec_attr_len == 0) {
		u8     acl[9];
		size_t blen = sizeof(acl);

		r = cardos_acl_to_bytes(card, file, acl, &blen);
		if (r != SC_SUCCESS)
			return r;
		r = sc_file_set_sec_attr(file, acl, blen);
		if (r != SC_SUCCESS)
			return r;
	}
	return SC_SUCCESS;
}

/* newer versions of cardos seems to prefer the FCP */
static int cardos_construct_fcp(sc_card_t *card, const sc_file_t *file,
	u8 *out, size_t *outlen)
{
	u8     buf[64], *p = out;
	size_t inlen = *outlen, len;
	int    r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	if (out == NULL || inlen < 64)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* add FCP tag */
	*p++ = 0x62;
	/* we will add the length later  */
	p++;

	memset(buf, 0, sizeof(buf));

	/* set the length */
	buf[0] = (file->size >> 8) & 0xff;
	buf[1] = file->size        & 0xff;
	if (file->type == SC_FILE_TYPE_DF)
		r = sc_asn1_put_tag(0x81, buf, 2, p, 4, &p);
	else
		r = sc_asn1_put_tag(0x80, buf, 2, p, 4, &p);
	if (r != SC_SUCCESS)
		return r;
	/* set file type  */
	if (file->shareable != 0)
		buf[0] = 0x40;
	else
		buf[0] = 0x00;
	if (file->type == SC_FILE_TYPE_WORKING_EF) {
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			buf[0] |= 0x01;
			break;
		case SC_FILE_EF_LINEAR_VARIABLE_TLV:
			buf[0] |= 0x05;
			break;
		case SC_FILE_EF_LINEAR_FIXED:
			buf[0] |= 0x02;
			buf[1] |= 0x21;
			buf[2] |= 0x00;
			buf[3] |= (u8) file->record_length;
			buf[4] |= (u8) file->record_count;
			break;
		case SC_FILE_EF_CYCLIC:
			buf[0] |= 0x06;
			buf[1] |= 0x21;
			buf[2] |= 0x00;
			buf[3] |= (u8) file->record_length;
			buf[4] |= (u8) file->record_count;
			break;
		default:
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unknown EF type: %u", file->type);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		if (file->ef_structure == SC_FILE_EF_CYCLIC ||
		    file->ef_structure == SC_FILE_EF_LINEAR_FIXED)
		r = sc_asn1_put_tag(0x82, buf, 5, p, 8, &p);
	else
		r = sc_asn1_put_tag(0x82, buf, 1, p, 8, &p);
	} else if (file->type == SC_FILE_TYPE_DF) {
		buf[0] |= 0x38;
		r = sc_asn1_put_tag(0x82, buf, 1, p, 8, &p);
	} else
		return SC_ERROR_NOT_SUPPORTED;
	if (r != SC_SUCCESS)
		return r;
	/* set file id */
	buf[0] = (file->id >> 8) & 0xff;
	buf[1] = file->id        & 0xff;
	r = sc_asn1_put_tag(0x83, buf, 2, p, 8, &p);
	if (r != SC_SUCCESS)
		return r;
	/* set aid (for DF only) */
	if (file->type == SC_FILE_TYPE_DF && file->namelen != 0) {
		r = sc_asn1_put_tag(0x84, file->name, file->namelen, p, 20, &p);
		if (r != SC_SUCCESS)
			return r;
	}
	/* set proprietary file attributes */
	buf[0] = 0x00;		/* use default values */
	if (file->type == SC_FILE_TYPE_DF)
		r = sc_asn1_put_tag(0x85, buf, 1, p, 8, &p);
	else {
		buf[1] = 0x00;
		buf[2] = 0x00;
		r = sc_asn1_put_tag(0x85, buf, 1, p, 8, &p);
	}
	if (r != SC_SUCCESS)
		return r;
	/* set ACs  */
	len = 9;
	r = cardos_acl_to_bytes(card, file, buf, &len);
	if (r != SC_SUCCESS)
		return r;
	r = sc_asn1_put_tag(0x86, buf, len, p, 18, &p);
	if (r != SC_SUCCESS)
		return r;
	/* finally set the length of the FCP */
	out[1] = p - out - 2;

	*outlen = p - out;

	return SC_SUCCESS;
}

static int cardos_create_file(sc_card_t *card, sc_file_t *file)
{
	int       r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (card->type == SC_CARD_TYPE_CARDOS_GENERIC ||
	    card->type == SC_CARD_TYPE_CARDOS_M4_01) {
		r = cardos_set_file_attributes(card, file);
		if (r != SC_SUCCESS)
			return r;
		return iso_ops->create_file(card, file);
	} else if (card->type == SC_CARD_TYPE_CARDOS_M4_2 ||
	           card->type == SC_CARD_TYPE_CARDOS_M4_3 ||
		   card->type == SC_CARD_TYPE_CARDOS_M4_2B ||
	           card->type == SC_CARD_TYPE_CARDOS_M4_2C ||
		   card->type == SC_CARD_TYPE_CARDOS_M4_4) {
		u8        sbuf[SC_MAX_APDU_BUFFER_SIZE];
		size_t    len = sizeof(sbuf);
		sc_apdu_t apdu;

		r = cardos_construct_fcp(card, file, sbuf, &len);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to create FCP");
			return r;
		}
	
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
		apdu.lc      = len;
		apdu.datalen = len;
		apdu.data    = sbuf;

		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	} else
		return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Restore the indicated SE
 */
static int
cardos_restore_security_env(sc_card_t *card, int se_num)
{
	sc_apdu_t apdu;
	int	r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0, se_num);
	apdu.p1 = (card->type == SC_CARD_TYPE_CARDOS_CIE_V1 ? 0xF3 : 0x03);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
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
static int
cardos_set_security_env(sc_card_t *card,
			    const sc_security_env_t *env,
			    int se_num)
{
	sc_apdu_t apdu;
	u8	data[3];
	int	key_id, r;

	assert(card != NULL && env != NULL);

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || env->key_ref_len != 1) {
		sc_log(card->ctx, "No or invalid key reference\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	key_id = env->key_ref[0];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	if (card->type == SC_CARD_TYPE_CARDOS_CIE_V1) {
		cardos_restore_security_env(card, 0x30);
		apdu.p1 = 0xF1;
	} else {
		apdu.p1 = 0x41;
	}
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	data[0] = 0x83;
	data[1] = 0x01;
	data[2] = key_id;
	apdu.lc = apdu.datalen = 3;
	apdu.data = data;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	do   {
		const struct sc_supported_algo_info* algorithm_info = env->supported_algos;
		int i=0;
		int algorithm_id_count = 0;

		for(i=0;i<SC_MAX_SUPPORTED_ALGORITHMS;++i)  {
			struct sc_supported_algo_info alg = algorithm_info[i];

			if(alg.operations & SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE)  {
				unsigned int algorithm_id = alg.algo_ref;

				sc_log(card->ctx, "is signature");
				sc_log(card->ctx, "Adding ID %d at index %d", algorithm_id, algorithm_id_count);
				algorithm_ids_in_tokeninfo[algorithm_id_count++] = algorithm_id;
			}
			sc_log(card->ctx, "reference=%d, mechanism=%d, operations=%d, algo_ref=%d",
					alg.reference, alg.mechanism, alg.operations, alg.algo_ref);
		}
		algorithm_ids_in_tokeninfo_count = algorithm_id_count;
	} while (0);

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Compute digital signature
 */

/* internal function to do the actual signature computation */
static int
do_compute_signature(sc_card_t *card, const u8 *data, size_t datalen,
		     u8 *out, size_t outlen)
{
	int r;
	sc_apdu_t apdu;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x9E, 0x9A);
	apdu.resp    = out;
	apdu.le      = outlen;
	apdu.resplen = outlen;

	apdu.data    = data;
	apdu.lc      = datalen;
	apdu.datalen = datalen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, apdu.resplen);
	else
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int
cardos_compute_signature(sc_card_t *card, const u8 *data, size_t datalen,
			 u8 *out, size_t outlen)
{
	int    r;
	u8     buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t buf_len = sizeof(buf), tmp_len = buf_len;
	sc_context_t *ctx;
	int do_rsa_pure_sig = 0;
	int do_rsa_sig = 0;


	assert(card != NULL && data != NULL && out != NULL);
	ctx = card->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (datalen > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (outlen < datalen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	outlen = datalen;

	/* There are two ways to create a signature, depending on the way,
	 * the key was created: RSA_SIG and RSA_PURE_SIG.
	 * We can use the following reasoning, to determine the correct operation:
	 * 1. We check for several caps flags (as set in card->caps), to prevent generating
	 *    invalid signatures with duplicated hash prefixes with some cards
	 * 2. Use the information from AlgorithmInfo of the TokenInfo file.
	 *    This information is parsed in set_security_env and stored in a static variable.
	 *    The problem is, that that information is only available for the whole token and not
	      for a specific key, so if both operations are present, we can only do trial and error
	 *
	 * The Algorithm IDs for RSA_SIG are 0x86 and 0x88, those for RSA_PURE_SIG 0x8c and 0x8a
	 * (According to http://www.opensc-project.org/pipermail/opensc-devel/2010-September/014912.html
	 *   and www.crysys.hu/infsec/M40_Manual_E_2001_10.pdf)
	 */

	if (card->caps & SC_CARD_CAP_ONLY_RAW_HASH_STRIPPED){
		sc_log(ctx, "Forcing RAW_HASH_STRIPPED");
		do_rsa_sig = 1;
	}
	else if (card->caps & SC_CARD_CAP_ONLY_RAW_HASH){
		sc_log(ctx, "Forcing RAW_HASH");
		do_rsa_sig = 1;
	}
	else  {
		/* check the the algorithmIDs from the AlgorithmInfo */
		size_t i;
		for(i=0; i<algorithm_ids_in_tokeninfo_count;++i){
			unsigned int id = algorithm_ids_in_tokeninfo[i];
			if(id == 0x86 || id == 0x88)
				do_rsa_sig = 1;
			else if(id == 0x8C || id == 0x8A)
				do_rsa_pure_sig = 1;
		}
	}

	/* check if any operation was selected */
	if (do_rsa_sig == 0 && do_rsa_pure_sig == 0) {
		/* no operation selected. we just have to try both,
		 * for the lack of any better reasoning */
		sc_log(ctx, "I was unable to determine, whether this key can be used with RSA_SIG or RSA_PURE_SIG. I will just try both.");
		do_rsa_sig = 1;
		do_rsa_pure_sig = 1;
	}

	if(do_rsa_pure_sig == 1){
		sc_log(ctx, "trying RSA_PURE_SIG (padded DigestInfo)");
		r = do_compute_signature(card, data, datalen, out, outlen);
		if (r >= SC_SUCCESS)
			LOG_FUNC_RETURN(ctx, r);
	}

	if(do_rsa_sig == 1){
		sc_log(ctx, "trying RSA_SIG (just the DigestInfo)");
		/* remove padding: first try pkcs1 bt01 padding */
		r = sc_pkcs1_strip_01_padding(ctx, data, datalen, buf, &tmp_len);
		if (r != SC_SUCCESS) {
			const u8 *p = data;
			/* no pkcs1 bt01 padding => let's try zero padding
			 * This can only work if the data tbs doesn't have a
			 * leading 0 byte.  */
			tmp_len = buf_len;
			while (*p == 0 && tmp_len != 0) {
				++p;
				--tmp_len;
			}
			memcpy(buf, p, tmp_len);
		}
		if (!(card->caps & (SC_CARD_CAP_ONLY_RAW_HASH_STRIPPED | SC_CARD_CAP_ONLY_RAW_HASH)) || card->caps & SC_CARD_CAP_ONLY_RAW_HASH ) {
			sc_log(ctx, "trying to sign raw hash value with prefix");
			r = do_compute_signature(card, buf, tmp_len, out, outlen);
			if (r >= SC_SUCCESS)
				LOG_FUNC_RETURN(ctx, r);
		}
		if (card->caps & SC_CARD_CAP_ONLY_RAW_HASH) {
			sc_log(ctx, "Failed to sign raw hash value with prefix when forcing");
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		}
		sc_log(ctx, "trying to sign stripped raw hash value (card is responsible for prefix)");
		r = sc_pkcs1_strip_digest_info_prefix(NULL,buf,tmp_len,buf,&buf_len);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(ctx, r);
		return do_compute_signature(card, buf, buf_len, out, outlen);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
}

static int
cardos_decipher(struct sc_card *card,
		const u8 * crgram, size_t crgram_len,
		u8 * out, size_t outlen)
{
	int r;
	size_t card_max_send_size = card->max_send_size;
	size_t reader_max_send_size = card->reader->max_send_size;

	if (sc_get_max_send_size(card) < crgram_len + 1) {
		/* CardOS doesn't support chaining for PSO:DEC, so we just _hope_
		 * that both, the reader and the card are able to send enough data.
		 * (data is prefixed with 1 byte padding content indicator) */
		card->max_send_size = crgram_len + 1;
		card->reader->max_send_size = crgram_len + 1;
	}

	r = iso_ops->decipher(card, crgram, crgram_len, out, outlen);

	/* reset whatever we've modified above */
	card->max_send_size = card_max_send_size;
	card->reader->max_send_size = reader_max_send_size;

	return r;
}

static int
cardos_lifecycle_get(sc_card_t *card, int *mode)
{
	sc_apdu_t	apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int		r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x83);
	apdu.cla = 0x00;
	apdu.le = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	if (apdu.resplen < 1) {
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Lifecycle byte not in response");
	}

	r = SC_SUCCESS;
	switch (rbuf[0]) {
	case 0x10:
		*mode = SC_CARDCTRL_LIFECYCLE_USER;
		break;
	case 0x20:
		*mode = SC_CARDCTRL_LIFECYCLE_ADMIN;
		break;
	case 0x34: /* MANUFACTURING */
		*mode = SC_CARDCTRL_LIFECYCLE_OTHER;
		break;
	default:
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Unknown lifecycle byte %d", rbuf[0]);
		r = SC_ERROR_INTERNAL;
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int
cardos_lifecycle_set(sc_card_t *card, int *mode)
{
	sc_apdu_t	apdu;
	int		r;

	int current;
	int target;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	target = *mode;

	r = cardos_lifecycle_get(card, &current);
	
	if (r != SC_SUCCESS)
		return r;

	if (current == target || current == SC_CARDCTRL_LIFECYCLE_OTHER)
		return SC_SUCCESS;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x10, 0, 0);
	apdu.cla = 0x80;
	apdu.le = 0;
	apdu.resplen = 0;
	apdu.resp = NULL;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int
cardos_put_data_oci(sc_card_t *card,
			struct sc_cardctl_cardos_obj_info *args)
{
	sc_apdu_t	apdu;
	int		r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x00;
	apdu.ins = 0xda;
	apdu.p1  = 0x01;
	apdu.p2  = 0x6e;
	apdu.lc  = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int
cardos_put_data_seci(sc_card_t *card,
			struct sc_cardctl_cardos_obj_info *args)
{
	sc_apdu_t	apdu;
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x00;
	apdu.ins = 0xda;
	apdu.p1  = 0x01;
	apdu.p2  = 0x6d;
	apdu.lc  = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	return r;
}

static int
cardos_generate_key(sc_card_t *card,
		struct sc_cardctl_cardos_genkey_info *args)
{
	sc_apdu_t	apdu;
	u8		data[8];
	int		r;

	data[0] = 0x20;		/* store as PSO object */
	data[1] = args->key_id;
	data[2] = args->fid >> 8;
	data[3] = args->fid & 0xff;
	data[4] = 0;		/* additional Rabin Miller tests */
	data[5] = 0x10;		/* length difference between p, q (bits) */
	data[6] = 0;		/* default length of exponent, MSB */
	data[7] = 0x20;		/* default length of exponent, LSB */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x00;
	apdu.ins = 0x46;
	apdu.p1  = 0x00;
	apdu.p2  = 0x00;
	apdu.data= data;
	apdu.datalen = apdu.lc = sizeof(data);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "GENERATE_KEY failed");

	return r;
}

static int cardos_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;
	sc_apdu_t apdu;
	u8  rbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x81);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le   = 256;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r,  "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	if (apdu.resplen != 32) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unexpected response to GET DATA serial"
				" number\n");
		return SC_ERROR_INTERNAL;
	}
	/* cache serial number */
	memcpy(card->serialnr.value, &rbuf[10], 6);
	card->serialnr.len = 6;
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	return SC_SUCCESS;
}

static int
cardos_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_CARDOS_PUT_DATA_FCI:
		break;
	case SC_CARDCTL_CARDOS_PUT_DATA_OCI:
		return cardos_put_data_oci(card,
			(struct sc_cardctl_cardos_obj_info *) ptr);
		break;
	case SC_CARDCTL_CARDOS_PUT_DATA_SECI:
		return cardos_put_data_seci(card,
			(struct sc_cardctl_cardos_obj_info *) ptr);
		break;
	case SC_CARDCTL_CARDOS_GENERATE_KEY:
		return cardos_generate_key(card,
			(struct sc_cardctl_cardos_genkey_info *) ptr);
	case SC_CARDCTL_LIFECYCLE_GET:
		return cardos_lifecycle_get(card, (int *) ptr);
	case SC_CARDCTL_LIFECYCLE_SET:
		return cardos_lifecycle_set(card, (int *) ptr);
	case SC_CARDCTL_GET_SERIALNR:
		return cardos_get_serialnr(card, (sc_serial_number_t *)ptr);
	}
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * The 0x80 thing tells the card it's okay to search parent
 * directories as well for the referenced object.
 * Unfortunately, it doesn't seem to work without this flag :-/
 */
static int
cardos_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data,
		 int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(card->ctx);

	data->flags |= SC_PIN_CMD_NEED_PADDING;
	data->pin_reference |= 0x80;

	sc_log(ctx, "PIN_CMD(cmd:%i, ref:%i)", data->cmd, data->pin_reference);
	sc_log(ctx,
	       "PIN1(max:%"SC_FORMAT_LEN_SIZE_T"u, min:%"SC_FORMAT_LEN_SIZE_T"u)",
	       data->pin1.max_length, data->pin1.min_length);
	sc_log(ctx,
	       "PIN2(max:%"SC_FORMAT_LEN_SIZE_T"u, min:%"SC_FORMAT_LEN_SIZE_T"u)",
	       data->pin2.max_length, data->pin2.min_length);

	/* FIXME: the following values depend on what pin length was
	 * used when creating the BS objects */
	if (data->pin1.max_length == 0)
		data->pin1.max_length = 8;
	if (data->pin2.max_length == 0)
		data->pin2.max_length = 8;

	rv = iso_ops->pin_cmd(card, data, tries_left);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
cardos_logout(sc_card_t *card)
{
	if (card->type == SC_CARD_TYPE_CARDOS_M4_01
		   	|| card->type == SC_CARD_TYPE_CARDOS_M4_2
		   	|| card->type == SC_CARD_TYPE_CARDOS_M4_2B
		   	|| card->type == SC_CARD_TYPE_CARDOS_M4_2C
		   	|| card->type == SC_CARD_TYPE_CARDOS_M4_3
		   	|| card->type == SC_CARD_TYPE_CARDOS_M4_4
			|| card->type == SC_CARD_TYPE_CARDOS_V5_0) {
		sc_apdu_t apdu;
		int       r;
		sc_path_t path;

		sc_format_path("3F00", &path);
		r = sc_select_file(card, &path, NULL);
		if (r != SC_SUCCESS)
			return r;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xEA, 0x00, 0x00);
		apdu.cla = 0x80;

		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	} else
		return SC_ERROR_NOT_SUPPORTED;
}

/* eToken R2 supports WRITE_BINARY, PRO Tokens support UPDATE_BINARY */

static struct sc_card_driver * sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	cardos_ops = *iso_ops;
	cardos_ops.match_card = cardos_match_card;
	cardos_ops.init = cardos_init;
	cardos_ops.select_file = cardos_select_file;
	cardos_ops.create_file = cardos_create_file;
	cardos_ops.set_security_env = cardos_set_security_env;
	cardos_ops.restore_security_env = cardos_restore_security_env;
	cardos_ops.compute_signature = cardos_compute_signature;
	cardos_ops.decipher = cardos_decipher;

	cardos_ops.list_files = cardos_list_files;
	cardos_ops.check_sw = cardos_check_sw;
	cardos_ops.card_ctl = cardos_card_ctl;
	cardos_ops.pin_cmd = cardos_pin_cmd;
	cardos_ops.logout  = cardos_logout;

	return &cardos_drv;
}

#if 1
struct sc_card_driver * sc_get_cardos_driver(void)
{
	return sc_get_driver();
}
#endif
