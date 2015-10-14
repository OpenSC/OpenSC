/*
 * card-miocos.c: Support for PKI cards by Miotec
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include "asn1.h"
#include "cardctl.h"

static struct sc_atr_table miocos_atrs[] = {
	/* Test card with 32 kB memory */
	{ "3B:9D:94:40:23:00:68:10:11:4D:69:6F:43:4F:53:00:90:00", NULL, NULL, SC_CARD_TYPE_MIOCOS_GENERIC, 0, NULL },
	/* Test card with 64 kB memory */
	{ "3B:9D:94:40:23:00:68:20:01:4D:69:6F:43:4F:53:00:90:00", NULL, NULL, SC_CARD_TYPE_MIOCOS_GENERIC, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations miocos_ops;
static struct sc_card_driver miocos_drv = {
	"MioCOS 1.1",
	"miocos",
	&miocos_ops,
	NULL, 0, NULL
};

static int miocos_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, miocos_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int miocos_init(sc_card_t *card)
{
	card->name = "MioCOS";
	card->cla = 0x00;

	if (1) {
		unsigned long flags;
		
		flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1;
		flags |= SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA1;

		_sc_card_add_rsa_alg(card, 1024, flags, 0);
	}

	/* read_binary and friends shouldn't do more than 244 bytes
	 * per operation */
	card->max_send_size = 244;
	card->max_recv_size = 244;

	return 0;
}

static const struct sc_card_operations *iso_ops = NULL;

static int acl_to_byte(const sc_acl_entry_t *e)
{
	switch (e->method) {
	case SC_AC_NONE:
		return 0x00;
	case SC_AC_CHV:
	case SC_AC_TERM:
	case SC_AC_AUT:
		if (e->key_ref == SC_AC_KEY_REF_NONE)
			return -1;
		if (e->key_ref < 1 || e->key_ref > 14)
			return -1;
		return e->key_ref;
	case SC_AC_NEVER:
		return 0x0F;
	}
	return 0x00;
}

static int encode_file_structure(sc_card_t *card, const sc_file_t *file,
				 u8 *buf, size_t *buflen)
{
	u8 *p = buf;
	const int df_ops[8] = {
		SC_AC_OP_DELETE, SC_AC_OP_CREATE,
		/* RFU */ -1, /* CREATE AC */ SC_AC_OP_CREATE,
		/* UPDATE AC */ SC_AC_OP_CREATE, -1, -1, -1
	};
	const int ef_ops[8] = {
		/* DELETE */ SC_AC_OP_UPDATE, -1, SC_AC_OP_READ,
		SC_AC_OP_UPDATE, -1, -1, SC_AC_OP_INVALIDATE,
		SC_AC_OP_REHABILITATE
	};
	const int key_ops[8] = {
		/* DELETE */ SC_AC_OP_UPDATE, -1, -1,
		SC_AC_OP_UPDATE, SC_AC_OP_CRYPTO, -1, SC_AC_OP_INVALIDATE,
		SC_AC_OP_REHABILITATE
	};
        const int *ops;
        int i;

	*p++ = file->id >> 8;
	*p++ = file->id & 0xFF;
	switch (file->type) {
	case SC_FILE_TYPE_DF:
		*p++ = 0x20;
		ops = df_ops;
		break;
	case SC_FILE_TYPE_WORKING_EF:
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			*p++ = 0x40;
			break;
		case SC_FILE_EF_LINEAR_FIXED:
			*p++ = 0x41;
                        break;
		case SC_FILE_EF_CYCLIC:
			*p++ = 0x43;
			break;
		default:
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid EF structure\n");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		ops = ef_ops;
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		*p++ = 0x44;
		ops = key_ops;
		break;
	default:
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Unknown file type\n");
                return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (file->type == SC_FILE_TYPE_DF) {
		*p++ = 0;
		*p++ = 0;
	} else {
		*p++ = file->size >> 8;
		*p++ = file->size & 0xFF;
	}
	if (file->sec_attr_len == 4) {
		memcpy(p, file->sec_attr, 4);
		p += 4;
	} else for (i = 0; i < 8; i++) {
		u8 nibble;

		if (ops[i] == -1)
			nibble = 0x00;
		else {
			int byte = acl_to_byte(sc_file_get_acl_entry(file, ops[i]));
			if (byte < 0) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid ACL\n");
				return SC_ERROR_INVALID_ARGUMENTS;
			}
			nibble = byte;
		}
		if ((i & 1) == 0)
			*p = nibble << 4;
		else {
			*p |= nibble & 0x0F;
			p++;
		}
	}
	if (file->type == SC_FILE_TYPE_WORKING_EF &&
	    file->ef_structure != SC_FILE_EF_TRANSPARENT)
                *p++ = file->record_length;
	else
		*p++ = 0;
	if (file->status & SC_FILE_STATUS_INVALIDATED)
		*p++ = 0;
	else
		*p++ = 0x01;
	if (file->type == SC_FILE_TYPE_DF && file->namelen) {
                assert(file->namelen <= 16);
		memcpy(p, file->name, file->namelen);
		p += file->namelen;
	}
	*buflen = p - buf;

        return 0;
}

static int miocos_create_file(sc_card_t *card, sc_file_t *file)
{
	sc_apdu_t apdu;
	u8 sbuf[32];
        size_t buflen;
	int r;

	r = encode_file_structure(card, file, sbuf, &buflen);
	if (r)
		return r;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
	apdu.data = sbuf;
	apdu.datalen = buflen;
	apdu.lc = buflen;

	r = sc_transmit_apdu(card, &apdu);
        SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
        if (apdu.sw1 == 0x6A && apdu.sw2 == 0x89)
        	return SC_ERROR_FILE_ALREADY_EXISTS;
        r = sc_check_sw(card, apdu.sw1, apdu.sw2);
        SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	return 0;
}

static int miocos_set_security_env(sc_card_t *card,
				  const sc_security_env_t *env,
				  int se_num)
{
	if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
		sc_security_env_t tmp;

		tmp = *env;
		tmp.flags &= ~SC_SEC_ENV_ALG_PRESENT;
		tmp.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
		if (tmp.algorithm != SC_ALGORITHM_RSA) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Only RSA algorithm supported.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		tmp.algorithm_ref = 0x00;
		/* potential FIXME: return an error, if an unsupported
		 * pad or hash was requested, although this shouldn't happen.
		 */
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			tmp.algorithm_ref = 0x02;
		if (tmp.algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
			tmp.algorithm_ref |= 0x10;
		return iso_ops->set_security_env(card, &tmp, se_num);
	}
	return iso_ops->set_security_env(card, env, se_num);
}

static void add_acl_entry(sc_file_t *file, int op, u8 byte)
{
	unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

	switch (byte) {
	case 0:
		method = SC_AC_NONE;
		break;
	case 15:
		method = SC_AC_NEVER;
		break;
	default:
		method = SC_AC_CHV;
		key_ref = byte;
		break;
	}
	sc_file_add_acl_entry(file, op, method, key_ref);
}

static void parse_sec_attr(sc_file_t *file, const u8 *buf, size_t len)
{
	int i;
	const int df_ops[8] = {
		SC_AC_OP_DELETE, SC_AC_OP_CREATE,
		-1, /* CREATE AC */ -1, /* UPDATE AC */ -1, -1, -1, -1
	};
	const int ef_ops[8] = {
		SC_AC_OP_DELETE, -1, SC_AC_OP_READ,
		SC_AC_OP_UPDATE, -1, -1, SC_AC_OP_INVALIDATE,
		SC_AC_OP_REHABILITATE
	};
	const int key_ops[8] = {
		SC_AC_OP_DELETE, -1, -1,
		SC_AC_OP_UPDATE, SC_AC_OP_CRYPTO, -1, SC_AC_OP_INVALIDATE,
		SC_AC_OP_REHABILITATE
	};
        const int *ops;

	if (len < 4)
                return;
	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		ops = ef_ops;
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		ops = key_ops;
		break;
	case SC_FILE_TYPE_DF:
		ops = df_ops;
		break;
	default:
                return;
	}
	for (i = 0; i < 8; i++) {
		if (ops[i] == -1)
			continue;
		if ((i & 1) == 0)
			add_acl_entry(file, ops[i], (u8)(buf[i / 2] >> 4));
		else
			add_acl_entry(file, ops[i], (u8)(buf[i / 2] & 0x0F));
	}
}

static int miocos_get_acl(sc_card_t *card, sc_file_t *file)
{
	sc_apdu_t apdu;
	u8 rbuf[256];
	const u8 *seq = rbuf;
	size_t left;
	int r;
	unsigned int i;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x01);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	left = apdu.resplen;
	seq = sc_asn1_skip_tag(card->ctx, &seq, &left,
			       SC_ASN1_SEQUENCE | SC_ASN1_CONS, &left);
	if (seq == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Unable to process reply");
	for (i = 1; i < 15; i++) {
		int j;
		const u8 *tag;
		size_t taglen;
		
		tag = sc_asn1_skip_tag(card->ctx, &seq, &left,
				       SC_ASN1_CTX | i, &taglen);
		if (tag == NULL || taglen == 0)
			continue;
		for (j = 0; j < SC_MAX_AC_OPS; j++) {
			sc_acl_entry_t *e;
			
			e = (sc_acl_entry_t *) sc_file_get_acl_entry(file, j);
			if (e == NULL)
				continue;
			if (e->method != SC_AC_CHV)
				continue;
			if (e->key_ref != i)
				continue;
			switch (tag[0]) {
			case 0x01:
				e->method = SC_AC_CHV;
				break;
			case 0x02:
				e->method = SC_AC_AUT;
				break;
			default:
				e->method = SC_AC_UNKNOWN;
				break;
			}
		}
	}
	return 0;
}

static int miocos_select_file(sc_card_t *card,
			       const sc_path_t *in_path,
			       sc_file_t **file)
{
	int r;

	r = iso_ops->select_file(card, in_path, file);
	if (r)
		return r;
	if (file != NULL) {
		parse_sec_attr(*file, (*file)->sec_attr, (*file)->sec_attr_len);
		miocos_get_acl(card, *file);
	}

	return 0;
}

static int miocos_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0);
	apdu.resp = buf;
	apdu.resplen = buflen;
	apdu.le = buflen > 256 ? 256 : buflen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	return apdu.resplen;
}

static int miocos_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
	}
	r = sc_select_file(card, path, NULL);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Unable to select file to be deleted");
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);
	apdu.cla = 0xA0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int miocos_create_ac(sc_card_t *card,
			    struct sc_cardctl_miocos_ac_info *ac)
{
	sc_apdu_t apdu;
	u8 sbuf[20];
	int miocos_type, r;
	size_t sendsize;
	
	if (ac->max_tries > 15)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
	switch (ac->type) {
	case SC_CARDCTL_MIOCOS_AC_PIN:
		if (ac->max_unblock_tries > 15)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
		miocos_type = 0x01;
		sbuf[0] = (ac->max_tries << 4) | ac->max_tries;
		sbuf[1] = 0xFF; /* FIXME... */
		memcpy(sbuf + 2, ac->key_value, 8);
		sbuf[10] = (ac->max_unblock_tries << 4) | ac->max_unblock_tries;
		sbuf[11] = 0xFF;
		memcpy(sbuf + 12, ac->unblock_value, 8);
		sendsize = 20;
		break;
	default:
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "AC type %d not supported\n", ac->type);
		return SC_ERROR_NOT_SUPPORTED;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x1E, miocos_type,
		       ac->ref);
	apdu.lc = sendsize;
	apdu.datalen = sendsize;
	apdu.data = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int miocos_card_ctl(sc_card_t *card, unsigned long cmd,
			   void *arg)
{
	switch (cmd) {
	case SC_CARDCTL_MIOCOS_CREATE_AC:
		return miocos_create_ac(card, (struct sc_cardctl_miocos_ac_info *) arg);
	}
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "card_ctl command 0x%X not supported\n", cmd);
	return SC_ERROR_NOT_SUPPORTED;
}


static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	miocos_ops = *iso_drv->ops;
	miocos_ops.match_card = miocos_match_card;
	miocos_ops.init = miocos_init;
	if (iso_ops == NULL)
                iso_ops = iso_drv->ops;
	miocos_ops.create_file = miocos_create_file;
	miocos_ops.set_security_env = miocos_set_security_env;
	miocos_ops.select_file = miocos_select_file;
	miocos_ops.list_files = miocos_list_files;
	miocos_ops.delete_file = miocos_delete_file;
	miocos_ops.card_ctl = miocos_card_ctl;
	
        return &miocos_drv;
}

#if 1
struct sc_card_driver * sc_get_miocos_driver(void)
{
	return sc_get_driver();
}
#endif
