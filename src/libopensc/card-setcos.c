/*
 * card-setcos.c: Support for PKI cards by Setec
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
#include <stdlib.h>
#include <string.h>

#define SETEC_PKI	1
#define SETEC_OTHER	2

static struct sc_atr_table setcos_atrs[] = {
	/* the current FINEID card has this ATR: */
	{ (const u8 *) "\x3B\x9F\x94\x40\x1E\x00\x67\x11\x43\x46\x49\x53\x45\x10\x52\x66\xFF\x81\x90\x00", 20, SETEC_PKI },
	/* RSA SecurID 3100 */
	{ (const u8 *) "\x3B\x9F\x94\x40\x1E\x00\x67\x16\x43\x46\x49\x53\x45\x10\x52\x66\xFF\x81\x90\x00", 20, SETEC_PKI },
	/* this is from a Nokia branded SC */
	{ (const u8 *) "\x3B\x1F\x11\x00\x67\x80\x42\x46\x49\x53\x45\x10\x52\x66\xFF\x81\x90\x00", 18, SETEC_OTHER },
	{ NULL }
};

struct setcos_priv_data {
	int type;
};

#define DRVDATA(card)        ((struct setcos_priv_data *) ((card)->drv_data))

static struct sc_card_operations setcos_ops;
static struct sc_card_driver setcos_drv = {
	"Setec smartcards",
	"setcos",
	&setcos_ops
};

static int setcos_finish(struct sc_card *card)
{
	free(DRVDATA(card));
	return 0;
}

static int setcos_match_card(struct sc_card *card)
{
	int i;
	const u8 *hist_bytes = card->slot->atr_info.hist_bytes;

	if (card->slot->atr_info.hist_bytes_len < 8)
		return 0;
	if (memcmp(hist_bytes + 4, "FISE", 4) != 0)
		return 0;
	
	i = _sc_match_atr(card, setcos_atrs, NULL);
	if (i < 0)
		return 0;
	return 1;
}

static int setcos_init(struct sc_card *card)
{
	int i, id;
	struct setcos_priv_data *priv = NULL;

	i = _sc_match_atr(card, setcos_atrs, &id);
	if (i < 0)
		return 0;
	priv = (struct setcos_priv_data *) malloc(sizeof(struct setcos_priv_data));
	if (priv == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	card->name = "SetCOS";
	card->drv_data = priv;
	card->cla = 0x80;
	priv->type = id;
	if (id == SETEC_PKI) {
		unsigned long flags;
		
		flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1;
		flags |= SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA1;

		_sc_card_add_rsa_alg(card, 1024, flags, 0);
	}

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG;

	return 0;
}

static const struct sc_card_operations *iso_ops = NULL;

static u8 acl_to_byte(const struct sc_acl_entry *e)
{
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
		default:
			return 0x00;
		}
		break;
	case SC_AC_TERM:
		return 0x04;
	case SC_AC_NEVER:
		return 0x0F;
	}
	return 0x00;
}

static int setcos_create_file(struct sc_card *card, struct sc_file *file)
{
	if (file->prop_attr_len == 0)
		sc_file_set_prop_attr(file, (const u8 *) "\x03\x00\x00", 3);
	if (file->sec_attr_len == 0) {
		int idx[6], i;
		u8 buf[6];

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

		sc_file_set_sec_attr(file, buf, 6);
	}

	return iso_ops->create_file(card, file);
}

static int setcos_set_security_env2(struct sc_card *card,
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
		apdu.p1 = 0x41;	/* Should be 0x81 */
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x81; /* Should be 0x41 */
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
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
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
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}

static int setcos_set_security_env(struct sc_card *card,
				  const struct sc_security_env *env,
				  int se_num)
{
	struct setcos_priv_data *priv = DRVDATA(card);
	
	if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
		struct sc_security_env tmp;

		tmp = *env;
		tmp.flags &= ~SC_SEC_ENV_ALG_PRESENT;
		tmp.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
		if (tmp.algorithm != SC_ALGORITHM_RSA) {
			sc_error(card->ctx, "Only RSA algorithm supported.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		if (priv->type != SETEC_PKI) {
			sc_error(card->ctx, "Card does not support RSA.\n");
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
		return setcos_set_security_env2(card, &tmp, se_num);
	}
        return setcos_set_security_env2(card, env, se_num);
}

static void add_acl_entry(struct sc_file *file, int op, u8 byte)
{
	unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

	switch (byte >> 4) {
	case 0:
		method = SC_AC_NONE;
		break;
	case 1:
		method = SC_AC_CHV;
		key_ref = 1;
		break;
	case 2:
		method = SC_AC_CHV;
		key_ref = 2;
		break;
	case 4:
		method = SC_AC_TERM;
		break;
	case 15:
		method = SC_AC_NEVER;
		break;
	default:
		method = SC_AC_UNKNOWN;
		break;
	}
	sc_file_add_acl_entry(file, op, method, key_ref);
}

static void parse_sec_attr(struct sc_file *file, const u8 *buf, size_t len)
{
	int i;
	int idx[6];

	if (len < 6)
		return;
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
		add_acl_entry(file, idx[i], buf[i]);
}

static int setcos_select_file(struct sc_card *card,
			       const struct sc_path *in_path,
			       struct sc_file **file)
{
	int r;
	
	r = iso_ops->select_file(card, in_path, file);
	if (r)
		return r;
	if (file != NULL)
		parse_sec_attr(*file, (*file)->sec_attr, (*file)->sec_attr_len);
	return 0;
}

static int setcos_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xAA, 0, 0);
	apdu.resp = buf;
	apdu.resplen = buflen;
	apdu.le = buflen > 256 ? 256 : buflen;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	return apdu.resplen;
}

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	setcos_ops = *iso_drv->ops;
	setcos_ops.match_card = setcos_match_card;
	setcos_ops.init = setcos_init;
        setcos_ops.finish = setcos_finish;
	if (iso_ops == NULL)
                iso_ops = iso_drv->ops;
	setcos_ops.create_file = setcos_create_file;
	setcos_ops.set_security_env = setcos_set_security_env;
	setcos_ops.select_file = setcos_select_file;
	setcos_ops.list_files = setcos_list_files;
	
        return &setcos_drv;
}

#if 1
struct sc_card_driver * sc_get_setcos_driver(void)
{
	return sc_get_driver();
}
#endif
