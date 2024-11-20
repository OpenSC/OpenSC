/*
 * card-dtrust.c: Support for (CardOS based) D-Trust Signature Cards
 *
 * Copyright (C) 2023 Mario Haustein <mario.haustein@hrz.tu-chemnitz.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * based on card-cardos.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "card-cardos-common.h"
#include "internal.h"

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations dtrust_ops;

// clang-format off
static struct sc_card_driver dtrust_drv = {
	"D-Trust Signature Card",
	"dtrust",
	&dtrust_ops,
	NULL, 0, NULL
};
// clang-format on

/* internal structure to save the current security environment */
struct dtrust_drv_data_t {
	const sc_security_env_t *env;
};

// clang-format off
static const struct sc_atr_table dtrust_atrs[] = {
	/* D-Trust Signature Card v4.1 and v4.4 - CardOS 5.4
	 *
	 * The ATR was intentionally omitted from minidriver_registration[] within win32/customactions.cpp
	 * as it is identical to that of CardOS v5.4 and therefore already included.
	 * Any new ATR may need an entry in minidriver_registration[]. */
	{ "3b:d2:18:00:81:31:fe:58:c9:04:11", NULL, NULL, SC_CARD_TYPE_DTRUST_V4_1_STD, 0, NULL },
	{ NULL,                               NULL, NULL, 0,                            0, NULL }
};
// clang-format on

// clang-format off
static struct dtrust_supported_ec_curves {
	struct sc_object_id oid;
	size_t size;
} dtrust_curves[] = {
	{ .oid = {{ 1, 2, 840, 10045, 3, 1, 7, -1 }}, .size = 256 },	/* secp256r1 */
	{ .oid = {{ -1 }},                            .size =   0 },
};
// clang-format on

static int
_dtrust_match_cardos(sc_card_t *card)
{
	int r;
	size_t prodlen;
	u8 buf[32];

	/* check OS version */
	r = sc_get_data(card, 0x0182, buf, 32);
	LOG_TEST_RET(card->ctx, r, "OS version check failed");

	if (r != 2 || buf[0] != 0xc9 || buf[1] != 0x04)
		return SC_ERROR_WRONG_CARD;

	/* check product name */
	r = sc_get_data(card, 0x0180, buf, 32);
	LOG_TEST_RET(card->ctx, r, "Product name check failed");

	prodlen = (size_t)r;
	if (prodlen != strlen("CardOS V5.4     2019") + 1 || memcmp(buf, "CardOS V5.4     2019", prodlen))
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}

static int
_dtrust_match_profile(sc_card_t *card)
{
	sc_path_t cia_path;
	int r;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t slen, plen;
	const u8 *sp, *pp;
	char *name;

	sc_format_path("5032", &cia_path);
	cia_path.aid.len = sizeof(cia_path.aid.value);
	r = sc_hex_to_bin("E8:28:BD:08:0F:A0:00:00:01:67:45:53:49:47:4E", (u8 *)&cia_path.aid.value, &cia_path.aid.len);
	LOG_TEST_RET(card->ctx, r, "Formatting AID failed");

	r = sc_select_file(card, &cia_path, NULL);
	LOG_TEST_RET(card->ctx, r, "Selecting CIA path failed");

	r = sc_read_binary(card, 0, buf, SC_MAX_APDU_BUFFER_SIZE, NULL);
	LOG_TEST_RET(card->ctx, r, "Reading CIA information failed");

	sp = sc_asn1_find_tag(card->ctx, buf, r, 0x30, &slen);
	if (sp == NULL)
		return SC_ERROR_WRONG_CARD;

	/* check vendor */
	pp = sc_asn1_find_tag(card->ctx, sp, slen, 0x0c, &plen);
	if (pp == NULL)
		return SC_ERROR_WRONG_CARD;

	if (plen != 16 || memcmp(pp, "D-TRUST GmbH (C)", 16))
		return SC_ERROR_WRONG_CARD;

	/* check profile */
	pp = sc_asn1_find_tag(card->ctx, sp, slen, 0x80, &plen);
	if (pp == NULL)
		return SC_ERROR_WRONG_CARD;

	/*
	 * The profile string contains (two) additional characters. They depend
	 * on the production process, but aren't relevant for determining the
	 * card profile.
	 */
	if (plen >= 27 && !memcmp(pp, "D-TRUST Card 4.1 Std. RSA 2", 27))
		card->type = SC_CARD_TYPE_DTRUST_V4_1_STD;
	else if (plen >= 28 && !memcmp(pp, "D-TRUST Card 4.1 Multi ECC 2", 28))
		card->type = SC_CARD_TYPE_DTRUST_V4_1_MULTI;
	else if (plen >= 27 && !memcmp(pp, "D-TRUST Card 4.1 M100 ECC 2", 27))
		card->type = SC_CARD_TYPE_DTRUST_V4_1_M100;
	else if (plen >= 27 && !memcmp(pp, "D-TRUST Card 4.4 Std. RSA 2", 27))
		card->type = SC_CARD_TYPE_DTRUST_V4_4_STD;
	else if (plen >= 28 && !memcmp(pp, "D-TRUST Card 4.4 Multi ECC 2", 28))
		card->type = SC_CARD_TYPE_DTRUST_V4_4_MULTI;
	else
		return SC_ERROR_WRONG_CARD;

	name = malloc(plen + 1);
	if (name == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(name, pp, plen);
	name[plen] = '\0';
	card->name = name;

	sc_log(card->ctx, "found %s", card->name);

	return SC_SUCCESS;
}

static int
dtrust_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, dtrust_atrs, &card->type) < 0)
		return 0;

	if (_dtrust_match_cardos(card) != SC_SUCCESS)
		return 0;

	if (_dtrust_match_profile(card) != SC_SUCCESS)
		return 0;

	sc_log(card->ctx, "D-Trust Signature Card (CardOS 5.4)");

	return 1;
}

static int
_dtrust_get_serialnr(sc_card_t *card)
{
	int r;
	u8 buf[32];

	r = sc_get_data(card, 0x0181, buf, 32);
	LOG_TEST_RET(card->ctx, r, "querying serial number failed");

	if (r != 8) {
		sc_log(card->ctx, "unexpected response to GET DATA serial number");
		return SC_ERROR_INTERNAL;
	}

	/* cache serial number */
	memcpy(card->serialnr.value, buf, 8);
	card->serialnr.len = 8;

	return SC_SUCCESS;
}

static int
dtrust_init(sc_card_t *card)
{
	int r;
	const size_t data_field_length = 437;
	unsigned long flags, ext_flags;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->cla = 0x00;

	card->drv_data = calloc(1, sizeof(struct dtrust_drv_data_t));
	if (card->drv_data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	r = _dtrust_get_serialnr(card);
	LOG_TEST_RET(card->ctx, r, "Error reading serial number.");

	card->caps |= SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_ISO7816_PIN_INFO;

	card->max_send_size = data_field_length - 6;
#ifdef _WIN32
	/* see card-cardos.c */
	if (card->reader->max_send_size == 255 && card->reader->max_recv_size == 256) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "resetting reader to use data_field_length");
		card->reader->max_send_size = data_field_length - 6;
		card->reader->max_recv_size = data_field_length - 3;
	}
#endif

	card->max_send_size = sc_get_max_send_size(card); /* see card-cardos.c */
	card->max_recv_size = data_field_length - 2;
	card->max_recv_size = sc_get_max_recv_size(card);

	flags = 0;
	r = SC_ERROR_WRONG_CARD;

	switch (card->type) {
	case SC_CARD_TYPE_DTRUST_V4_1_STD:
	case SC_CARD_TYPE_DTRUST_V4_4_STD:
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		flags |= SC_ALGORITHM_RSA_PAD_PSS;
		flags |= SC_ALGORITHM_RSA_PAD_OAEP;
		flags |= SC_ALGORITHM_RSA_HASH_SHA256;
		flags |= SC_ALGORITHM_RSA_HASH_SHA384;
		flags |= SC_ALGORITHM_RSA_HASH_SHA512;
		flags |= SC_ALGORITHM_MGF1_SHA256;
		flags |= SC_ALGORITHM_MGF1_SHA384;
		flags |= SC_ALGORITHM_MGF1_SHA512;

		_sc_card_add_rsa_alg(card, 3072, flags, 0);

		r = SC_SUCCESS;
		break;

	case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V4_1_M100:
	case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
		flags |= SC_ALGORITHM_ECDH_CDH_RAW;
		flags |= SC_ALGORITHM_ECDSA_RAW;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE;
		for (unsigned int i = 0; dtrust_curves[i].oid.value[0] >= 0; i++) {
			_sc_card_add_ec_alg(card, dtrust_curves[i].size, flags, ext_flags, &dtrust_curves[i].oid);
		}

		r = SC_SUCCESS;
		break;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
dtrust_finish(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	free((char *)card->name);
	free(card->drv_data);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
dtrust_pin_cmd(struct sc_card *card,
		struct sc_pin_cmd_data *data,
		int *tries_left)
{
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (!data)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* Upper layers may try to verify the PIN twice, first with PIN type
	 * SC_AC_CHV and then with PIN type SC_AC_CONTEXT_SPECIFIC. For the
	 * second attempt we first check by SC_PIN_CMD_GET_INFO whether a
	 * second PIN authentication is still necessary. If not, we simply
	 * return without a second verification attempt. Otherwise we perform
	 * the verification as requested. This only matters for pin pad readers
	 * to prevent the user from prompting the PIN twice. */
	if (data->cmd == SC_PIN_CMD_VERIFY && data->pin_type == SC_AC_CONTEXT_SPECIFIC) {
		struct sc_pin_cmd_data data2;

		memset(&data2, 0, sizeof(struct sc_pin_cmd_data));
		data2.pin_reference = data->pin_reference;
		data2.pin1 = data->pin1;

		/* Check verification state */
		data2.cmd = SC_PIN_CMD_GET_INFO;
		data2.pin_type = data->pin_type;
		r = iso_ops->pin_cmd(card, &data2, tries_left);

		if (data2.pin1.logged_in == SC_PIN_STATE_LOGGED_IN) {
			/* Return if we are already authenticated */
			data->pin1 = data2.pin1;
			LOG_FUNC_RETURN(card->ctx, r);
		}
	}

	r = iso_ops->pin_cmd(card, data, tries_left);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
dtrust_set_security_env(sc_card_t *card,
		const sc_security_env_t *env,
		int se_num)
{
	struct dtrust_drv_data_t *drv_data;

	if (card == NULL || env == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;
	drv_data->env = env;

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || env->key_ref_len != 1) {
		sc_log(card->ctx, "No or invalid key reference");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/*
	 * The card does not support to set a security environment. Instead a
	 * predefined template has to be loaded via MSE RESTORE which depends
	 * on the algorithm used.
	 */

	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02) {
			se_num = 0x31;
		} else if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_OAEP) {
			switch (env->algorithm_flags & SC_ALGORITHM_MGF1_HASHES) {
			case SC_ALGORITHM_MGF1_SHA256:
				se_num = 0x32;
				break;
			case SC_ALGORITHM_MGF1_SHA384:
				se_num = 0x33;
				break;
			case SC_ALGORITHM_MGF1_SHA512:
				se_num = 0x34;
				break;

			default:
				return SC_ERROR_NOT_SUPPORTED;
			}
		} else {
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;

	case SC_SEC_OPERATION_SIGN:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01) {
			switch (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) {
			case SC_ALGORITHM_RSA_HASH_SHA256:
				se_num = 0x25;
				break;
			case SC_ALGORITHM_RSA_HASH_SHA384:
				se_num = 0x26;
				break;
			case SC_ALGORITHM_RSA_HASH_SHA512:
				se_num = 0x27;
				break;

			default:
				return SC_ERROR_NOT_SUPPORTED;
			}
		} else if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS) {
			/*
			 * According to the specification the message digest has
			 * to match the hash function used for the PSS scheme.
			 * We don't enforce this constraint here as the output
			 * is valid in all cases as long as the message digest
			 * is calculated in software and not on the card.
			 */

			switch (env->algorithm_flags & SC_ALGORITHM_MGF1_HASHES) {
			case SC_ALGORITHM_MGF1_SHA256:
				se_num = 0x19;
				break;
			case SC_ALGORITHM_MGF1_SHA384:
				se_num = 0x1A;
				break;
			case SC_ALGORITHM_MGF1_SHA512:
				se_num = 0x1B;
				break;

			default:
				return SC_ERROR_NOT_SUPPORTED;
			}
		} else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_RAW) {
			se_num = 0x21;
		} else {
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;

	case SC_SEC_OPERATION_DERIVE:
		if (env->algorithm_flags & SC_ALGORITHM_ECDH_CDH_RAW) {
			se_num = 0x39;
		} else {
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;

	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	return iso_ops->restore_security_env(card, se_num);
}

static int
dtrust_compute_signature(struct sc_card *card, const u8 *data,
		size_t data_len, u8 *out, size_t outlen)
{
	struct dtrust_drv_data_t *drv_data;
	unsigned long flags;
	size_t buflen = 0, tmplen;
	u8 *buf = NULL;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;
	flags = drv_data->env->algorithm_flags;

	/*
	 * PKCS#1 padded signatures require some special handling. When using
	 * the PKCS#1 scheme, first a digest info OID is prepended to the
	 * message digest. Afterward this resulting octet string is padded to
	 * the length of the key modulus. The card performs padding, but
	 * requires the digest info to be prepended in software.
	 */

	/* Only PKCS#1 signature scheme requires special handling */
	if (!(flags & SC_ALGORITHM_RSA_PAD_PKCS1))
		return iso_ops->compute_signature(card, data, data_len, out, outlen);

	/*
	 * We have to clear the padding flag, because padding is done in
	 * hardware. We are keeping the hash algorithm flags, to ensure the
	 * digest info is prepended before padding.
	 */
	flags &= ~SC_ALGORITHM_RSA_PAD_PKCS1;
	flags |= SC_ALGORITHM_RSA_PAD_NONE;

	/* 32 Bytes should be enough to prepend the digest info */
	buflen = data_len + 32;
	buf = sc_mem_secure_alloc(buflen);
	if (buf == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	tmplen = buflen;

	/* Prepend digest info */
	r = sc_pkcs1_encode(card->ctx, flags, data, data_len, buf, &tmplen, 0, NULL);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Prepending digest info failed");

	/* Do padding in hardware and compute signature */
	r = iso_ops->compute_signature(card, buf, tmplen, out, outlen);

err:
	sc_mem_secure_clear_free(buf, buflen);

	return r;
}

static int
dtrust_decipher(struct sc_card *card, const u8 *data,
		size_t data_len, u8 *out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	switch (card->type) {
	/* No special handling necessary for RSA cards. */
	case SC_CARD_TYPE_DTRUST_V4_1_STD:
	case SC_CARD_TYPE_DTRUST_V4_4_STD:
		LOG_FUNC_RETURN(card->ctx, iso_ops->decipher(card, data, data_len, out, outlen));

	/* Elliptic Curve cards cannot use PSO:DECIPHER command and need to
	 * perform key agreement by a CardOS specific command. */
	case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V4_1_M100:
	case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
		LOG_FUNC_RETURN(card->ctx, cardos_ec_compute_shared_value(card, data, data_len, out, outlen));

	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int
dtrust_logout(sc_card_t *card)
{
	sc_path_t path;
	int r;

	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);

	return r;
}

struct sc_card_driver *
sc_get_dtrust_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	dtrust_ops = *iso_ops;
	dtrust_ops.match_card = dtrust_match_card;
	dtrust_ops.init = dtrust_init;
	dtrust_ops.finish = dtrust_finish;
	dtrust_ops.pin_cmd = dtrust_pin_cmd;
	dtrust_ops.set_security_env = dtrust_set_security_env;
	dtrust_ops.compute_signature = dtrust_compute_signature;
	dtrust_ops.decipher = dtrust_decipher;
	dtrust_ops.logout = dtrust_logout;

	return &dtrust_drv;
}
