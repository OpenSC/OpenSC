/*
 * pkcs15-init driver for JavaCards with IsoApplet installed.
 *
 * Copyright (C) 2014 Philip Wendland <wendlandphilip@gmail.com>
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

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "../libopensc/log.h"
#include "../libopensc/internal.h"
#include "../libopensc/opensc.h"
#include "../libopensc/cardctl.h"
#include "../libopensc/asn1.h"
#include "pkcs15-init.h"
#include "profile.h"

#define ISOAPPLET_KEY_ID_MIN 0
#define ISOAPPLET_KEY_ID_MAX 15


struct ec_curve
{
	const struct sc_lv_data oid;
	const struct sc_lv_data prime;
	const struct sc_lv_data coefficientA;
	const struct sc_lv_data coefficientB;
	const struct sc_lv_data basePointG;
	const struct sc_lv_data order;
	const struct sc_lv_data coFactor;
};

static struct ec_curve curves[] =
{

	{
		{ (unsigned char *) "\x2B\x24\x03\x03\x02\x08\x01\x01\x03", 9},	/* brainpoolP192r1 */
		{ (unsigned char *) "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x30\x93\xD1\x8D\xB7\x8F\xCE\x47\x6D\xE1\xA8\x62\x97", 24},
		{ (unsigned char *) "\x6A\x91\x17\x40\x76\xB1\xE0\xE1\x9C\x39\xC0\x31\xFE\x86\x85\xC1\xCA\xE0\x40\xE5\xC6\x9A\x28\xEF", 24},
		{ (unsigned char *) "\x46\x9A\x28\xEF\x7C\x28\xCC\xA3\xDC\x72\x1D\x04\x4F\x44\x96\xBC\xCA\x7E\xF4\x14\x6F\xBF\x25\xC9", 24},
		{ (unsigned char *) "\xC0\xA0\x64\x7E\xAA\xB6\xA4\x87\x53\xB0\x33\xC5\x6C\xB0\xF0\x90\x0A\x2F\x5C\x48\x53\x37\x5F\xD6\x14\xB6\x90\x86\x6A\xBD\x5B\xB8\x8B\x5F\x48\x28\xC1\x49\x00\x02\xE6\x77\x3F\xA2\xFA\x29\x9B\x8F", 48},
		{ (unsigned char *) "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x2F\x9E\x9E\x91\x6B\x5B\xE8\xF1\x02\x9A\xC4\xAC\xC1", 24},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		{ (unsigned char *) "\x2A\x86\x48\xCE\x3D\x03\x01\x07", 8},	/* secp256r1 aka prime256v1 */
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 32},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32},
		{ (unsigned char *) "\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B", 32},
		{ (unsigned char *) "\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5", 64},
		{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51", 32},
		{ (unsigned char *) "\x00\x01", 2}
	},

	{
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0},
		{ NULL, 0}
	}
};


/*
 * Create DF, using default pkcs15init functions.
 */
static int
isoApplet_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df)
{
	sc_card_t *card = p15card->card;
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	if(!profile || !p15card || !df || !p15card->card || !p15card->card->ctx)
	{
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	r = sc_pkcs15init_create_file(profile, p15card, df);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Select a PIN reference.
 *
 * Basically (as I understand it) the caller passes an auth_info object and the
 * auth_info->attrs.pin.reference is supposed to be set accordingly and return.
 *
 * The IsoApplet only supports a PIN and a PUK at the moment.
 * The reference for the PIN is 1, for the PUK 2.
 */
static int
isoApplet_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                               sc_pkcs15_auth_info_t *auth_info)
{
	sc_card_t *card = p15card->card;
	int		preferred, current;

	LOG_FUNC_CALLED(card->ctx);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
	{
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);
	}

	current = auth_info->attrs.pin.reference;
	if (current < 0)
	{
		current = 0;
	}

	if(current > 2)
	{
		/* Only two PINs supported: User PIN and PUK. */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_TOO_MANY_OBJECTS);
	}
	else
	{
		if(auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
		{
			/* PUK */
			preferred = 2;
		}
		else
		{
			/* PIN */
			preferred = 1;
		}
	}

	auth_info->attrs.pin.reference = preferred;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * Create a PIN and store it on the card using CHANGE REFERENCE DATA for PIN transmission.
 * First, the PUK is transmitted, then the PIN. Now, the IsoApplet is in the
 * "STATE_OPERATIONAL_ACTIVATED" lifecycle state.
 */
static int
isoApplet_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df,
                     sc_pkcs15_object_t *pin_obj,
                     const u8 *pin, size_t pin_len,
                     const u8 *puk, size_t puk_len)
{
	sc_card_t *card = p15card->card;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if(!pin || !pin_len || !p15card || !p15card->card || !df || !&df->path)
	{
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if(pin_attrs->reference != 1 &&	pin_attrs->reference != 2)
	{
		/* Reject PIN reference. */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE);
	}

	/* If we have a PUK, set it first. */
	if(puk && puk_len)
	{
		/* The PUK has a incremented reference, i.e. pins are odd, puks are equal (+1). */
		r = sc_change_reference_data(p15card->card, SC_AC_CHV,
		                             pin_attrs->reference+1,
		                             NULL, 0,
		                             puk, puk_len, NULL);
		if(r < 0)
		{
			LOG_FUNC_RETURN(card->ctx, r);
		}
	}

	/* Store PIN: (use CHANGE REFERENCE DATA). */
	r = sc_change_reference_data(p15card->card, SC_AC_CHV,
	                             pin_attrs->reference,
	                             NULL, 0,
	                             pin, pin_len, NULL);

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * @brief Get the OID of the curve specified by a curve name.
 *
 * @param[in] named_curve 	The name of the curve to search the OID of.
 *							Supported values are: brainpoolP192r1, prime256v1.
 * @param[out] oid			The OID of the curve.
 *
 * @returns	SC_SUCCESS: If the curve was found.
 *			SC_ERROR_INVALID_ARGUMENTS: If named_curve was null or the curve
 *										was not found
 */
static int
isoApplet_get_curve_oid(const char* named_curve, const struct sc_lv_data **oid)
{
	if(!named_curve)
		return SC_ERROR_INVALID_ARGUMENTS;

	if(strncmp(named_curve, "brainpoolP192r1", 15) == 0)
	{
		*oid = &curves[0].oid;
		return SC_SUCCESS;
	}
	else if(strncmp(named_curve, "prime256v1", 10) == 0)
	{
		*oid = &curves[1].oid;
		return SC_SUCCESS;
	}
	return SC_ERROR_INVALID_ARGUMENTS;
}

/*
 * @brief Check the consistency of TLV-encoded EC curve parameters.
 *
 * Check the EC params in buf (length: len) that are structured according
 * to ISO 7816-8 table 3 - Public key data objects.
 * The params are compared with the ones given in the curve struct.
 *
 * @param[in] ctx
 * @param[in] buf	The buffer containing the TLV-encoded (ISO 7816-8 table 3)
 *					EC parameters.
 * @param[in] len 	The length of buf.
 * @param[in] curve	An ec_curve struct that should be used to check the
 *					parameters in buf.
 *
 * @return	SC_SUCCESS: If the EC parameters are consistent.
 *			SC_ERROR_INCOMPATIBLE_KEY: If the curve is unknown or the EC
 *										parameters are not consistent.
 */
static int
checkEcParams(sc_context_t* ctx, const u8* buf, size_t len, const struct ec_curve curve)
{
	const u8 *curr_pos = NULL;
	size_t tag_len;
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);

	/* Check the field. */
	curr_pos = sc_asn1_find_tag(ctx, buf, len, (unsigned int) 0x81, &tag_len);
	if(curr_pos == NULL || tag_len != curve.prime.len)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "Could not find any EC field tag in the response template or the length was unexpected.");
	}
	if(memcmp(curr_pos, curve.prime.value, curve.prime.len) != 0)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "The EC field by the smartcard was unexpected.");
	}

	/* Check the coefficient A. */
	curr_pos = sc_asn1_find_tag(ctx, buf, len, (unsigned int) 0x82, &tag_len);
	if(curr_pos == NULL || tag_len != curve.coefficientA.len)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "Could not find any EC coefficient A tag in the response template or the length was unexpected.");
	}
	if(memcmp(curr_pos, curve.coefficientA.value, curve.coefficientA.len) != 0)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "The EC coefficient A returned by the smartcard was unexpected.");
	}

	/* Check the coefficient B. */
	curr_pos = sc_asn1_find_tag(ctx, buf, len, (unsigned int) 0x83, &tag_len);
	if(curr_pos == NULL || tag_len != curve.coefficientB.len)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "Could not find any EC coefficient B tag in the response template or the length was unexpected.");
	}
	if(memcmp(curr_pos, curve.coefficientB.value, curve.coefficientB.len) != 0)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "The EC coefficient B returned by the smartcard was unexpected.");
	}

	/* Check the basepoint G.
	 * Note: The IsoApplet omits the 0x04 (uncompressed) tag. */
	curr_pos = sc_asn1_find_tag(ctx, buf, len, (unsigned int) 0x84, &tag_len);
	if(curr_pos == NULL || tag_len != curve.basePointG.len)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "Could not find any EC basepoint G tag in the response template or the length was unexpected.");
	}
	if(memcmp(curr_pos, curve.basePointG.value, curve.basePointG.len) != 0)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "The EC basepoint G returned by the smartcard was unexpected.");
	}

	/* Check the order. */
	curr_pos = sc_asn1_find_tag(ctx, buf, len, (unsigned int) 0x85, &tag_len);
	if(curr_pos == NULL || tag_len != curve.order.len)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "Could not find any EC order tag in the response template or the length was unexpected.");
	}
	if(memcmp(curr_pos, curve.order.value, curve.order.len) != 0)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "The EC order returned by the smartcard was unexpected.");
	}

	/* Check the coFactor. */
	curr_pos = sc_asn1_find_tag(ctx, buf, len, (unsigned int) 0x87, &tag_len);
	if(curr_pos == NULL || tag_len != curve.coFactor.len)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "Could not find any EC cofactor tag in the response template or the length was unexpected.");
	}
	if(memcmp(curr_pos, curve.coFactor.value, curve.coFactor.len) != 0)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		LOG_TEST_RET(ctx, r,
		             "The EC cofactor returned by the smartcards was unexpected.");
	}

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * @brief Generate a RSA private key on the card.
 *
 * A MANAGE SECURITY ENVIRONMENT apdu must have been sent before.
 * This function uses card_ctl to access the card-isoApplet driver.
 *
 * @param[in]	key_info
 * @param[in]	card
 * @param[in]	pubkey	The public key of the generated key pair
 *						returned by the card.
 *
 * @return	SC_ERROR_INVALID_ARGURMENTS: Invalid key length.
 *			SC_ERROR_OUT_OF_MEMORY
 */
static int
generate_key_rsa(sc_pkcs15_prkey_info_t *key_info, sc_card_t *card,
                 sc_pkcs15_pubkey_t *pubkey)
{
	int rv;
	size_t keybits;
	struct sc_cardctl_isoApplet_genkey args;

	LOG_FUNC_CALLED(card->ctx);

	/* Check key size: */
	keybits = key_info->modulus_length;
	if (keybits != 2048)
	{
		rv = SC_ERROR_INVALID_ARGUMENTS;
		sc_log(card->ctx, "%s: RSA private key length is unsupported, correct length is 2048", sc_strerror(rv));
		goto err;
	}

	/* Generate the key.
	 * Note: keysize is not explicitly passed to the card. It assumes 2048 along with the algorithm reference. */
	memset(&args, 0, sizeof(args));
	args.algorithm_ref = SC_ISOAPPLET_ALG_REF_RSA_GEN_2048;
	args.priv_key_ref = key_info->key_reference;

	args.pubkey_len = keybits / 8;
	args.pubkey = malloc(args.pubkey_len);
	if (!args.pubkey)
	{
		rv = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key buffer.", sc_strerror(rv));
		goto err;
	}

	args.exponent_len = 3;
	args.exponent = malloc(args.exponent_len);
	if(!args.exponent)
	{
		rv = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key exponent buffer.", sc_strerror(rv));
		goto err;
	}

	rv = sc_card_ctl(card, SC_CARDCTL_ISOAPPLET_GENERATE_KEY, &args);
	if (rv < 0)
	{
		sc_log(card->ctx, "%s: Error in card_ctl", sc_strerror(rv));
		goto err;
	}

	/* extract public key */
	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len   = args.pubkey_len;
	pubkey->u.rsa.modulus.data  = args.pubkey;
	pubkey->u.rsa.exponent.len  = args.exponent_len;
	pubkey->u.rsa.exponent.data = args.exponent;
	rv = SC_SUCCESS;
	LOG_FUNC_RETURN(card->ctx, rv);
err:
	if (args.pubkey)
	{
		free(args.pubkey);
		pubkey->u.rsa.modulus.data = NULL;
		pubkey->u.rsa.modulus.len = 0;
	}
	if (args.exponent)
	{
		free(args.exponent);
		pubkey->u.rsa.exponent.data = NULL;
		pubkey->u.rsa.exponent.len = 0;
	}
	LOG_FUNC_RETURN(card->ctx, rv);
}

/*
 * @brief Generate a EC private key on the card.
 *
 * A MANAGE SECURITY ENVIRONMENT apdu must have been sent before.
 * This function uses card_ctl to access the card-isoApplet driver.
 *
 * @param[in]	key_info
 * @param[in]	card
 * @param[in]	pubkey	The public key of the generated key pair
 *						returned by the card.
 *
 * @return	SC_ERROR_INVALID_ARGURMENTS: Invalid key length or curve.
 *			SC_ERROR_OUT_OF_MEMORY
 *			SC_ERROR_INCOMPATIBLE_KEY: The data returned by the card
 *										was unexpected and can not be
 *										handled.
 */
static int
generate_key_ec(const sc_pkcs15_prkey_info_t *key_info, sc_card_t *card,
                sc_pkcs15_pubkey_t *pubkey)
{
	int		r;
	u8*		p = NULL;
	u8* 	ecPubKeyPoint = NULL;
	size_t 	tag_len;
	size_t 	all_tags_len;
	const u8*					curr_pos = NULL;
	struct sc_ec_params*		ecp = NULL;
	const struct sc_lv_data*	oid = NULL;
	sc_cardctl_isoApplet_genkey_t			args;
	const struct sc_pkcs15_ec_parameters*	info_ecp =
	    (struct sc_pkcs15_ec_parameters *) key_info->params.data;

	LOG_FUNC_CALLED(card->ctx);

	/* Check key size: */
	if(key_info->field_length != 192
	        && key_info->field_length != 256)
	{
		sc_log(card->ctx, "EC field length is unsupported, length provided was: %d.", key_info->field_length);
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	if(info_ecp->named_curve && strncmp(info_ecp->named_curve, "brainpoolP192r1", 15) != 0
	        && strncmp(info_ecp->named_curve, "prime256v1", 10) != 0)
	{
		sc_log(card->ctx, "EC key generation failed: Unsupported curve: [%s].", info_ecp->named_curve);
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	/* Generate the key.
	 * Note: THe field size is not explicitly passed to the card.
	 *		 It assumes it along with the algorithm reference. */
	memset(&args, 0, sizeof(args));

	args.pubkey_len = 512;
	args.pubkey = malloc(args.pubkey_len);
	if(!args.pubkey)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key buffer.", sc_strerror(r));
		goto err;
	}

	if(strncmp(info_ecp->named_curve, "brainpoolP192r1", 15) == 0)
	{
		args.algorithm_ref = SC_ISOAPPLET_ALG_REF_EC_GEN_BRAINPOOLP192R1;
	}
	else if(strncmp(info_ecp->named_curve, "prime256v1", 10) == 0)
	{
		args.algorithm_ref = SC_ISOAPPLET_ALG_REF_EC_GEN_PRIME256V1;
	}
	args.priv_key_ref = key_info->key_reference;

	r = sc_card_ctl(card, SC_CARDCTL_ISOAPPLET_GENERATE_KEY, &args);
	if (r < 0)
	{
		sc_log(card->ctx, "%s: Error in card_ctl.", sc_strerror(r));
		goto err;
	}

	/* Extract the public key. */
	pubkey->algorithm = SC_ALGORITHM_EC;

	/* Get the curves OID. */
	r = isoApplet_get_curve_oid(info_ecp->named_curve, &oid);
	if(r < 0)
	{
		sc_log(card->ctx, "Error obtaining the curve OID.", sc_strerror(r));
		goto err;
	}

	/* der-encoded parameters */
	ecp = calloc(1, sizeof(struct sc_ec_params));
	if(!ecp)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	ecp->der_len = oid->len + 2;
	ecp->der = calloc(ecp->der_len, 1);
	if(!ecp->der)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key buffer.", sc_strerror(r));
		goto err;
	}
	ecp->der[0] = 0x06;
	ecp->der[1] = (u8)oid->len;
	memcpy(ecp->der + 2, oid->value, oid->len);
	ecp->type = 1; /* named curve */

	pubkey->alg_id = (struct sc_algorithm_id *)calloc(1, sizeof(struct sc_algorithm_id));
	if(!pubkey->alg_id)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key sc_algorithm_id.", sc_strerror(r));
		goto err;
	}
	pubkey->alg_id->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->params = ecp;

	p = args.pubkey;
	if(memcmp(info_ecp->named_curve, "brainpoolP192r1", 15) == 0)
	{
		/* The applet returns the public key encoded according to
		 * ISO 7816-8 table 3 - Public key data objects. This is a
		 * 2-byte tag. A length of 0xD0 = 208 is expected for BrainpoolP192r1. */
		if(memcmp(p, "\x7F\x49\x81\xD0", 4) != 0)
		{
			r = SC_ERROR_INCOMPATIBLE_KEY;
			sc_log(card->ctx, "%s: Key generation error: Unexpected EC public key received length.", sc_strerror(r));
			goto err;
		}
		else
		{
			p += 4; /* p points to the value field of the outer (7F 49) tag.
					 * This value field is a TLV-structure again. */
			all_tags_len = 208; /* 0xD0 bytes */
		}

		/* Check EC params. */
		r = checkEcParams(card->ctx, p, all_tags_len, curves[0]);
		if(r != SC_SUCCESS)
		{
			goto err;
		}
	}
	else if(memcmp(info_ecp->named_curve, "prime256v1", 10) == 0)
	{
		/* The applet returns the public key encoded according to
		 * ISO 7816-8 table 3 - Public key data objects. This is a
		 * 2-byte tag. A length of 0x011A = 282 is expected for Prime256v1. */
		if(memcmp(p, "\x7F\x49\x82\x01\x1A", 5) != 0)
		{
			r = SC_ERROR_INCOMPATIBLE_KEY;
			sc_log(card->ctx, "%s: Key generation error: Unexpected EC public key parameters.", sc_strerror(r));
			goto err;
		}
		else
		{
			p += 5; /* p points to the value field of the outer (7F 49) tag.
					 * This value field is a TLV-structure again. */
			all_tags_len = 282; /* 0x011A bytes */
		}

		/* Check EC params. */
		r = checkEcParams(card->ctx, p, all_tags_len, curves[1]);
		if(r != SC_SUCCESS)
		{
			goto err;
		}
	}

	/* Extract ecpointQ */
	curr_pos = sc_asn1_find_tag(card->ctx, p, all_tags_len, (unsigned int) 0x86, &tag_len);
	if(curr_pos == NULL || tag_len == 0)
	{
		r = SC_ERROR_INCOMPATIBLE_KEY;
		sc_log(card->ctx, "%s: Could not find any EC pointQ tag in the response template.", sc_strerror(r));
		goto err;
	}
	ecPubKeyPoint = malloc(tag_len+1);
	if(!ecPubKeyPoint)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key ecpointQ buffer.", sc_strerror(r));
		goto err;
	}
	*ecPubKeyPoint = 0x04; /* uncompressed */
	memcpy(ecPubKeyPoint+1, curr_pos, tag_len);
	pubkey->u.ec.ecpointQ.value = ecPubKeyPoint;
	pubkey->u.ec.ecpointQ.len = tag_len+1;

	/* OID for the public key */
	pubkey->u.ec.params.der.value = malloc(ecp->der_len);
	if(!pubkey->u.ec.params.der.value)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		sc_log(card->ctx, "%s: Unable to allocate public key ec params buffer.", sc_strerror(r));
		goto err;
	}
	memcpy(pubkey->u.ec.params.der.value, ecp->der, ecp->der_len);
	pubkey->u.ec.params.der.len = ecp->der_len;

	r = sc_pkcs15_fix_ec_parameters(card->ctx, &pubkey->u.ec.params);
	LOG_FUNC_RETURN(card->ctx, r);
err:
	if(pubkey)
	{
		if(pubkey->alg_id)
		{
			free(pubkey->alg_id);
			pubkey->alg_id = NULL;
		}
		if(pubkey->u.ec.params.der.value)
		{
			free(pubkey->u.ec.params.der.value);
			pubkey->u.ec.params.der.value = NULL;
			pubkey->u.ec.params.der.len = 0;
		}
		memset(pubkey, 0, sizeof(sc_pkcs15_pubkey_t));
	}
	if(args.pubkey)
	{
		free(args.pubkey);
		args.pubkey = NULL;
		args.pubkey_len = 0;
	}
	if(ecPubKeyPoint)
	{
		free(ecPubKeyPoint);
		ecPubKeyPoint = NULL;
	}
	if(ecp)
	{
		if(ecp->der)
		{
			free(ecp->der);
			ecp->der = NULL;
		}
		free(ecp);
		ecp = NULL;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
isoApplet_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                       sc_pkcs15_object_t *obj,
                       sc_pkcs15_pubkey_t *pubkey)
{
	int			 r;
	sc_pkcs15_prkey_info_t* key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	sc_file_t*		privKeyFile=NULL;
	sc_card_t*		card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	/* Authentication stuff. */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &privKeyFile);
	if(!privKeyFile)
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	r = sc_pkcs15init_authenticate(profile, p15card, privKeyFile, SC_AC_OP_CREATE_EF);
	if(r < 0)
	{
		sc_file_free(privKeyFile);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	sc_file_free(privKeyFile);

	/* Generate the key. */
	switch(obj->type)
	{
	case SC_PKCS15_TYPE_PRKEY_RSA:
		r = generate_key_rsa(key_info, card, pubkey);
		break;

	case SC_PKCS15_TYPE_PRKEY_EC:
		r = generate_key_ec(key_info, card, pubkey);
		break;

	default:
		r = SC_ERROR_NOT_SUPPORTED;
		sc_log(card->ctx, "%s: Key generation failed: Unknown/unsupported key type.", strerror(r));
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * Create a new key file. This is a no-op, because private keys are stored as key objects on the javacard.
 */
static int
isoApplet_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *obj)
{
	sc_card_t *card = p15card->card;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * Select a key reference.
 */
static int
isoApplet_select_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                               sc_pkcs15_prkey_info_t *key_info)
{
	int rv = SC_SUCCESS;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	if(key_info->key_reference < ISOAPPLET_KEY_ID_MIN)
	{
		key_info->key_reference = ISOAPPLET_KEY_ID_MIN;
		rv = SC_SUCCESS;
	}
	if(key_info->key_reference > ISOAPPLET_KEY_ID_MAX)
	{
		rv = SC_ERROR_TOO_MANY_OBJECTS;
	}
	LOG_FUNC_RETURN(card->ctx, rv);
}

/*
 * Store a usable private key on the card.
 */
static int
isoApplet_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *object,
                    sc_pkcs15_prkey_t *key)
{
	sc_card_t *card = p15card->card;
	sc_pkcs15_prkey_info_t* key_info = (sc_pkcs15_prkey_info_t *) object->data;
	sc_file_t*			  privKeyFile=NULL;
	sc_cardctl_isoApplet_import_key_t args;
	int r;
	char *p = NULL;

	LOG_FUNC_CALLED(card->ctx);

	/* Authentication stuff. */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &privKeyFile);
	if(!privKeyFile)
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	r = sc_pkcs15init_authenticate(profile, p15card, privKeyFile, SC_AC_OP_CREATE_EF);
	if(r < 0)
	{
		sc_file_free(privKeyFile);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}
	sc_file_free(privKeyFile);

	/* Key import. */
	switch(object->type)
	{
	case SC_PKCS15_TYPE_PRKEY_RSA:
		args.algorithm_ref = SC_ISOAPPLET_ALG_REF_RSA_GEN_2048;
		break;

	case SC_PKCS15_TYPE_PRKEY_EC:
		p = key->u.ec.params.named_curve;
		if(!p)
		{
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		}

		if(strncmp(p, "brainpoolP192r1", 15) == 0)
		{
			args.algorithm_ref = SC_ISOAPPLET_ALG_REF_EC_GEN_BRAINPOOLP192R1;
		}
		else if(strncmp(p, "prime256v1", 10) == 0)
		{
			args.algorithm_ref = SC_ISOAPPLET_ALG_REF_EC_GEN_PRIME256V1;
		}
		break;

	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	args.priv_key_ref = key_info->key_reference;
	args.prkey = key;

	r = sc_card_ctl(card, SC_CARDCTL_ISOAPPLET_IMPORT_KEY, &args);
	if (r < 0)
	{
		sc_log(card->ctx, "%s: Error in card_ctl", sc_strerror(r));
		LOG_FUNC_RETURN(card->ctx, r);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static struct sc_pkcs15init_operations sc_pkcs15init_isoApplet_operations =
{
	NULL,							/* erase_card */
	NULL,							/* init_card */
	isoApplet_create_dir,			/* create_dir */
	NULL,							/* create_domain */
	isoApplet_select_pin_reference,	/* pin_reference*/
	isoApplet_create_pin,			/* create_pin */
	isoApplet_select_key_reference,	/* key_reference */
	isoApplet_create_key,			/* create_key */
	isoApplet_store_key,			/* store_key */
	isoApplet_generate_key,			/* generate_key */
	NULL, NULL,						/* encode private/public key */
	NULL,	  						/* finalize */
	NULL, 							/* delete_object */
	NULL, NULL, NULL, NULL, NULL, 	/* pkcs15init emulation */
	NULL,							/* sanity_check*/
};

struct
sc_pkcs15init_operations *sc_pkcs15init_get_isoApplet_ops(void)
{
	return &sc_pkcs15init_isoApplet_operations;
}
