/*
 * partial PKCS15 emulation for CAC-II cards
 * only minimal use of the authentication cert and key
 *
 * Copyright (C) 2005,2006,2007,2008,2009,2010
 *               Douglas E. Engert <deengert@anl.gov>
 *               2004, Nils Larsch <larsch@trustcenter.de>
 * Copyright (C) 2006, Identity Alliance,
 *               Thomas Harning <thomas.harning@identityalliance.com>
 * Copyright (C) 2007, EMC, Russell Larner <rlarner@rsa.com>
 * Copyright (C) 2016, Red Hat, Inc.
 *
 * CAC driver author: Robert Relyea <rrelyea@redhat.com>
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
#include <stdio.h>
#include <ctype.h>

#include "internal.h"
#include "cardctl.h"
#include "pkcs15.h"
/* X509 Key Usage flags */
#include "../pkcs15init/pkcs15-init.h"

/* probably should get manufacturer ID from cuid */
#define MANU_ID		"Common Access Card"

int sc_pkcs15emu_cac_init_ex(sc_pkcs15_card_t *, struct sc_aid *, sc_pkcs15emu_opt_t *);



typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	unsigned int storedlen;
	int         flags;
	int         tries_left;
	const unsigned char  pad_char;
	int         obj_flags;
} pindata;

static int cac_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (card->type < SC_CARD_TYPE_CAC_GENERIC
		|| card->type >= SC_CARD_TYPE_CAC_GENERIC+1000)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}

#define CAC_NUM_CERTS_AND_KEYS 10

static const char * cac_get_name(int type)
{
    switch (type) {
    case SC_CARD_TYPE_CAC_I: return ("CAC I");
    case SC_CARD_TYPE_CAC_II: return ("CAC II");
    default: break;
    }
    return ("CAC");
}

/*
 * These could move to a helper file for other cards that wish to use usage as a way of getting flags
 */

/* Only certain usages are valid for a given algorithm, return all the usages that the algorithm supports so we
 * can use it as a filter for all the public and private key usages */
static unsigned int
cac_alg_flags_from_algorithm(int algorithm)
{
	switch (algorithm) {
	case SC_ALGORITHM_RSA:
		return SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP |
		       SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER |
		       SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP |
		       SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER |
		       SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	case SC_ALGORITHM_DSA:
		return SC_PKCS15_PRKEY_USAGE_VERIFY| SC_PKCS15_PRKEY_USAGE_SIGN |
		       SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
#ifdef SC_ALGORITHM_DH
	case SC_ALGORITHM_DH:
		return SC_PKCS15_PRKEY_USAGE_DERIVE ;
#endif
	case SC_ALGORITHM_EC:
		return SC_PKCS15_PRKEY_USAGE_DERIVE | SC_PKCS15_PRKEY_USAGE_VERIFY|
		       SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	case SC_ALGORITHM_GOSTR3410:
		return SC_PKCS15_PRKEY_USAGE_DERIVE | SC_PKCS15_PRKEY_USAGE_VERIFY|
		       SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	}
	return 0;
}

/* These are the cert key usage bits that map to various PKCS #11 (and thus PKCS #15) flags */
#define CAC_X509_USAGE_SIGNATURE \
	(SC_X509_DIGITAL_SIGNATURE | \
	SC_X509_NON_REPUDIATION    | \
	SC_X509_KEY_CERT_SIGN      | \
	SC_X509_CRL_SIGN)
#define CAC_X509_USAGE_DERIVE \
	SC_X509_KEY_AGREEMENT
#define CAC_X509_USAGE_UNWRAP \
	(SC_X509_KEY_ENCIPHERMENT | \
	SC_X509_KEY_AGREEMENT)
#define CAC_X509_USAGE_DECRYPT \
	(SC_X509_DATA_ENCIPHERMENT | \
	SC_X509_ENCIPHER_ONLY)
#define CAC_X509_USAGE_NONREPUDIATION \
	SC_X509_NON_REPUDIATION

/* map a cert usage and algorithm to public and private key usages */
static int
cac_map_usage(unsigned int cert_usage, int algorithm, unsigned int *pub_usage_ptr, unsigned int *pr_usage_ptr, int allow_nonrepudiation)
{
	unsigned int pub_usage = 0, pr_usage = 0;
	unsigned int alg_flags = cac_alg_flags_from_algorithm(algorithm);

	if (cert_usage & CAC_X509_USAGE_SIGNATURE) {
		pub_usage |= SC_PKCS15_PRKEY_USAGE_VERIFY|SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
		pr_usage |= SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
	}
	if (cert_usage & CAC_X509_USAGE_DERIVE) {
		pub_usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
		pr_usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
	}
	if (cert_usage & (CAC_X509_USAGE_DECRYPT|CAC_X509_USAGE_UNWRAP)) {
		pub_usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
		pr_usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
	}
	if (allow_nonrepudiation && (cert_usage & CAC_X509_USAGE_NONREPUDIATION)) {
		pub_usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
		pr_usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	}
	/* filter usages algorithm */
	if (pub_usage_ptr) {
		*pub_usage_ptr = pub_usage & alg_flags;
	}
	if (pr_usage_ptr) {
		*pr_usage_ptr = pr_usage & alg_flags;
	}
	return SC_SUCCESS;
}

static int sc_pkcs15emu_cac_init(sc_pkcs15_card_t *p15card)
{
	static const pindata pins[] = {
		{ "1", "PIN", "", 0x00,
		  SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		  8, 4, 8,
		  SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
		  SC_PKCS15_PIN_FLAG_INITIALIZED ,
		  -1, 0xFF,
		  SC_PKCS15_CO_FLAG_PRIVATE },
		{ NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	};
	/* oid for key usage */
	static const struct sc_object_id usage_type = {{ 2, 5, 29, 15, -1 }};
	unsigned int usage;


	/*
	 * The size of the key or the algid is not really known
	 * but can be derived from the certificates.
	 * the cert, pubkey and privkey are a set.
	 * Key usages bits taken from certificate key usage extension.
	 */

	int    r, i;
	sc_card_t *card = p15card->card;
	sc_serial_number_t serial;
	char buf[SC_MAX_SERIALNR * 2 + 1];
	int count;
	char *token_name = NULL;


	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&serial, 0, sizeof(serial));

	/* could read this off card if needed */

	p15card->tokeninfo->label = strdup(cac_get_name(card->type));
	p15card->tokeninfo->manufacturer_id = strdup(MANU_ID);

	/*
	 * get serial number
	 */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r < 0) {
		sc_log(card->ctx, "sc_card_ctl rc=%d",r);
		p15card->tokeninfo->serial_number = strdup("00000000");
	} else {
		sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
		p15card->tokeninfo->serial_number = strdup(buf);
	}

	/* set pins */
	/* TODO we should not create PIN objects if it is not initialized
	 * (opensc-tool -s 0020000000 returns 0x6A 0x88)
	 */
	sc_log(card->ctx,  "CAC adding pins...");
	for (i = 0; pins[i].id; i++) {
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object   pin_obj;
		const char * label;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj,  0, sizeof(pin_obj));

		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		sc_pkcs15_format_id(pins[i].id, &pin_info.auth_id);
		pin_info.attrs.pin.reference     = pins[i].ref;
		pin_info.attrs.pin.flags         = pins[i].flags;
		pin_info.attrs.pin.type          = pins[i].type;
		pin_info.attrs.pin.min_length    = pins[i].minlen;
		pin_info.attrs.pin.stored_length = pins[i].storedlen;
		pin_info.attrs.pin.max_length    = pins[i].maxlen;
		pin_info.attrs.pin.pad_char      = pins[i].pad_char;
		sc_format_path(pins[i].path, &pin_info.path);
		pin_info.tries_left    = -1;

		label = pins[i].label;
		sc_log(card->ctx,  "CAC Adding pin %d label=%s",i, label);
		strncpy(pin_obj.label, label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj.flags = pins[i].obj_flags;

		/* get the ACA path in case it needs to be selected before PIN verify */
		r = sc_card_ctl(card, SC_CARDCTL_CAC_GET_ACA_PATH, &pin_info.path);
		if (r < 0) {
			LOG_FUNC_RETURN(card->ctx, r);
		}

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
	}

	/* set other objects */
	r = (card->ops->card_ctl)(card, SC_CARDCTL_CAC_INIT_GET_GENERIC_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not initiate generic objects.");

	for (i = 0; i < count; i++) {
		struct sc_pkcs15_data_info obj_info;
		struct sc_pkcs15_object    obj_obj;

		r = (card->ops->card_ctl)(card, SC_CARDCTL_CAC_GET_NEXT_GENERIC_OBJECT, &obj_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
		memset(&obj_obj, 0, sizeof(obj_obj));
		memcpy(obj_obj.label, obj_info.app_label, sizeof(obj_obj.label));

		r = sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_DATA_OBJECT,
			&obj_obj, &obj_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
	}
	r = (card->ops->card_ctl)(card, SC_CARDCTL_CAC_FINAL_GET_GENERIC_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not finalize generic objects.");

	/*
	 * certs, pubkeys and priv keys are related and we assume
	 * they are in order
	 * We need to read the cert, get modulus and keylen
	 * We use those for the pubkey, and priv key objects.
	 */
	sc_log(card->ctx,  "CAC adding certs, pub and priv keys...");
	r = (card->ops->card_ctl)(card, SC_CARDCTL_CAC_INIT_GET_CERT_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not initiate cert objects.");

	for (i = 0; i < count; i++) {
		struct sc_pkcs15_data_info obj_info;
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object cert_obj;
		struct sc_pkcs15_object pubkey_obj;
		struct sc_pkcs15_object prkey_obj;
		sc_pkcs15_der_t   cert_der;
		sc_pkcs15_cert_t *cert_out = NULL;

		r = (card->ops->card_ctl)(card, SC_CARDCTL_CAC_GET_NEXT_CERT_OBJECT, &obj_info);
		LOG_TEST_RET(card->ctx, r, "Can not get next object");

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&pubkey_info, 0, sizeof(pubkey_info));
		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&cert_obj,  0, sizeof(cert_obj));
		memset(&pubkey_obj,  0, sizeof(pubkey_obj));
		memset(&prkey_obj,  0, sizeof(prkey_obj));

		cert_info.id = obj_info.id;
		pubkey_info.id = obj_info.id;
		prkey_info.id = obj_info.id;
		cert_info.path = obj_info.path;
		prkey_info.path = obj_info.path;
		/* Add 0x3f00 to the front of prkey_info.path to make sc_key_file happy */
		/* only do this if our path.len is 1 or 2 */
		if (prkey_info.path.len && prkey_info.path.len <= 2) {
			prkey_info.path.value[2] = prkey_info.path.value[0];
			prkey_info.path.value[3] = prkey_info.path.value[1];
			prkey_info.path.value[0] = 0x3f;
			prkey_info.path.value[1] = 0x00;
			prkey_info.path.len += 2;
		}
		pubkey_info.native        = 1;
		pubkey_info.key_reference = ((int)obj_info.id.value[0]) << 8 | obj_info.id.value[1];
		prkey_info.key_reference = ((int)obj_info.id.value[0]) << 8 | obj_info.id.value[1];
		prkey_info.native        = 1;

		memcpy(cert_obj.label, obj_info.app_label, sizeof(obj_info.app_label));
		memcpy(pubkey_obj.label, obj_info.app_label, sizeof(obj_info.app_label));
		memcpy(prkey_obj.label, obj_info.app_label, sizeof(obj_info.app_label));
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
		sc_pkcs15_format_id(pins[0].id, &prkey_obj.auth_id);

		r = sc_pkcs15_read_file(p15card, &cert_info.path, &cert_der.value, &cert_der.len);

		if (r) {
			sc_log(card->ctx,  "No cert found,i=%d", i);
			continue;
		}
		cert_info.path.count = cert_der.len;

		sc_log(card->ctx, 
			 "cert len=%"SC_FORMAT_LEN_SIZE_T"u, cert_info.path.count=%d r=%d\n",
			 cert_der.len, cert_info.path.count, r);
		sc_log_hex(card->ctx, "cert", cert_der.value, cert_der.len);

		/* cache it using the PKCS15 emulation objects */
		/* as it does not change */
		if (cert_der.value) {
			cert_info.value.value = cert_der.value;
			cert_info.value.len = cert_der.len;
			cert_info.path.len = 0; /* use in mem cert from now on */
		}

		/* following will find the cached cert in cert_info */
		r =  sc_pkcs15_read_certificate(p15card, &cert_info, &cert_out);
		if (r < 0 || cert_out->key == NULL) {
			sc_log(card->ctx,  "Failed to read/parse the certificate r=%d",r);
			if (cert_out != NULL)
				sc_pkcs15_free_certificate(cert_out);
			continue;
		}

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0) {
			sc_log(card->ctx,  " Failed to add cert obj r=%d",r);
			sc_pkcs15_free_certificate(cert_out);
			continue;
		}
		/* set the token name to the name of the CN of the first certificate */
		if (!token_name) {
			u8 * cn_name = NULL;
			size_t cn_len = 0;
			static const struct sc_object_id cn_oid = {{ 2, 5, 4, 3, -1 }};
			r = sc_pkcs15_get_name_from_dn(card->ctx, cert_out->subject,
				cert_out->subject_len, &cn_oid, &cn_name, &cn_len);
			if (r == SC_SUCCESS) {
				token_name = malloc (cn_len+1);
				if (!token_name) {
					free(cn_name);
					r = SC_ERROR_OUT_OF_MEMORY;
					goto fail;
				}
				memcpy(token_name, cn_name, cn_len);
				free(cn_name);
				token_name[cn_len] = 0;
				free(p15card->tokeninfo->label);
				p15card->tokeninfo->label = token_name;
			}
		}


		r = sc_pkcs15_encode_pubkey_as_spki(card->ctx, cert_out->key, &pubkey_info.direct.spki.value, &pubkey_info.direct.spki.len);
		if (r < 0)
			goto fail;
		pubkey_obj.emulated = cert_out->key;

		r = sc_pkcs15_get_bitstring_extension(card->ctx, cert_out, &usage_type, &usage, NULL);
		if (r < 0) {
			usage = 0xd9ULL; /* basic default usage */
		}
		cac_map_usage(usage, cert_out->key->algorithm, &pubkey_info.usage, &prkey_info.usage, 1);
		sc_log(card->ctx,   "cert %s: cert_usage=0x%x, pub_usage=0x%x priv_usage=0x%x\n",
				sc_dump_hex(cert_info.id.value, cert_info.id.len),
				 usage, pubkey_info.usage, prkey_info.usage);
		if (cert_out->key->algorithm != SC_ALGORITHM_RSA) {
			sc_log(card->ctx, "unsupported key.algorithm %d", cert_out->key->algorithm);
			sc_pkcs15_free_certificate(cert_out);
			continue;
		} else {
			pubkey_info.modulus_length = cert_out->key->u.rsa.modulus.len * 8;
			prkey_info.modulus_length = cert_out->key->u.rsa.modulus.len * 8;
			r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
			sc_log(card->ctx,  "adding rsa public key r=%d usage=%x",r, pubkey_info.usage);
			if (r < 0)
				goto fail;
			r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
			sc_log(card->ctx,  "adding rsa private key r=%d usage=%x",r, prkey_info.usage);
		}

		cert_out->key = NULL;
fail:
		sc_pkcs15_free_certificate(cert_out);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r); /* should not fail */

	}
	r = (card->ops->card_ctl)(card, SC_CARDCTL_CAC_FINAL_GET_CERT_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not finalize cert objects.");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_cac_init_ex(sc_pkcs15_card_t *p15card,
		struct sc_aid *aid, sc_pkcs15emu_opt_t *opts)
{
	sc_card_t   *card = p15card->card;
	sc_context_t    *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	if (cac_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_cac_init(p15card);
}
