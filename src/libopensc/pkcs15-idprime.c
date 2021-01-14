/*
 * partial PKCS15 emulation for IDPrime cards.
 *
 * We can not use the ISO code, since the EF.DIR and EF.ATR for
 * object discovery are missing
 *
 * Copyright (C) 2019, Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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

#include <string.h>
#include <stdlib.h>
#include "internal.h"
#include "cardctl.h"
#include "pkcs15.h"

#define CERT_LABEL_TEMPLATE "Certificate %d"
#define PUBKEY_LABEL_TEMPLATE "Public key %d"
#define PRIVKEY_LABEL_TEMPLATE "Private key %d"

static int idprime_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (card->type < SC_CARD_TYPE_IDPRIME_BASE
		|| card->type >= SC_CARD_TYPE_IDPRIME_BASE+1000)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}

static int sc_pkcs15emu_idprime_init(sc_pkcs15_card_t *p15card)
{
	int r, i;
	sc_card_t *card = p15card->card;
	sc_serial_number_t serial;
	char buf[SC_MAX_SERIALNR * 2 + 1];
	int count;
	char *token_name = NULL;
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object   pin_obj;
	const char pin_label[] = "PIN";
	const char *pin_id = "11";

	/* oid for key usage */
	static const struct sc_object_id usage_type = {{ 2, 5, 29, 15, -1 }};
	unsigned int usage;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* could read this off card if needed */
	set_string(&p15card->tokeninfo->label, "IDPrime");
	set_string(&p15card->tokeninfo->manufacturer_id, "Gemalto");

	/*
	 * get serial number
	 */
	memset(&serial, 0, sizeof(serial));
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r < 0) {
		sc_log(card->ctx, "sc_card_ctl rc=%d", r);
		set_string(&p15card->tokeninfo->serial_number, "00000000");
	} else {
		sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
		set_string(&p15card->tokeninfo->serial_number, buf);
	}
	/* set pin */
	sc_log(card->ctx,  "IDPrime adding pin...");
	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj,  0, sizeof(pin_obj));

	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	sc_pkcs15_format_id(pin_id, &pin_info.auth_id);
	pin_info.attrs.pin.reference     = 0x11;
	pin_info.attrs.pin.flags         = SC_PKCS15_PIN_FLAG_INITIALIZED;
	pin_info.attrs.pin.type          = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length    = 4;
	pin_info.attrs.pin.stored_length = 0;
	pin_info.attrs.pin.max_length    = 16;
	pin_info.tries_left    = -1;

	if (card->type == SC_CARD_TYPE_IDPRIME_V3) {
		pin_info.attrs.pin.flags |= SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
		pin_info.attrs.pin.stored_length = 16;
		pin_info.attrs.pin.pad_char = 0x00;
	}

	sc_log(card->ctx,  "IDPrime Adding pin with label=%s", pin_label);
	strncpy(pin_obj.label, pin_label, SC_PKCS15_MAX_LABEL_SIZE - 1);
	pin_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	if (r < 0)
		LOG_FUNC_RETURN(card->ctx, r);

	/*
	 * get token name if provided
	 */
	r = sc_card_ctl(card, SC_CARDCTL_IDPRIME_GET_TOKEN_NAME, &token_name);
	if (r < 0) {
		/* On failure we will get the token name from certificates later */
		sc_log(card->ctx, "sc_card_ctl rc=%d", r);
	} else {
		free(p15card->tokeninfo->label);
		p15card->tokeninfo->label = token_name;
		sc_log(card->ctx,  "IDPrime setting token label = %s", token_name);
	}
	/*
	 * certs, pubkeys and priv keys are related and we assume
	 * they are in order
	 * We need to read the cert, get modulus and keylen
	 * We use those for the pubkey, and priv key objects.
	 */
	sc_log(card->ctx,  "IDPrime adding certs, pub and priv keys...");
	r = (card->ops->card_ctl)(card, SC_CARDCTL_IDPRIME_INIT_GET_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not initiate cert objects.");

	for (i = 0; i < count; i++) {
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_object cert_obj;
		struct sc_pkcs15_object pubkey_obj;
		struct sc_pkcs15_object prkey_obj;
		sc_pkcs15_der_t cert_der;
		sc_pkcs15_cert_t *cert_out = NULL;

		r = (card->ops->card_ctl)(card, SC_CARDCTL_IDPRIME_GET_NEXT_OBJECT, &prkey_info);
		LOG_TEST_RET(card->ctx, r, "Can not get next object");

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&pubkey_info, 0, sizeof(pubkey_info));
		/* prkey_info cleaned by the card_ctl call */
		memset(&cert_obj,  0, sizeof(cert_obj));
		memset(&pubkey_obj,  0, sizeof(pubkey_obj));
		memset(&prkey_obj,  0, sizeof(prkey_obj));

		cert_info.id = prkey_info.id;
		pubkey_info.id = prkey_info.id;
		cert_info.path = prkey_info.path;
		/* For private keys, we no longer care for the path, just
		 * the key reference later used in the security environment */
		prkey_info.path.len = 0;
		prkey_info.path.aid.len = 0;
		pubkey_info.key_reference = prkey_info.key_reference;
		sc_log(card->ctx,  "Key ref r=%x", prkey_info.key_reference);

		pubkey_info.native        = 1;
		prkey_info.native        = 1;

		snprintf(cert_obj.label, SC_PKCS15_MAX_LABEL_SIZE, CERT_LABEL_TEMPLATE, i+1);
		snprintf(pubkey_obj.label, SC_PKCS15_MAX_LABEL_SIZE, PUBKEY_LABEL_TEMPLATE, i+1);
		snprintf(prkey_obj.label, SC_PKCS15_MAX_LABEL_SIZE, PRIVKEY_LABEL_TEMPLATE, i+1);
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
		sc_pkcs15_format_id(pin_id, &prkey_obj.auth_id);

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
			free(cert_der.value);
			continue;
		}

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0) {
			sc_log(card->ctx,  " Failed to add cert obj r=%d",r);
			sc_pkcs15_free_certificate(cert_out);
			free(cert_der.value);
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
				token_name[cn_len] = '\0';
				free(p15card->tokeninfo->label);
				p15card->tokeninfo->label = token_name;
			}
		}


		r = sc_pkcs15_encode_pubkey_as_spki(card->ctx, cert_out->key,
			&pubkey_info.direct.spki.value, &pubkey_info.direct.spki.len);
		if (r < 0)
			goto fail;
		pubkey_obj.emulated = cert_out->key;

		r = sc_pkcs15_get_bitstring_extension(card->ctx, cert_out, &usage_type, &usage, NULL);
		if (r < 0) {
			usage = SC_X509_DATA_ENCIPHERMENT|SC_X509_DIGITAL_SIGNATURE; /* basic default usage */
		}
		sc_pkcs15_map_usage(usage, cert_out->key->algorithm, &pubkey_info.usage, &prkey_info.usage, 1);
		sc_log(card->ctx, "cert %s: cert_usage=0x%x, pub_usage=0x%x priv_usage=0x%x\n",
			sc_dump_hex(cert_info.id.value, cert_info.id.len),
			usage, pubkey_info.usage, prkey_info.usage);
		if (cert_out->key->algorithm != SC_ALGORITHM_RSA) {
			sc_log(card->ctx, "unsupported key.algorithm %d", cert_out->key->algorithm);
			sc_pkcs15_free_certificate(cert_out);
			continue;
		} else {
			pubkey_info.modulus_length = cert_out->key->u.rsa.modulus.len * 8;
			prkey_info.modulus_length = cert_out->key->u.rsa.modulus.len * 8;
			sc_log(card->ctx,  "adding rsa public key r=%d usage=%x",r, pubkey_info.usage);
			r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
			if (r < 0)
				goto fail;
			sc_log(card->ctx,  "adding rsa private key r=%d usage=%x",r, prkey_info.usage);
			r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
			if (r < 0)
				goto fail;
		}

		cert_out->key = NULL;
fail:
		sc_pkcs15_free_certificate(cert_out);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r); /* should not fail */

	}
	r = (card->ops->card_ctl)(card, SC_CARDCTL_IDPRIME_FINAL_GET_OBJECTS, &count);
	LOG_TEST_RET(card->ctx, r, "Can not finalize cert objects.");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_idprime_init_ex(sc_pkcs15_card_t *p15card,
		struct sc_aid *aid)
{
	sc_card_t   *card = p15card->card;
	sc_context_t    *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	if (idprime_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_idprime_init(p15card);
}
