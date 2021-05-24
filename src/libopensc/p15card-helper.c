/*
 * p15card-helper.c: Utility library to assist in PKCS#15 emulation on Non-filesystem cards
 *
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <thomas.harning@identityalliance.com>
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

#ifdef ENABLE_OPENSSL	/* empty file without openssl */
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "internal.h"
#include "p15card-helper.h"
#include "opensc.h"
#include "types.h"
#include "log.h"
#include "pkcs15.h"

int sc_pkcs15emu_initialize_objects(sc_pkcs15_card_t *p15card, p15data_items *items) {
	sc_card_t* card = p15card->card;
	const objdata* objects = items->objects;
	int i, r;
	if(!objects) return SC_SUCCESS;
	for (i = 0; objects[i].label; i++) {
		struct sc_pkcs15_data_info obj_info;
		struct sc_pkcs15_object    obj_obj;

		memset(&obj_info, 0, sizeof(obj_info));
		memset(&obj_obj, 0, sizeof(obj_obj));
		sc_pkcs15_format_id(objects[i].id, &obj_info.id);
		sc_format_path(objects[i].path, &obj_info.path);
		strncpy(obj_info.app_label, objects[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		r = sc_format_oid(&obj_info.app_oid, objects[i].aoid);
		if (r != SC_SUCCESS)
			return r;

		strncpy(obj_obj.label, objects[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		obj_obj.flags = objects[i].obj_flags;
		
		r = sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_DATA_OBJECT, 
			&obj_obj, &obj_info); 
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
	}
	return SC_SUCCESS;
}

static const prdata* get_prkey_by_cert(p15data_items* items, const cdata* cert) {
	const prdata* keys;
	if(!items->private_keys)
		return NULL;
	for(keys = items->private_keys; keys->id; keys++) {
		if(0 == strcmp(cert->id, keys->id))
			return keys;
	}
	return NULL;
}

static int add_private_key(sc_pkcs15_card_t *p15card, const prdata* key, int usage, int modulus_length) {
	struct sc_pkcs15_prkey_info prkey_info;
	struct sc_pkcs15_object     prkey_obj;

	memset(&prkey_info, 0, sizeof(prkey_info));
	memset(&prkey_obj,  0, sizeof(prkey_obj));
	
	sc_pkcs15_format_id(key->id, &prkey_info.id);
	
	prkey_info.native        = 1;
	prkey_info.key_reference = key->ref;

	if(!modulus_length) modulus_length = key->modulus_len;
	prkey_info.modulus_length= modulus_length;
	
	sc_format_path(key->path, &prkey_info.path);
	
	strncpy(prkey_obj.label, key->label, SC_PKCS15_MAX_LABEL_SIZE - 1);
	
	prkey_obj.flags = key->obj_flags;
	
	/* Setup key usage */
	if(!usage) usage = key->usage;
	prkey_info.usage = usage;
	
	if (key->auth_id)
		sc_pkcs15_format_id(key->auth_id, &prkey_obj.auth_id);
	
	return sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
}

static int add_public_key(sc_pkcs15_card_t *p15card, const pubdata *key, int usage, int modulus_length) {
	struct sc_pkcs15_pubkey_info pubkey_info;
	struct sc_pkcs15_object     pubkey_obj;

	memset(&pubkey_info, 0, sizeof(pubkey_info));
	memset(&pubkey_obj,  0, sizeof(pubkey_obj));

	sc_pkcs15_format_id(key->id, &pubkey_info.id);
	if(!usage) usage = key->usage;
	pubkey_info.usage         = usage;
	pubkey_info.native        = 1;
	pubkey_info.key_reference = key->ref;
	if(!modulus_length) modulus_length = key->modulus_len;
	pubkey_info.modulus_length= modulus_length;
	/* we really don't know how many bits or module length,
	 * we will assume 1024 for now 
	 */
	sc_format_path(key->path, &pubkey_info.path);

	strncpy(pubkey_obj.label, key->label, SC_PKCS15_MAX_LABEL_SIZE - 1);

	pubkey_obj.flags = key->obj_flags;

	if (key->auth_id)
		sc_pkcs15_format_id(key->auth_id, &pubkey_obj.auth_id);

	return sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
}

/* int default_cert_handle(sc_pkcs15_card_t *p15card, p15data_items* items, cdata* cert, u8* data, size_t length) { */
CERT_HANDLE_FUNCTION(default_cert_handle) {
	/* Certificate data exists, parse it */
	int r;
	X509 *cert_data = NULL;
	EVP_PKEY *pkey = NULL;
	const RSA * rsa = NULL;
	int certtype = 0;
	int modulus_len = 0;
	const prdata* key = get_prkey_by_cert(items, cert);
	if(!key) {
		sc_log(p15card->card->ctx,  "Error: No key for this certificate");
		return SC_ERROR_INTERNAL;
	}

	if(!d2i_X509(&cert_data, (const u8**)&data, length)) {
		sc_log(p15card->card->ctx,  "Error converting certificate");
		return SC_ERROR_INTERNAL;
	}

	pkey = X509_get_pubkey(cert_data);
	
	if(pkey == NULL) {
		sc_log(p15card->card->ctx,  "Error: no public key associated with the certificate");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	certtype = X509_certificate_type(cert_data, pkey);
	if(! (EVP_PK_RSA & certtype)) {
		sc_log(p15card->card->ctx,  "Error: certificate is not for an RSA key");
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	rsa = EVP_PKEY_get0_RSA(pkey);
	if( rsa == NULL) {
		sc_log(p15card->card->ctx,  "Error: no modulus associated with the certificate");
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	
	modulus_len =  RSA_bits(rsa);

	/* printf("Key Size: %d bits\n\n", modulus_len); */
	/* cached_cert->modulusLength = modulus_len; */
	
	if(key->label) {
		int usage = 0;
		if (certtype & EVP_PKT_SIGN) {
			usage |= SC_PKCS15_PRKEY_USAGE_SIGN;
			usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
		}
		
		if (certtype & EVP_PKT_ENC) {
			usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
			usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
		}
		if (certtype & EVP_PKT_EXCH) {
			usage |= SC_PKCS15_PRKEY_USAGE_WRAP;
			usage |= SC_PKCS15_PRKEY_USAGE_UNWRAP;
		}
		r = add_private_key(p15card, key, usage, modulus_len);
		if (r < 0)
			goto err;
	}
	r = SC_SUCCESS;
err:
	if(pkey) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	if(cert_data) {
		X509_free(cert_data);
		cert_data = NULL;
	}
	LOG_FUNC_RETURN(p15card->card->ctx, r);
}

int sc_pkcs15emu_initialize_certificates(sc_pkcs15_card_t *p15card, p15data_items* items) {
	/* set certs */
	sc_card_t* card = p15card->card;
	const cdata* certs = items->certs;
	int onFailResume = items->cert_continue;
	int i, r;
	if(!certs) return SC_SUCCESS;
	for (i = 0; certs[i].label; i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object    cert_obj;
		
		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));
		
		sc_pkcs15_format_id(certs[i].id, &cert_info.id);
		cert_info.authority = certs[i].authority;
		sc_format_path(certs[i].path, &cert_info.path);

		strncpy(cert_obj.label, certs[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		cert_obj.flags = certs[i].obj_flags;
		
		if(items->cert_load) {
			u8* cert_buffer = NULL;
			size_t cert_length = 0;
			int should_free = 0;
			if(SC_SUCCESS != sc_select_file(card, &cert_info.path, NULL)) {
				if(onFailResume)
					continue;
				else
					break;
			}
			if(SC_SUCCESS != (r = items->cert_load(card, &cert_buffer, &cert_length, &should_free))) {
				if(onFailResume)
					continue;
				else
					break;
			}
			/* Handle cert */
			/* If no cert handler, add.. if cert handler succeeds.. add */
			if(!items->cert_handle || SC_SUCCESS == (r = items->cert_handle(p15card, items, &certs[i], cert_buffer, cert_length))) {
				r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
			}
			if(should_free)
				free(cert_buffer);
			if(SC_SUCCESS != r) {
				if(onFailResume)
					continue;
				else
					break;
			}
		} else { /* Automatically add */
			if(SC_SUCCESS != sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info)) {
				if(onFailResume)
					continue;
				else
					break;
			}
		}
	}
	return SC_SUCCESS;
}

int sc_pkcs15emu_initialize_pins(sc_pkcs15_card_t *p15card, p15data_items* items) {
	/* set pins */
	int i,r;
	const pindata* pins = items->pins;
	if(!pins) return SC_SUCCESS;
	for (i = 0; pins[i].label; i++) {
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object   pin_obj;

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

		strncpy(pin_obj.label, pins[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj.flags = pins[i].obj_flags;

		if(0 > (r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info)))
			LOG_FUNC_RETURN(p15card->card->ctx, r);
	}
	return SC_SUCCESS;
}

int sc_pkcs15emu_initialize_private_keys(sc_pkcs15_card_t *p15card, p15data_items* items) {
	const prdata *prkeys = items->private_keys;
	int i, r;
	if(!prkeys) return SC_SUCCESS;
	/* set private keys */
	for (i = 0; prkeys[i].label; i++) {
		r = add_private_key(p15card, &prkeys[i], 0, 0);
		if (r < 0)
			LOG_FUNC_RETURN(p15card->card->ctx, r);
	}
	return SC_SUCCESS;
}

int sc_pkcs15emu_initialize_public_keys(sc_pkcs15_card_t *p15card, p15data_items *items) {
	const pubdata *keys = items->public_keys;
	int i, r;
	if(!keys) return SC_SUCCESS;
	/* set public keys */
	for (i = 0; keys[i].label; i++) {
		r = add_public_key(p15card, &keys[i], 0, 0);
		if (r < 0)
			LOG_FUNC_RETURN(p15card->card->ctx, r);
	}
	return SC_SUCCESS;

}

int sc_pkcs15emu_initialize_all(sc_pkcs15_card_t *p15card, p15data_items* items) {
	int r;
	if(SC_SUCCESS != (r = sc_pkcs15emu_initialize_objects(p15card, items)))
		return r;
	if(SC_SUCCESS != (r = sc_pkcs15emu_initialize_certificates(p15card, items)))
		return r;
	if(SC_SUCCESS != (r = sc_pkcs15emu_initialize_pins(p15card, items)))
		return r;

	if(items->forced_private && (SC_SUCCESS != (r = sc_pkcs15emu_initialize_private_keys(p15card, items))))
		return r;
	if(items->forced_public && (SC_SUCCESS != (r = sc_pkcs15emu_initialize_public_keys(p15card, items))))
		return r;
	return SC_SUCCESS;
}

#endif	/* ENABLE_OPENSSL */
