/*
 * pkcs15-westcos.c: pkcs15 emulation for westcos card
 *
 * Copyright (C) 2009 francois.leblanc@cev-sa.com 
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"
#include "common/compat_strlcpy.h"

int sc_pkcs15emu_westcos_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static int sc_pkcs15emu_westcos_init(sc_pkcs15_card_t * p15card)
{
	int i, r;
	int modulus_length = 0;
	char buf[256];
	sc_card_t *card = p15card->card;
	sc_serial_number_t serial;
	sc_path_t path;
	sc_file_t *file = NULL;
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, &file);
	if (r)
		goto out;
	if (file)
		sc_file_free(file);
	file = NULL;
	if (p15card->tokeninfo->label != NULL)
		free(p15card->tokeninfo->label);
	p15card->tokeninfo->label = strdup("westcos");
	if (p15card->tokeninfo->manufacturer_id != NULL)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = strdup("CEV");

	/* get serial number */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	r = sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
	if (r)
		goto out;
	if (p15card->tokeninfo->serial_number != NULL)
		free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = strdup(buf);
	sc_format_path("AAAA", &path);
	r = sc_select_file(card, &path, &file);
	if (r) 
	{
		goto out;
	}
	else
	{
		for (i = 0; i <= 1; i++) {
			unsigned int flags;
			struct sc_pkcs15_auth_info pin_info;
			struct sc_pkcs15_object pin_obj;
			memset(&pin_info, 0, sizeof(pin_info));
			memset(&pin_obj, 0, sizeof(pin_obj));
			flags = SC_PKCS15_PIN_FLAG_INITIALIZED;
			if (i == 1) {
				flags |=
					SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED |
					SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
			}
			pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
			pin_info.auth_id.len = 1;
			pin_info.auth_id.value[0] = i + 1;
			pin_info.attrs.pin.reference = i;
			pin_info.attrs.pin.flags = flags;
			pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_BCD;
			pin_info.attrs.pin.min_length = 4;
			pin_info.attrs.pin.stored_length = 8;
			pin_info.attrs.pin.max_length = 8;
			pin_info.attrs.pin.pad_char = 0xff;
			pin_info.path = path;
			pin_info.tries_left = -1;
			if (i == 1)
				strlcpy(pin_obj.label, "Unblock",
					sizeof(pin_obj.label));

			else
				strlcpy(pin_obj.label, "User",
					sizeof(pin_obj.label));
			pin_obj.flags =
				SC_PKCS15_CO_FLAG_MODIFIABLE |
				SC_PKCS15_CO_FLAG_PRIVATE;
			r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj,
							 &pin_info);
			if (r)
				goto out;
		}
	}
	
	if (file)
		sc_file_free(file);
	file = NULL;
	sc_format_path("0002", &path);
	r = sc_select_file(card, &path, &file);
	if (r) 
	{
		goto out;
	}
	else
	{
		/* certificate file */
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;
		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_object pubkey_obj;
		struct sc_pkcs15_pubkey *pkey = NULL;
		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));
		cert_info.id.len = 1;
		cert_info.id.value[0] = 0x45;
		cert_info.authority = 0;
		cert_info.path = path;
		r = sc_pkcs15_read_certificate(p15card, &cert_info,
					       (sc_pkcs15_cert_t
						**) (&cert_obj.data));
		if (!r) {
			sc_pkcs15_cert_t *cert =
			    (sc_pkcs15_cert_t *) (cert_obj.data);
			strlcpy(cert_obj.label, "User certificat",
				sizeof(cert_obj.label));
			cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;
			r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj,
						       &cert_info);
			if (r)
				goto out;
			pkey = cert->key;
			
			if (pkey->algorithm == SC_ALGORITHM_RSA) {
				modulus_length = (int)(pkey->u.rsa.modulus.len * 8);
			}

		}
		else
		{
			/* or public key */
			memset(&pubkey_info, 0, sizeof(pubkey_info));
			memset(&pubkey_obj, 0, sizeof(pubkey_obj));
			pubkey_info.id.len = 1;
			pubkey_info.id.value[0] = 0x45;
			pubkey_info.modulus_length = modulus_length;
			pubkey_info.key_reference = 1;
			pubkey_info.native = 1;
			pubkey_info.usage =
			    SC_PKCS15_PRKEY_USAGE_VERIFY |
			    SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER |
			    SC_PKCS15_PRKEY_USAGE_ENCRYPT |
			    SC_PKCS15_PRKEY_USAGE_WRAP;
			pubkey_info.path = path;
			strlcpy(pubkey_obj.label, "Public Key",
				sizeof(pubkey_obj.label));
			pubkey_obj.auth_id.len = 1;
			pubkey_obj.auth_id.value[0] = 1;
			pubkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
			pubkey_obj.type = SC_PKCS15_TYPE_PUBKEY_RSA;
			if (pkey == NULL) {
				pubkey_obj.data = &pubkey_info;
				r = sc_pkcs15_read_pubkey(p15card, &pubkey_obj, &pkey);
				if (r)
					goto out;
				/* not sure if necessary */
				pubkey_obj.flags = 0;
			}
			if (pkey->algorithm == SC_ALGORITHM_RSA) {
				modulus_length = (int)(pkey->u.rsa.modulus.len * 8);
			}
			pubkey_info.modulus_length = modulus_length;
			pubkey_obj.data = pkey;
			r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj,
							&pubkey_info);
			if (r < 0)
				goto out;
		}
	}
	if (file)
		sc_file_free(file);
	file = NULL;
	sc_format_path("0001", &path);
	r = sc_select_file(card, &path, &file);
	if (r) 
	{
		goto out;
	}
	else
	{
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object prkey_obj;
		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj, 0, sizeof(prkey_obj));
		prkey_info.id.len = 1;
		prkey_info.id.value[0] = 0x45;
		prkey_info.usage =
			SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT
			| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
		prkey_info.native = 1;
		prkey_info.key_reference = 1;
		prkey_info.modulus_length = modulus_length;
		prkey_info.path = path;
		strlcpy(prkey_obj.label, "Private Key",
			sizeof(prkey_obj.label));
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = 1;
		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj,
					&prkey_info);
		if (r < 0)
			goto out;
	}
	r = 0;
out:
	if (file)
		sc_file_free(file);
	return r;
}

static int westcos_detect_card(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_context_t *ctx = card->ctx;
	const char *name = "WESTCOS";
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
		"westcos_detect_card (%s)", card->name);
	if (strncmp(card->name, name, strlen(name)))
		return SC_ERROR_WRONG_CARD;
	return SC_SUCCESS;
}

int sc_pkcs15emu_westcos_init_ex(sc_pkcs15_card_t * p15card,
				 sc_pkcs15emu_opt_t * opts)
{
	int r;
	sc_card_t *card = p15card->card;
	sc_context_t *ctx = card->ctx;
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
		"sc_pkcs15_init_func_ex westcos\n");
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_westcos_init(p15card);
	r = westcos_detect_card(p15card);
	if (r)
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_westcos_init(p15card);
}
