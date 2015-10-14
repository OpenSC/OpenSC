/*
 * PKCS15 emulation layer for EstEID card.
 *
 * Copyright (C) 2004, Martin Paljak <martin@martinpaljak.net>
 * Copyright (C) 2004, Bud P. Bruegger <bud@comune.grosseto.it>
 * Copyright (C) 2004, Antonino Iacono <ant_iacono@tin.it>
 * Copyright (C) 2003, Olaf Kirch <okir@suse.de>
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
#ifdef ENABLE_OPENSSL
#include <openssl/x509v3.h>
#endif

#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"

#include "internal.h"
#include "pkcs15.h"
#include "esteid.h"

int sc_pkcs15emu_esteid_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static void
set_string (char **strp, const char *value)
{
	if (*strp)
		free (*strp);
	*strp = value ? strdup (value) : NULL;
}


int
select_esteid_df (sc_card_t * card)
{
	int r;
	sc_path_t tmppath;
	sc_format_path ("3F00EEEE", &tmppath);
	r = sc_select_file (card, &tmppath, NULL);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "esteid select DF failed");
	return r;
}

static int
sc_pkcs15emu_esteid_init (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	unsigned char buff[128];
	int r, i;
	sc_path_t tmppath;

	set_string (&p15card->tokeninfo->label, "ID-kaart");
	set_string (&p15card->tokeninfo->manufacturer_id, "AS Sertifitseerimiskeskus");

	/* Select application directory */
	sc_format_path ("3f00eeee5044", &tmppath);
	r = sc_select_file (card, &tmppath, NULL);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "select esteid PD failed");

	/* read the serial (document number) */	
	r = sc_read_record (card, SC_ESTEID_PD_DOCUMENT_NR, buff, sizeof(buff), SC_RECORD_BY_REC_NR);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "read document number failed");
	buff[r] = '\0';
	set_string (&p15card->tokeninfo->serial_number, (const char *) buff);

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION
				  | SC_PKCS15_TOKEN_EID_COMPLIANT
				  | SC_PKCS15_TOKEN_READONLY;

	/* add certificates */
	for (i = 0; i < 2; i++) {
		static const char *esteid_cert_names[2] = {
			"Isikutuvastus",
			"Allkirjastamine"};
		static char const *esteid_cert_paths[2] = {
			"3f00eeeeaace",
			"3f00eeeeddce"};
		static int esteid_cert_ids[2] = {1, 2};
			
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;
		
		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		cert_info.id.value[0] = esteid_cert_ids[i];
		cert_info.id.len = 1;
		sc_format_path(esteid_cert_paths[i], &cert_info.path);
		strlcpy(cert_obj.label, esteid_cert_names[i], sizeof(cert_obj.label));
		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
#ifdef ENABLE_OPENSSL
		if (i == 0) {
			BIO *mem = NULL;
			X509 *x509 = NULL;
			sc_pkcs15_cert_t *cert;
			char cardholder_name[64];
			unsigned char *tmp = NULL;
			r = sc_pkcs15_read_certificate(p15card, &cert_info, &cert);
			if (r == SC_SUCCESS) {
				mem = BIO_new_mem_buf(cert->data.value, cert->data.len);
				if (!mem) {
					sc_pkcs15_free_certificate(cert);
					return SC_ERROR_INTERNAL;
				}
				x509 = d2i_X509_bio(mem, NULL);
				BIO_free(mem);
				sc_pkcs15_free_certificate(cert);
				if (!x509)
					return SC_ERROR_INTERNAL;
				r = X509_NAME_get_index_by_NID(X509_get_subject_name(x509), NID_commonName, -1);
				if (r >= 0) {
					X509_NAME_ENTRY *ne;
					ASN1_STRING *a_str;
					ne = X509_NAME_get_entry(X509_get_subject_name(x509), r);
					if (!ne) {
						X509_free(x509);
						return SC_ERROR_INTERNAL;
					}
					a_str = X509_NAME_ENTRY_get_data(ne);
					if (!a_str) {
						X509_free(x509);
						return SC_ERROR_INTERNAL;
					}
					r = ASN1_STRING_to_UTF8(&tmp, a_str);
					if (r > 0) {
						if ((unsigned)r > sizeof(cardholder_name) - 1)
							r = sizeof(cardholder_name) -1;
						memcpy(cardholder_name, tmp, r);
						cardholder_name[r] = '\0';
						set_string(&p15card->tokeninfo->label, cardholder_name);
						OPENSSL_free(tmp);
					}
				}
				X509_free(x509);
			}
		}
#endif
	}

	/* the file with key pin info (tries left) */
	sc_format_path ("3f000016", &tmppath);
	r = sc_select_file (card, &tmppath, NULL);
	if (r < 0)
		return SC_ERROR_INTERNAL;

	/* add pins */
	for (i = 0; i < 3; i++) {
		unsigned char tries_left;
		static const char *esteid_pin_names[3] = {
			"PIN1",
			"PIN2",
			"PUK" };
			
		static const int esteid_pin_min[3] = {4, 5, 8};
		static const int esteid_pin_ref[3] = {1, 2, 0};
		static const int esteid_pin_authid[3] = {1, 2, 3};
		static const int esteid_pin_flags[3] = {0, 0, SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN};
		
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj, 0, sizeof(pin_obj));
		
		/* read the number of tries left for the PIN */
		r = sc_read_record (card, i + 1, buff, sizeof(buff), SC_RECORD_BY_REC_NR);
		if (r < 0)
			return SC_ERROR_INTERNAL;
		tries_left = buff[5];
		
		pin_info.auth_id.len = 1;
		pin_info.auth_id.value[0] = esteid_pin_authid[i];
		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;	
		pin_info.attrs.pin.reference = esteid_pin_ref[i];
		pin_info.attrs.pin.flags = esteid_pin_flags[i];
		pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length = esteid_pin_min[i];
		pin_info.attrs.pin.stored_length = 12;
		pin_info.attrs.pin.max_length = 12;
		pin_info.attrs.pin.pad_char = '\0';
		pin_info.tries_left = (int)tries_left;
		pin_info.max_tries = 3;

		strlcpy(pin_obj.label, esteid_pin_names[i], sizeof(pin_obj.label));
		pin_obj.flags = esteid_pin_flags[i];

		/* Link normal PINs with PUK */
		if (i < 2) {
			pin_obj.auth_id.len = 1;
			pin_obj.auth_id.value[0] = 3;
		}

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}
	
	/* add private keys */
	for (i = 0; i < 2; i++) {
		static int prkey_pin[2] = {1, 2};
		static int prkey_usage[2] = {
			SC_PKCS15_PRKEY_USAGE_ENCRYPT
			| SC_PKCS15_PRKEY_USAGE_DECRYPT
			| SC_PKCS15_PRKEY_USAGE_SIGN,
			SC_PKCS15_PRKEY_USAGE_NONREPUDIATION};
			
		static const char *prkey_name[2] = {
			"Isikutuvastus",
			"Allkirjastamine"};

		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj, 0, sizeof(prkey_obj));
		
		prkey_info.id.len = 1;
		prkey_info.id.value[0] = prkey_pin[i];
		prkey_info.usage  = prkey_usage[i];
		prkey_info.native = 1;
		prkey_info.key_reference = i + 1;
		if (card->type == SC_CARD_TYPE_MCRD_ESTEID_V30)
			prkey_info.modulus_length = 2048;
		else
			prkey_info.modulus_length = 1024;	

		strlcpy(prkey_obj.label, prkey_name[i], sizeof(prkey_obj.label));
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = prkey_pin[i];
		prkey_obj.user_consent = 0;
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}

	return SC_SUCCESS;
}

static int esteid_detect_card(sc_pkcs15_card_t *p15card)
{
	if (is_esteid_card(p15card->card))
		return SC_SUCCESS;
	else		
		return SC_ERROR_WRONG_CARD;
}

int sc_pkcs15emu_esteid_init_ex(sc_pkcs15_card_t *p15card,
				sc_pkcs15emu_opt_t *opts)
{

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_esteid_init(p15card);
	else {
		int r = esteid_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_esteid_init(p15card);
	}
}
