/*
 * PKCS15 emulation layer for EstEID card.
 *
 * Copyright (C) 2004, Martin Paljak <martin@paljak.pri.ee>
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

#include "internal.h"
#include "pkcs15.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esteid.h"
#include <compat_strlcpy.h>

#ifdef ENABLE_ICONV
#include <iconv.h>
#endif

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
	tmppath.type = SC_PATH_TYPE_PATH;
	r = sc_select_file (card, &tmppath, NULL);
	SC_TEST_RET (card->ctx, r, "esteid select DF failed");
	return r;
}

static int
sc_pkcs15emu_esteid_init (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
#ifdef ENABLE_ICONV
	iconv_t iso_utf;
	char *inptr, *outptr;
	size_t inbytes, outbytes, result;
	unsigned char label[64], name1[32], name2[32];
#endif
	unsigned char buff[128];
	int r, i, flags;
	sc_path_t tmppath;

	set_string (&p15card->label, "ID-kaart");
	set_string (&p15card->manufacturer_id, "AS Sertifitseerimiskeskus");

	/* Select application directory */
	sc_format_path ("3f00eeee5044", &tmppath);
	tmppath.type = SC_PATH_TYPE_PATH;
	r = sc_select_file (card, &tmppath, NULL);
	SC_TEST_RET (card->ctx, r, "select esteid PD failed");

	/* read the serial (document number) */	
	r = sc_read_record (card, SC_ESTEID_PD_DOCUMENT_NR, buff, sizeof(buff), SC_RECORD_BY_REC_NR);
	SC_TEST_RET (card->ctx, r, "read document number failed");
	buff[r] = '\0';
	set_string (&p15card->serial_number, (const char *) buff);

#ifdef ENABLE_ICONV
	/* Read the name of the cardholder and convert it into UTF-8 */
	iso_utf  = iconv_open ("UTF-8", "ISO-8859-1");
	if (iso_utf == (iconv_t) -1)
		return SC_ERROR_INTERNAL;
	
	r = sc_read_record (card, SC_ESTEID_PD_GIVEN_NAMES1, buff, sizeof(buff), SC_RECORD_BY_REC_NR);
	SC_TEST_RET (card->ctx, r, "read name1 failed");
	inptr = buff;
	outptr = name1;
	inbytes = r;
	outbytes = 32;
	result = iconv(iso_utf, &inptr, &inbytes, &outptr, &outbytes);
	if (result == (size_t) -1)
		return SC_ERROR_INTERNAL;	
	*outptr = '\0';
	
	r = sc_read_record (card, SC_ESTEID_PD_SURNAME, buff, sizeof(buff), SC_RECORD_BY_REC_NR);
	SC_TEST_RET (card->ctx, r, "read name2 failed");
	inptr = buff;
	outptr = name2;
	inbytes = r;
	outbytes = 32;
	result = iconv(iso_utf, &inptr, &inbytes, &outptr, &outbytes);
	if (result == (size_t) -1)
		return SC_ERROR_INTERNAL;
	*outptr = '\0';
	
	snprintf(label, sizeof(label), "%s %s", name1, name2);
	set_string (&p15card->label, label);
#endif
	p15card->flags = SC_PKCS15_CARD_FLAG_PRN_GENERATION
	                 | SC_PKCS15_CARD_FLAG_EID_COMPLIANT
	                 | SC_PKCS15_CARD_FLAG_READONLY;

	/* EstEID uses 1024b RSA */
	card->algorithm_count = 0;
	flags = SC_ALGORITHM_RSA_PAD_PKCS1;
	_sc_card_add_rsa_alg (card, 1024, flags, 0);

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
		
		struct sc_pkcs15_pin_info pin_info;
		struct sc_pkcs15_object pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj, 0, sizeof(pin_obj));
		
		/* read the number of tries left for the PIN */
		r = sc_read_record (card, i + 1, buff, 128, SC_RECORD_BY_REC_NR);
		if (r < 0)
			return SC_ERROR_INTERNAL;
		tries_left = buff[5];
		
		pin_info.auth_id.len = 1;
		pin_info.auth_id.value[0] = esteid_pin_authid[i];
		pin_info.reference = esteid_pin_ref[i];
		pin_info.flags = esteid_pin_flags[i];
		pin_info.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.min_length = esteid_pin_min[i];
		pin_info.stored_length = 12;
		pin_info.max_length = 12;
		pin_info.pad_char = '\0';
		pin_info.tries_left = (int)tries_left;

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
			| SC_PKCS15_PRKEY_USAGE_SIGN
			| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
			| SC_PKCS15_PRKEY_USAGE_WRAP
			| SC_PKCS15_PRKEY_USAGE_UNWRAP,
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
		prkey_info.modulus_length= 1024;

		strlcpy(prkey_obj.label, prkey_name[i], sizeof(prkey_obj.label));
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = prkey_pin[i];
		prkey_obj.user_consent = (i == 1) ? 1 : 0;
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}
	return SC_SUCCESS;
}

static int esteid_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type == SC_CARD_TYPE_MCRD_ESTEID)
		return SC_SUCCESS;
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
