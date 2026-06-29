/*
 * PKCS#15 emulation for the Uruguayan national eID (cédula de identidad digital),
 * driven by card-cedulauy.c.
 *
 * The card's on-card EF(TokenInfo) encodes one supportedAlgorithms entry with an
 * empty SEQUENCE (30 00) where PKCS#15 expects NULL/OID, which the generic binder
 * rejects. Instead of parsing the on-card PKCS#15 structure, this emulator builds
 * a synthetic view from AGESIC's publicly documented file layout:
 *   - IAS application AID  A0 00 00 00 18 40 00 00 01 63 42 00
 *   - signing certificate  EF B001
 *   - signing key          reference 0x01 (RSA 2048)
 *   - Global PIN           reference 0x11 (VERIFY 00 20 00 11)
 * References: AGESIC "Documentación técnica de la cédula de identidad con chip"
 * and the AGESIC reference code at https://github.com/eIDuy/apdu-services .
 *
 * Copyright (C) 2026 Carlos Andrés Planchón Prestes <carlosandresplanchonprestes@gmail.com>
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "internal.h"
#include "common/compat_strlcpy.h"
#include "log.h"
#include "pkcs15.h"
#include <stdlib.h>
#include <string.h>

/* IAS application AID (AGESIC, documented) */
static const unsigned char cedulauy_aid[] = {
	0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00
};

#define CEDULAUY_CERT_FID	"B001"	/* signing certificate EF */
#define CEDULAUY_KEY_REF	0x01	/* signing private key reference */
#define CEDULAUY_PIN_REF	0x11	/* Global PIN reference */
#define CEDULAUY_OBJ_ID		0x01	/* links cert <-> prkey */

static int
sc_pkcs15emu_cedulauy_init(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_aid aid;
	sc_path_t path;
	int r;

	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;
	struct sc_pkcs15_cert_info cert_info;
	struct sc_pkcs15_object cert_obj;
	struct sc_pkcs15_prkey_info prkey_info;
	struct sc_pkcs15_object prkey_obj;

	LOG_FUNC_CALLED(ctx);

	memcpy(aid.value, cedulauy_aid, sizeof cedulauy_aid);
	aid.len = sizeof cedulauy_aid;

	/* Select the IAS application; if it is not there, this is not our card. */
	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, cedulauy_aid, sizeof cedulauy_aid, 0, 0);
	if (sc_select_file(p15card->card, &path, NULL) != SC_SUCCESS)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	/* Global PIN (reference 0x11, ASCII numeric, zero-padded to 12 bytes). */
	memset(&pin_info, 0, sizeof pin_info);
	memset(&pin_obj, 0, sizeof pin_obj);
	pin_info.auth_id.value[0] = CEDULAUY_OBJ_ID;
	pin_info.auth_id.len = 1;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = CEDULAUY_PIN_REF;
	pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length = 4;
	pin_info.attrs.pin.stored_length = 12;
	pin_info.attrs.pin.max_length = 12;
	pin_info.attrs.pin.pad_char = 0x00;
	pin_info.tries_left = -1;
	pin_info.max_tries = -1;
	strlcpy(pin_obj.label, "PIN", sizeof pin_obj.label);
	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	LOG_TEST_RET(ctx, r, "Cannot add Global PIN object");

	/* Signing certificate (EF B001 under the IAS application). */
	memset(&cert_info, 0, sizeof cert_info);
	memset(&cert_obj, 0, sizeof cert_obj);
	sc_format_path("i" CEDULAUY_CERT_FID, &cert_info.path);	/* 'i' => select by file ID */
	cert_info.path.aid = aid;
	cert_info.id.value[0] = CEDULAUY_OBJ_ID;
	cert_info.id.len = 1;
	strlcpy(cert_obj.label, "Certificado de Firma", sizeof cert_obj.label);
	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	LOG_TEST_RET(ctx, r, "Cannot add signing certificate object");

	/* Set the token label from the certificate CN, when readable. */
	{
		struct sc_pkcs15_cert *cert = NULL;
		if (sc_pkcs15_read_certificate(p15card, &cert_info, 0, &cert) == SC_SUCCESS) {
			static const struct sc_object_id cn_oid = {{ 2, 5, 4, 3, -1 }};
			u8 *cn = NULL;
			size_t cn_len = 0;
			sc_pkcs15_get_name_from_dn(ctx, cert->subject, cert->subject_len,
					&cn_oid, &cn, &cn_len);
			if (cn_len > 0) {
				char *label = malloc(cn_len + 1);
				if (label) {
					memcpy(label, cn, cn_len);
					label[cn_len] = '\0';
					free(p15card->tokeninfo->label);
					p15card->tokeninfo->label = label;
				}
			}
			free(cn);
			sc_pkcs15_free_certificate(cert);
		}
	}

	/* Signing private key (reference 0x01, RSA 2048, PIN-protected). */
	memset(&prkey_info, 0, sizeof prkey_info);
	memset(&prkey_obj, 0, sizeof prkey_obj);
	prkey_info.id.value[0] = CEDULAUY_OBJ_ID;
	prkey_info.id.len = 1;
	prkey_info.usage = SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	prkey_info.native = 1;
	prkey_info.key_reference = CEDULAUY_KEY_REF;
	prkey_info.modulus_length = 2048;
	prkey_obj.auth_id.value[0] = CEDULAUY_OBJ_ID;
	prkey_obj.auth_id.len = 1;
	prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	strlcpy(prkey_obj.label, "Clave de Firma", sizeof prkey_obj.label);
	r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
	LOG_TEST_RET(ctx, r, "Cannot add signing private key object");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
sc_pkcs15emu_cedulauy_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	if (p15card->card->type != SC_CARD_TYPE_CEDULAUY)
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_cedulauy_init(p15card);
}
