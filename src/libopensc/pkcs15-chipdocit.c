/*
 * PKCS#15 emulation for the Bit4id Digital-DNA Key (Italian CNS/eID on an NXP
 * ChipDoc chip; driver card-chipdocit).
 *
 * The certificates are stored in a Bit4id-specific container (raw-DEFLATE with
 * a preset dictionary, see bit4id-cert-dict.h) that the generic reader cannot
 * decode. We read the two certificate EFs (authentication 0001, qualified-
 * signature DS3 0002, both under the "Generic" applet), inflate them, and
 * expose them together with the two RSA keys and the single user PIN. The key
 * references, EFs and PIN layout are card constants confirmed against a live
 * enumeration.
 *
 * Copyright (C) 2026 Grid Society S.r.l.
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

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"
#include "pkcs15.h"

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE) && defined(ENABLE_ZLIB)

#include "asn1.h"
#include "bit4id-cert-dict.h"
#include "cards.h"
#include "common/compat_strlcpy.h"
#include <zlib.h>

/* "Generic" applet AID (certs live behind it); user PIN / PUK P2 values. */
static const u8 CHIPDOCIT_GENERIC_AID[] = {
		0xE8, 0x28, 0xBD, 0x08, 0x0F, 0x01, 0x4E, 0x58, 0x50, 0x30};
#define PIN_P2	0x83 /* user PIN  BSO 0x03 | 0x80 */
#define PUK_P2	0x86 /* user PUK  BSO 0x06 | 0x80 */
#define AUTH_ID 1

/* Read cert EF <fid> under the Generic applet and inflate the 7A82 container. */
static int
read_ds_cert(sc_pkcs15_card_t *p15card, unsigned fid,
		const sc_pkcs15_id_t *cert_id, const char *label, int user_consent_hint)
{
	sc_card_t *card = p15card->card;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE], raw[4096], *der = NULL, *rot = NULL;
	u8 fidbuf[2] = {(u8)(fid >> 8), (u8)(fid & 0xff)};
	int rawlen, i, r;
	size_t hdr, bodylen, dlen;
	unsigned int cla, tag;
	const u8 *dict, *body;
	z_stream z;
	sc_pkcs15_cert_info_t cinfo;
	sc_pkcs15_object_t cobj;

	(void)user_consent_hint;

	/* SELECT Generic AID, then SELECT the cert EF by file id (clear reads). */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x04);
	apdu.lc = apdu.datalen = sizeof CHIPDOCIT_GENERIC_AID;
	apdu.data = CHIPDOCIT_GENERIC_AID;
	apdu.resp = rbuf;
	apdu.resplen = sizeof rbuf;
	apdu.le = 256;
	if (sc_transmit_apdu(card, &apdu) != SC_SUCCESS || sc_check_sw(card, apdu.sw1, apdu.sw2) != SC_SUCCESS)
		return SC_SUCCESS; /* applet absent: skip quietly */

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);
	apdu.lc = apdu.datalen = 2;
	apdu.data = fidbuf;
	apdu.resp = rbuf;
	apdu.resplen = sizeof rbuf;
	apdu.le = 256;
	if (sc_transmit_apdu(card, &apdu) != SC_SUCCESS || sc_check_sw(card, apdu.sw1, apdu.sw2) != SC_SUCCESS)
		return SC_SUCCESS; /* no such cert: skip quietly */

	rawlen = sc_read_binary(card, 0, raw, sizeof raw, 0);
	if (rawlen < 2)
		return SC_SUCCESS;
	if (raw[0] != 0x5a && raw[0] != 0x7a && raw[0] != 0x30) {
		sc_log(card->ctx, "ChipDoc cert %04x: unexpected tag %02x", fid, raw[0]);
		return SC_SUCCESS;
	}
	/* Parse the container tag and length with the ASN.1 helper (it does the
	 * bounds and format checking); body then points at the value. */
	body = raw;
	if (sc_asn1_read_tag(&body, (size_t)rawlen, &cla, &tag, &bodylen) != SC_SUCCESS || !body)
		return SC_SUCCESS;
	hdr = (size_t)(body - raw);
	if (hdr + bodylen > (size_t)rawlen)
		return SC_SUCCESS;

	memset(&cinfo, 0, sizeof cinfo);
	if (raw[0] == 0x30) { /* plain DER */
		der = malloc(hdr + bodylen);
		if (!der)
			return SC_ERROR_OUT_OF_MEMORY;
		memcpy(der, raw, hdr + bodylen);
		cinfo.value.len = hdr + bodylen;
	} else { /* 7A82 = dict rotated left 15; 5A82 = as-is */
		dict = bit4id_cert_dict;
		dlen = sizeof bit4id_cert_dict;
		if (raw[0] == 0x7a) {
			rot = malloc(dlen);
			if (!rot)
				return SC_ERROR_OUT_OF_MEMORY;
			for (i = 0; (size_t)i < dlen; i++)
				rot[i] = dict[((size_t)i + 15) % dlen];
			dict = rot;
		}
		der = malloc(8192);
		if (!der) {
			free(rot);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		memset(&z, 0, sizeof z);
		if (inflateInit2(&z, -15) != Z_OK || inflateSetDictionary(&z, dict, (uInt)dlen) != Z_OK) {
			inflateEnd(&z);
			free(der);
			free(rot);
			return SC_ERROR_INTERNAL;
		}
		z.next_in = raw + hdr;
		z.avail_in = (uInt)bodylen;
		z.next_out = der;
		z.avail_out = 8192;
		r = inflate(&z, Z_FINISH);
		free(rot);
		if (r != Z_STREAM_END) {
			sc_log(card->ctx, "ChipDoc cert %04x: inflate failed (%d)", fid, r);
			inflateEnd(&z);
			free(der);
			return SC_SUCCESS;
		}
		cinfo.value.len = z.total_out;
		inflateEnd(&z);
	}

	memset(&cobj, 0, sizeof cobj);
	cinfo.id = *cert_id;
	cinfo.value.value = der; /* ownership passes to the cert object */
	strlcpy(cobj.label, label, sizeof cobj.label);
	r = sc_pkcs15emu_add_x509_cert(p15card, &cobj, &cinfo);
	if (r != SC_SUCCESS) {
		free(der);
		LOG_TEST_RET(card->ctx, r, "add x509 cert failed");
	}
	sc_log(card->ctx, "ChipDoc cert %04x exposed (%lu B DER)",
			fid, (unsigned long)cinfo.value.len);
	return SC_SUCCESS;
}

static int
add_pin(sc_pkcs15_card_t *p15card)
{
	struct sc_pkcs15_auth_info info;
	struct sc_pkcs15_object obj;

	memset(&info, 0, sizeof info);
	info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	info.auth_id.len = 1;
	info.auth_id.value[0] = AUTH_ID;
	info.attrs.pin.reference = PIN_P2;
	info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL;
	info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	info.attrs.pin.min_length = 4; /* unpadded, variable length */
	info.attrs.pin.max_length = 8;
	info.attrs.pin.stored_length = 0;
	info.attrs.pin.pad_char = 0x00;
	info.tries_left = -1;
	info.logged_in = SC_PIN_STATE_UNKNOWN;

	memset(&obj, 0, sizeof obj);
	strlcpy(obj.label, "PIN", sizeof obj.label);
	obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	return sc_pkcs15emu_add_pin_obj(p15card, &obj, &info);
}

static int
add_prkey(sc_pkcs15_card_t *p15card, const sc_pkcs15_id_t *id,
		const char *label, int ref, int usage, int user_consent)
{
	struct sc_pkcs15_prkey_info info;
	struct sc_pkcs15_object obj;

	memset(&info, 0, sizeof info);
	info.id = *id;
	info.modulus_length = 2048;
	info.usage = usage;
	info.native = 1;
	info.key_reference = ref;

	memset(&obj, 0, sizeof obj);
	strlcpy(obj.label, label, sizeof obj.label);
	obj.auth_id.len = 1;
	obj.auth_id.value[0] = AUTH_ID;
	obj.user_consent = user_consent; /* DS3: re-verify PIN per signature */
	obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	return sc_pkcs15emu_add_rsa_prkey(p15card, &obj, &info);
}

int
sc_pkcs15emu_chipdocit_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	sc_card_t *card = p15card->card;
	sc_pkcs15_id_t id_auth, id_ds;
	struct sc_apdu apdu;

	memset(&id_auth, 0, sizeof id_auth);
	id_auth.len = 1;
	id_auth.value[0] = 0x01;
	memset(&id_ds, 0, sizeof id_ds);
	id_ds.len = 1;
	id_ds.value[0] = 0x02;
	u8 csn[32];
	int r;

	(void)aid;
	LOG_FUNC_CALLED(card->ctx);
	if (card->type != SC_CARD_TYPE_CHIPDOC_IT)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_CARD);

	set_string(&p15card->tokeninfo->label, card->name);
	set_string(&p15card->tokeninfo->manufacturer_id, "Bit4id / NXP");

	/* Serial = card serial number (GET DATA 00 CA 01 14), read in clear. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x14);
	apdu.resp = csn;
	apdu.resplen = sizeof csn;
	apdu.le = 256;
	if (sc_transmit_apdu(card, &apdu) == SC_SUCCESS && sc_check_sw(card, apdu.sw1, apdu.sw2) == SC_SUCCESS && apdu.resplen) {
		char hex[2 * sizeof(csn) + 1];
		sc_bin_to_hex(csn, apdu.resplen, hex, sizeof hex, 0);
		set_string(&p15card->tokeninfo->serial_number, hex);
	}

	r = add_pin(p15card);
	LOG_TEST_RET(card->ctx, r, "add PIN failed");

	/* Auth key/cert: LCNS0, key ref 0x10, EF 0001. */
	r = read_ds_cert(p15card, 0x0001, &id_auth, "CNS", 0);
	LOG_TEST_RET(card->ctx, r, "read auth cert failed");
	r = add_prkey(p15card, &id_auth, "CNS",
			0x10, SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT, 0);
	LOG_TEST_RET(card->ctx, r, "add auth key failed");

	/* Qualified-signature key/cert: DS3, key ref 0x11, EF 0002, nonRepudiation. */
	r = read_ds_cert(p15card, 0x0002, &id_ds, "DS3", 1);
	LOG_TEST_RET(card->ctx, r, "read DS cert failed");
	r = add_prkey(p15card, &id_ds, "DS3",
			0x11, SC_PKCS15_PRKEY_USAGE_NONREPUDIATION, 1);
	LOG_TEST_RET(card->ctx, r, "add DS key failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

#else

int
sc_pkcs15emu_chipdocit_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	return SC_ERROR_WRONG_CARD;
}

#endif
