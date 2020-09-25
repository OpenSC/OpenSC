/*
 * PKCS15 emulation layer for Italian CNS.
 *
 * Copyright (C) 2008, Emanuele Pucciarelli <ep@acm.org>
 * Many snippets have been taken out from other PKCS15 emulation layer
 * modules in this directory; their copyright is their authors'.
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

/*
 * Specifications for the development of this driver come from:
 * http://www.servizidemografici.interno.it/sitoCNSD/documentazioneRicerca.do?metodo=contenutoDocumento&servizio=documentazione&ID_DOCUMENTO=1043
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef ENABLE_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#include "internal.h"
#include "pkcs15.h"
#include "log.h"
#include "cards.h"
#include "itacns.h"
#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"

#ifdef ENABLE_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

static const char path_serial[] = "10001003";

/* Manufacturers */

const char * itacns_mask_manufacturers[] = {
	"Unknown",
	"Kaitech",
	"Gemplus",
	"Ghirlanda",
	"Giesecke & Devrient",
	"Oberthur Card Systems",
	"Orga",
	"Axalto",
	"Siemens",
	"STIncard",
	"GEP",
	"EPS Corp",
	"Athena"
};

const char * iso7816_ic_manufacturers[] = {
	"Unknown",
	"Motorola",
	"STMicroelectronics",
	"Hitachi",
	"NXP Semiconductors",
	"Infineon",
	"Cylinc",
	"Texas Instruments",
	"Fujitsu",
	"Matsushita",
	"NEC",
	"Oki",
	"Toshiba",
	"Mitsubishi",
	"Samsung",
	"Hynix",
	"LG",
	"Emosyn-EM",
	"INSIDE",
	"ORGA",
	"SHARP",
	"ATMEL",
	"EM Microelectronic-Marin",
	"KSW Microtec",
	"ZMD",
	"XICOR",
	"Sony",
	"Malaysia Microelectronic Solutions",
	"Emosyn",
	"Shanghai Fudan",
	"Magellan",
	"Melexis",
	"Renesas",
	"TAGSYS",
	"Transcore",
	"Shanghai belling",
	"Masktech",
	"Innovision",
	"Hitachi",
	"Cypak",
	"Ricoh",
	"ASK",
	"Unicore",
	"Dallas",
	"Impinj",
	"RightPlug Alliance",
	"Broadcom",
	"MStar",
	"BeeDar",
	"RFIDsec",
	"Schweizer Electronic",
	"AMIC Technology",
	"Mikron",
	"Fraunhofer",
	"IDS Microchip",
	"Kovio",
	"HMT Microelectronic",
	"Silicon Craft",
	"Advanced Film Device",
	"Nitecrest",
	"Verayo",
	"HID Gloval",
	"Productivity Engineering",
	"Austriamicrosystems",
	"Gemalto"
};

/* Data files */

static const struct {
	const char *label;
	const char *path;
	int cie_only;
} itacns_data_files[] = {
	{ "EF_DatiProcessore", "3F0010001002", 0 },
	{ "EF_IDCarta", "3F0010001003", 0 },
	{ "EF_DatiSistema", "3F0010001004", 1 },
	{ "EF_DatiPersonali", "3F0011001102", 0 },
	{ "EF_DatiPersonali_Annotazioni", "3F0011001103", 1 },
	{ "EF_Impronte", "3F0011001104", 1 },
	{ "EF_Foto", "3F0011001104", 1 },
	{ "EF_DatiPersonaliAggiuntivi", "3F0012001201", 0 },
	{ "EF_MemoriaResidua", "3F0012001202", 0 },
	{ "EF_ServiziInstallati", "3F0012001203", 0 },
	{ "EF_INST_FILE", "3F0012004142", 0 },
	{ "EF_CardStatus", "3F003F02", 0 },
	{ "EF_GDO", "3F002F02", 0 },
	{ "EF_RootInstFile", "3F000405", 0 }
};


/*
 * Utility functions
 */

static int loadFile(const sc_pkcs15_card_t *p15card, const sc_path_t *path,
	u8 *buf, const size_t buflen)
{
	int sc_res;
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_NORMAL);

	sc_res = sc_select_file(p15card->card, path, NULL);
	if(sc_res != SC_SUCCESS)
		return sc_res;

	sc_res = sc_read_binary(p15card->card, 0, buf, buflen, 0);
	return sc_res;
}

/*
 * The following functions add objects to the card emulator.
 */

static int itacns_add_cert(sc_pkcs15_card_t *p15card,
	int type, int authority, const sc_path_t *path,
	const sc_pkcs15_id_t *id, const char *label, int obj_flags,
	int *ext_info_ok, int *key_usage, int *x_key_usage)
{
	int r;
	/* const char *label = "Certificate"; */
	sc_pkcs15_cert_info_t info;
	sc_pkcs15_object_t    obj;
#ifdef ENABLE_OPENSSL
	X509 *x509;
	sc_pkcs15_cert_t *cert;
#endif

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_NORMAL);

	if(type != SC_PKCS15_TYPE_CERT_X509) {
		sc_log(p15card->card->ctx,
			"Cannot add a certificate of a type other than X.509");
		return 1;
	}

	*ext_info_ok = 0;


	memset(&info, 0, sizeof(info));
	memset(&obj,  0, sizeof(obj));

	info.id                = *id;
	info.authority         = authority;
	if (path)
		info.path = *path;

	strlcpy(obj.label, label, sizeof(obj.label));
	obj.flags = obj_flags;

	r = sc_pkcs15emu_add_x509_cert(p15card, &obj, &info);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add X.509 certificate");

	/* If we have OpenSSL, read keyUsage */
#ifdef ENABLE_OPENSSL

	r = sc_pkcs15_read_certificate(p15card, &info, &cert);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not read X.509 certificate");

	{
		const u8 *throwaway = cert->data.value;
		x509 = d2i_X509(NULL, &throwaway, cert->data.len);
	}
	sc_pkcs15_free_certificate(cert);
	if (!x509) return SC_SUCCESS;
	X509_check_purpose(x509, -1, 0);

	if(X509_get_extension_flags(x509) & EXFLAG_KUSAGE) {
		*ext_info_ok = 1;
		*key_usage = X509_get_key_usage(x509);
		*x_key_usage = X509_get_extended_key_usage(x509);
	}
	OPENSSL_free(x509);

	return SC_SUCCESS;

#else /* ENABLE_OPENSSL */

	return SC_SUCCESS;

#endif /* ENABLE_OPENSSL */

}

static int itacns_add_pubkey(sc_pkcs15_card_t *p15card,
	 const sc_path_t *path, const sc_pkcs15_id_t *id, const char *label,
	int usage, int ref, int obj_flags, int *modulus_len_out)
{
	int r;
	sc_pkcs15_pubkey_info_t info;
	sc_pkcs15_object_t obj;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_NORMAL);

	memset(&info, 0, sizeof(info));
	memset(&obj,  0, sizeof(obj));

	info.id  		= *id;
	if (path)
		info.path	= *path;
	info.usage		= usage;
	info.key_reference	= ref;
	strlcpy(obj.label, label, sizeof(obj.label));
	obj.flags		= obj_flags;

	/*
	 * This is hard-coded, unless unforeseen versions of the CNS
	 * turn up sometime.
	 */
	info.modulus_length = 1024;

	*modulus_len_out = info.modulus_length;
	r = sc_pkcs15emu_add_rsa_pubkey(p15card, &obj, &info);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add pub key");
	return r;
}

static int itacns_add_prkey(sc_pkcs15_card_t *p15card,
                const sc_pkcs15_id_t *id,
                const char *label,
                int type, unsigned int modulus_length, int usage,
		const sc_path_t *path, int ref,
                const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_prkey_info_t info;
	sc_pkcs15_object_t obj;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_NORMAL);

	if(type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_log(p15card->card->ctx,
			"Cannot add a private key of a type other than RSA");
		return 1;
	}

	memset(&info, 0, sizeof(info));
	memset(&obj,  0, sizeof(obj));

	info.id			= *id;
	info.modulus_length	= modulus_length;
	info.usage		= usage;
	info.native		= 1;
	info.key_reference	= ref;

	if (path)
	        info.path = *path;

	obj.flags = obj_flags;
	strlcpy(obj.label, label, sizeof(obj.label));
	if (auth_id != NULL)
		obj.auth_id = *auth_id;

	return sc_pkcs15emu_add_rsa_prkey(p15card, &obj, &info);
}

static int itacns_add_pin(sc_pkcs15_card_t *p15card,
	char *label,
	int id,
	int auth_id,
	int reference,
	sc_path_t *path,
	int flags)
{
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_NORMAL);

	memset(&pin_info, 0, sizeof(pin_info));
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.auth_id.len = 1;
	pin_info.auth_id.value[0] = id;
	pin_info.attrs.pin.reference = reference;
	pin_info.attrs.pin.flags = flags;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length = 5;
	pin_info.attrs.pin.stored_length = 8;
	pin_info.attrs.pin.max_length = 8;
	pin_info.attrs.pin.pad_char = 0xff;
	pin_info.logged_in = SC_PIN_STATE_UNKNOWN;
	if(path)
        pin_info.path = *path;

	memset(&pin_obj, 0, sizeof(pin_obj));
	strlcpy(pin_obj.label, label, sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE |
		(auth_id ? SC_PKCS15_CO_FLAG_MODIFIABLE : 0);
	if (auth_id) {
		pin_obj.auth_id.len = 1;
		pin_obj.auth_id.value[0] = auth_id;
	} else
		pin_obj.auth_id.len = 0;

	return sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
}

static int hextoint(char *src, unsigned int len)
{
	char hex[16];
	char *end;
	int res;

	if(len >= sizeof(hex))
		return -1;
	strncpy(hex, src, len);
	hex[len] = '\0';
	res = strtol(hex, &end, 0x10);
	if(end != (char*)&hex[len])
		return -1;
	return res;
}

static int get_name_from_EF_DatiPersonali(unsigned char *EFdata,
	size_t EFdata_len, char name[], int name_len)
{
	const unsigned int EF_personaldata_maxlen = 400;
	const unsigned int tlv_length_size = 6;
	char *file = NULL;
	int file_size;

	/*
	 * Bytes 0-5 contain the ASCII encoding of the following TLV
	 * structure's total size, in base 16.
	 */
	if (EFdata_len < tlv_length_size) {
		/* We need at least 6 bytes for file length here */
		return -1;
	}
	file_size = hextoint((char*)EFdata, tlv_length_size);
	if (EFdata_len < (file_size + tlv_length_size)) {
		/* Inconsistent external file length and internal file length
		 * suggests we are trying to process junk data.
		 * If the internal data length is shorter, the data can be padded,
		 * but we should be fine as we will not go behind the buffer limits */
		return -1;
	}
	file = (char*)&EFdata[tlv_length_size];

	enum {
		f_issuer_code = 0,
		f_issuing_date,
		f_expiry_date,
		f_last_name,
		f_first_name,
		f_birth_date,
		f_sex,
		f_height,
		f_codice_fiscale,
		f_citizenship_code,
		f_birth_township_code,
		f_birth_country,
		f_birth_certificate,
		f_residence_township_code,
		f_residence_address,
		f_expat_notes
	};

	/* Read the fields up to f_first_name */
	struct {
		int len;
		char value[256];
	} fields[f_first_name+1];
	int i=0; /* offset inside the file */
	int f; /* field number */

	if (file_size < 0)
		return -1;

	/*
	 * This shouldn't happen, but let us be protected against wrong
	 * or malicious cards
	 */
	if(file_size > (int)EF_personaldata_maxlen - (int)tlv_length_size)
		file_size = EF_personaldata_maxlen - tlv_length_size;


	memset(fields, 0, sizeof(fields));

	for(f=0; f<f_first_name+1; f++) {
		int field_size;

		/* Don't read beyond the allocated buffer */
		if(i+2 > file_size)
			return -1;
		field_size = hextoint((char*) &file[i], 2);
		i += 2;

		if (field_size < 0
				|| i + field_size > file_size
				|| field_size >= (int)sizeof(fields[f].value))
			return -1;

		fields[f].len = field_size;
		strncpy(fields[f].value, &file[i], field_size);
		fields[f].value[field_size] = '\0';
		i += field_size;
	}

	if (fields[f_first_name].len + fields[f_last_name].len + 1 >= name_len)
		return -1;

	/* the lengths are already checked that they will fit in buffer */
	snprintf(name, name_len, "%.*s %.*s",
		fields[f_first_name].len, fields[f_first_name].value,
		fields[f_last_name].len, fields[f_last_name].value);
	return 0;
}

static int itacns_add_data_files(sc_pkcs15_card_t *p15card)
{
	const size_t array_size =
		sizeof(itacns_data_files)/sizeof(itacns_data_files[0]);
	unsigned int i;
	int rv;
	sc_pkcs15_data_t *p15_personaldata = NULL;
	sc_pkcs15_data_info_t dinfo;
	struct sc_pkcs15_object *objs[32];
	struct sc_pkcs15_data_info *cinfo;

	for(i=0; i < array_size; i++) {
		sc_path_t path;
		sc_pkcs15_data_info_t data;
		sc_pkcs15_object_t    obj;

		if (itacns_data_files[i].cie_only &&
			p15card->card->type != SC_CARD_TYPE_ITACNS_CIE_V2)
			continue;

		sc_format_path(itacns_data_files[i].path, &path);

		memset(&data, 0, sizeof(data));
		memset(&obj, 0, sizeof(obj));
		strlcpy(data.app_label, itacns_data_files[i].label,
			sizeof(data.app_label));
		strlcpy(obj.label, itacns_data_files[i].label,
			sizeof(obj.label));
		data.path = path;
		rv = sc_pkcs15emu_add_data_object(p15card, &obj, &data);
		LOG_TEST_RET(p15card->card->ctx, rv,
			"Could not add data file");
	}

	/*
	 * If we got this far, we can read the Personal Data file and glean
	 * the user's full name. Thus we can use it to put together a
	 * user-friendlier card name.
	 */
	memset(&dinfo, 0, sizeof(dinfo));
	strlcpy(dinfo.app_label, "EF_DatiPersonali", sizeof(dinfo.app_label));

	/* Find EF_DatiPersonali */

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT,
		objs, 32);
	if(rv < 0) {
		sc_log(p15card->card->ctx,
			"Data enumeration failed");
		return SC_SUCCESS;
	}

	for(i=0; i<32; i++) {
		cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;
		if(!strcmp("EF_DatiPersonali", objs[i]->label))
			break;
	}

	if(i>=32) {
		sc_log(p15card->card->ctx,
			"Could not find EF_DatiPersonali: "
			"keeping generic card name");
		return SC_SUCCESS;
	}

	rv = sc_pkcs15_read_data_object(p15card, cinfo, &p15_personaldata);
	if (rv) {
		sc_log(p15card->card->ctx,
			"Could not read EF_DatiPersonali: "
			"keeping generic card name");
		return SC_SUCCESS;
	}

	if (p15_personaldata->data) {
		char fullname[160];
		if (get_name_from_EF_DatiPersonali(p15_personaldata->data,
			p15_personaldata->data_len, fullname, sizeof(fullname))) {
			sc_log(p15card->card->ctx,
				"Could not parse EF_DatiPersonali: "
				"keeping generic card name");
			sc_pkcs15_free_data_object(p15_personaldata);
			free(cinfo->data.value);
			cinfo->data.value = NULL;
			return SC_SUCCESS;
		}
		set_string(&p15card->tokeninfo->label, fullname);
	}
	free(cinfo->data.value);
	cinfo->data.value = NULL;
	sc_pkcs15_free_data_object(p15_personaldata);
	return SC_SUCCESS;
}

static int itacns_add_keyset(sc_pkcs15_card_t *p15card,
	const char *label, int sec_env, sc_pkcs15_id_t *cert_id,
	const char *pubkey_path, const char *prkey_path,
	unsigned int pubkey_usage_flags, unsigned int prkey_usage_flags,
	u8 pin_ref)
{
	int r;
	sc_path_t path;
	sc_path_t *private_path = NULL;
	char pinlabel[16];
	int fake_puk_authid, pin_flags;

	/* This is hard-coded, for the time being. */
	int modulus_length = 1024;

	/* Public key; not really needed */
	/* FIXME: set usage according to the certificate. */
	if (pubkey_path) {
		sc_format_path(pubkey_path, &path);
		r = itacns_add_pubkey(p15card, &path, cert_id, label,
			pubkey_usage_flags, sec_env, 0, &modulus_length);
		LOG_TEST_RET(p15card->card->ctx, r,
			"Could not add public key");
	}

	/*
	 * FIXME: usage should be inferred from the X.509 certificate, and not
	 * from whether the key needs Secure Messaging.
	 */
	if (prkey_path) {
		sc_format_path(prkey_path, &path);
		private_path = &path;
	}
	r = itacns_add_prkey(p15card, cert_id, label, SC_PKCS15_TYPE_PRKEY_RSA,
		modulus_length,
		prkey_usage_flags,
		private_path, sec_env, cert_id, SC_PKCS15_CO_FLAG_PRIVATE);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add private key");

	/* PIN and PUK */
	strlcpy(pinlabel, "PIN ", sizeof(pinlabel));
	strlcat(pinlabel, label, sizeof(pinlabel));

	/* We are making up ID 0x90+ to link the PIN and the PUK. */
	fake_puk_authid = 0x90 + pin_ref;
	pin_flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE
		| SC_PKCS15_PIN_FLAG_INITIALIZED;
	r = itacns_add_pin(p15card, pinlabel, sec_env, fake_puk_authid, pin_ref,
	    private_path, pin_flags);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add PIN");

	strlcpy(pinlabel, "PUK ", sizeof(pinlabel));
	strlcat(pinlabel, label, sizeof(pinlabel));
	/*
	 * Looking at pkcs15-tcos.c and pkcs15-framework.c, it seems that the
	 * right thing to do here is to define a PUK as a SO PIN. Can anybody
	 * comment on this?
	 */
	pin_flags |= SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN
	| SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED;
	r = itacns_add_pin(p15card, pinlabel, fake_puk_authid, 0, pin_ref+1,
	    private_path, pin_flags);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add PUK");

	return 0;
}

/*
 * itacns_check_and_add_keyset() checks for the existence and correctness
 * of an X.509 certificate. If it is all right, it adds the related keys;
 * otherwise it aborts.
 */

static int itacns_check_and_add_keyset(sc_pkcs15_card_t *p15card,
	const char *label, int sec_env, size_t cert_offset,
	const char *cert_path, const char *pubkey_path, const char *prkey_path,
	u8 pin_ref, int *found_certificates)
{
	int r;
	sc_path_t path;
	sc_pkcs15_id_t cert_id;
	int ext_info_ok;
	int ku = 0, xku = 0;
	int pubkey_usage_flags = 0, prkey_usage_flags = 0;

	cert_id.len = 1;
	cert_id.value[0] = sec_env;
	*found_certificates = 0;

	/* Certificate */
	if (!cert_path) {
		sc_log(p15card->card->ctx,
			"We cannot use keys without a matching certificate");
		return SC_ERROR_NOT_SUPPORTED;
	}

	sc_format_path(cert_path, &path);
	r = sc_select_file(p15card->card, &path, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND)
		return 0;
	if (r != SC_SUCCESS) {
		sc_log(p15card->card->ctx,
			"Could not find certificate for %s", label);
		return r;
	}

	/*
	 * Infocamere 1204 (and others?) store a more complex structure. We
	 * are going to read the first bytes to guess its length, and invoke
	 * itacns_add_cert so that it only reads the certificate.
	 */
	if (cert_offset) {
		u8 certlen[3];
		memset(certlen, 0, sizeof certlen);
		r = loadFile(p15card, &path, certlen, sizeof(certlen));
		LOG_TEST_RET(p15card->card->ctx, r,
			"Could not read certificate file");
		if (r < 3)
			return SC_ERROR_INVALID_DATA;
		path.index = cert_offset;
		path.count = (certlen[1] << 8) + certlen[2];
		/* If those bytes are 00, then we are probably dealing with an
		 * empty file. */
		if (path.count == 0)
			return 0;
	}

	r = itacns_add_cert(p15card, SC_PKCS15_TYPE_CERT_X509, 0,
		&path, &cert_id, label, 0, &ext_info_ok, &ku, &xku);
	if (r == SC_ERROR_INVALID_ASN1_OBJECT)
		return 0;
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add certificate");
	(*found_certificates)++;

	/* Set usage flags */
	if(ext_info_ok) {
#ifdef ENABLE_OPENSSL
		if (ku & KU_DIGITAL_SIGNATURE) {
			pubkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_VERIFY;
			prkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_SIGN;
		}
		if (ku & KU_NON_REPUDIATION) {
			pubkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_VERIFY;
			prkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
		}
		if (ku & KU_KEY_ENCIPHERMENT || ku & KU_KEY_AGREEMENT
			|| xku & XKU_SSL_CLIENT) {
			pubkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_WRAP;
			prkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_UNWRAP;
		}
		if (ku & KU_DATA_ENCIPHERMENT || xku & XKU_SMIME) {
			pubkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
			prkey_usage_flags |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
		}
#else /* ENABLE_OPENSSL */
		sc_log(p15card->card->ctx,
			"Extended certificate info retrieved without OpenSSL. "
			"How is this possible?");
		return SC_ERROR_INTERNAL;
#endif /* ENABLE_OPENSSL */
	} else {
		/* Certificate info not retrieved; fall back onto defaults */
		pubkey_usage_flags =
			  SC_PKCS15_PRKEY_USAGE_VERIFY
			| SC_PKCS15_PRKEY_USAGE_WRAP;
		prkey_usage_flags =
			  SC_PKCS15_PRKEY_USAGE_SIGN
			| SC_PKCS15_PRKEY_USAGE_UNWRAP;
	}

	r = itacns_add_keyset(p15card, label, sec_env, &cert_id,
		pubkey_path, prkey_path, pubkey_usage_flags, prkey_usage_flags,
		pin_ref);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add keys for this certificate");

	return r;
}

/* Initialization. */

static int itacns_init(sc_pkcs15_card_t *p15card)
{
	int r;
	sc_path_t path;
	int certificate_count = 0;
	int found_certs;
	int card_is_cie_v1, cns0_secenv;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_NORMAL);

	set_string(&p15card->tokeninfo->label, p15card->card->name);
	if(p15card->card->drv_data) {
		unsigned int mask_code, ic_code;
		char buffer[256];
		itacns_drv_data_t *data =
			(itacns_drv_data_t*) p15card->card->drv_data;
		mask_code = data->mask_manufacturer_code;
		if (mask_code >= sizeof(itacns_mask_manufacturers)
			/sizeof(itacns_mask_manufacturers[0]))
			mask_code = 0;
		ic_code = data->ic_manufacturer_code;
		if (ic_code >= sizeof(iso7816_ic_manufacturers)
			/sizeof(iso7816_ic_manufacturers[0]))
			ic_code = 0;
		snprintf(buffer, sizeof(buffer), "IC: %s; mask: %s",
			iso7816_ic_manufacturers[ic_code],
			itacns_mask_manufacturers[mask_code]);
		set_string(&p15card->tokeninfo->manufacturer_id, buffer);
	}

	/* Read and set serial */
	{
		u8 serial[17];
		int bytes;
		sc_format_path(path_serial, &path);
		bytes = loadFile(p15card, &path, serial, 16);
		if (bytes < 0) return bytes;
		if (bytes > 16) return -1;
		serial[bytes] = '\0';
		set_string(&p15card->tokeninfo->serial_number, (char*)serial);
	}

	/* Is the card a CIE v1? */
	card_is_cie_v1 =
		   (p15card->card->type == SC_CARD_TYPE_ITACNS_CIE_V1)
		|| (p15card->card->type == SC_CARD_TYPE_CARDOS_CIE_V1);
	cns0_secenv = (card_is_cie_v1 ? 0x31 : 0x01);

	/* If it's a Siemens CIE v1 card, set algo flags accordingly. */
	if (card_is_cie_v1) {
		int i;
		for (i = 0; i < p15card->card->algorithm_count; i++) {
			sc_algorithm_info_t *info =
				&p15card->card->algorithms[i];

			if (info->algorithm != SC_ALGORITHM_RSA)
				continue;
			info->flags &= ~(SC_ALGORITHM_RSA_RAW
				| SC_ALGORITHM_RSA_HASH_NONE);
			info->flags |= (SC_ALGORITHM_RSA_PAD_PKCS1
				| SC_ALGORITHM_RSA_HASHES);
		}
	}

	/* Data files */
	r = itacns_add_data_files(p15card);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add data files");

	/*** Certificate and keys. ***/
	/* Standard CNS */
	r = itacns_check_and_add_keyset(p15card, "CNS0", cns0_secenv,
		0, "3F0011001101", "3F003F01", NULL,
		0x10, &found_certs);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add CNS0");
	certificate_count += found_certs;

	/* Infocamere 1204 */
	r = itacns_check_and_add_keyset(p15card, "CNS01", 0x21,
		5, "3F002FFF8228", NULL, "3F002FFF0000",
		0x10, &found_certs);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add CNS01");
	certificate_count += found_certs;

	/* Digital signature */
	r = itacns_check_and_add_keyset(p15card, "CNS1", 0x10,
		0, "3F0014009010", "3F00140081108010", "3F0014008110",
		0x1a, &found_certs);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not add CNS1");
	certificate_count += found_certs;

	/* Did we find anything? */
	if (certificate_count == 0)
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
			"Warning: no certificates found!");

	/* Back to Master File */
	sc_format_path("3F00", &path);
	r = sc_select_file(p15card->card, &path, NULL);
	LOG_TEST_RET(p15card->card->ctx, r,
		"Could not select master file again");

	return r;
}

int sc_pkcs15emu_itacns_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	sc_card_t *card = p15card->card;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	/* Check card */
	if (! (
			(card->type > SC_CARD_TYPE_ITACNS_BASE &&
			card->type < SC_CARD_TYPE_ITACNS_BASE + 1000)
		|| card->type == SC_CARD_TYPE_CARDOS_CIE_V1)
		)
		return SC_ERROR_WRONG_CARD;

	/* Init card */
	return itacns_init(p15card);
}
