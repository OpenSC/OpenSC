/*
 * PKCS15 emulation layer for 1202, 1203 and 1400 Infocamere card.
 * To see how this works, run p15dump on your Infocamere card.
 *
 * Copyright (C) 2005, Sirio Capizzi <graaf@virgilio.it>
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
#ifdef ENABLE_ZLIB
#include <zlib.h>
#endif

#include "common/compat_strlcpy.h"
#include "pkcs15.h"
#include "log.h"

int sc_pkcs15emu_infocamere_init_ex(sc_pkcs15_card_t *, struct sc_aid *aid,
		sc_pkcs15emu_opt_t *);

static int (*set_security_env) (sc_card_t *, const sc_security_env_t *,
		int);

static int set_sec_env(sc_card_t * card, const sc_security_env_t * env,
		int se_num)
{
	sc_security_env_t tenv = *env;
	if (tenv.operation == SC_SEC_OPERATION_SIGN)
		tenv.operation = SC_SEC_OPERATION_DECIPHER;
	return set_security_env(card, &tenv, se_num);
}

static int do_sign(sc_card_t * card, const u8 * in, size_t inlen, u8 * out,
		size_t outlen)
{
	return card->ops->decipher(card, in, inlen, out, outlen);
}

static void set_string(char **strp, const char *value)
{
	if (*strp)
		free(*strp);
	*strp = value ? strdup(value) : NULL;
}

#if 1
/* XXX: temporary copy of the old pkcs15emu functions,
 *      to be removed */
static int sc_pkcs15emu_add_pin(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id, const char *label,
		const sc_path_t *path, int ref, int type,
		unsigned int min_length,
		unsigned int max_length,
		int flags, int tries_left, const char pad_char, int obj_flags)
{
	sc_pkcs15_auth_info_t info;
	sc_pkcs15_object_t   obj;

	memset(&info, 0, sizeof(info));
	memset(&obj,  0, sizeof(obj));

	info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	info.auth_id           = *id;
	info.attrs.pin.min_length        = min_length;
	info.attrs.pin.max_length        = max_length;
	info.attrs.pin.stored_length     = max_length;
	info.attrs.pin.type              = type;
	info.attrs.pin.reference         = ref;
	info.attrs.pin.flags             = flags;
	info.attrs.pin.pad_char          = pad_char;
	info.tries_left        = tries_left;
	info.logged_in = SC_PIN_STATE_UNKNOWN;

	if (path)
		info.path = *path;
	if (type == SC_PKCS15_PIN_TYPE_BCD)
		info.attrs.pin.stored_length /= 2;

	strlcpy(obj.label, label, sizeof(obj.label));
	obj.flags = obj_flags;

	return sc_pkcs15emu_add_pin_obj(p15card, &obj, &info);
}

static int sc_pkcs15emu_add_prkey(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id,
		const char *label,
		int type, unsigned int modulus_length, int usage,
		const sc_path_t *path, int ref,
		const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_prkey_info_t info;
	sc_pkcs15_object_t     obj;

	memset(&info, 0, sizeof(info));
	memset(&obj,  0, sizeof(obj));

	info.id                = *id;
	info.modulus_length    = modulus_length;
	info.usage             = usage;
	info.native            = 1;
	info.key_reference     = ref;

	if (path)
		info.path = *path;

	obj.flags = obj_flags;
	strlcpy(obj.label, label, sizeof(obj.label));
	if (auth_id != NULL)
		obj.auth_id = *auth_id;

	return sc_pkcs15emu_add_rsa_prkey(p15card, &obj, &info);
}

static int sc_pkcs15emu_add_cert(sc_pkcs15_card_t *p15card,
		int type, int authority, const sc_path_t *path,
		const sc_pkcs15_id_t *id, const char *label, int obj_flags)
{
	/* const char *label = "Certificate"; */
	sc_pkcs15_cert_info_t info;
	sc_pkcs15_object_t    obj;

	memset(&info, 0, sizeof(info));
	memset(&obj,  0, sizeof(obj));

	info.id                = *id;
	info.authority         = authority;
	if (path)
		info.path = *path;

	strlcpy(obj.label, label, sizeof(obj.label));
	obj.flags = obj_flags;

	return sc_pkcs15emu_add_x509_cert(p15card, &obj, &info);
}
#endif

static int infocamere_1200_init(sc_pkcs15_card_t * p15card)
{
	const int prkey_usage = SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	const int authprkey_usage = SC_PKCS15_PRKEY_USAGE_SIGN
		| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
		| SC_PKCS15_PRKEY_USAGE_ENCRYPT
		| SC_PKCS15_PRKEY_USAGE_DECRYPT;

	sc_card_t *card = p15card->card;
	sc_path_t path;
	sc_pkcs15_id_t id, auth_id;
	char serial[256];
	unsigned char certlen[2];
	int authority, change_sign = 0;
	struct sc_pkcs15_cert_info cert_info;
	struct sc_pkcs15_object    cert_obj;

	const char *label = "User Non-repudiation Certificate";
	const char *calabel = "CA Certificate";
	const char *authlabel = "User Authentication Certificate";

	const char *infocamere_cert_path[2] = {
		"DF01C000",
		"3F00000011111A02"
	};

	const char *infocamere_auth_certpath[2] = {
		"11111A02",
		"000011111B02"
	};

	const char *infocamere_cacert_path[2] = {
		"DF01C008",
		"000011114101"
	};

	const char *infocamere_auth_path[2] = {
		"3F001111",
		"3F0000001111"
	};

	const char *infocamere_nrepud_path[2] = {
		"3F00DF01",
		"3F0000001111"
	};

	const int infocamere_idpin_auth_obj[2] = {
		0x95,
		0x81
	};

	const int infocamere_idpin_nrepud_obj[2] = {
		0x99,
		0x81
	};

	const int infocamere_idprkey_auth_obj[2] = {
		0x9B,
		0x01
	};

	const int infocamere_idprkey_nrepud_obj[2] = {
		0x84,
		0x01
	};

	const char *authPIN = "Authentication PIN";
	const char *nonrepPIN = "Non-repudiation PIN";

	const char *authPRKEY = "Authentication Key";
	const char *nonrepPRKEY = "Non repudiation Key";

	const int flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
		SC_PKCS15_PIN_FLAG_INITIALIZED |
		SC_PKCS15_PIN_FLAG_NEEDS_PADDING;

	int r;

	unsigned char chn[8];
	size_t chn_len = sizeof chn;
	sc_serial_number_t iccsn;
	iccsn.len = sizeof iccsn.value;


	r = sc_parse_ef_gdo(card, iccsn.value, &iccsn.len, chn, &chn_len);
	if (r < 0)
		return r;

	if (!iccsn.len || chn_len < 2 || chn_len > 8) {
		return SC_ERROR_WRONG_CARD;
	}

	sc_bin_to_hex(iccsn.value, iccsn.len, serial, sizeof(serial), 0);

	if (!
			(chn[0] == 0x12
			 && (chn[1] == 0x02 || chn[1] == 0x03))) {
		/* Not Infocamere Card */
		return SC_ERROR_WRONG_CARD;
	}

	set_string(&p15card->tokeninfo->serial_number, serial);

	if (chn[1] == 0x02)
		set_string(&p15card->tokeninfo->label, "Infocamere 1202 Card");
	else {
		set_string(&p15card->tokeninfo->label, "Infocamere 1203 Card");
		change_sign = 1;
	}

	set_string(&p15card->tokeninfo->manufacturer_id, "Infocamere");

	authority = 0;

	/* Get the authentication certificate length */

	sc_format_path(infocamere_auth_certpath[chn[1]-2], &path);

	r = sc_select_file(card, &path, NULL);

	if (r >= 0) {

		sc_read_binary(card, 0, certlen, 2, 0);

		/* Now set the certificate offset/len */

		path.index = 2;
		path.count = (certlen[1] << 8) + certlen[0];

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));

		sc_pkcs15_format_id("01", &cert_info.id);
		cert_info.authority = authority;
		cert_info.path = path;
		strlcpy(cert_obj.label, authlabel, sizeof(cert_obj.label));
		cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;

		/* XXX: the IDs for the key/pin in case of the 1203 type 
		 * are wrong, therefore I disable them for now -- Nils */
		if (!change_sign) {    
			/* add authentication PIN */

			sc_format_path(infocamere_auth_path[chn[1]-2], &path);

			sc_pkcs15_format_id("01", &id);
			sc_pkcs15emu_add_pin(p15card, &id,
					authPIN, &path, infocamere_idpin_auth_obj[chn[1]-2],
					SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
					5, 8, flags, 3, 0, 
					SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE);

			/* add authentication private key */

			auth_id.value[0] = 1;
			auth_id.len = 1;

			sc_pkcs15emu_add_prkey(p15card, &id,
					authPRKEY,
					SC_PKCS15_TYPE_PRKEY_RSA, 
					1024, authprkey_usage,
					&path, infocamere_idprkey_auth_obj[chn[1]-2],
					&auth_id, SC_PKCS15_CO_FLAG_PRIVATE);
		}

	}

	/* Get the non-repudiation certificate length */

	sc_format_path(infocamere_cert_path[chn[1]-2], &path);

	if (sc_select_file(card, &path, NULL) < 0) {
		return SC_ERROR_INTERNAL;
	}

	sc_read_binary(card, 0, certlen, 2, 0);

	/* Now set the certificate offset/len */
	path.index = 2;
	path.count = (certlen[1] << 8) + certlen[0];

	memset(&cert_info, 0, sizeof(cert_info));
	memset(&cert_obj,  0, sizeof(cert_obj));

	sc_pkcs15_format_id("02", &cert_info.id);

	cert_info.authority = authority;
	cert_info.path = path;
	strlcpy(cert_obj.label, label, sizeof(cert_obj.label));
	cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	if (r < 0)
		return SC_ERROR_INTERNAL;

	/* Get the CA certificate length */

	authority = 1;

	sc_format_path(infocamere_cacert_path[chn[1]-2], &path);

	r = sc_select_file(card, &path, NULL);

	if (r >= 0) {
		size_t len;

		sc_read_binary(card, 0, certlen, 2, 0);

		len = (certlen[1] << 8) + certlen[0];

		if (len != 0) {
			/* Now set the certificate offset/len */
			path.index = 2;
			path.count = len;

			memset(&cert_info, 0, sizeof(cert_info));
			memset(&cert_obj,  0, sizeof(cert_obj));

			sc_pkcs15_format_id("03", &cert_info.id);
			cert_info.authority = authority;
			cert_info.path = path;
			strlcpy(cert_obj.label, calabel, sizeof(cert_obj.label));
			cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

			r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
			if (r < 0)
				return SC_ERROR_INTERNAL;
		}
	}

	/* add non repudiation PIN */

	sc_format_path(infocamere_nrepud_path[chn[1]-2], &path);

	sc_pkcs15_format_id("02", &id);
	sc_pkcs15emu_add_pin(p15card, &id,
			nonrepPIN, &path, infocamere_idpin_nrepud_obj[chn[1]-2],
			SC_PKCS15_PIN_TYPE_ASCII_NUMERIC, 5, 8, flags, 3, 0,
			SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE);


	/* add non repudiation private key */

	auth_id.value[0] = 2;
	auth_id.len = 1;

	sc_pkcs15emu_add_prkey(p15card, &id, nonrepPRKEY,
			SC_PKCS15_TYPE_PRKEY_RSA, 
			1024, prkey_usage,
			&path, infocamere_idprkey_nrepud_obj[chn[1]-2],
			&auth_id, SC_PKCS15_CO_FLAG_PRIVATE);


	/* return to MF */
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	if (r != SC_SUCCESS)
		return r;

	if (change_sign) {
		/* save old signature funcs */
		set_security_env = card->ops->set_security_env;
		/* set new one */
		card->ops->set_security_env = set_sec_env;
		card->ops->compute_signature = do_sign;
	}

	return SC_SUCCESS;
}

static int infocamere_1400_set_sec_env(struct sc_card *card,
		const struct sc_security_env *env,
		int se_num)
{
	int r;

	struct sc_security_env tenv = *env;
	if (tenv.operation == SC_SEC_OPERATION_SIGN)
		tenv.operation = SC_SEC_OPERATION_DECIPHER;

	if ((r =
				card->ops->restore_security_env(card, 0x40)) == SC_SUCCESS)
		return set_security_env(card, &tenv, se_num);
	else
		return r;
}

#ifdef ENABLE_ZLIB

static const u8 ATR_1400[] =
{ 0x3b, 0xfc, 0x98, 0x00, 0xff, 0xc1, 0x10, 0x31, 0xfe, 0x55, 0xc8,
	0x03, 0x49, 0x6e, 0x66, 0x6f, 0x63, 0x61, 0x6d, 0x65, 0x72, 0x65,
	0x28
};

/* Loads certificates.
 * Certificates are stored in a ZLib compressed form with
 * a 4 byte header, so we extract, decompress and cache
 * them.
 */
static int loadCertificate(sc_pkcs15_card_t * p15card, int i,
		const char *certPath, const char *certLabel)
{
	unsigned char *compCert = NULL, *cert = NULL, size[2];
	unsigned long int compLen, len;
	sc_pkcs15_cert_info_t cert_info;
	sc_pkcs15_object_t cert_obj;
	sc_path_t cpath;
	sc_card_t *card = p15card->card;
	sc_pkcs15_id_t id;
	int r;

	memset(&cert_info, 0, sizeof(cert_info));
	memset(&cert_obj, 0, sizeof(cert_obj));

	sc_format_path(certPath, &cpath);

	if (sc_select_file(card, &cpath, NULL) != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;

	sc_read_binary(card, 2, size, 2, 0);

	compLen = (size[0] << 8) + size[1];
	compCert = malloc(compLen * sizeof(unsigned char));
	len = 4 * compLen;	/*Approximation of the uncompressed size */
	cert = malloc(len * sizeof(unsigned char));
	if (!cert || !compCert) {
		free(cert);
		free(compCert);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	sc_read_binary(card, 4, compCert, compLen, 0);

	if ((r = uncompress(cert, &len, compCert, compLen)) != Z_OK) {
		sc_log(p15card->card->ctx,  "Zlib error: %d", r);
		return SC_ERROR_INTERNAL;
	}

	cpath.index = 0;
	cpath.count = len;

	sc_pkcs15_cache_file(p15card, &cpath, cert, len);

	id.len=1;
	id.value[0] = i + 1;

	cert_info.id = id;
	cert_info.path = cpath;
	cert_info.authority = (i == 2);

	strlcpy(cert_obj.label, certLabel, sizeof(cert_obj.label));
	cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

	sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);

	return SC_SUCCESS;
}


static int infocamere_1400_init(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_path_t path;
	sc_pkcs15_id_t id, auth_id;
	unsigned char serial[16];
	int flags;
	int r;
	int hasAuthCert = 0;

	const char *certLabel[] = { "User Non-repudiation Certificate",
		"User Authentication Certificate",
		"CA Certificate"
	};

	const char *certPath[] =
	{ "300060000000", "300060000001", "300060000002" };

	const char *pinLabel[] =
	{ "Non-repudiation PIN", "Authentication PIN" };
	int retries[] = { 3, -1 };

	const char *keyPath[] = { "30004000001", "30004000002" };
	const char *keyLabel[] =
	{ "Non repudiation Key", "Authentication Key" };
	static int usage[] = { SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
		SC_PKCS15_PRKEY_USAGE_SIGN
			| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
			| SC_PKCS15_PRKEY_USAGE_ENCRYPT
			| SC_PKCS15_PRKEY_USAGE_DECRYPT
	};

	auth_id.len = 1;
	id.len = 1;

	/* OpenSC doesn't define constants to identify BSOs for
	 * restoring security environment, so we overload
	 * the set_security_env function to support restore_sec_env */
	set_security_env = card->ops->set_security_env;
	card->ops->set_security_env = infocamere_1400_set_sec_env;
	card->ops->compute_signature = do_sign;
	p15card->opts.use_file_cache = 1;

	sc_format_path("30000001", &path);

	r = sc_select_file(card, &path, NULL);

	if (r != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;

	sc_read_binary(card, 15, serial, 15, 0);
	serial[15] = '\0';

	set_string(&p15card->tokeninfo->serial_number, (char *)serial);
	set_string(&p15card->tokeninfo->label, "Infocamere 1400 Card");
	set_string(&p15card->tokeninfo->manufacturer_id, "Infocamere");

	if ((r = loadCertificate(p15card, 0, certPath[0], certLabel[0])) !=
			SC_SUCCESS) {
		sc_log(p15card->card->ctx,  "%s", sc_strerror(r));
		return SC_ERROR_WRONG_CARD;
	}

	hasAuthCert =
		loadCertificate(p15card, 1, certPath[1],
				certLabel[1]) == SC_SUCCESS;
	loadCertificate(p15card, 2, certPath[2], certLabel[2]);

	flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
		SC_PKCS15_PIN_FLAG_INITIALIZED |
		SC_PKCS15_PIN_FLAG_NEEDS_PADDING;

	/* adding PINs & private keys */

	sc_format_path("30004000", &path);
	id.value[0] = 1;

	sc_pkcs15emu_add_pin(p15card, &id,
			pinLabel[0], &path, 1,
			SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
			5, 8, flags, retries[0], 0,
			SC_PKCS15_CO_FLAG_MODIFIABLE |
			SC_PKCS15_CO_FLAG_PRIVATE);

	sc_format_path(keyPath[0], &path);
	auth_id.value[0] = 1;
	sc_pkcs15emu_add_prkey(p15card, &id,
			keyLabel[0],
			SC_PKCS15_TYPE_PRKEY_RSA,
			1024, usage[0],
			&path, 1,
			&auth_id, SC_PKCS15_CO_FLAG_PRIVATE);


	if (hasAuthCert) {
		sc_format_path("30004000", &path);
		id.value[0] = 2;

		sc_pkcs15emu_add_pin(p15card, &id,
				pinLabel[1], &path, 2,
				SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
				5, 8, flags, retries[1], 0,
				SC_PKCS15_CO_FLAG_MODIFIABLE |
				SC_PKCS15_CO_FLAG_PRIVATE);

		sc_format_path(keyPath[1], &path);
		auth_id.value[0] = 2;
		sc_pkcs15emu_add_prkey(p15card, &id,
				keyLabel[1],
				SC_PKCS15_TYPE_PRKEY_RSA,
				1024, usage[1],
				&path, 2,
				&auth_id,
				SC_PKCS15_CO_FLAG_PRIVATE);
	}

	/* return to MF */
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	return r;
}

#endif

static const u8 ATR_1600[] = { 0x3B, 0xF4, 0x98, 0x00, 0xFF, 0xC1, 0x10,
	0x31, 0xFE, 0x55, 0x4D, 0x34, 0x63, 0x76, 0xB4
};

static int infocamere_1600_init(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_path_t path;
	sc_pkcs15_id_t id, auth_id;
	unsigned char serial[17];
	int flags;
	int r;
	int hasAuthCert = 0;

	const char *certLabel[] = { "User Non-repudiation Certificate",
		"User Authentication Certificate"
	};

	const char *certPath[] = { "200020010008", "20002001000E" };

	const char *pinLabel[] =
	{ "Non-repudiation PIN", "Authentication PIN" };
	int retries[] = { 3, -1 };

	const char *keyPath[] = { "200020010004", "20002001000A" };
	const char *keyLabel[] =
	{ "Non repudiation Key", "Authentication Key" };
	static int usage[] = { SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
		SC_PKCS15_PRKEY_USAGE_SIGN
			| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
			| SC_PKCS15_PRKEY_USAGE_ENCRYPT
			| SC_PKCS15_PRKEY_USAGE_DECRYPT
	};

	auth_id.len = 1;
	id.len = 1;

	/* OpenSC doesn't define constants to identify BSOs for
	 * restoring security environment, so we overload
	 * the set_security_env function to support restore_sec_env */
	set_security_env = card->ops->set_security_env;
	card->ops->set_security_env = infocamere_1400_set_sec_env;
	card->ops->compute_signature = do_sign;

	sc_format_path("200020012002", &path);

	r = sc_select_file(card, &path, NULL);

	if (r != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;

	sc_read_binary(card, 30, serial, 16, 0);
	serial[16] = '\0';

	set_string(&p15card->tokeninfo->serial_number, (char *) serial);
	set_string(&p15card->tokeninfo->label, "Infocamere 1600 Card");
	set_string(&p15card->tokeninfo->manufacturer_id, "Infocamere");

	/* Adding certificates.
	 * Certificates are stored in a ZLib compressed form with
	 * a 4 byte header, so we extract, decompress and cache
	 * them.
	 */
	sc_format_path(certPath[0], &path);
	if (sc_select_file(card, &path, NULL) != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;

	id.value[0] = 1;

	sc_pkcs15emu_add_cert(p15card,
			SC_PKCS15_TYPE_CERT_X509, 0,
			&path, &id, certLabel[0],
			SC_PKCS15_CO_FLAG_MODIFIABLE);

	sc_format_path(certPath[1], &path);
	if (sc_select_file(card, &path, NULL) == SC_SUCCESS) {
		hasAuthCert = 1;

		id.value[0] = 2;

		sc_pkcs15emu_add_cert(p15card,
				SC_PKCS15_TYPE_CERT_X509, 1,
				&path, &id, certLabel[1],
				SC_PKCS15_CO_FLAG_MODIFIABLE);
	}

	flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
		SC_PKCS15_PIN_FLAG_INITIALIZED |
		SC_PKCS15_PIN_FLAG_NEEDS_PADDING;

	/* adding PINs & private keys */
	sc_format_path("2000", &path);
	id.value[0] = 1;

	sc_pkcs15emu_add_pin(p15card, &id,
			pinLabel[0], &path, 1,
			SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
			5, 8, flags, retries[0], 0,
			SC_PKCS15_CO_FLAG_MODIFIABLE |
			SC_PKCS15_CO_FLAG_PRIVATE);

	sc_format_path(keyPath[0], &path);
	auth_id.value[0] = 1;
	sc_pkcs15emu_add_prkey(p15card, &id,
			keyLabel[0],
			SC_PKCS15_TYPE_PRKEY_RSA,
			1024, usage[0],
			&path, 1,
			&auth_id, SC_PKCS15_CO_FLAG_PRIVATE);

	if (hasAuthCert) {
		id.value[0] = 2;

		sc_pkcs15emu_add_pin(p15card, &id,
				pinLabel[1], &path, 2,
				SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
				5, 8, flags, retries[1], 0,
				SC_PKCS15_CO_FLAG_MODIFIABLE |
				SC_PKCS15_CO_FLAG_PRIVATE);

		sc_format_path(keyPath[1], &path);
		auth_id.value[0] = 2;
		sc_pkcs15emu_add_prkey(p15card, &id,
				keyLabel[1],
				SC_PKCS15_TYPE_PRKEY_RSA,
				1024, usage[1],
				&path, 2,
				&auth_id,
				SC_PKCS15_CO_FLAG_PRIVATE);
	}

	/* return to MF */
	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);

	return SC_SUCCESS;
}

static int infocamere_detect_card(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "STARCOS")
			&& strcmp(card->name, "CardOS M4"))
		return SC_ERROR_WRONG_CARD;
	return SC_SUCCESS;
}

int sc_pkcs15emu_infocamere_init_ex(sc_pkcs15_card_t * p15card,
		struct sc_aid *aid,
		sc_pkcs15emu_opt_t * opts)
{

	if (!(opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)) {
		if (infocamere_detect_card(p15card))
			return SC_ERROR_WRONG_CARD;
	}

	if (memcmp(p15card->card->atr.value, ATR_1600, sizeof(ATR_1600)) == 0)
		return infocamere_1600_init(p15card);
#ifdef ENABLE_ZLIB
	else if (memcmp(p15card->card->atr.value, ATR_1400, sizeof(ATR_1400)) ==
			0)
		return infocamere_1400_init(p15card);
#endif
	else
		return infocamere_1200_init(p15card);

}
