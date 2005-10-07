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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <opensc/pkcs15.h>
#include <opensc/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

int sc_pkcs15emu_infocamere_init_ex(sc_pkcs15_card_t *,
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

static int infocamere_1200_init(sc_pkcs15_card_t * p15card)
{
	const int prkey_usage = SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	const int authprkey_usage = SC_PKCS15_PRKEY_USAGE_SIGN
	    | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
	    | SC_PKCS15_PRKEY_USAGE_ENCRYPT
	    | SC_PKCS15_PRKEY_USAGE_DECRYPT;

	sc_card_t *card = p15card->card;
	sc_path_t path;
	sc_file_t *file;
	sc_pkcs15_id_t id, auth_id;
	unsigned char buffer[256];
	unsigned char ef_gdo[256];
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

	int r, len_iccsn, len_chn;

	sc_format_path("3F002F02", &path);

	card->ctx->suppress_errors++;
	r = sc_select_file(card, &path, &file);
	card->ctx->suppress_errors--;
	
	if (r != SC_SUCCESS || file->size > 255) {
		/* Not EF.GDO */
		return SC_ERROR_WRONG_CARD;
	}

	sc_read_binary(card, 0, ef_gdo, file->size, 0);

	if (ef_gdo[0] != 0x5A || file->size < 3) {
		/* Not EF.GDO */
		return SC_ERROR_WRONG_CARD;
	}

	len_iccsn = ef_gdo[1];

	memcpy(buffer, ef_gdo + 2, len_iccsn);

	sc_bin_to_hex(buffer, len_iccsn, serial, sizeof(serial), 0);

	if (file->size < (size_t) (len_iccsn + 5)) {
		/* Not CHN */
		return SC_ERROR_WRONG_CARD;
	}

	if (!
	    (ef_gdo[len_iccsn + 2] == 0x5F
	     && ef_gdo[len_iccsn + 3] == 0x20)) {
		/* Not CHN */
		return SC_ERROR_WRONG_CARD;
	}

	len_chn = ef_gdo[len_iccsn + 4];

	if (len_chn < 2 || len_chn > 8) {
		/* Length CHN incorrect */
		return SC_ERROR_WRONG_CARD;
	}

	if (!
	    (ef_gdo[len_iccsn + 5] == 0x12
	     && (ef_gdo[len_iccsn + 6] == 0x02
		 || ef_gdo[len_iccsn + 6] == 0x03))) {
		/* Not Infocamere Card */
		return SC_ERROR_WRONG_CARD;
	}

	set_string(&p15card->serial_number, serial);

	if (ef_gdo[len_iccsn + 6] == 0x02)
		set_string(&p15card->label, "Infocamere 1202 Card");
	else {
		set_string(&p15card->label, "Infocamere 1203 Card");
		change_sign = 1;
	}

	set_string(&p15card->manufacturer_id, "Infocamere");

	authority = 0;

	/* Get the authentication certificate length */

	sc_format_path(infocamere_auth_certpath[ef_gdo[len_iccsn+6]-2], &path);

	card->ctx->suppress_errors++;
	r = sc_select_file(card, &path, NULL);
	card->ctx->suppress_errors--;

	if (r >= 0) {

		sc_read_binary(card, 0, certlen, 2, 0);

		/* Now set the certificate offset/len */

		path.index = 2;
		path.count = (certlen[1] << 8) + certlen[0];

		memset(&cert_info, 0, sizeof(cert_info));
                memset(&cert_obj,  0, sizeof(cert_obj));

		sc_pkcs15_format_id("1", &cert_info.id);
        	cert_info.authority = authority;
        	cert_info.path = path;
		strncpy(cert_obj.label, authlabel, SC_PKCS15_MAX_LABEL_SIZE - 1);
	        cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
        	if (r < 0)
        		return SC_ERROR_INTERNAL;

		/* XXX: the IDs for the key/pin in case of the 1203 type 
		 * are wrong, therefore I disable them for now -- Nils */
		if (!change_sign) {    
		/* add authentication PIN */

                sc_format_path(infocamere_auth_path[ef_gdo[len_iccsn+6]-2], &path);
                
		sc_pkcs15_format_id("1", &id);
		sc_pkcs15emu_add_pin(p15card, &id,
                                authPIN, &path, infocamere_idpin_auth_obj[ef_gdo[len_iccsn+6]-2],
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
				&path, infocamere_idprkey_auth_obj[ef_gdo[len_iccsn+6]-2],
				&auth_id, SC_PKCS15_CO_FLAG_PRIVATE);
		}

	}

	/* Get the non-repudiation certificate length */

	sc_format_path(infocamere_cert_path[ef_gdo[len_iccsn+6]-2], &path);

	if (sc_select_file(card, &path, NULL) < 0)
		{
		return SC_ERROR_INTERNAL;
		}

	sc_read_binary(card, 0, certlen, 2, 0);

	/* Now set the certificate offset/len */
	path.index = 2;
	path.count = (certlen[1] << 8) + certlen[0];
	
        memset(&cert_info, 0, sizeof(cert_info));
        memset(&cert_obj,  0, sizeof(cert_obj));

	sc_pkcs15_format_id("2", &cert_info.id);

        cert_info.authority = authority;
        cert_info.path = path;
        strncpy(cert_obj.label, label, SC_PKCS15_MAX_LABEL_SIZE - 1);
        cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
        if (r < 0)
        	return SC_ERROR_INTERNAL;

	/* Get the CA certificate length */

	authority = 1;

	sc_format_path(infocamere_cacert_path[ef_gdo[len_iccsn+6]-2], &path);

	card->ctx->suppress_errors++;
	r = sc_select_file(card, &path, NULL);
	card->ctx->suppress_errors--;

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

			sc_pkcs15_format_id("3", &cert_info.id);
	        	cert_info.authority = authority;
	        	cert_info.path = path;
	        	strncpy(cert_obj.label, calabel, SC_PKCS15_MAX_LABEL_SIZE - 1);
		        cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

			r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
        		if (r < 0)
        		return SC_ERROR_INTERNAL;
		}
	}               

        /* add non repudiation PIN */

	sc_format_path(infocamere_nrepud_path[ef_gdo[len_iccsn+6]-2], &path);

	sc_pkcs15_format_id("2", &id);
	sc_pkcs15emu_add_pin(p15card, &id,
		nonrepPIN, &path, infocamere_idpin_nrepud_obj[ef_gdo[len_iccsn+6]-2],
		SC_PKCS15_PIN_TYPE_ASCII_NUMERIC, 5, 8, flags, 3, 0,
		SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE);


	/* add non repudiation private key */

	auth_id.value[0] = 2;
	auth_id.len = 1;

	sc_pkcs15emu_add_prkey(p15card, &id, nonrepPRKEY,
			       SC_PKCS15_TYPE_PRKEY_RSA, 
                               1024, prkey_usage,
                               &path, infocamere_idprkey_nrepud_obj[ef_gdo[len_iccsn+6]-2],
                               &auth_id, SC_PKCS15_CO_FLAG_PRIVATE);


	/* return to MF */
	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);

	if (change_sign) {
		/* save old signature funcs */
		set_security_env = card->ops->set_security_env;
		/* set new one */
		card->ops->set_security_env = set_sec_env;
		card->ops->compute_signature = do_sign;
	}

	return SC_SUCCESS;
}

#ifdef HAVE_ZLIB_H

static const u8 ATR_1400[] =
    { 0x3b, 0xfc, 0x98, 0x00, 0xff, 0xc1, 0x10, 0x31, 0xfe, 0x55, 0xc8,
	0x03, 0x49, 0x6e, 0x66, 0x6f, 0x63, 0x61, 0x6d, 0x65, 0x72, 0x65,
	    0x28
};

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

static int infocamere_1400_init(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_path_t path;
	sc_pkcs15_id_t id, auth_id;
	unsigned char serial[16];
	int flags;
	int i, r;

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
	p15card->opts.use_cache = 1;

	sc_format_path("30000001", &path);

	r = sc_select_file(card, &path, NULL);
	
	if (r != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;

	sc_read_binary(card, 15, serial, 15, 0);
	serial[15] = '\0';

	set_string(&p15card->serial_number, (char *)serial);
	set_string(&p15card->label, "Infocamere 1400 Card");
	set_string(&p15card->manufacturer_id, "Infocamere");

	/* Adding certificates.
	 * Certificates are stored in a ZLib compressed form with
	 * a 4 byte header, so we extract, decompress and cache
	 * them.
	 */
	for (i = 0; i < 3; i++) {
		unsigned char *compCert = NULL, *cert = NULL, size[2];
		unsigned int compLen, len;
		sc_pkcs15_cert_info_t cert_info;
		sc_pkcs15_object_t cert_obj;
		sc_path_t cpath;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		sc_format_path(certPath[i], &cpath);

		if (sc_select_file(card, &cpath, NULL) != SC_SUCCESS)
			return SC_ERROR_WRONG_CARD;

		sc_read_binary(card, 2, size, 2, 0);

		compLen = (size[0] << 8) + size[1];
		compCert =
		    (unsigned char *) malloc(compLen *
					     sizeof(unsigned char));
		len = 3 * compLen;	/*Approximation of the uncompressed size */
		cert =
		    (unsigned char *) malloc(len * sizeof(unsigned char));

		sc_read_binary(card, 4, compCert, compLen, 0);

		if (uncompress
		    (cert, (unsigned long int *) &len, compCert,
		     compLen) != Z_OK)
			return SC_ERROR_INTERNAL;

		cpath.index = 0;
		cpath.count = len;

		sc_pkcs15_cache_file(p15card, &cpath, cert, len);

		id.value[0] = i + 1;

		cert_info.id = id;
		cert_info.path = cpath;
		cert_info.authority = (i == 2);

		strncpy(cert_obj.label, certLabel[i],
			SC_PKCS15_MAX_LABEL_SIZE - 1);
		cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

		sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	}


	flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
	    SC_PKCS15_PIN_FLAG_INITIALIZED |
	    SC_PKCS15_PIN_FLAG_NEEDS_PADDING;

	/* adding PINs & private keys */
	for (i = 0; i < 2; i++) {
		sc_format_path("30004000", &path);
		id.value[0] = i + 1;

		sc_pkcs15emu_add_pin(p15card, &id,
				     pinLabel[i], &path, i + 1,
				     SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
				     5, 8, flags, retries[i], 0,
				     SC_PKCS15_CO_FLAG_MODIFIABLE |
				     SC_PKCS15_CO_FLAG_PRIVATE);

		sc_format_path(keyPath[i], &path);
		auth_id.value[0] = i + 1;
		sc_pkcs15emu_add_prkey(p15card, &id,
				       keyLabel[i],
				       SC_PKCS15_TYPE_PRKEY_RSA,
				       1024, usage[i],
				       &path, i + 1,
				       &auth_id,
				       SC_PKCS15_CO_FLAG_PRIVATE);
	}

	/* return to MF */
	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);

	return SC_SUCCESS;
}

#endif

static int infocamere_detect_card(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "STARCOS SPK 2.3")
	    && strcmp(card->name, "CardOS M4"))
		return SC_ERROR_WRONG_CARD;
	return SC_SUCCESS;
}

int sc_pkcs15emu_infocamere_init_ex(sc_pkcs15_card_t * p15card,
				    sc_pkcs15emu_opt_t * opts)
{

	if (!(opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)) {
		if (infocamere_detect_card(p15card))
			return SC_ERROR_WRONG_CARD;
	}
#ifdef HAVE_ZLIB_H

	if (memcmp(p15card->card->atr, ATR_1400, sizeof(ATR_1400)) == 0)
		return infocamere_1400_init(p15card);
	else
		return infocamere_1200_init(p15card);

#else

	return infocamere_1200_init(p15card);

#endif
}
