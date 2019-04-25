/*
 * PKCS15 emulation layer for Actalis card.
 * To see how this works, run p15dump on your Actalis Card.
 *
 * Copyright (C) 2005, Andrea Frigido <andrea@frisoft.it>
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
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"

int sc_pkcs15emu_actalis_init_ex(sc_pkcs15_card_t *, struct sc_aid *, sc_pkcs15emu_opt_t *);

static int (*set_security_env) (sc_card_t *, const sc_security_env_t *, int);

static int set_sec_env(sc_card_t * card, const sc_security_env_t *env,
		       int se_num)
{
	int r;
	sc_security_env_t tenv = *env;
	if (tenv.operation == SC_SEC_OPERATION_SIGN)
		tenv.operation = SC_SEC_OPERATION_DECIPHER;
	
	if ((r =
	     card->ops->restore_security_env(card, 0x40)) == SC_SUCCESS)
		return set_security_env(card, &tenv, se_num);
	else
		return r;
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

        info.auth_id           = *id;
	info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
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
#endif

static int sc_pkcs15emu_actalis_init(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_path_t path;
	sc_pkcs15_id_t id, auth_id;
	unsigned char serial_buf[13], *serial;
	int flags;
	int r;

#ifdef ENABLE_ZLIB
	int i = 0, j = 0;
	const char *certLabel[] = {
		"User Non-repudiation Certificate",	/* "User Non-repudiation Certificate" */
		"TSA Certificate",
		"CA Certificate"
	};	
	const char *certPath[] =
	    { "3F00300060006002", "3F00300060006003", "3F00300060006004" };
#endif

	const char *keyPath = "3F00300040000008";
	const char *pinDfName = "05040200";
	
	/* const int prkey_usage = SC_PKCS15_PRKEY_USAGE_NONREPUDIATION; */
	const int authprkey_usage = SC_PKCS15_PRKEY_USAGE_SIGN
				| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
				| SC_PKCS15_PRKEY_USAGE_ENCRYPT
				| SC_PKCS15_PRKEY_USAGE_DECRYPT;
	    
	const char *authPIN = "Authentication PIN";
	/* const char *nonrepPIN = "Non-repudiation PIN"; */

	const char *authPRKEY = "Authentication Key";
	/* const char *nonrepPRKEY = "Non repudiation Key"; */
	
	p15card->opts.use_file_cache = 1;	

	/* Get Serial number */
	sc_format_path("3F0030000001", &path);
	r = sc_select_file(card, &path, NULL);
	if (r != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;

	sc_read_binary(card, 0xC3, serial_buf, 12, 0);
	serial = serial_buf;

	/*
	 * The serial number is 8 characters long. Later versions of the
	 * card have the serial number at a different offset, after 4 more
	 * bytes.
	 */
	if (serial[0] != 'H') {
		if (serial[4] == 'H')
			serial = &serial_buf[4];
		else
			return SC_ERROR_WRONG_CARD;
	}
	serial[8] = '\0';

	/* Controllo che il serial number inizi per "H" */
	if( serial[0] != 'H' ) 
		return SC_ERROR_WRONG_CARD;
			
	set_string(&p15card->tokeninfo->label, "Actalis");
	set_string(&p15card->tokeninfo->manufacturer_id, "Actalis");
	set_string(&p15card->tokeninfo->serial_number, (char *)serial);

#ifdef ENABLE_ZLIB
	for (i = 0; i < 3; i++) {
		sc_path_t cpath;
		sc_format_path(certPath[i], &cpath);

		if (sc_select_file(card, &cpath, NULL) == SC_SUCCESS) {
			unsigned char *compCert = NULL, *cert = NULL, size[2];
			unsigned long compLen, len;

			sc_pkcs15_cert_info_t cert_info;
			sc_pkcs15_object_t cert_obj;
			memset(&cert_info, 0, sizeof(cert_info));
			memset(&cert_obj, 0, sizeof(cert_obj));

			if (SC_SUCCESS != sc_read_binary(card, 2, size, 2, 0))
				continue;
			compLen = (size[0] << 8) + size[1];
			compCert = malloc(compLen * sizeof(unsigned char));
			len = 3 * compLen;	/*Approximation of the uncompressed size */
			cert = malloc(len * sizeof(unsigned char));
			if (!cert || !compCert) {
				free(cert);
				free(compCert);
				return SC_ERROR_OUT_OF_MEMORY;
			}

			if (sc_read_binary(card, 4, compCert, compLen, 0) != SC_SUCCESS
					|| uncompress(cert, &len, compCert, compLen) != Z_OK) {
				free(cert);
				free(compCert);
				continue;
			}
			cpath.index = 0;
			cpath.count = len;

			sc_pkcs15_cache_file(p15card, &cpath, cert, len);
			id.value[0] = j + 1;
			id.len = 1;
			cert_info.id = id;
			cert_info.path = cpath;
			cert_info.authority = (j>0);

			strlcpy(cert_obj.label, certLabel[j], sizeof(cert_obj.label));

			j++;
			cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;
			sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);

			free(cert);
			free(compCert);
		}
	}
#endif
	
	/* adding PINs & private keys */
	flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
	    SC_PKCS15_PIN_FLAG_INITIALIZED |
	    SC_PKCS15_PIN_FLAG_NEEDS_PADDING;	
	
	sc_format_path(pinDfName, &path);
	path.type = SC_PATH_TYPE_DF_NAME;
	
	id.value[0] = 1;
	id.len = 1;
	sc_pkcs15emu_add_pin(p15card, &id,
			     authPIN, &path, 0x81,
			     SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
			     5, 8, flags, 3, 0,
			     SC_PKCS15_CO_FLAG_MODIFIABLE |
			     SC_PKCS15_CO_FLAG_PRIVATE);
	
	sc_format_path(keyPath, &path);
	id.value[0] = 1;
	id.len = 1;
	auth_id.value[0] = 1;
	auth_id.len = 1;
	sc_pkcs15emu_add_prkey(p15card, &id,
		       authPRKEY,
		       SC_PKCS15_TYPE_PRKEY_RSA,
		       1024, authprkey_usage,
		       &path, 0x08,
		       &auth_id,
		       SC_PKCS15_CO_FLAG_PRIVATE);
	
	/* return to MF */
	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);
	{
		/* save old signature funcs */
		set_security_env = card->ops->set_security_env;
		/* set new one             */
		card->ops->set_security_env  = set_sec_env;
		card->ops->compute_signature = do_sign;
	}
	
	return SC_SUCCESS;

}

static int actalis_detect_card(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "CardOS M4"))
		return SC_ERROR_WRONG_CARD;
	
	return SC_SUCCESS;
}

int sc_pkcs15emu_actalis_init_ex(sc_pkcs15_card_t * p15card,
				 struct sc_aid *aid,
				 sc_pkcs15emu_opt_t * opts)
{
	if (actalis_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_actalis_init(p15card);
}
