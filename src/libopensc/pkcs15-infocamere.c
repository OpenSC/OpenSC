/*
 * PKCS15 emulation layer for Infocamere SPK2.3 card.
 * To see how this works, run p15dump on your Infocamere SPK2.3 card.
 *
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

static void
set_string(char **strp, const char *value)
{
	if (*strp)
		free(strp);
	*strp = value? strdup(value) : NULL;
}

int
sc_pkcs15emu_infocamere_init(sc_pkcs15_card_t *p15card)
{

   static int      prkey_usage =         SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;

   static int      authprkey_usage =      SC_PKCS15_PRKEY_USAGE_SIGN
                                        | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
					| SC_PKCS15_PRKEY_USAGE_ENCRYPT         
					| SC_PKCS15_PRKEY_USAGE_DECRYPT  ;

	sc_card_t	*card = p15card->card;
	sc_path_t	path;
	struct sc_file	*file;
	sc_pkcs15_id_t	id, auth_id;
	unsigned char   buffer[256];
	unsigned char   ef_gdo[256];
	unsigned char   serial[256];
	unsigned char	certlen[2];
        int             flags;
	int 		authority;

	const char *label	=	"User Non-repudiation Certificate";
	const char *calabel  	= 	"CA Certificate";
	const char *authlabel	= 	"User Authentication Certificate";

	const char *infocamere_cert_path	= "DF01C000";
	const char *infocamere_auth_cert_path	= "11111A02";
	const char *infocamere_cacert_path	= "DF01C008";

	const char *authPIN	= 	"Authentication PIN";
	const char *nonrepPIN	= 	"Non-repudiation PIN";

	const char *authPRKEY	= 	"Authentication Key";
	const char *nonrepPRKEY	= 	"Non repudiation Key";

	int		r;
	size_t		len_chn, len_iccsn;

	sc_format_path("3F002F02", &path);

	r = sc_select_file(card, &path, &file);
	
	if (r < 0 || file->size > 255)
		{
		/* Not EF.GDO */
		r = SC_ERROR_WRONG_CARD;
		goto failed;
		}

	sc_read_binary(card, 0, ef_gdo, file->size, 0);

	if (ef_gdo[0]!=0x5A || file->size < 3)
		{
		/* Not EF.GDO */
		r = SC_ERROR_WRONG_CARD;
		goto failed; 	
		}

	len_iccsn = ef_gdo[1];

	memcpy(buffer,ef_gdo+2,len_iccsn);

        sc_bin_to_hex(buffer, len_iccsn , serial, sizeof(serial), 0);

	if (file->size < (len_iccsn + 5))
		{
		/* Not CHN */
		r = SC_ERROR_WRONG_CARD;
		goto failed; 	
		}

	if (!(ef_gdo[len_iccsn+2]==0x5F && ef_gdo[len_iccsn+3]==0x20))
		{
		/* Not CHN */
		r = SC_ERROR_WRONG_CARD;
		goto failed; 	
		}
			    	
	len_chn = ef_gdo[len_iccsn+4];

	if (len_chn < 2 || len_chn > 8)
		{
		/* Length CHN incorrect */
		r = SC_ERROR_WRONG_CARD;
		goto failed; 	
		}

	if (!(ef_gdo[len_iccsn+5]==0x12 && ef_gdo[len_iccsn+6]==0x02))
		{
		/* Not Infocamere SPK2.3 Card*/
		r = SC_ERROR_WRONG_CARD;
		goto failed; 	
		}

        set_string(&p15card->serial_number, serial);
	set_string(&p15card->label, "Infocamere SPK2.3 Card");
	set_string(&p15card->manufacturer_id, "Infocamere");

	authority = 0;

	/* Get the non-repudiation certificate length */

	sc_format_path(infocamere_auth_cert_path, &path);

	if (sc_select_file(card, &path, NULL) < 0)
		{
		r = SC_ERROR_WRONG_CARD;
		goto failed;
		}

	sc_read_binary(card, 0, certlen, 2, 0);

	/* Now set the certificate offset/len */
	path.index = 2;
	path.count = (certlen[1] << 8) + certlen[0];

	id.value[0] = 1;
	id.len = 1;

	sc_pkcs15emu_add_cert(p15card,
				SC_PKCS15_TYPE_CERT_X509, authority,
				&path, &id, authlabel, SC_PKCS15_CO_FLAG_MODIFIABLE);


	/* Get the authentication certificate length */

	sc_format_path(infocamere_cert_path, &path);

	if (sc_select_file(card, &path, NULL) < 0)
		{
		r = SC_ERROR_INTERNAL;
		goto failed;
		}

	sc_read_binary(card, 0, certlen, 2, 0);

	/* Now set the certificate offset/len */
	path.index = 2;
	path.count = (certlen[1] << 8) + certlen[0];
	
	id.value[0] = 2;

	sc_pkcs15emu_add_cert(p15card,
				SC_PKCS15_TYPE_CERT_X509, authority,
				&path, &id, label, SC_PKCS15_CO_FLAG_MODIFIABLE);


	/* Get the CA certificate length */

	authority = 1;

	sc_format_path(infocamere_cacert_path, &path);

	if (sc_select_file(card, &path, NULL) < 0)
		{
		r = SC_ERROR_INTERNAL;
		goto failed;
		}

	sc_read_binary(card, 0, certlen, 2, 0);

	/* Now set the certificate offset/len */
	path.index = 2;
	path.count = (certlen[1] << 8) + certlen[0];

	id.value[0] = 3;

	sc_pkcs15emu_add_cert(p15card,
				SC_PKCS15_TYPE_CERT_X509, authority,
				&path, &id, calabel, SC_PKCS15_CO_FLAG_MODIFIABLE);

               
        flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
                SC_PKCS15_PIN_FLAG_INITIALIZED |
                SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
        
		/* add authntication PIN */

                sc_format_path("3F001111", &path);
                id.value[0] = 1;
                
		sc_pkcs15emu_add_pin(p15card, &id,
                                authPIN, &path, 0x95,
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
                                &path, 0x9B,
                                &auth_id, SC_PKCS15_CO_FLAG_PRIVATE);

		/* add non repudiation PIN */

                sc_format_path("3F00DF01", &path);
                id.value[0] = 2;
                
		sc_pkcs15emu_add_pin(p15card, &id,
                                nonrepPIN, &path, 0x99,
                                SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
                                5, 8, flags, -1, 0,
				SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE);


		/* add non repudiation private key */

                auth_id.value[0] = 2;
                sc_pkcs15emu_add_prkey(p15card, &id,
                                nonrepPRKEY,
                                SC_PKCS15_TYPE_PRKEY_RSA, 
                                1024, prkey_usage,
                                &path, 0x84,
                                &auth_id, SC_PKCS15_CO_FLAG_PRIVATE);


	/* return to MF */
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);

	return 0;

failed: 
	if (r != SC_ERROR_WRONG_CARD)
		sc_error(card->ctx, "Failed to initialize Infocamere SPK2.3 emulation: %s\n", sc_strerror(r));
        return r;

}

static int infocamere_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "STARCOS SPK 2.3"))
		return SC_ERROR_WRONG_CARD;
	return SC_SUCCESS;
}


int sc_pkcs15emu_infocamere_init_ex(sc_pkcs15_card_t *p15card,
				    sc_pkcs15emu_opt_t *opts)
{
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_infocamere_init(p15card);
	else {
		int r = infocamere_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_infocamere_init(p15card);
	}
}
