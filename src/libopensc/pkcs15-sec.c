/*
 * sc-pkcs15-sec.c: PKCS#15 cryptography functions
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "sc.h"
#include "sc-pkcs15.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
		       const struct sc_pkcs15_prkey_info *prkey,
		       const u8 * in, int inlen, u8 *out, int outlen)
{
	int r;
	struct sc_security_env senv;
	
	
	senv.algorithm_ref = 0x02;
	senv.key_file_id = prkey->file_id;
	senv.signature = 0;
	senv.key_ref = prkey->key_reference;
	
	r = sc_select_file(p15card->card, &p15card->file_app,
			   &p15card->file_app.path, SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;
	r = sc_restore_security_env(p15card->card, 0); /* empty SE */
	if (r)
		return r;
	r = sc_set_security_env(p15card->card, &senv);
	if (r)
		return r;
	r = sc_decipher(p15card->card, in, inlen, out, outlen);
	if (r)
		return r;
	
	return 0;
}
