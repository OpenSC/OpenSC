/*
 * pkcs15-default.c: Obsolete
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

#include "opensc-pkcs15.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if 0
static void format_path(struct sc_path *path, const char *str)
{
	int len = 0;
	u8 *p = path->value;

	while (str) {
		int byte;
		
		if (sscanf(str, "%02X", &byte) != 1)
			break;
		*p++ = byte;
		len++;
		str += 2;
	}
	path->len = len;
	return;
}

static void format_file_struct(struct sc_file *file, const char *path, int type)
{
	format_path(&file->path, path);
	file->type = type;
}

static void format_cert_struct(struct sc_pkcs15_cert_info *cert,
			       const char *label, const u8 *id,
			       int id_len, int CA, const char *path)
{
	strcpy(cert->com_attr.label, label);
	memcpy(cert->id.value, id, id_len);
	cert->id.len = id_len;
	cert->authority = CA;
	format_path(&cert->path, path);
}

static void format_prkey_struct(struct sc_pkcs15_prkey_info *prkey,
				const char *label, const u8 *id,
				int id_len, const u8 *pin_id,
				int pin_id_len, int usage, int access_flags,
				int mod_len, const char *file_id)
{
	strcpy(prkey->com_attr.label, label);
	memcpy(prkey->id.value, id, id_len);
	prkey->id.len = id_len;
	memcpy(prkey->com_attr.auth_id.value, pin_id, pin_id_len);
	prkey->com_attr.auth_id.len = pin_id_len;
	prkey->usage = usage;
	prkey->access_flags = access_flags;
	prkey->modulus_length = mod_len;
	format_path(&prkey->file_id, file_id);
}

static int fineid_pkcs15_defaults(struct sc_pkcs15_card *arg,
				  int type)
{
	struct sc_pkcs15_card *card = (struct sc_pkcs15_card *) arg;
	struct sc_pkcs15_pin_info *pin;

	if (card->label)
		free(card->label);
	switch (type) {
	case 1:
		card->label = strdup("FINEID S4-1");
		break;
	case 2:
		card->label = strdup("FINEID S4-2");
		break;
	}
	card->manufacturer_id = strdup("VRK-FINSIGN");
	card->flags = SC_PKCS15_CARD_FLAG_EID_COMPLIANT;
	card->version = 1;
	card->alg_info[0].reference = 0;
	card->alg_info[0].algorithm = 0;
	card->alg_info[0].supported_operations = 0xa2;
	
	format_file_struct(&card->file_app, "5015", 7); /* 7 = DF, 0 = EF */
	card->aodf_count = 1;
	format_file_struct(&card->file_aodf[0], "50154401", 0);
	format_file_struct(&card->file_prkdf, "50154402", 0);
	card->cdf_count = 3;
	format_file_struct(&card->file_cdf[0], "50154403", 0);
	format_file_struct(&card->file_cdf[1], "50154404", 0);
	format_file_struct(&card->file_cdf[2], "50154405", 0);
	format_file_struct(&card->file_dodf, "50154406", 0);
	format_file_struct(&card->file_odf, "50155031", 0);
	format_file_struct(&card->file_tokeninfo, "50155032", 0);
	format_file_struct(&card->file_dir, "2F00", 0);
	
	card->pin_count = 2;
	pin = &card->pin_info[0];
	strcpy(pin->com_attr.label, "perustunnusluku");
	pin->flags = 0x30;
	pin->type = 1;
	pin->min_length = 4;
	pin->stored_length = 8;
	pin->pad_char = 0;
	format_path(&pin->path, "3F00");
	pin->auth_id.value[0] = 0x01;
	pin->auth_id.len = 1;
	pin->magic = SC_PKCS15_PIN_MAGIC;

	pin = &card->pin_info[1];
	strcpy(pin->com_attr.label, "allekirjoitustunnusluku");
	pin->flags = 0x32;
	pin->type = 1;
	pin->min_length = 4;
	pin->stored_length = 8;
	pin->pad_char = 0;
	format_path(&pin->path, "5015");
	pin->auth_id.value[0] = 0x02;
	pin->auth_id.len = 1;
	pin->magic = SC_PKCS15_PIN_MAGIC;

	card->cert_count = 3;
	format_cert_struct(&card->cert_info[0], "todentamis- ja salausvarmenne", (const u8 *) "\x45", 1, 0, "50154331");
	format_cert_struct(&card->cert_info[1], "allekirjoitusvarmenne", (const u8 *) "\x46", 1, 0, "50154332");
	switch (type) {
	case 1:
		format_cert_struct(&card->cert_info[2], "FINSIGN CA for Citizen", (const u8 *) "\x47", 1, 1, "50154333");
		break;
	case 2:
		format_cert_struct(&card->cert_info[2], "Test CA for S4-2", (const u8 *) "\x47", 1, 1, "50154333");
		break;
	}

	card->prkey_count = 2;
	format_prkey_struct(&card->prkey_info[0], "todentamis- ja salausavain", (const u8 *) "\x45", 1, (const u8 *) "\x01", 1,
			    0x26, 0x1d, 1024, "4B01");
	format_prkey_struct(&card->prkey_info[1], "allekirjoitusavain", (const u8 *) "\x46", 1, (const u8 *) "\x02", 1,
			    0x200, 0x1d, 1024, "4B02");

	return 0;
}

const struct sc_pkcs15_defaults sc_pkcs15_card_table[] = {
	{ "61:2D:4F:0C:A0:00:00:00:63:50:4B:43:53:2D:31:35:50:0B:46:"
	  "49:4E:45:49:44:20:53:34:2D:31:51:04:3F:00:50:15:73:0A:06:"
	  "08:2A:81:76:84:05:04:01:01", fineid_pkcs15_defaults, 1 },
	{ "61:2C:4F:0C:A0:00:00:00:63:50:4B:43:53:2D:31:35:50:0B:46:"
	  "49:4E:45:49:44:20:53:34:2D:32:51:04:3F:00:50:15:73:09:06:"
	  "07:2A:81:76:84:05:03:01", fineid_pkcs15_defaults, 2 },
	{ NULL, NULL, 0 }
};
#endif
