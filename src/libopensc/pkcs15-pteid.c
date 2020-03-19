/*
 * PKCS15 emulation layer for Portugal eID card.
 *
 * Copyright (C) 2016-2017, Nuno Goncalves <nunojpg@gmail.com>
 * Copyright (C) 2009, Joao Poupino <joao.poupino@ist.utl.pt>
 * Copyright (C) 2004, Martin Paljak <martin@martinpaljak.net>
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
 *
 * Based on the PKCS#15 emulation layer for EstEID card by Martin Paljak
 *
 */

/*
 * The card has a valid PKCS#15 file system. However, the private keys
 * are missing the SC_PKCS15_CO_FLAG_PRIVATE flag and this causes problems
 * with some applications (i.e. they don't work).
 *
 * The three main objectives of the emulation layer are:
 *
 * 1. Add the necessary SC_PKCS15_CO_FLAG_PRIVATE flag to private keys.
 * 2. Hide "superfluous" PKCS#15 objects, e.g. PUKs (the user can't use them).
 * 3. Improve usability by providing more descriptive names for the PINs, Keys, etc.
 *
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "pkcs15.h"

static int pteid_detect_card(struct sc_card *card);

static
int dump_ef(sc_card_t * card, const char *path, u8 * buf, size_t * buf_len)
{
	int rv;
	sc_file_t *file = NULL;
	sc_path_t scpath;
	sc_format_path(path, &scpath);
	rv = sc_select_file(card, &scpath, &file);
	if (rv < 0) {
		sc_file_free(file);
		return rv;
	}
	if (file->size > *buf_len) {
		sc_file_free(file);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	rv = sc_read_binary(card, 0, buf, file->size, 0);
	sc_file_free(file);
	if (rv < 0)
		return rv;
	*buf_len = rv;

	return SC_SUCCESS;
}

static const struct sc_asn1_entry c_asn1_odf[] = {
	{"privateKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL, NULL},
	{"publicKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL,	 NULL},
	{"trustedPublicKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0, NULL, NULL},
	{"secretKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 3 | SC_ASN1_CONS, 0, NULL,	 NULL},
	{"certificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0,	 NULL, NULL},
	{"trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS,	 0, NULL, NULL},
	{"usefulCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 6 | SC_ASN1_CONS,	 0, NULL, NULL},
	{"dataObjects", SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL,	 NULL},
	{"authObjects", SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL,	 NULL},
	{NULL, 0, 0, 0, NULL, NULL}
};

static const unsigned int odf_indexes[] = {
	SC_PKCS15_PRKDF,		//0
	SC_PKCS15_PUKDF,		//1
	SC_PKCS15_PUKDF_TRUSTED,	//2
	SC_PKCS15_SKDF,			//3
	SC_PKCS15_CDF,			//4
	SC_PKCS15_CDF_TRUSTED,		//5
	SC_PKCS15_CDF_USEFUL,		//6
	SC_PKCS15_DODF,			//7
	SC_PKCS15_AODF,			//8
};

static
int parse_odf(const u8 * buf, size_t buflen, struct sc_pkcs15_card *p15card)
{
	const u8 *p = buf;
	size_t left = buflen;
	int r, i, type;
	sc_path_t path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{"path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0,
		 &path, NULL},
		{NULL, 0, 0, 0, NULL, NULL}
	};
	struct sc_asn1_entry asn1_odf[10];

	sc_path_t path_prefix;

	sc_format_path("3F004F00", &path_prefix);

	sc_copy_asn1_entry(c_asn1_odf, asn1_odf);
	for (i = 0; asn1_odf[i].name != NULL; i++)
		sc_format_asn1_entry(asn1_odf + i, asn1_obj_or_path, NULL, 0);
	while (left > 0) {
		r = sc_asn1_decode_choice(p15card->card->ctx, asn1_odf, p, left,
					  &p, &left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r < 0)
			return r;
		type = r;
		r = sc_pkcs15_make_absolute_path(&path_prefix, &path);
		if (r < 0)
			return r;
		r = sc_pkcs15_add_df(p15card, odf_indexes[type], &path);
		if (r)
			return r;
	}
	return 0;
}

static int sc_pkcs15emu_pteid_init(sc_pkcs15_card_t * p15card)
{
	u8 buf[1024];
	sc_pkcs15_df_t *df;
	sc_pkcs15_object_t *p15_obj;
	sc_path_t path;
	struct sc_file *file = NULL;
	size_t len;
	int rv;
	int i;

	sc_context_t *ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);

	/* Check for correct card atr */
	if (pteid_detect_card(p15card->card) != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;

	sc_log(p15card->card->ctx, "Selecting application DF");
	sc_format_path("4F00", &path);
	rv = sc_select_file(p15card->card, &path, &file);
	if (rv != SC_SUCCESS || !file)
		return SC_ERROR_INTERNAL;
	/* set the application DF */
	sc_file_free(p15card->file_app);
	p15card->file_app = file;

	/* Load TokenInfo */
	len = sizeof(buf);
	rv = dump_ef(p15card->card, "4F005032", buf, &len);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Reading of EF.TOKENINFO failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}
	memset(p15card->tokeninfo, 0, sizeof(*p15card->tokeninfo));
	rv = sc_pkcs15_parse_tokeninfo(p15card->card->ctx, p15card->tokeninfo,
				       buf, len);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Decoding of EF.TOKENINFO failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}

	p15card->tokeninfo->flags |= SC_PKCS15_TOKEN_PRN_GENERATION
				  | SC_PKCS15_TOKEN_EID_COMPLIANT
				  | SC_PKCS15_TOKEN_READONLY;

	/* Load ODF */
	len = sizeof(buf);
	rv = dump_ef(p15card->card, "4F005031", buf, &len);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Reading of ODF failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}
	rv = parse_odf(buf, len, p15card);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Decoding of ODF failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}

	/* Decode EF.PrKDF, EF.PuKDF, EF.CDF and EF.AODF */
	for (df = p15card->df_list; df != NULL; df = df->next) {
		if (df->type == SC_PKCS15_PRKDF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_log(ctx,
				       "Decoding of EF.PrKDF (%s) failed: %d",
				       sc_print_path(&df->path), rv);
			}
		}
		if (df->type == SC_PKCS15_PUKDF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_log(ctx,
				       "Decoding of EF.PuKDF (%s) failed: %d",
				       sc_print_path(&df->path), rv);
			}
		}
		if (df->type == SC_PKCS15_CDF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_log(ctx,
				       "Decoding of EF.CDF (%s) failed: %d",
				       sc_print_path(&df->path), rv);
			}
		}
		if (df->type == SC_PKCS15_AODF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_log(ctx,
				       "Decoding of EF.AODF (%s) failed: %d",
				       sc_print_path(&df->path), rv);
			}
		}
	}

	p15_obj = p15card->obj_list;
	while (p15_obj != NULL) {
		if ( p15_obj->df && (p15_obj->df->type == SC_PKCS15_PRKDF) ) {
			struct sc_pkcs15_prkey_info *prkey_info = (sc_pkcs15_prkey_info_t *) p15_obj->data;
			prkey_info->access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
					| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
					| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
					| SC_PKCS15_PRKEY_ACCESS_LOCAL;
			p15_obj->flags = SC_PKCS15_CO_FLAG_PRIVATE;
		}


		if ( p15_obj->df && (p15_obj->df->type == SC_PKCS15_AODF) ) {
			static const char *pteid_pin_names[3] = {
			    "Auth PIN",
			    "Sign PIN",
			    "Address PIN"
			};

			struct sc_pin_cmd_data pin_cmd_data;
			struct sc_pkcs15_auth_info *pin_info = (sc_pkcs15_auth_info_t *) p15_obj->data;

			strlcpy(p15_obj->label, pteid_pin_names[pin_info->auth_id.value[0]-1], sizeof(p15_obj->label));

			pin_info->attrs.pin.flags |= SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
			pin_info->tries_left = -1;
			pin_info->max_tries = 3;
			pin_info->auth_method = SC_AC_CHV;

			memset(&pin_cmd_data, 0, sizeof(pin_cmd_data));
			pin_cmd_data.cmd = SC_PIN_CMD_GET_INFO;
			pin_cmd_data.pin_type = pin_info->attrs.pin.type;
			pin_cmd_data.pin_reference = pin_info->attrs.pin.reference;
			rv = sc_pin_cmd(p15card->card, &pin_cmd_data, NULL);
			if (rv == SC_SUCCESS) {
				pin_info->tries_left = pin_cmd_data.pin1.tries_left;
				pin_info->logged_in = pin_cmd_data.pin1.logged_in;
			}
		}
		/* Remove found public keys as cannot be read_binary()'d */
		if ( p15_obj->df && (p15_obj->df->type == SC_PKCS15_PUKDF) ) {
			sc_pkcs15_object_t *puk = p15_obj;
			p15_obj = p15_obj->next;
			sc_pkcs15_remove_object(p15card, puk);
			sc_pkcs15_free_object(puk);
		} else {
			p15_obj = p15_obj->next;
		}
	}

	/* Add data objects */
	for (i = 0; i < 5; i++) {
		static const char *object_labels[5] = {
			"Trace",
			"Citizen Data",
			"Citizen Address Data",
			"SOd",
			"Citizen Notepad",
		};
		static const char *object_authids[5] = {NULL, NULL, "3", NULL, NULL};
		static const char *object_paths[5] = {
			"3f000003",
			"3f005f00ef02",
			"3f005f00ef05",
			"3f005f00ef06",
			"3f005f00ef07",
		};
		static const int object_flags[5] = {
			0,
			0,
			SC_PKCS15_CO_FLAG_PRIVATE,
			0,
			0,
		};
		struct sc_pkcs15_data_info obj_info;
		struct sc_pkcs15_object obj_obj;

		memset(&obj_info, 0, sizeof(obj_info));
		memset(&obj_obj, 0, sizeof(obj_obj));

		sc_format_path(object_paths[i], &obj_info.path);
		strlcpy(obj_info.app_label, object_labels[i], SC_PKCS15_MAX_LABEL_SIZE);
		if (object_authids[i] != NULL)
			sc_pkcs15_format_id(object_authids[i], &obj_obj.auth_id);
		strlcpy(obj_obj.label, object_labels[i], SC_PKCS15_MAX_LABEL_SIZE);
		obj_obj.flags = object_flags[i];

		rv = sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_DATA_OBJECT, &obj_obj, &obj_info);
		if (rv != SC_SUCCESS){
			sc_log(ctx, "Object add failed: %d", rv);
			break;
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int pteid_detect_card(struct sc_card *card)
{
	if (card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID)
		return SC_SUCCESS;
	return SC_ERROR_WRONG_CARD;
}

int sc_pkcs15emu_pteid_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	int r=SC_SUCCESS;
	sc_context_t *ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);

	/* check for proper card */
	r = pteid_detect_card(p15card->card);
	if (r == SC_ERROR_WRONG_CARD)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
	/* ok: initialize and return */
	LOG_FUNC_RETURN(ctx, sc_pkcs15emu_pteid_init(p15card));
}
