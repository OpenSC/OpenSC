/**
 * PKCS15 emulation layer for DNIe card.
 *
 * Copyright (C) 2011, Andre Zepezauer <andre.zepezauer@student.uni-halle.de> 
 * Copyright (C) 2011, Juan Antonio Martinez <jonsito@terra.es>
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

#include <stdlib.h>
#include <string.h>
#if HAVE_CONFIG_H
#include "config.h"
#endif
#include "libopensc/log.h"
#include "libopensc/asn1.h"
#include "libopensc/pkcs15.h"
#include "libopensc/cwa14890.h"
#include "libopensc/cwa-dnie.h"

/* Card driver related */
#if defined(ENABLE_OPENSSL) && defined(ENABLE_SM)

extern int dnie_match_card(struct sc_card *card);

/* Helper functions to get the pkcs15 stuff bound. */

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
	{"privateKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL,
	 NULL},
	{"publicKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL,
	 NULL},
	{"trustedPublicKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0,
	 NULL, NULL},
	{"secretKeys", SC_ASN1_STRUCT, SC_ASN1_CTX | 3 | SC_ASN1_CONS, 0, NULL,
	 NULL},
	{"certificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0,
	 NULL, NULL},
	{"trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS,
	 0, NULL, NULL},
	{"usefulCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 6 | SC_ASN1_CONS,
	 0, NULL, NULL},
	{"dataObjects", SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL,
	 NULL},
	{"authObjects", SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL,
	 NULL},
	{NULL, 0, 0, 0, NULL, NULL}
};

static const unsigned int odf_indexes[] = {
	SC_PKCS15_PRKDF,
	SC_PKCS15_PUKDF,
	SC_PKCS15_PUKDF_TRUSTED,
	SC_PKCS15_SKDF,
	SC_PKCS15_CDF,
	SC_PKCS15_CDF_TRUSTED,
	SC_PKCS15_CDF_USEFUL,
	SC_PKCS15_DODF,
	SC_PKCS15_AODF,
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

	sc_format_path("3F005015", &path_prefix);

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

static int sc_pkcs15emu_dnie_init(sc_pkcs15_card_t * p15card)
{
	u8 buf[1024];
	sc_pkcs15_df_t *df;
	sc_pkcs15_object_t *p15_obj;
	size_t len = sizeof(buf);
	int rv;
	struct sc_pkcs15_cert_info *p15_info = NULL;

	sc_context_t *ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);

	/* Check for correct card driver (i.e. iso7816) */
	if (strcmp(p15card->card->driver->short_name, "dnie") != 0)
		return SC_ERROR_WRONG_CARD;

	/* Check for correct card atr */
	if (dnie_match_card(p15card->card) != 1)
		return SC_ERROR_WRONG_CARD;

	/* The two keys inside DNIe 3.0 needs login before performing any signature.
	 * They are CKA_ALWAYS_AUTHENTICATE although they are not tagged like that.
	 * For the moment caching is forced if 3.0 is detected to make it work properly. */
	if (p15card->card->atr.value[15] >= DNIE_30_VERSION) {
		p15card->opts.use_pin_cache = 1;
		p15card->opts.pin_cache_counter = DNIE_30_CACHE_COUNTER;
		sc_log(ctx, "DNIe 3.0 detected - PKCS#15 options reset: use_file_cache=%d use_pin_cache=%d pin_cache_counter=%d pin_cache_ignore_user_consent=%d",
			p15card->opts.use_file_cache,
			p15card->opts.use_pin_cache,
			p15card->opts.pin_cache_counter,
			p15card->opts.pin_cache_ignore_user_consent);
        }

	/* Set root path of this application */
	p15card->file_app = sc_file_new();
	sc_format_path("3F00", &p15card->file_app->path);

	/* Load TokenInfo */
	rv = dump_ef(p15card->card, "3F0050155032", buf, &len);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Reading of EF.TOKENINFO failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}
	rv = sc_pkcs15_parse_tokeninfo(p15card->card->ctx, p15card->tokeninfo,
				       buf, len);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Decoding of EF.TOKENINFO failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}

	/* Only accept the original stuff */
	if (strcmp(p15card->tokeninfo->manufacturer_id, "DGP-FNMT") != 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	/* Load ODF */
	rv = dump_ef(p15card->card, "3F0050155031", buf, &len);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Reading of ODF failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}
	rv = parse_odf(buf, len, p15card);
	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Decoding of ODF failed: %d", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}

	/* Decode EF.PrKDF, EF.PuKDF and EF.CDF */
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
		if (df->type == SC_PKCS15_DODF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_log(ctx,
				       "Decoding of EF.DODF (%s) failed: %d",
				       sc_print_path(&df->path), rv);
			}
		}
	}

	/* Perform required fixes */
	p15_obj = p15card->obj_list;
	while (p15_obj != NULL) {
		/* Add missing 'auth_id' to private objects */
		if ((p15_obj->flags & SC_PKCS15_CO_FLAG_PRIVATE)
		    && (p15_obj->auth_id.len == 0)) {
			p15_obj->auth_id.value[0] = 0x01;
			p15_obj->auth_id.len = 1;
		};
		/* Set path count to -1 for public certificates, as they
		   will need to be decompressed and read_binary()'d, so
		   we make sure we end up reading the file->size and not the
		   path->count which is the compressed size on newer
                   DNIe versions  */
		if ( p15_obj->df && (p15_obj->df->type == SC_PKCS15_CDF) ) {
                    p15_info = (struct sc_pkcs15_cert_info *) p15_obj ->data;
		    p15_info ->path.count = -1;
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
	
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif

/****************************************/
/* public functions for in-built module */
/****************************************/
int sc_pkcs15emu_dnie_init_ex(sc_pkcs15_card_t * p15card,
			      struct sc_aid *aid,
			      sc_pkcs15emu_opt_t * opts)
{
	int r=SC_SUCCESS;
	sc_context_t *ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);

#if defined(ENABLE_OPENSSL) && defined(ENABLE_SM)
	/* check for proper card */
	r = dnie_match_card(p15card->card);
	if (r == 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
	/* ok: initialize and return */
	LOG_FUNC_RETURN(ctx, sc_pkcs15emu_dnie_init(p15card));
#else
	r = SC_ERROR_WRONG_CARD;
	LOG_FUNC_RETURN(ctx, r);
#endif
}
