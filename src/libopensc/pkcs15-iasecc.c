/*
 * PKCS15 emulation layer for IAS/ECC card.
 *
 * Copyright (C) 2016, Viktor Tarasov <viktor.tarasov@gmail.com>
 * Copyright (C) 2004, Bud P. Bruegger <bud@comune.grosseto.it>
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
#ifdef ENABLE_OPENSSL
#include <openssl/x509v3.h>
#endif

#include "internal.h"
#include "pkcs15.h"
#include "iasecc.h"
#include "aux-data.h"

#define IASECC_GEMALTO_MD_APPLICAITON_NAME "CSP"
#define IASECC_GEMALTO_MD_DEFAULT_CONT_LABEL "Default Key Container"

static int
_iasecc_md_update_keyinfo(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *dobj, int default_cont)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_object *prkey_object = NULL;
	struct sc_pkcs15_data *ddata = NULL;
	struct sc_pkcs15_id id;
	int rv, offs;
	unsigned flags;

	LOG_FUNC_CALLED(ctx);

	if (!dobj)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = sc_pkcs15_read_data_object(p15card, (struct sc_pkcs15_data_info *)dobj->data, &ddata);
	LOG_TEST_RET(ctx, rv, "Failed to read container DATA object data");

	offs = 0;
	rv = SC_ERROR_INVALID_DATA;
	if (*(ddata->data + offs++) != 0x01)   {
		sc_pkcs15_free_data_object(ddata);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}

	id.len = *(ddata->data + offs++);
	memcpy(id.value, ddata->data + offs, id.len);
	offs += (int) id.len;

	if (*(ddata->data + offs++) != 0x02)  {
		sc_pkcs15_free_data_object(ddata);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}
	if (*(ddata->data + offs++) != 0x01)  {
		sc_pkcs15_free_data_object(ddata);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}

	flags = *(ddata->data + offs);
	if (default_cont)
		flags |= SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER;

	sc_pkcs15_free_data_object(ddata);

	rv = sc_pkcs15_find_prkey_by_id(p15card, &id, &prkey_object);
	LOG_TEST_RET(ctx, rv, "Find related PrKey error");

	prkey_info = (struct sc_pkcs15_prkey_info *)prkey_object->data;
	if (prkey_info->aux_data == NULL)   {
		rv = sc_aux_data_allocate(ctx, &prkey_info->aux_data, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot allocate MD auxiliary data");
	}

	rv = sc_aux_data_set_md_guid(ctx, prkey_info->aux_data, dobj->label);
	LOG_TEST_RET(ctx, rv, "Cannot set MD CMAP Guid");

	rv = sc_aux_data_set_md_flags(ctx, prkey_info->aux_data, flags);
	LOG_TEST_RET(ctx, rv, "Cannot set MD CMAP record flags");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
_iasecc_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *dobjs[32];
	struct sc_pkcs15_data *default_guid = NULL;
	int rv, ii, count;

	LOG_FUNC_CALLED(ctx);

	if (!df)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_parse_df(p15card, df);
	LOG_TEST_RET(ctx, rv, "DF parse error");

	if (p15card->card->type != SC_CARD_TYPE_IASECC_GEMALTO)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (df->type != SC_PKCS15_PRKDF)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	sc_log(ctx, "parse of SC_PKCS15_PRKDF");

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, dobjs, sizeof(dobjs)/sizeof(dobjs[0]));
	LOG_TEST_RET(ctx, rv, "Cannot get DATA objects list");

	count = rv;
	for(ii=0; ii<count; ii++)   {
		struct sc_pkcs15_data_info *dinfo = (struct sc_pkcs15_data_info *)dobjs[ii]->data;

		if (strcmp(dinfo->app_label, IASECC_GEMALTO_MD_APPLICAITON_NAME))
			continue;

		if (!strcmp(dobjs[ii]->label, IASECC_GEMALTO_MD_DEFAULT_CONT_LABEL))   {
			rv = sc_pkcs15_read_data_object(p15card, (struct sc_pkcs15_data_info *)dobjs[ii]->data, &default_guid);
			LOG_TEST_RET(ctx, rv, "Failed to read 'default container' DATA object data");
			break;
		}
	}

	for(ii=0; ii<count; ii++)   {
		struct sc_pkcs15_data_info *dinfo = (struct sc_pkcs15_data_info *)dobjs[ii]->data;
		int default_cont = 0;

		if (strcmp(dinfo->app_label, IASECC_GEMALTO_MD_APPLICAITON_NAME))
			continue;

		if (!strcmp(dobjs[ii]->label, IASECC_GEMALTO_MD_DEFAULT_CONT_LABEL))
			continue;

		if (default_guid)
			if (strlen(dobjs[ii]->label) == default_guid->data_len)
				if (!memcmp(dobjs[ii]->label, default_guid->data, default_guid->data_len))
					default_cont = 1;

		rv = _iasecc_md_update_keyinfo(p15card, dobjs[ii], default_cont);
		LOG_TEST_RET(ctx, rv, "Cannot update key MD info");
	}

	sc_pkcs15_free_data_object(default_guid);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pkcs15emu_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type < SC_CARD_TYPE_IASECC_BASE)
		return SC_ERROR_WRONG_CARD;

	if (p15card->card->type > SC_CARD_TYPE_IASECC_BASE + 10)
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}


static int
sc_pkcs15emu_iasecc_init (struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15_bind_internal(p15card, aid);

	p15card->ops.parse_df = _iasecc_parse_df;

	LOG_FUNC_RETURN(ctx, rv);
}


int
sc_pkcs15emu_iasecc_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid, struct sc_pkcs15emu_opt *opts)
{
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_iasecc_init(p15card, aid);

	if (iasecc_pkcs15emu_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_iasecc_init(p15card, aid);
}
