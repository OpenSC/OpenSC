/*
 * aux-data.c: Auxiliary data help functions
 *
 * Copyright (C) 2016 Viktor Tarasov <viktor.tarasov@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "internal.h"
#include "common/compat_strlcat.h"

#include <libopensc/errors.h>
#include <libopensc/types.h>
#include <libopensc/log.h>
#include <libopensc/aux-data.h>


int
sc_aux_data_allocate(struct sc_context *ctx, struct sc_auxiliary_data **dst, struct sc_auxiliary_data *src)
{
	int rv = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(ctx);

	if (!dst)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot allocate auxiliary data");

	if (*dst == NULL)   {
		*dst = calloc(1, sizeof(struct sc_auxiliary_data));
		if (*dst == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate aux. data");
	}

	if ((src == NULL) || (src->type == SC_AUX_DATA_TYPE_NO_DATA))
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	switch(src->type) {
	case SC_AUX_DATA_TYPE_MD_CMAP_RECORD:
		**dst = *src;
		rv = SC_SUCCESS;
		break;
	default:
		sc_log(ctx, "Invalid aux-data type %X", src->type);
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unknown aux-data type");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
sc_aux_data_set_md_guid(struct sc_context *ctx, struct sc_auxiliary_data *aux_data, char *guid)
{
	struct sc_md_cmap_record *rec;
	int rv = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(ctx);
	if (!aux_data || !guid || strlen(guid) > SC_MD_MAX_CONTAINER_NAME_LEN)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot set guid for MD container");

	switch(aux_data->type) {
	case SC_AUX_DATA_TYPE_NO_DATA:
		memset(aux_data, 0, sizeof(*aux_data));
		aux_data->type = SC_AUX_DATA_TYPE_MD_CMAP_RECORD;
		/* fallthrough */
	case SC_AUX_DATA_TYPE_MD_CMAP_RECORD:
		rec = &aux_data->data.cmap_record;
		memcpy(rec->guid, guid, strlen(guid));
		rec->guid_len = strlen(guid);
		sc_log(ctx, "set MD container GUID '%s'", aux_data->data.cmap_record.guid);
		rv = SC_SUCCESS;
		break;
	default:
		sc_log(ctx, "Invalid aux-data type %X", aux_data->type);
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unknown aux-data type");
	}

	LOG_FUNC_RETURN(ctx, rv);
	return rv;
}


int
sc_aux_data_set_md_flags(struct sc_context *ctx, struct sc_auxiliary_data *aux_data, unsigned char flags)
{
	int rv = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(ctx);
	if (!aux_data)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot set flags of MD container");

	switch(aux_data->type) {
	case SC_AUX_DATA_TYPE_NO_DATA:
		memset(aux_data, 0, sizeof(*aux_data));
		aux_data->type = SC_AUX_DATA_TYPE_MD_CMAP_RECORD;
		/* fallthrough */
	case SC_AUX_DATA_TYPE_MD_CMAP_RECORD:
		aux_data->data.cmap_record.flags = flags;
		sc_log(ctx, "set MD container flags '0x%X'", flags);
		rv = SC_SUCCESS;
		break;
	default:
		sc_log(ctx, "Invalid aux-data type %X", aux_data->type);
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unknown aux-data type");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
sc_aux_data_get_md_guid(struct sc_context *ctx, struct sc_auxiliary_data *aux_data,
		unsigned flags, unsigned char *out, size_t *out_size)
{
	struct sc_md_cmap_record *cmap_record = NULL;
	char guid[SC_MD_MAX_CONTAINER_NAME_LEN + 3];

	LOG_FUNC_CALLED(ctx);
	if(!aux_data || !out || !out_size)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	cmap_record = &aux_data->data.cmap_record;

	/* Ignore silently request of '{}' frame is output buffer is too small */
	if (!flags && *out_size < strlen((char *)cmap_record->guid) + 2)
		flags = 1;

	*guid = '\0';
	if (!flags)
		strncpy(guid, "{", sizeof guid);
	strlcat(guid, (char *)cmap_record->guid, sizeof(guid)-1);
	if (!flags)
		strlcat(guid, "}", sizeof(guid));

	if (*out_size < strlen(guid))   {
		sc_log(ctx,
		       "aux-data: buffer too small: out_size:%"SC_FORMAT_LEN_SIZE_T"u < guid-length:%"SC_FORMAT_LEN_SIZE_T"u",
		       *out_size, strlen(guid));
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}

	memset(out, 0, *out_size);
	memcpy(out, guid, strlen(guid));
	*out_size = strlen(guid);

	sc_log(ctx, "aux-data: returns guid '%s'", (char *)out);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_aux_data_get_md_flags(struct sc_context *ctx, struct sc_auxiliary_data *aux_data,
		unsigned char *flags)
{
	LOG_FUNC_CALLED(ctx);
	if(!aux_data || !flags)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	*flags = aux_data->data.cmap_record.flags;

	sc_log(ctx, "aux-data: returns flags '0x%X'", *flags);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


void
sc_aux_data_free(struct sc_auxiliary_data **data)
{
	if (data == NULL || *data == NULL)
		return;

	switch((*data)->type) {
	case SC_AUX_DATA_TYPE_MD_CMAP_RECORD:
		free(*data);
		break;
	default:
		break;
	}

	*data = NULL;
}

