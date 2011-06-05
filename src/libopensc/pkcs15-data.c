/*
 * pkcs15-data.c: PKCS #15 data object functions
 *
 * Copyright (C) 2002  Danny De Cock <daniel.decock@postbox.be>
 *
 * This source file was inspired by pkcs15-cert.c.
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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "internal.h"
#include "asn1.h"
#include "pkcs15.h"

static const struct sc_asn1_entry     c_asn1_data_object[] = {
        { "dataObject", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
        { NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15_read_data_object(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_data_info *info,
			       struct sc_pkcs15_data **data_object_out)
{
	int r;
	struct sc_pkcs15_data *data_object;
	u8 *data = NULL;
	size_t len;
	
	if (p15card == NULL || info == NULL || data_object_out == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = sc_pkcs15_read_file(p15card, &info->path, &data, &len);
	if (r)
		return r;
	data_object = malloc(sizeof(struct sc_pkcs15_data));
	if (data_object == NULL) {
		free(data);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memset(data_object, 0, sizeof(struct sc_pkcs15_data));
	
	data_object->data = data;
	data_object->data_len = len;
	*data_object_out = data_object;
	return 0;
}

static const struct sc_asn1_entry c_asn1_data[] = {
	{ "data", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_com_data_attr[] = {
	{ "appName", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "appOID", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_type_data_attr[] = {
	{ "path", SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15_decode_dodf_entry(struct sc_pkcs15_card *p15card,
			       struct sc_pkcs15_object *obj,
			       const u8 ** buf, size_t *buflen)
{
        sc_context_t *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info info;
	struct sc_asn1_entry	asn1_com_data_attr[3],
				asn1_type_data_attr[2],
				asn1_data[2];
	struct sc_asn1_pkcs15_object data_obj = { obj, asn1_com_data_attr, NULL,
					     asn1_type_data_attr };
	size_t label_len = sizeof(info.app_label);
	int r;

	sc_copy_asn1_entry(c_asn1_com_data_attr, asn1_com_data_attr);
	sc_copy_asn1_entry(c_asn1_type_data_attr, asn1_type_data_attr);
	sc_copy_asn1_entry(c_asn1_data, asn1_data);
	
	sc_format_asn1_entry(asn1_com_data_attr + 0, &info.app_label, &label_len, 0);
	sc_format_asn1_entry(asn1_com_data_attr + 1, &info.app_oid, NULL, 0);
	sc_format_asn1_entry(asn1_type_data_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_data + 0, &data_obj, NULL, 0);

	/* Fill in defaults */
	memset(&info, 0, sizeof(info));
	info.app_oid.value[0] = -1;

	r = sc_asn1_decode(ctx, asn1_data, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "ASN.1 decoding failed");

	if (!p15card->app || !p15card->app->ddo.aid.len)   {
		r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &info.path);
		if (r < 0)
			return r;
	}
	else   {
		info.path.aid = p15card->app->ddo.aid;
	}

	obj->type = SC_PKCS15_TYPE_DATA_OBJECT;
	obj->data = malloc(sizeof(info));
	if (obj->data == NULL)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}

int sc_pkcs15_encode_dodf_entry(sc_context_t *ctx,
			       const struct sc_pkcs15_object *obj,
			       u8 **buf, size_t *bufsize)
{
	struct sc_asn1_entry	asn1_com_data_attr[4],
				asn1_type_data_attr[2],
				asn1_data[2];
	struct sc_pkcs15_data_info *info;
	struct sc_asn1_pkcs15_object data_obj = { (struct sc_pkcs15_object *) obj,
							asn1_com_data_attr, NULL,
							asn1_type_data_attr };
	size_t label_len;

	info = (struct sc_pkcs15_data_info *) obj->data;
	label_len = strlen(info->app_label);

	sc_copy_asn1_entry(c_asn1_com_data_attr, asn1_com_data_attr);
	sc_copy_asn1_entry(c_asn1_type_data_attr, asn1_type_data_attr);
	sc_copy_asn1_entry(c_asn1_data, asn1_data);
	
	if (label_len) {
		sc_format_asn1_entry(asn1_com_data_attr + 0,
				&info->app_label, &label_len, 1);
	}
	if (info->app_oid.value[0] != -1) {
		sc_format_asn1_entry(asn1_com_data_attr + 1,
				&info->app_oid, NULL, 1);
	}
	sc_format_asn1_entry(asn1_type_data_attr + 0, &info->path, NULL, 1);
	sc_format_asn1_entry(asn1_data + 0, &data_obj, NULL, 1);

	return sc_asn1_encode(ctx, asn1_data, buf, bufsize);
}

void sc_pkcs15_free_data_object(struct sc_pkcs15_data *data_object)
{
	if (data_object == NULL)
		return;

	free(data_object->data);
	free(data_object);
}

void sc_pkcs15_free_data_info(sc_pkcs15_data_info_t *data)
{
	free(data);
}
