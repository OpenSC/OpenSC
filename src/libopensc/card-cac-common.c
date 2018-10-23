/*
 * card-cac-common.c: Code shared among CAC1 and CAC2 drivers
 *
 * Copyright (C) 2018, Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "internal.h"
#include "iso7816.h"
#include "card-cac-common.h"

/* default certificate labels for the CAC card */
const char *cac_labels[MAX_CAC_SLOTS] = {
	"CAC ID Certificate",
	"CAC Email Signature Certificate",
	"CAC Email Encryption Certificate",
	"CAC Cert 4",
	"CAC Cert 5",
	"CAC Cert 6",
	"CAC Cert 7",
	"CAC Cert 8",
	"CAC Cert 9",
	"CAC Cert 10",
	"CAC Cert 11",
	"CAC Cert 12",
	"CAC Cert 13",
	"CAC Cert 14",
	"CAC Cert 15",
	"CAC Cert 16"
};

const char *get_cac_label(int index)
{
	if (index < 0 || index >= MAX_CAC_SLOTS)
		return NULL;

	return cac_labels[index];
}

static int cac_list_compare_path(const void *a, const void *b)
{
	if (a == NULL || b == NULL)
		return 1;
	return memcmp( &((cac_object_t *) a)->path,
		&((cac_object_t *) b)->path, sizeof(sc_path_t));
}

/* For SimCList autocopy, we need to know the size of the data elements */
static size_t cac_list_meter(const void *el) {
	return sizeof(cac_object_t);
}

cac_private_data_t *cac_new_private_data(void)
{
	cac_private_data_t *priv;

	priv = calloc(1, sizeof(cac_private_data_t));
	if (priv == NULL)
		return NULL;

	/* Initialize PKI Applets list */
	if (list_init(&priv->pki_list) != 0 ||
	    list_attributes_comparator(&priv->pki_list, cac_list_compare_path) != 0 ||
	    list_attributes_copy(&priv->pki_list, cac_list_meter, 1) != 0) {
		cac_free_private_data(priv);
		return NULL;
	}

	/* Initialize General Applets List */
	if (list_init(&priv->general_list) != 0 ||
	    list_attributes_comparator(&priv->general_list, cac_list_compare_path) != 0 ||
	    list_attributes_copy(&priv->general_list, cac_list_meter, 1) != 0) {
		cac_free_private_data(priv);
		return NULL;
	}

	return priv;
}

void cac_free_private_data(cac_private_data_t *priv)
{
	free(priv->cac_id);
	free(priv->cache_buf);
	free(priv->aca_path);
	list_destroy(&priv->pki_list);
	list_destroy(&priv->general_list);
	free(priv);
	return;
}

int cac_add_object_to_list(list_t *list, const cac_object_t *object)
{
	if (list_append(list, object) < 0)
		return SC_ERROR_UNKNOWN;
	return SC_SUCCESS;
}

