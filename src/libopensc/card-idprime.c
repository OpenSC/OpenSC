/*
 * card-idprime.c: Support for Gemalto IDPrime smart cards
 *
 * Copyright (c) 2019 Red Hat, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "internal.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "cardctl.h"
#include "pkcs15.h"

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations idprime_ops;
static struct sc_card_driver idprime_drv = {
	"Gemalto IDPrime",
	"idprime",
	&idprime_ops,
	NULL, 0, NULL
};

/* This ATR says, there is no EF.DIR nor EF.ATR so ISO discovery mechanisms
 * are not useful here */
static const struct sc_atr_table idprime_atrs[] = {
	/* known ATRs for IDPrime 3810:
	 * 3b:7f:96:00:00:80:31:80:65:b0:84:41:3d:f6:12:0f:fe:82:90:00    Jakuje/xhanulik
	 */
	{ "3b:7f:96:00:00:80:31:80:65:b0:84:41:3d:f6:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:ff:ff:ff",
	  "Gemalto IDPrime 3810",
	  SC_CARD_TYPE_IDPRIME_3810, 0, NULL },
	/* known ATRs for IDPrime 930:
	 * 3b:7f:96:00:00:80:31:80:65:b0:84:56:51:10:12:0f:fe:82:90:00    Jakuje/xhanulik
	 */
	{ "3b:7f:96:00:00:80:31:80:65:b0:84:56:51:10:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:ff:ff:ff",
	  "Gemalto IDPrime 830",
	  SC_CARD_TYPE_IDPRIME_830, 0, NULL },
	/* known ATRs for IDPrime 930:
	 * 3b:7f:96:00:00:80:31:80:65:b0:84:61:60:fb:12:0f:fd:82:90:00    Jakuje/xhanulik
	 */
	{ "3b:7f:96:00:00:80:31:80:65:b0:84:61:60:fb:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:ff:ff:ff",
	  "Gemalto IDPrime 930/3930",
	  SC_CARD_TYPE_IDPRIME_930, 0, NULL },
	/* known ATRs:
	 * 3b:ff:96:00:00:81:31:fe:43:80:31:80:65:b0:84:65:66:fb:12:01:78:82:90:00:85    metsma
	 */
	{ "3b:ff:96:00:00:81:31:fe:43:80:31:80:65:b0:84:65:66:fb:12:01:78:82:90:00:85",
	  "ff:ff:00:ff:ff:ff:ff:00:ff:ff:ff:ff:ff:ff:00:00:00:00:ff:ff:ff:ff:ff:ff:00",
	  "based Gemalto IDPrime 930 (eToken 5110+ FIPS)",
	  SC_CARD_TYPE_IDPRIME_930, 0, NULL },
	/* known ATR for IDPrime 940: Placing in front of the 940 as its mask overlaps this one!
	 * 3b:7f:96:00:00:80:31:80:65:b0:85:03:00:ef:12:0f:fe:82:90:00   msetina
	 */
	{ "3b:7f:96:00:00:80:31:80:65:b0:85:03:00:ef:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:ff:ff:ff",
	  "Gemalto IDPrime 840",
	  SC_CARD_TYPE_IDPRIME_840, 0, NULL },
	/* known ATR for IDPrime 940:
	 * 3b:7f:96:00:00:80:31:80:65:b0:85:59:56:fb:12:0f:fe:82:90:00    Jakuje/xhanulik, msetina, kirichkov
	 */
	{ "3b:7f:96:00:00:80:31:80:65:b0:85:59:56:fb:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:00:00:00:ff:00:00:ff:ff:ff",
	  "Gemalto IDPrime 940",
	  SC_CARD_TYPE_IDPRIME_940, 0, NULL },
	/* Known ATRs:
	 * 3b:7f:96:00:00:80:31:80:65:b0:85:05:00:39:12:0f:fe:82:90:00    vbonamy
	 */
	{ "3b:7f:96:00:00:80:31:80:65:b0:85:05:00:39:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:ff:ff:ff",
	  "Gemalto IDPrime 940C",
	  SC_CARD_TYPE_IDPRIME_940, 0, NULL },
	/* Known ATRs for IDPrime 940 (eToken 5110)
	 * 3b:ff:96:00:00:81:31:fe:43:80:31:80:65:b0:85:59:56:fb:12:0f:fe:82:90:00:00    metsma, jurajsarinay
	 */
	{ "3b:ff:96:00:00:81:31:fe:43:80:31:80:65:b0:85:59:56:fb:12:0f:fe:82:90:00:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:00:00:ff:ff:ff:ff:ff:ff:00",
	  "Gemalto IDPrime MD 940 (eToken 5110)",
	  SC_CARD_TYPE_IDPRIME_940, 0, NULL },
	{ "3b:7f:96:00:00:80:31:80:65:b0:84:41:3d:f6:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:00:00:00:00:ff:00:00:ff:ff:ff",
	  "Gemalto IDPrime MD 8840, 3840, 3810, 840, 830 and MD 940 Cards",
	  SC_CARD_TYPE_IDPRIME_GENERIC, 0, NULL },
	/* Known ATRs: Overlaps partially with 930 and 940
	 * 3b:ff:96:00:00:81:31:80:43:80:31:80:65:b0:85:03:00:ef:12:0f:fe:82:90:00:66    metsma
	 */
	{ "3b:ff:96:00:00:81:31:80:43:80:31:80:65:b0:85:03:00:ef:12:0f:fe:82:90:00:66",
	  "ff:ff:00:ff:ff:ff:ff:00:ff:ff:ff:ff:ff:ff:00:00:00:00:ff:ff:ff:ff:ff:ff:00",
	  "Gemalto IDPrime MD 8840, 3840, 3810, 840 and 830 Cards (eToken)",
	  SC_CARD_TYPE_IDPRIME_GENERIC, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static const sc_path_t idprime_path = {
	"", 0,
	0, 0, SC_PATH_TYPE_DF_NAME,
	{ "\xA0\x00\x00\x00\x18\x80\x00\x00\x00\x06\x62", 11 }
};

/* data structures to store meta data about IDPrime objects */
typedef struct idprime_object {
	int fd;
	int key_reference;
	int valid_key_ref;
	u8 df[2];
	unsigned short length;
	int pin_index;
} idprime_object_t;

/*
 * IDPrime Container structure
 * Simplification of auxiliary data from aux-data.c
 */
#define MAX_CONTAINER_NAME_LEN 39
#define CONTAINER_OBJ_LEN 86
typedef struct idprime_container {
	uint8_t index;							/* Index of the container */
	char guid[MAX_CONTAINER_NAME_LEN + 1];	/* Container name */
} idprime_container_t;

/*
 * IDPrime key reference structure
 */
#define KEYREF_OBJ_LEN 8
typedef struct idprime_keyref {
	uint8_t index;					/* Index of the key reference */
	uint8_t pin_index;				/* Index of the auth pin used for accessing key */
	int key_reference;	/* Key reference used for accessing key */
} idprime_keyref_t;

/*
 * IDPrime private data per card state
 */
typedef struct idprime_private_data {
	u8 *cache_buf;				/* cached version of the currently selected file */
	size_t cache_buf_len;			/* length of the cached selected file */
	int cached;				/* is the cached selected file valid */
	size_t file_size;			/* this is real file size since IDPrime is quite strict about lengths */
	list_t pki_list;			/* list of pki containers */
	idprime_object_t *pki_current;		/* current pki object _ctl function */
	int tinfo_present;			/* Token Info Label object is present*/
	u8 tinfo_df[2];				/* DF of object with Token Info Label */
	unsigned long current_op;		/* current operation set by idprime_set_security_env */
	list_t containers;			/* list of private key containers */
	list_t keyrefmap;			/* list of key references for private keys */
} idprime_private_data_t;

/* For SimCList autocopy, we need to know the size of the data elements */
static size_t idprime_list_meter(const void *el) {
	return sizeof(idprime_object_t);
}

static size_t idprime_container_list_meter(const void *el) {
	return sizeof(idprime_container_t);
}

static size_t idprime_keyref_list_meter(const void *el) {
	return sizeof(idprime_keyref_t);
}

static int idprime_add_container_to_list(list_t *list, const idprime_container_t *container)
{
	if (list_append(list, container) < 0)
		return SC_ERROR_INTERNAL;
	return SC_SUCCESS;
}

static int idprime_container_list_seeker(const void *el, const void *key)
{
	const idprime_container_t *container = (idprime_container_t *)el;

	if ((el == NULL) || (key == NULL))
		return 0;
	if (container->index == *(uint8_t *)key)
		return 1;
	return 0;
}

static int idprime_add_keyref_to_list(list_t *list, const idprime_keyref_t *keyref)
{
	if (list_append(list, keyref) < 0)
		return SC_ERROR_INTERNAL;
	return SC_SUCCESS;
}

static int idprime_keyref_list_seeker(const void *el, const void *key)
{
	const idprime_keyref_t *keyref = (idprime_keyref_t *)el;

	if ((el == NULL) || (key == NULL))
		return 0;
	if (keyref->index == *(uint8_t *)key)
		return 1;
	return 0;
}

void idprime_free_private_data(idprime_private_data_t *priv)
{
	free(priv->cache_buf);
	list_destroy(&priv->pki_list);
	list_destroy(&priv->containers);
	list_destroy(&priv->keyrefmap);
	free(priv);
	return;
}

idprime_private_data_t *idprime_new_private_data(void)
{
	idprime_private_data_t *priv;

	priv = calloc(1, sizeof(idprime_private_data_t));
	if (priv == NULL)
		return NULL;

	/* Initialize PKI Applets list */
	if (list_init(&priv->pki_list) != 0 ||
	    list_attributes_copy(&priv->pki_list, idprime_list_meter, 1) != 0) {
		idprime_free_private_data(priv);
		return NULL;
	}

	/* Initialize container list */
	if (list_init(&priv->containers) != 0 ||
	    list_attributes_copy(&priv->containers, idprime_container_list_meter, 1) != 0 ||
	    list_attributes_seeker(&priv->containers, idprime_container_list_seeker) != 0) {
		idprime_free_private_data(priv);
		return NULL;
	}

	/* Initialize keyref list */
	if (list_init(&priv->keyrefmap) != 0 ||
	    list_attributes_copy(&priv->keyrefmap, idprime_keyref_list_meter, 1) != 0 ||
	    list_attributes_seeker(&priv->keyrefmap, idprime_keyref_list_seeker) != 0) {
		idprime_free_private_data(priv);
		return NULL;
	}
	return priv;
}

int idprime_add_object_to_list(list_t *list, const idprime_object_t *object)
{
	if (list_append(list, object) < 0)
		return SC_ERROR_INTERNAL;
	return SC_SUCCESS;
}

/* This selects main IDPrime AID which is used for communication with
 * the card */
static int idprime_select_idprime(sc_card_t *card)
{
	return iso_ops->select_file(card, &idprime_path, NULL);
}

/* Select file by string path */
static int idprime_select_file_by_path(sc_card_t *card, const char *str_path)
{
	int r;
	sc_file_t *file = NULL;
	sc_path_t index_path;

	/* First, we need to make sure the IDPrime AID is selected */
	r = idprime_select_idprime(card);
	if (r != SC_SUCCESS) {
		LOG_FUNC_RETURN(card->ctx, r);
	}

	/* Returns FCI with expected length of data */
	sc_format_path(str_path, &index_path);
	r = iso_ops->select_file(card, &index_path, &file);

	if (r != SC_SUCCESS) {
		LOG_FUNC_RETURN(card->ctx, r);
	}
	/* Ignore too large files */
	if (file->size > MAX_FILE_SIZE) {
		r = SC_ERROR_INVALID_DATA;
	} else {
		r = (int)file->size;
	}
	sc_file_free(file);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int idprime_process_containermap(sc_card_t *card, idprime_private_data_t *priv, int length)
{
	u8 *buf = NULL;
	int r = SC_ERROR_OUT_OF_MEMORY;
	int i;
	uint8_t max_entries, container_index;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	buf = malloc(length);
	if (buf == NULL) {
		goto done;
	}

	r = 0;
	do {
		/* Read at most CONTAINER_OBJ_LEN bytes */
		int read_length = length - r > CONTAINER_OBJ_LEN ? CONTAINER_OBJ_LEN : length - r;
		if (length == r) {
			r = SC_ERROR_NOT_ENOUGH_MEMORY;
			goto done;
		}
		const int got = iso_ops->read_binary(card, r, buf + r, read_length, 0);
		if (got < 1) {
			r = SC_ERROR_WRONG_LENGTH;
			goto done;
		}

		r += got;
		/* Try to read chunks of container size and stop when last container looks empty */
		container_index = r > CONTAINER_OBJ_LEN ? (r / CONTAINER_OBJ_LEN - 1) * CONTAINER_OBJ_LEN : 0;
	} while(length - r > 0 && buf[container_index] != 0);
	max_entries = r / CONTAINER_OBJ_LEN;

	for (i = 0; i < max_entries; i++) {
		u8 *start = &buf[i * CONTAINER_OBJ_LEN];
		idprime_container_t new_container = {0};
		if (start[0] == 0) /* Empty record */
			break;

		new_container.index = i;
		/* Reading UNICODE characters but skipping second byte */
		int j = 0;
		for (j = 0; j < MAX_CONTAINER_NAME_LEN; j++) {
			if (start[2 * j] == 0)
				break;
			new_container.guid[j] = start[2 * j];
		}

		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found container with index=%d, guid=%s", new_container.index, new_container.guid);

		if ((r = idprime_add_container_to_list(&priv->containers, &new_container)) != SC_SUCCESS) {
			goto done;
		}
	}

	r = SC_SUCCESS;
done:
	free(buf);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int idprime_process_keyrefmap(sc_card_t *card, idprime_private_data_t *priv, int length)
{
	u8 *buf = NULL;
	int r = SC_ERROR_OUT_OF_MEMORY;
	int i, max_entries;

	buf = malloc(length);
	if (buf == NULL) {
		goto done;
	}

	r = 0;
	do {
		if (length == r) {
			r = SC_ERROR_NOT_ENOUGH_MEMORY;
			goto done;
		}
		const int got = iso_ops->read_binary(card, r, buf + r, length - r, 0);
		if (got < 1) {
			r = SC_ERROR_WRONG_LENGTH;
			goto done;
		}

		r += got;
	} while(length - r > 0);
	max_entries = r / KEYREF_OBJ_LEN;

	for (i = 0; i < max_entries; i++) {
		idprime_keyref_t new_keyref;
		u8 *start = &buf[i * KEYREF_OBJ_LEN];
		if (start[0] == 0) /* Empty key ref */
			continue;

		new_keyref.index = start[2];
		new_keyref.key_reference = start[1];
		new_keyref.pin_index = start[7];
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found key reference with index=%d, pin=%d, keyref=%d", new_keyref.index, new_keyref.pin_index, new_keyref.key_reference);

		if ((r = idprime_add_keyref_to_list(&priv->keyrefmap, &new_keyref)) != SC_SUCCESS) {
			goto done;
		}
	}
	r = SC_SUCCESS;
done:
	free(buf);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int idprime_process_index(sc_card_t *card, idprime_private_data_t *priv, int length)
{
	u8 *buf = NULL;
	int r = SC_ERROR_OUT_OF_MEMORY;
	int i, num_entries;
	idprime_object_t new_object;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	buf = malloc(length);
	if (buf == NULL) {
		goto done;
	}

	r = 0;
	do {
		if (length == r) {
			r = SC_ERROR_NOT_ENOUGH_MEMORY;
			goto done;
		}
		const int got = iso_ops->read_binary(card, r, buf + r, length - r, 0);
		if (got < 1) {
			r = SC_ERROR_WRONG_LENGTH;
			goto done;
		}
		/* First byte shows the number of entries, each of them 21 bytes long */
		num_entries = buf[0];
		r += got;
	} while(r < num_entries * 21 + 1);

	new_object.fd = 0;
	for (i = 0; i < num_entries; i++) {
		u8 *start = &buf[i*21+1];

		/* First two bytes specify the object DF */
		new_object.df[0] = start[0];
		new_object.df[1] = start[1];
		/* Second two bytes refer to the object size */
		new_object.length = bebytes2ushort(&start[2]);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "df=%s, len=%u",
			sc_dump_hex(new_object.df, sizeof(new_object.df)), new_object.length);
		/* in minidriver, mscp/kxcNN or kscNN lists certificates */
		if (((memcmp(&start[4], "ksc", 3) == 0) || memcmp(&start[4], "kxc", 3) == 0)
			&& (memcmp(&start[12], "mscp", 5) == 0)) {
			uint8_t cert_id = 0;
			idprime_container_t *container = NULL;

			if (start[7] >= '0' && start[7] <= '9' && start[8] >= '0' && start[8] <= '9') {
				cert_id = (start[7] - '0') * 10 + start[8] - '0';
			}
			new_object.fd++;
			new_object.key_reference = -1;
			new_object.valid_key_ref = 0;
			new_object.pin_index = 1;

			container = (idprime_container_t *) list_seek(&priv->containers, &cert_id);
			if (!container) {
				/* Container map missing container with certificate ID */
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "No corresponding container with private key found for certificate with id=%d", cert_id);
				if (card->type != SC_CARD_TYPE_IDPRIME_940) {
					/* For cards other than the 940, we don't know how to recognize
					certificates missing keys other than to check
					that there is a corresponding entry in the container map.*/
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Adding certificate with fd=%d", new_object.fd);
					idprime_add_object_to_list(&priv->pki_list, &new_object);
					continue;
				}
			}

			switch (card->type) {
			case SC_CARD_TYPE_IDPRIME_3810:
				new_object.key_reference = 0x31 + cert_id;
				break;
			case SC_CARD_TYPE_IDPRIME_830:
				new_object.key_reference = 0x41 + cert_id;
				break;
			case SC_CARD_TYPE_IDPRIME_930:
				new_object.key_reference = 0x11 + cert_id * 2;
				break;
			case SC_CARD_TYPE_IDPRIME_940: {
					idprime_keyref_t *keyref = (idprime_keyref_t *) list_seek(&priv->keyrefmap, &cert_id);
					if (!keyref) {
						/* Key reference file does not contain record of the key for given certificate */
						sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "No corresponding key reference found for certificate with id=%d", cert_id);
						sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Adding certificate with fd=%d", new_object.fd);
						idprime_add_object_to_list(&priv->pki_list, &new_object);
						continue;
					}
					new_object.key_reference = keyref->key_reference;
					new_object.pin_index = keyref->pin_index;
					break;
				}
			case SC_CARD_TYPE_IDPRIME_840:
				new_object.key_reference = 0xf7 + cert_id;
				break;
			default:
				new_object.key_reference = 0x56 + cert_id;
				break;
			}
			new_object.valid_key_ref = 1;
			if (container != NULL) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found certificate with fd=%d, key_ref=%d corresponding to container \"%s\"",
					new_object.fd, new_object.key_reference, container->guid);
			} else {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found certificate with fd=%d, key_ref=%d without corresponding container",
					new_object.fd, new_object.key_reference);
			}

			idprime_add_object_to_list(&priv->pki_list, &new_object);

		/* This looks like non-standard extension listing pkcs11 token info label in my card */
		} else if ((memcmp(&start[4], "tinfo", 6) == 0) && (memcmp(&start[12], "p11", 4) == 0)) {
			memcpy(priv->tinfo_df, new_object.df, sizeof(priv->tinfo_df));
			priv->tinfo_present = 1;
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found p11/tinfo object");
		} else if ((memcmp(&start[4], "cmapfile", 8) == 0) && (memcmp(&start[12], "mscp", 4) == 0)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found mscp/cmapfile object %s",
					(start[0] == 02 && start[1] == 04 ? "(already processed)" : "(in non-standard path!)"));
		} else if (memcmp(&start[4], "cardapps", 8) == 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found cardapps object");
		} else if (memcmp(&start[4], "cardid", 6) == 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found cardid object");
		} else if (memcmp(&start[4], "cardcf", 6) == 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found cardcf object");
		}
	}

	r = SC_SUCCESS;
done:
	free(buf);
	LOG_FUNC_RETURN(card->ctx, r);
}

/* CPLC has 42 bytes, but we get it with 3B header */
#define CPLC_LENGTH 45
static int idprime_init(sc_card_t *card)
{
	int r;
	unsigned long flags, ext_flags;
	idprime_private_data_t *priv = NULL;
	struct sc_apdu apdu;
	u8 rbuf[CPLC_LENGTH];
	size_t rbuflen = sizeof(rbuf);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* We need to differentiate the OS version since they behave slightly differently */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xCA, 0x9F, 0x7F);
	apdu.resp = rbuf;
	apdu.resplen = rbuflen;
	apdu.le = rbuflen;
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS && apdu.resplen == CPLC_LENGTH) {
		/* We are interested in the OS release level here */
		switch (rbuf[11]) {
		case 0x01:
			sc_log(card->ctx, "Detected IDPrime applet version 1");
			break;
		case 0x02:
			sc_log(card->ctx, "Detected IDPrime applet version 2");
			break;
		case 0x03:
			sc_log(card->ctx, "Detected IDPrime applet version 3");
			break;
		case 0x04:
			sc_log(card->ctx, "Detected IDPrime applet version 4");
			break;
		default:
			sc_log(card->ctx, "Unknown OS version received: %d", rbuf[11]);
			break;
		}
	} else {
		sc_log(card->ctx, "Failed to get CPLC data or invalid length returned, "
			"err=%d, len=%"SC_FORMAT_LEN_SIZE_T"u",
			r, apdu.resplen);
	}

	/* Proprietary data -- Applet version */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xCA, 0xDF, 0x30);
	apdu.resp = rbuf;
	apdu.resplen = rbuflen;
	apdu.le = rbuflen;
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS && apdu.resplen >= 10) {
		/* Ber-TLV encoded */
		if (rbuf[0] == 0xDF && rbuf[1] == 0x30 && rbuf[2] == apdu.resplen - 3) {
			sc_log(card->ctx, "IDPrime Java Applet version %.*s", (int)apdu.resplen - 3, rbuf + 3);
		}
	}

	priv = idprime_new_private_data();
	if (!priv) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	/* Select and process container file */
	r = idprime_select_file_by_path(card, "0204");;
	if (r <= 0) {
		idprime_free_private_data(priv);
		if (r == 0)
			r = SC_ERROR_INVALID_DATA;
		LOG_FUNC_RETURN(card->ctx, r);
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Container file found");

	r = idprime_process_containermap(card, priv, r);
	if (r != SC_SUCCESS) {
		idprime_free_private_data(priv);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	if (card->type == SC_CARD_TYPE_IDPRIME_940) {
		if ((r = idprime_select_file_by_path(card, "0005")) <= 0) {
			idprime_free_private_data(priv);
			if (r == 0)
				r = SC_ERROR_INVALID_DATA;
			LOG_FUNC_RETURN(card->ctx, r);
		}

		if ((r = idprime_process_keyrefmap(card, priv, r)) != SC_SUCCESS) {
			idprime_free_private_data(priv);
			LOG_FUNC_RETURN(card->ctx, r);
		}
	}

	/* Select and process the index file */
	r = idprime_select_file_by_path(card, "0101");
	if (r <= 0) {
		idprime_free_private_data(priv);
		if (r == 0)
			r = SC_ERROR_INVALID_DATA;
		LOG_FUNC_RETURN(card->ctx, r);
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Index file found");

	r = idprime_process_index(card, priv, r);
	if (r != SC_SUCCESS) {
		idprime_free_private_data(priv);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	card->drv_data = priv;

	switch (card->type) {
	case SC_CARD_TYPE_IDPRIME_3810:
		card->name = "Gemalto IDPrime 3810";
		break;
	case SC_CARD_TYPE_IDPRIME_830:
		card->name = "Gemalto IDPrime MD 830";
		break;
	case SC_CARD_TYPE_IDPRIME_930:
		card->name = "Gemalto IDPrime 930/3930";
		break;
	case SC_CARD_TYPE_IDPRIME_940:
		card->name = "Gemalto IDPrime 940";
		break;
	case SC_CARD_TYPE_IDPRIME_840:
		card->name = "Gemalto IDPrime MD 840";
		break;
	case SC_CARD_TYPE_IDPRIME_GENERIC:
	default:
		card->name = "Gemalto IDPrime (generic)";
		break;
	}
	card->cla = 0x00;

	/* Set up algorithm info for RSA. */
	flags = SC_ALGORITHM_RSA_PAD_PKCS1
		| SC_ALGORITHM_RSA_PAD_PSS
		| SC_ALGORITHM_RSA_PAD_OAEP
		/* SHA-1 mechanisms are not allowed in the card I have */
		| (SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_RSA_HASH_SHA512)
		| (SC_ALGORITHM_MGF1_SHA256 | SC_ALGORITHM_MGF1_SHA384 | SC_ALGORITHM_MGF1_SHA512)
		;

	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	if (card->type == SC_CARD_TYPE_IDPRIME_930
	    || card->type == SC_CARD_TYPE_IDPRIME_940) {
		_sc_card_add_rsa_alg(card, 4096, flags, 0);
	}
	if (card->type == SC_CARD_TYPE_IDPRIME_930 ||
			card->type == SC_CARD_TYPE_IDPRIME_940 ||
			card->type == SC_CARD_TYPE_IDPRIME_840) {
		/* Set up algorithm info for EC */
		flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
		ext_flags = SC_ALGORITHM_EXT_EC_F_P
			| SC_ALGORITHM_EXT_EC_ECPARAMETERS
			| SC_ALGORITHM_EXT_EC_NAMEDCURVE
			| SC_ALGORITHM_EXT_EC_UNCOMPRESES
			;
		_sc_card_add_ec_alg(card, 256, flags, ext_flags, NULL);
		_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);
		_sc_card_add_ec_alg(card, 521, flags, ext_flags, NULL);
	}

	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;

	card->caps |= SC_CARD_CAP_RNG;

	LOG_FUNC_RETURN(card->ctx, 0);
}

static int idprime_finish(sc_card_t *card)
{
	idprime_private_data_t * priv = card->drv_data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (priv) {
		idprime_free_private_data(priv);
	}
	return SC_SUCCESS;
}

static int idprime_match_card(sc_card_t *card)
{
	int i, r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	i = _sc_match_atr(card, idprime_atrs, &card->type);
	if (i < 0)
		return 0;

	r = idprime_select_file_by_path(card, "0101");
	LOG_FUNC_RETURN(card->ctx, r > 0);
}

/* initialize getting a list and return the number of elements in the list */
static int idprime_get_init_and_get_count(list_t *list, idprime_object_t **entry, int *countp)
{
	if (countp == NULL || entry == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	*countp = list_size(list);
	list_iterator_start(list);
	*entry = list_iterator_next(list);
	return SC_SUCCESS;
}

/* finalize the list iterator */
static int idprime_final_iterator(list_t *list)
{
	list_iterator_stop(list);
	return SC_SUCCESS;
}

/* fill in the prkey_info for the current object on the list and advance to the next object */
static int idprime_fill_prkey_info(list_t *list, idprime_object_t **entry, sc_pkcs15_prkey_info_t *prkey_info)
{
	memset(prkey_info, 0, sizeof(sc_pkcs15_prkey_info_t));
	if (*entry == NULL) {
		return SC_ERROR_FILE_END_REACHED;
	}

	prkey_info->path.len = sizeof((*entry)->df);
	memcpy(prkey_info->path.value, (*entry)->df, sizeof((*entry)->df));
	prkey_info->path.type = SC_PATH_TYPE_FILE_ID;
	/* Do not specify the length -- it will be read from the FCI */
	prkey_info->path.count = -1;

	/* TODO figure out the IDs as the original driver? */
	prkey_info->id.value[0] = ((*entry)->fd >> 8) & 0xff;
	prkey_info->id.value[1] = (*entry)->fd & 0xff;
	prkey_info->id.len = 2;
	if ((*entry)->valid_key_ref)
		prkey_info->key_reference = (*entry)->key_reference;
	else
		prkey_info->key_reference = -1;
	*entry = list_iterator_next(list);
	return SC_SUCCESS;
}

/* get PIN id of the current object on the list */
static int idprime_get_pin_id(list_t *list, idprime_object_t **entry, const char **pin_id)
{
	if (pin_id == NULL || entry == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	*pin_id = "11"; // normal PIN id
	if ((*entry)->pin_index != 1)
		*pin_id = "83"; // signature PIN id
	return SC_SUCCESS;
}

#define IDPRIME_CARDID_LEN 16

static int idprime_get_serial(sc_card_t* card, sc_serial_number_t* serial)
{
	sc_path_t cardid_path;
	sc_file_t *file = NULL;
	u8 buf[IDPRIME_CARDID_LEN];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	/* XXX this is assumed to be cardid for windows. It can be read from the index file */
	sc_format_path("0201", &cardid_path);
	r = iso_ops->select_file(card, &cardid_path, &file);
	if (r != SC_SUCCESS || file->size != IDPRIME_CARDID_LEN) { /* The cardid is always 16 B */
		sc_file_free(file);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_LENGTH);
	}

	r = iso_ops->read_binary(card, 0, buf, file->size, 0);
	sc_file_free(file);
	if (r < 1) {
		LOG_FUNC_RETURN(card->ctx, r);
	} else if (r != IDPRIME_CARDID_LEN) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_DATA);
	}

	serial->len = MIN(IDPRIME_CARDID_LEN, SC_MAX_SERIALNR);
	memcpy(serial->value, buf, serial->len);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int idprime_get_token_name(sc_card_t* card, char** tname)
{
	idprime_private_data_t * priv = card->drv_data;
	sc_path_t tinfo_path = {"\x00\x00", 2, 0, 0, SC_PATH_TYPE_PATH, {"", 0}};
	sc_file_t *file = NULL;
	u8 buf[2];
	char *name;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (tname == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (!priv->tinfo_present) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	memcpy(tinfo_path.value, priv->tinfo_df, 2);
	r = iso_ops->select_file(card, &tinfo_path, &file);
	if (r != SC_SUCCESS || file->size == 0) {
		sc_file_free(file);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	/* First two bytes lists 0x01, the second indicates length */
	r = iso_ops->read_binary(card, 0, buf, 2, 0);
	if (r < 2 || buf[1] > file->size) { /* make sure we do not overrun */
		sc_file_free(file);
		LOG_FUNC_RETURN(card->ctx, r);
	}
	sc_file_free(file);

	name = malloc(buf[1]);
	if (name == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	r = iso_ops->read_binary(card, 2, (unsigned char *)name, buf[1], 0);
	if (r < 1) {
		free(name);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	if (name[r-1] != '\0') {
		name[r-1] = '\0';
	}
	*tname = name;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int idprime_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	idprime_private_data_t * priv = card->drv_data;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "cmd=%ld ptr=%p", cmd, ptr);

	if (priv == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	switch (cmd) {
		case SC_CARDCTL_GET_SERIALNR:
			return idprime_get_serial(card, (sc_serial_number_t *) ptr);
		case SC_CARDCTL_IDPRIME_GET_TOKEN_NAME:
			return idprime_get_token_name(card, (char **) ptr);
		case SC_CARDCTL_IDPRIME_INIT_GET_OBJECTS:
			return idprime_get_init_and_get_count(&priv->pki_list, &priv->pki_current,
				(int *)ptr);
		case SC_CARDCTL_IDPRIME_GET_NEXT_OBJECT:
			return idprime_fill_prkey_info(&priv->pki_list, &priv->pki_current,
				(sc_pkcs15_prkey_info_t *)ptr);
		case SC_CARDCTL_IDPRIME_FINAL_GET_OBJECTS:
			return idprime_final_iterator(&priv->pki_list);
		case SC_CARDCTL_IDPRIME_GET_PIN_ID:
			return idprime_get_pin_id(&priv->pki_list, &priv->pki_current,
				(const char **)ptr);
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

#define HEADER_LEN 4

static int idprime_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	int r;
	idprime_private_data_t * priv = card->drv_data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* forget any old cached values */
	if (priv->cache_buf) {
		free(priv->cache_buf);
		priv->cache_buf = NULL;
	}
	priv->cache_buf_len = 0;
	priv->cached = 0;

	r = iso_ops->select_file(card, in_path, file_out);
	if (r == SC_SUCCESS && file_out != NULL) {
 	 	/* Cache the real file size for the caching read_binary() */
 	 	priv->file_size = (*file_out)->size;
	}
	/* Return the exit code of the select command */
	return r;
}

// used to read existing certificates
static int idprime_read_binary(sc_card_t *card, unsigned int offset,
	unsigned char *buf, size_t count, unsigned long *flags)
{
	struct idprime_private_data *priv = card->drv_data;
	int r = 0;
	int size;
	size_t sz;

	sc_log(card->ctx, "called; %"SC_FORMAT_LEN_SIZE_T"u bytes at offset %d",
		count, offset);

	if (!priv->cached && offset == 0) {
		/* Read what was reported by FCI from select command */
		size_t left = priv->file_size;
		unsigned read = 0;

		// this function is called to read and uncompress the certificate
		u8 buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
		u8 *data_buffer = buffer;
		if (sizeof(buffer) < count || sizeof(buffer) < priv->file_size) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
		}
		while (left > 0) {
			r = iso_ops->read_binary(card, read, buffer + read, priv->file_size - read, flags);
			if (r <= 0) {
				LOG_FUNC_RETURN(card->ctx, r);
			}
			left -= r;
			read += r;
		}
		if (read < 4 || read != priv->file_size) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_DATA);
		}
		if (buffer[0] == 1 && buffer[1] == 0) {
			/* Data will be decompressed later */
			data_buffer += 4;
			sz = priv->file_size - 4;
			if (flags)
				*flags |= SC_FILE_FLAG_COMPRESSED_AUTO;
		} else {
			sz = priv->file_size;
		}
		priv->cache_buf = malloc(sz);
		if (priv->cache_buf == NULL) {
			return SC_ERROR_OUT_OF_MEMORY;
		}
		memcpy(priv->cache_buf, data_buffer, sz);
		priv->cache_buf_len = sz;
		priv->cached = 1;
	}
	if (offset >= priv->cache_buf_len) {
		return 0;
	}
	size = (int) MIN((priv->cache_buf_len - offset), count);
	memcpy(buf, priv->cache_buf + offset, size);
	return size;
}

static int
idprime_set_security_env(struct sc_card *card,
	const struct sc_security_env *env, int se_num)
{
	int r;
	struct sc_security_env new_env;
	idprime_private_data_t *priv = NULL;

	if (card == NULL || env == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	priv = card->drv_data;

	/* The card requires algorithm reference here */
	new_env = *env;
	new_env.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
	/* SHA-1 mechanisms are not allowed in the card I have available */
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_OAEP) {
			if (env->algorithm_flags & SC_ALGORITHM_MGF1_SHA1) {
				new_env.algorithm_ref = 0x1D;
			} else if (env->algorithm_flags & SC_ALGORITHM_MGF1_SHA256) {
				new_env.algorithm_ref = 0x4D;
			} else if (env->algorithm_flags & SC_ALGORITHM_MGF1_SHA384) {
				new_env.algorithm_ref = 0x5D;
			} else if (env->algorithm_flags & SC_ALGORITHM_MGF1_SHA512) {
				new_env.algorithm_ref = 0x6D;
			}
		} else { /* RSA-PKCS without hashing */
			new_env.algorithm_ref = 0x1A;
		}
		break;
	case SC_SEC_OPERATION_SIGN:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS) {
			if (env->algorithm_flags & SC_ALGORITHM_MGF1_SHA256) {
				new_env.algorithm_ref = 0x45;
			} else if (env->algorithm_flags & SC_ALGORITHM_MGF1_SHA384) {
				new_env.algorithm_ref = 0x55;
			} else if (env->algorithm_flags & SC_ALGORITHM_MGF1_SHA512) {
				new_env.algorithm_ref = 0x65;
			}
			priv->current_op = SC_ALGORITHM_RSA;
		} else if (env->algorithm_flags & (SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_PAD_OAEP)) {
			if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
				new_env.algorithm_ref = 0x42;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384) {
				new_env.algorithm_ref = 0x52;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) {
				new_env.algorithm_ref = 0x62;
			} else { /* RSA-PKCS without hashing */
				new_env.algorithm_ref = 0x02;
			}
			priv->current_op = SC_ALGORITHM_RSA;
		} else if (env->algorithm == SC_ALGORITHM_EC) {
			new_env.algorithm_ref = 0x44;
			priv->current_op = SC_ALGORITHM_EC;
		}
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	r = iso_ops->set_security_env(card,
		(const struct sc_security_env *) &new_env, se_num);

	LOG_FUNC_RETURN(card->ctx, r);
}

/* These are mostly ISO versions updated to IDPrime specifics */
static int
idprime_compute_signature(struct sc_card *card,
	const u8 * data, size_t datalen, u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 *p;
	u8 sbuf[128] = {0}; /* For SHA-512 we need 64 + 2 bytes */
	u8 rbuf[4096]; /* needs work. for 3072 keys, needs 384+2 or so */
	size_t rbuflen = sizeof(rbuf);
	idprime_private_data_t *priv = card->drv_data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* We should be signing hashes only so we should not reach this limit */
	if (datalen + 2 > sizeof(sbuf)) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	/* The data for ECDSA should be padded to the length of a multiple of 8 */
	size_t pad = 0;
	if (priv->current_op == SC_ALGORITHM_EC && datalen % 8 != 0) {
		pad = 8 - (datalen % 8);
		datalen += pad;
	}

	p = sbuf;
	*(p++) = 0x90;
	*(p++) = datalen;
	memcpy(p + pad, data, datalen - pad);
	p += datalen;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x90  Hash code
	 * P2:  0xA0  Input template for the computation of a hash-code (the template is hashed) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x90, 0xA0);
	apdu.resp = rbuf;
	apdu.resplen = rbuflen;
	apdu.le = datalen;

	apdu.data = sbuf;
	apdu.lc = p - sbuf;
	apdu.datalen = p - sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	/* This just returns the passed data (hash code) (for verification?) */
	if (apdu.resplen != datalen || memcmp(rbuf + pad, data, datalen - pad) != 0) {
		sc_log(card->ctx, "The initial APDU did not return the same data");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x2A, 0x9E, 0x9A);
	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = outlen;
	if (apdu.le > sc_get_max_recv_size(card)) {
		/* The lower layers will automatically do a GET RESPONSE, if possible.
		 * All other workarounds must be carried out by the upper layers. */
		apdu.le = sc_get_max_recv_size(card);
	}

	apdu.data = NULL;
	apdu.datalen = 0;
	apdu.lc = 0;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}

/* These are mostly ISO versions updated to IDPrime specifics */
static int
idprime_decipher(struct sc_card *card,
	const u8 * crgram, size_t crgram_len,
	u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 *sbuf = NULL;

	if (card == NULL || crgram == NULL || out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
		"IDPrime decipher: in-len %"SC_FORMAT_LEN_SIZE_T"u, out-len %"SC_FORMAT_LEN_SIZE_T"u",
		crgram_len, outlen);

	sbuf = malloc(crgram_len + 1);
	if (sbuf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x80, 0x86);
	apdu.resp    = out;
	apdu.resplen = outlen;
	apdu.le      = outlen;

	sbuf[0] = 0x81; /* padding indicator byte, 0x81 = Proprietary */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	if (apdu.lc > sc_get_max_send_size(card)) {
		/* The lower layers will automatically do chaining */
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
	}
	if (apdu.le > sc_get_max_recv_size(card)) {
		/* The lower layers will automatically do a GET RESPONSE, if possible.
		 * All other workarounds must be carried out by the upper layers. */
		apdu.le = sc_get_max_recv_size(card);
	}
	apdu.datalen = crgram_len + 1;

	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, crgram_len + 1);
	free(sbuf);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
	else
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int
idprime_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{
	u8 rbuf[16];
	size_t out_len;
	struct sc_apdu apdu;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (len <= 8) {
		/* official closed driver always calls this regardless the length */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x84, 0x00, 0x01);
		apdu.le = apdu.resplen = 8;
	} else {
		/* this was discovered accidentally - all 16 bytes seem random */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x84, 0x00, 0x00);
		apdu.le = apdu.resplen = 16;
	}
	apdu.resp = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "GET CHALLENGE failed");

	out_len = len < apdu.resplen ? len : apdu.resplen;
	memcpy(rnd, rbuf, out_len);

	LOG_FUNC_RETURN(card->ctx, (int) out_len);
}

static struct sc_card_driver * sc_get_driver(void)
{
	if (iso_ops == NULL) {
		iso_ops = sc_get_iso7816_driver()->ops;
	}

	idprime_ops = *iso_ops;
	idprime_ops.match_card = idprime_match_card;
	idprime_ops.init = idprime_init;
	idprime_ops.finish = idprime_finish;

	idprime_ops.read_binary = idprime_read_binary;
	idprime_ops.select_file = idprime_select_file;
	idprime_ops.card_ctl = idprime_card_ctl;
	idprime_ops.set_security_env = idprime_set_security_env;
	idprime_ops.compute_signature = idprime_compute_signature;
	idprime_ops.decipher = idprime_decipher;

	idprime_ops.get_challenge = idprime_get_challenge;

	return &idprime_drv;
}

struct sc_card_driver * sc_get_idprime_driver(void)
{
	return sc_get_driver();
}
