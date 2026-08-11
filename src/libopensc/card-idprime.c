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

#include "asn1.h"
#include "cardctl.h"
#include "iso7816.h"
#include "pkcs15.h"
#include "sm/sm-idprime.h"

#ifdef ENABLE_OPENSSL
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#endif /* ENABLE_OPENSSL */

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
// clang-format off
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
	  "ff:ff:00:ff:ff:ff:ff:00:ff:ff:ff:ff:ff:ff:ff:00:00:00:ff:ff:ff:ff:ff:ff:00",
	  "based Gemalto IDPrime 930 (eToken 5110+ FIPS)",
	  SC_CARD_TYPE_IDPRIME_930_PLUS, 0, NULL },
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
	 * 3b:ff:96:00:00:81:31:fe:43:80:31:80:65:b0:85:59:56:fb:12:01:78:82:90:00:88    hardening
	 */
	{ "3b:ff:96:00:00:81:31:fe:43:80:31:80:65:b0:85:59:56:fb:12:0f:fe:82:90:00:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00:00:00:ff:f0:00:ff:ff:ff:00",
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
// clang-format on

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

	/* ECC Mutual Authentication / proprietary Secure Messaging state, mirroring
	 * the proprietary driver's idp_maType / idp_isFIPS / idp_isFullSM. This is
	 * detection only for now -- the SM channel itself is not implemented yet,
	 * see idprime_probe_ecc_ma() / idprime_get_ecc_full_sm(). */
	unsigned int ma_point_len; /* 0 if no MA reference key present, else EC point length (65/97/133) */
	unsigned int sm_key_len;   /* AES key length (bytes) the card expects once MA is used (16 or 32) */
	int is_fips;		   /* applet reports a FIPS-restricted operation mode */
	int fips_identify;	   /* 0 = not FIPS, 2/3 = the two FIPS applet variants seen in app_opt bits */
	int full_sm;		   /* mirrors idp_isFullSM: every APDU must be SM-wrapped */
	int sm_authenticated;	   /* mutual authentication succeeded -- SM channel is active.
				    * The card rejects re-selecting the IDPrime AID once we're
				    * already sitting authenticated in it, so once this is set
				    * idprime_select_idprime() must skip the re-select. */
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

/* Select a 2-byte file id under full SM. The generic iso7816_select_file()
 * (used for the non-SM path) requests the FCI back via a protected Le
 * (DO'97'), but the card rejects any SELECT command carrying that DO once
 * mutual-authenticated -- it responds with a bare, unprotected SW=6982
 * (i.e. it doesn't even attempt SM/MAC processing on the command). The
 * captured proprietary driver trace confirms SELECT is always sent as
 * Lc+data only (no Le at all) under this SM; the card still returns FCI in
 * the encrypted response regardless of the absence of a request Le. */
static int
idprime_sm_select_file_by_id(sc_card_t *card, const sc_path_t *path, sc_file_t **file_out)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	const u8 *buffer;
	unsigned int cla, tag;
	size_t buffer_len;
	sc_file_t *file;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x00);
	apdu.data = path->value;
	apdu.datalen = apdu.lc = path->len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, r);

	if (file_out == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (apdu.resplen < 2)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	switch (apdu.resp[0]) {
	case ISO7816_TAG_FCI:
	case ISO7816_TAG_FCP:
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *path;
		if (card->ops->process_fci == NULL) {
			sc_file_free(file);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
		}
		buffer = apdu.resp;
		r = sc_asn1_read_tag(&buffer, apdu.resplen, &cla, &tag, &buffer_len);
		if (r == SC_SUCCESS)
			card->ops->process_fci(card, file, buffer, buffer_len);
		*file_out = file;
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	return SC_SUCCESS;
}

/* This selects main IDPrime AID which is used for communication with
 * the card */
static int idprime_select_idprime(sc_card_t *card)
{
	idprime_private_data_t *priv = (idprime_private_data_t *)card->drv_data;

	/* Once mutual authentication has established the SM channel, the card
	 * is already sitting authenticated inside the IDPrime AID and rejects
	 * (SW=6982) a redundant re-select of the same AID. Skip it. */
	if (priv && priv->sm_authenticated)
		return SC_SUCCESS;

	return iso_ops->select_file(card, &idprime_path, NULL);
}

/* Select file by string path */
static int idprime_select_file_by_path(sc_card_t *card, const char *str_path)
{
	int r;
	sc_file_t *file = NULL;
	sc_path_t index_path;
	idprime_private_data_t *priv = (idprime_private_data_t *)card->drv_data;

	/* First, we need to make sure the IDPrime AID is selected */
	r = idprime_select_idprime(card);
	if (r != SC_SUCCESS) {
		LOG_FUNC_RETURN(card->ctx, r);
	}

	/* Returns FCI with expected length of data */
	sc_format_path(str_path, &index_path);
	if (priv && priv->sm_authenticated && index_path.len == 2)
		r = idprime_sm_select_file_by_id(card, &index_path, &file);
	else
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
			uint8_t key_index;
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
				/* Container map missing a container whose index matches the
				 * certificate's embedded 2-digit id. This is not on its own proof
				 * the certificate has no private key: the real driver's
				 * idp_getKeyId() (decompiled from libIDPrimeTokenEngine.so) derives
				 * the key reference from the container's own sequential index,
				 * discovered by iterating containers independently of certificates
				 * -- cert_id and container index are simply different numbers that
				 * only happen to coincide when a card's containers and certs were
				 * both created in matching order. Confirmed on a real FIPS
				 * 930_PLUS eToken with exactly one populated container (index 0)
				 * but a certificate whose embedded id is 10: the real driver still
				 * exposes a working private key on it, using key reference
				 * 0x31 + 0 (container index), not a formula involving cert_id=10.
				 * We can't replicate the real driver's independent container
				 * enumeration here, but when there is exactly one populated
				 * container and this certificate has none, pairing them is the
				 * only sensible choice and matches what was observed on real
				 * hardware. */
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "No corresponding container with private key found for certificate with id=%d", cert_id);
				if (list_size(&priv->containers) == 1) {
					container = (idprime_container_t *)list_get_at(&priv->containers, 0);
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Falling back to the single populated container \"%s\" (index=%d)",
							container->guid, container->index);
				}
			}
			/* Use the container's own index when available -- it is what the key
			 * reference formulas below are actually keyed on. When no container
			 * was found (or matched) at all, cert_id remains the closest thing we
			 * have to go on, matching this function's prior (pre-container-index)
			 * behavior for that edge case. */
			key_index = container ? container->index : cert_id;

			switch (card->type) {
			case SC_CARD_TYPE_IDPRIME_3810:
				new_object.key_reference = 0x31 + key_index;
				break;
			case SC_CARD_TYPE_IDPRIME_830:
				new_object.key_reference = 0x41 + key_index;
				break;
			case SC_CARD_TYPE_IDPRIME_930:
				new_object.key_reference = 0x11 + key_index * 2;
				break;
			case SC_CARD_TYPE_IDPRIME_930_PLUS:
				if (priv->full_sm) {
					/* Confirmed via a live gdb hook + decompile of idp_getKeyId()
					 * against a real FIPS/full-SM 930_PLUS eToken: this applet
					 * variant takes idp_getKeyId()'s older/simpler branch
					 * (container_index + 0x31), not the container_index*2 + 0x10
					 * scheme used below for the plain (non-SM) 930_PLUS path --
					 * the real driver picks between the two based on the
					 * applet's own version/isNet flags, which we don't
					 * replicate, so key it off priv->full_sm instead, since
					 * that's exactly the class of card where this was observed. */
					new_object.key_reference = 0x31 + key_index;
				} else {
					new_object.key_reference = 0x10 + key_index * 2;
				}
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
				new_object.key_reference = 0xf7 + key_index;
				break;
			default:
				new_object.key_reference = 0x56 + key_index;
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

/* Key reference of the ECC Mutual Authentication reference public key, as
 * used by the proprietary driver's GET DATA probe (idp_getEccMAKeys()). */
#define IDPRIME_ECC_MA_KEY_REF 2

/*
 * Recent IDPrime/eToken applets (FIPS-capable ones in particular) expose an
 * ECC public key under a dedicated key reference, retrievable with a plain
 * (non-SM) GET DATA. Its presence is what the proprietary driver uses to
 * decide whether a card supports its EC-based Mutual Authentication /
 * Secure Messaging channel (see idp_getEccMAKeys() in libIDPrimeTokenEngine.so).
 *
 * Older/non-FIPS applets simply don't have this key: priv->ma_point_len stays
 * 0 and the card keeps being driven exactly as today, in the clear.
 *
 * Cards that *do* have it get priv->ma_point_len/sm_key_len filled in for the
 * caller to inspect (see idprime_get_ecc_full_sm() below) -- the SM channel
 * itself is not implemented here yet.
 */
static int
idprime_probe_ecc_ma(sc_card_t *card, idprime_private_data_t *priv)
{
	/* GET DATA (INS 0xCB, P1=0x00 P2=0xFF) request body -- verified against
	 * a live capture of the proprietary driver's idp_getEccExponent() call
	 * (keyId=0x2 exponent=0x86 keyUsageTag=0xa4) on real hardware:
	 *   00 cb 00 ff 0a a4 03 83 01 02 7f 49 02 86 00 00
	 * i.e. TWO SIBLING top-level TLVs (each apduAddTag() call closes the
	 * previous top-level element rather than nesting into it):
	 *   A4 03 { 83 01 02 }        CRT for Authentication: key reference = IDPRIME_ECC_MA_KEY_REF
	 *   7F 49 02 { 86 00 }        Public Key template: request element 0x86 (the public point)
	 */
	static const u8 req[] = {
			0xA4, 0x03,
			0x83, 0x01, IDPRIME_ECC_MA_KEY_REF,
			0x7F, 0x49, 0x02,
			0x86, 0x00};
	struct sc_apdu apdu;
	u8 rbuf[256];
	const u8 *outer, *point;
	size_t outer_len, point_len;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0xCB, 0x00, 0xFF);
	apdu.data = req;
	apdu.datalen = apdu.lc = sizeof(req);
	apdu.resp = rbuf;
	apdu.resplen = apdu.le = sizeof(rbuf);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
		/* No such reference key on this applet -- older/non-FIPS card,
		 * nothing changes for it. */
		sc_log(card->ctx, "No ECC Mutual Authentication reference key found (SW=%02X%02X)",
				apdu.sw1, apdu.sw2);
		return SC_SUCCESS;
	}

	outer = sc_asn1_find_tag(card->ctx, apdu.resp, apdu.resplen, 0x7F49, &outer_len);
	if (outer == NULL) {
		sc_log(card->ctx, "Unexpected GET DATA response, missing 7F49 template");
		return SC_SUCCESS;
	}
	point = sc_asn1_find_tag(card->ctx, outer, outer_len, 0x86, &point_len);
	if (point == NULL) {
		sc_log(card->ctx, "Unexpected GET DATA response, missing public point");
		return SC_SUCCESS;
	}

	priv->ma_point_len = (unsigned int)point_len;
	/* The proprietary driver defaults to AES-128 session keys and only
	 * upgrades to AES-256 for specific newer applet versions (major==4,
	 * minor>4 and odd -- see idp_getEccMAKeys()). This driver doesn't parse
	 * the applet version into that form yet, so default to AES-128. */
	priv->sm_key_len = 16;

	sc_log(card->ctx, "Card exposes an ECC Mutual Authentication reference key "
			  "(%" SC_FORMAT_LEN_SIZE_T "u-byte point)",
			point_len);

	return SC_SUCCESS;
}

/*
 * Mirrors idp_getAppletFipsConfig()/idp_getAppletSpecificParams(): a plain
 * GET DATA (INS 0xCA, P1=0xDF P2=0x0A) returns a 6-byte application
 * parameters block under tag 0xDF0A; byte 5 (app_opt) encodes the FIPS mode.
 * Best-effort: older applets simply don't support this tag, which just
 * leaves priv->is_fips/fips_identify at their default (not FIPS).
 */
static void
idprime_get_applet_fips_config(sc_card_t *card, idprime_private_data_t *priv)
{
	struct sc_apdu apdu;
	u8 rbuf[16];
	const u8 *params;
	size_t params_len;
	u8 app_opt;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xCA, 0xDF, 0x0A);
	apdu.resp = rbuf;
	apdu.resplen = apdu.le = sizeof(rbuf);

	if (sc_transmit_apdu(card, &apdu) != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
		return;
	}

	params = sc_asn1_find_tag(card->ctx, apdu.resp, apdu.resplen, 0xDF0A, &params_len);
	if (params == NULL || params_len < 6) {
		sc_log(card->ctx, "Unexpected applet params response, missing DF0A template");
		return;
	}

	app_opt = params[5];
	if ((app_opt & 6) == 4) {
		priv->is_fips = 1;
		priv->fips_identify = 2;
	} else if ((app_opt & 6) == 6) {
		priv->is_fips = 1;
		priv->fips_identify = 3;
	}
	sc_log(card->ctx, "applet app_opt=0x%02X -> is_fips=%d fips_identify=%d",
			app_opt, priv->is_fips, priv->fips_identify);
}

/* True if the given short path selects successfully, i.e. the file exists. */
static int
idprime_file_exists(sc_card_t *card, const char *path)
{
	return idprime_select_file_by_path(card, path) >= 0;
}

/*
 * Mirrors idp_GetSMACInfo(): reads 32 bytes starting at offset 0 from
 * DF 0011 -- verified against a live capture of the proprietary driver
 * (idp_READ_BIN(tolerantSM=1, offset=0x0, size=0x20)). That file id -- like
 * DF 0010 used by idprime_get_ecc_full_sm() below -- was identified
 * empirically from a captured proprietary-driver trace
 * (idp_SELECT_FILE_BY_PATH(path=(11)/(10)) resolving directly to file ids
 * 0x0011/0x0010); they don't follow the "02xx"/"01xx" naming used elsewhere
 * in this driver.
 *
 * A missing file is not an error -- it's treated the same way the
 * proprietary driver treats E_FILE_NOT_FOUND here, as all-zero info.
 */
static void
idprime_get_sm_ac_info(sc_card_t *card, u8 *info_byte)
{
	u8 buf[32];
	int r;

	*info_byte = 0;

	if (idprime_select_file_by_path(card, "0011") < 0) {
		return;
	}
	r = iso_ops->read_binary(card, 0, buf, sizeof(buf), 0);
	if (r < 1) {
		return;
	}
	*info_byte = buf[0];
}

/*
 * Mirrors idp_getECCFullSM(): decide whether *every* APDU must be SM-wrapped
 * once ECC Mutual Authentication is available, using the on-card SMAC-info
 * file (DF 0011) combined with the "CTL" file (DF 0010) presence check
 * (idp_CheckCTL()). Client-side config overrides (MutualAuthType/FullSMMode
 * in eToken.conf) are intentionally not reproduced here -- this always
 * follows the on-card indication, which is what actually applies to the FIPS
 * card this was reverse engineered against.
 */
static void
idprime_get_ecc_full_sm(sc_card_t *card, idprime_private_data_t *priv)
{
	u8 info = 0;
	int ctl;

	idprime_get_sm_ac_info(card, &info);
	ctl = idprime_file_exists(card, "0010");

	if ((info & 0x0F) == 0) {
		priv->full_sm = ((info & 0xF0) != 0) && ctl;
	} else {
		priv->full_sm = ctl ? ((info & 0xF0) != 0) : 1;
	}

	sc_log(card->ctx, "SMAC info=0x%02X ctl=%d -> full_sm=%d", info, ctl, priv->full_sm);
}

#if defined(ENABLE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L

static const char *
idprime_ecc_ma_curve_name(unsigned int point_len)
{
	switch (point_len) {
	case 65:
		return "prime256v1";
	case 97:
		return "secp384r1";
	case 133:
		return "secp521r1";
	default:
		return NULL;
	}
}

/*
 * Static P-256 terminal identity, extracted from libIDPrimeTokenEngine.so's
 * idp_getEccMAKeys() (see ETOKEN_FIPS_SM_NOTES.md section 7): a CV
 * certificate and its corresponding ECDSA private key, both baked
 * identically into every install of the proprietary driver (confirmed by
 * the placeholder-looking CHR/terminal-ID 0123456789abcdef). Verified by
 * checking d*G reproduces the certificate's public key exactly.
 *
 * Only the P-256 variant has been extracted so far -- P-384/P-521 cards
 * (97/133-byte MA point) are not supported by the code below yet.
 */
static const u8 idprime_p256_ma_cert[205] = {
		0x7f,
		0x21,
		0x81,
		0xc9,
		0x7f,
		0x4e,
		0x81,
		0x82,
		0x5f,
		0x29,
		0x01,
		0x70,
		0x42,
		0x08,
		0x46,
		0x52,
		0x47,
		0x54,
		0x4f,
		0x00,
		0x02,
		0x02,
		0x5f,
		0x20,
		0x0c,
		0x00,
		0x00,
		0x00,
		0x00,
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0x5f,
		0x4c,
		0x07,
		0xa0,
		0x00,
		0x00,
		0x00,
		0x18,
		0x40,
		0x01,
		0x06,
		0x09,
		0x2b,
		0x81,
		0x22,
		0xf4,
		0x2a,
		0x02,
		0x04,
		0x04,
		0x04,
		0x7f,
		0x49,
		0x4d,
		0x06,
		0x08,
		0x2a,
		0x86,
		0x48,
		0xce,
		0x3d,
		0x03,
		0x01,
		0x07,
		0x86,
		0x41,
		0x04,
		0x30,
		0xe5,
		0x5f,
		0xe8,
		0xf8,
		0x56,
		0xda,
		0x1c,
		0x72,
		0xfe,
		0x3a,
		0xb1,
		0x29,
		0x10,
		0x86,
		0x8d,
		0xee,
		0x76,
		0x73,
		0xf6,
		0xcb,
		0x12,
		0xa9,
		0xd3,
		0x2b,
		0xe9,
		0xbb,
		0x86,
		0x83,
		0xd3,
		0x7e,
		0xff,
		0xb7,
		0x39,
		0x92,
		0x9a,
		0x34,
		0xa8,
		0x9a,
		0xdc,
		0x25,
		0x5f,
		0x5a,
		0xd2,
		0xe0,
		0xb0,
		0x7f,
		0xc0,
		0xf9,
		0x5e,
		0x7c,
		0xd8,
		0x52,
		0x5b,
		0x20,
		0x43,
		0xef,
		0xb5,
		0x0c,
		0x9b,
		0x78,
		0x8e,
		0x79,
		0x59,
		0x5f,
		0x37,
		0x40,
		0x4d,
		0xce,
		0xfe,
		0x61,
		0x35,
		0xfa,
		0x5a,
		0xa3,
		0xa8,
		0x8d,
		0xae,
		0x25,
		0x3d,
		0x6f,
		0x07,
		0x09,
		0x1e,
		0x6d,
		0x98,
		0x5e,
		0x28,
		0xc8,
		0xc3,
		0x22,
		0x74,
		0x21,
		0x9e,
		0xa5,
		0x84,
		0xaf,
		0xf5,
		0x81,
		0xef,
		0x01,
		0x0f,
		0x1b,
		0x53,
		0x6f,
		0xb1,
		0x86,
		0x25,
		0x2e,
		0xe8,
		0x1f,
		0x04,
		0x3a,
		0xa6,
		0x33,
		0x92,
		0x62,
		0x7e,
		0xe8,
		0x96,
		0x88,
		0x36,
		0xd5,
		0xd7,
		0x11,
		0x14,
		0x6e,
		0x86,
		0xa0,
		0xda,
		0xb4,
};

static const u8 idprime_p256_ma_privkey_d[32] = {
		0x50,
		0x75,
		0xa8,
		0xf6,
		0x68,
		0xeb,
		0x12,
		0xa0,
		0xde,
		0x9e,
		0x0e,
		0x30,
		0x59,
		0x3b,
		0x44,
		0x82,
		0x90,
		0x14,
		0x26,
		0x7b,
		0xe8,
		0x33,
		0x30,
		0xf4,
		0x64,
		0xb3,
		0x00,
		0xf1,
		0x17,
		0x7b,
		0xef,
		0xba,
};

static const u8 idprime_p256_ma_terminal_id[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

/*
 * NIST P-256 domain parameters (p || a || b || G-uncompressed || n, 193
 * bytes), hashed as part of the EXTERNAL AUTHENTICATE signature input
 * below. These are the well-known, public curve constants -- not anything
 * card- or session-specific.
 */
static const u8 idprime_p256_domain_params[193] = {
		0xff,
		0xff,
		0xff,
		0xff,
		0x00,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0x00,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xfc,
		0x5a,
		0xc6,
		0x35,
		0xd8,
		0xaa,
		0x3a,
		0x93,
		0xe7,
		0xb3,
		0xeb,
		0xbd,
		0x55,
		0x76,
		0x98,
		0x86,
		0xbc,
		0x65,
		0x1d,
		0x06,
		0xb0,
		0xcc,
		0x53,
		0xb0,
		0xf6,
		0x3b,
		0xce,
		0x3c,
		0x3e,
		0x27,
		0xd2,
		0x60,
		0x4b,
		0x04,
		0x6b,
		0x17,
		0xd1,
		0xf2,
		0xe1,
		0x2c,
		0x42,
		0x47,
		0xf8,
		0xbc,
		0xe6,
		0xe5,
		0x63,
		0xa4,
		0x40,
		0xf2,
		0x77,
		0x03,
		0x7d,
		0x81,
		0x2d,
		0xeb,
		0x33,
		0xa0,
		0xf4,
		0xa1,
		0x39,
		0x45,
		0xd8,
		0x98,
		0xc2,
		0x96,
		0x4f,
		0xe3,
		0x42,
		0xe2,
		0xfe,
		0x1a,
		0x7f,
		0x9b,
		0x8e,
		0xe7,
		0xeb,
		0x4a,
		0x7c,
		0x0f,
		0x9e,
		0x16,
		0x2b,
		0xce,
		0x33,
		0x57,
		0x6b,
		0x31,
		0x5e,
		0xce,
		0xcb,
		0xb6,
		0x40,
		0x68,
		0x37,
		0xbf,
		0x51,
		0xf5,
		0xff,
		0xff,
		0xff,
		0xff,
		0x00,
		0x00,
		0x00,
		0x00,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xff,
		0xbc,
		0xe6,
		0xfa,
		0xad,
		0xa7,
		0x17,
		0x9e,
		0x84,
		0xf3,
		0xb9,
		0xca,
		0xc2,
		0xfc,
		0x63,
		0x25,
		0x51,
};

/*
 * Performs the EC key-agreement half of the proprietary "MA" (Mutual
 * Authentication) handshake: generates an ephemeral EC keypair on the same
 * curve as the card's MA reference key (see idprime_probe_ecc_ma() above),
 * exchanges public points with the card via MSE:SET AT + GENERAL
 * AUTHENTICATE, and computes the raw ECDH shared secret Z. See
 * ETOKEN_FIPS_SM_NOTES.md section 3.1 for the reverse-engineered protocol
 * this implements.
 *
 * IMPORTANT: this is only HALF of the handshake. The proprietary driver
 * immediately follows this key agreement with a certificate-based mutual
 * authentication (PSO:VERIFY CERTIFICATE / EXTERNAL AUTHENTICATE /
 * GET CHALLENGE / INTERNAL AUTHENTICATE) that is NOT implemented here.
 * Without it, a raw ECDH exchange like this one has no protection against a
 * man in the middle -- callers MUST NOT start Secure Messaging (i.e. call
 * idprime_sm_start()) with the Z this returns.
 */
static int
idprime_ecc_ma_key_agreement(sc_card_t *card, idprime_private_data_t *priv,
		u8 **z_out, size_t *zlen_out,
		u8 host_x_out[32], u8 card_x_out[32])
{
	static const u8 mse_set_at_data[] = {0x80, 0x01, 0x4F, 0x83, 0x01, 0x03};
	const char *curve_name;
	struct sc_apdu apdu;
	u8 apdu_data[256];
	u8 rbuf[256];
	int apdu_data_len;
	int r;

	EVP_PKEY_CTX *eph_ctx = NULL, *peer_ctx = NULL, *z_ctx = NULL;
	EVP_PKEY *eph_pkey = NULL, *peer_pkey = NULL;
	OSSL_PARAM eph_params[3], peer_params[3];
	u8 *host_point = NULL;
	size_t host_point_len = 0;
	const u8 *card_point = NULL;
	size_t card_point_len = 0;
	u8 *z = NULL;
	size_t zlen = 0;

	curve_name = idprime_ecc_ma_curve_name(priv->ma_point_len);
	if (!curve_name) {
		sc_log(card->ctx, "Unsupported MA reference key point length %u", priv->ma_point_len);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* MSE:SET AT -- algorithm ref 0x4F, key ref 3 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xA4);
	apdu.data = mse_set_at_data;
	apdu.datalen = apdu.lc = sizeof(mse_set_at_data);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "MSE:SET AT failed");

	/* Generate our ephemeral EC keypair on the card's MA curve */
	eph_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)curve_name, 0);
	eph_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
			"uncompressed", 0);
	eph_params[2] = OSSL_PARAM_construct_end();

	eph_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!eph_ctx || !EVP_PKEY_keygen_init(eph_ctx) ||
			!EVP_PKEY_CTX_set_params(eph_ctx, eph_params) ||
			!EVP_PKEY_generate(eph_ctx, &eph_pkey) ||
			!(host_point_len = EVP_PKEY_get1_encoded_public_key(eph_pkey, &host_point)) ||
			host_point_len != priv->ma_point_len) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx, "OpenSSL failed to create ephemeral EC key");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	apdu_data_len = idprime_sm_encode_general_authenticate(host_point, host_point_len,
			apdu_data, sizeof(apdu_data));
	if (apdu_data_len < 0) {
		r = apdu_data_len;
		goto err;
	}

	/* GENERAL AUTHENTICATE: send our point, the card returns its own
	 * ephemeral point in the response to this same command. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x86, 0x00, 0x00);
	apdu.data = apdu_data;
	apdu.datalen = apdu.lc = (size_t)apdu_data_len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		goto err;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS)
		goto err;

	r = idprime_sm_decode_general_authenticate(card->ctx, apdu.resp, apdu.resplen,
			&card_point, &card_point_len);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Unexpected GENERAL AUTHENTICATE response");
		goto err;
	}

	/* Wrap the card's raw point into an EVP_PKEY to derive against */
	peer_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)curve_name, 0);
	peer_params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
			(void *)card_point, card_point_len);
	peer_params[2] = OSSL_PARAM_construct_end();

	peer_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!peer_ctx || !EVP_PKEY_fromdata_init(peer_ctx) ||
			!EVP_PKEY_fromdata(peer_ctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, peer_params)) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx, "OpenSSL failed to import card's ephemeral EC point");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* Compute the raw ECDH shared secret Z */
	z_ctx = EVP_PKEY_CTX_new(eph_pkey, NULL);
	if (!z_ctx || EVP_PKEY_derive_init(z_ctx) <= 0 ||
			EVP_PKEY_derive_set_peer(z_ctx, peer_pkey) <= 0 ||
			EVP_PKEY_derive(z_ctx, NULL, &zlen) <= 0 ||
			(z = malloc(zlen)) == NULL ||
			EVP_PKEY_derive(z_ctx, z, &zlen) <= 0) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx, "OpenSSL failed to derive the ECDH shared secret");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* Stash the X-coordinates (needed for the mutual-authentication
	 * signature below) before the point buffers get freed. Only
	 * meaningful for the P-256 case (32-byte X); callers must check
	 * priv->ma_point_len == 65 before relying on these. */
	if (host_x_out && host_point_len >= 33)
		memcpy(host_x_out, host_point + 1, 32);
	if (card_x_out && card_point_len >= 33)
		memcpy(card_x_out, card_point + 1, 32);

	*z_out = z;
	*zlen_out = zlen;
	z = NULL;
	r = SC_SUCCESS;

err:
	if (z) {
		sc_mem_clear(z, zlen);
		free(z);
	}
	OPENSSL_free(host_point);
	EVP_PKEY_CTX_free(eph_ctx);
	EVP_PKEY_CTX_free(peer_ctx);
	EVP_PKEY_CTX_free(z_ctx);
	EVP_PKEY_free(eph_pkey);
	EVP_PKEY_free(peer_pkey);
	return r;
}

/*
 * Signs a 32-byte digest with the embedded P-256 MA private key
 * (idprime_p256_ma_privkey_d), producing a raw fixed-length r||s signature
 * (64 bytes) as required by EXTERNAL AUTHENTICATE.
 */
static int
idprime_ecc_ma_sign_digest(sc_context_t *ctx, const u8 digest[32], u8 sig_out[64])
{
	EVP_PKEY_CTX *keyctx = NULL;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM params[3];
	BIGNUM *d_bn = NULL;
	u8 priv_native[32];
	u8 *der_sig = NULL;
	size_t der_sig_len = 0;
	const unsigned char *p;
	ECDSA_SIG *ecdsa_sig = NULL;
	const BIGNUM *sig_r = NULL, *sig_s = NULL;
	int ret = SC_ERROR_INTERNAL;

	d_bn = BN_bin2bn(idprime_p256_ma_privkey_d, sizeof(idprime_p256_ma_privkey_d), NULL);
	if (!d_bn || !BN_bn2nativepad(d_bn, priv_native, sizeof(priv_native))) {
		sc_log_openssl(ctx);
		goto err;
	}

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)"prime256v1", 0);
	params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, priv_native, sizeof(priv_native));
	params[2] = OSSL_PARAM_construct_end();

	keyctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!keyctx || !EVP_PKEY_fromdata_init(keyctx) ||
			!EVP_PKEY_fromdata(keyctx, &pkey, EVP_PKEY_KEYPAIR, params)) {
		sc_log_openssl(ctx);
		goto err;
	}
	EVP_PKEY_CTX_free(keyctx);

	keyctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (!keyctx || EVP_PKEY_sign_init(keyctx) <= 0 ||
			EVP_PKEY_sign(keyctx, NULL, &der_sig_len, digest, 32) <= 0 ||
			(der_sig = malloc(der_sig_len)) == NULL ||
			EVP_PKEY_sign(keyctx, der_sig, &der_sig_len, digest, 32) <= 0) {
		sc_log_openssl(ctx);
		goto err;
	}

	p = der_sig;
	ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, (long)der_sig_len);
	if (!ecdsa_sig) {
		sc_log_openssl(ctx);
		goto err;
	}
	ECDSA_SIG_get0(ecdsa_sig, &sig_r, &sig_s);
	memset(sig_out, 0, 64);
	if (!BN_bn2binpad(sig_r, sig_out, 32) || !BN_bn2binpad(sig_s, sig_out + 32, 32)) {
		sc_log_openssl(ctx);
		goto err;
	}

	ret = SC_SUCCESS;
err:
	if (d_bn)
		BN_clear_free(d_bn);
	sc_mem_clear(priv_native, sizeof(priv_native));
	free(der_sig);
	if (ecdsa_sig)
		ECDSA_SIG_free(ecdsa_sig);
	EVP_PKEY_CTX_free(keyctx);
	EVP_PKEY_free(pkey);
	return ret;
}

/*
 * Completes the proprietary "MA" mutual-authentication handshake on top of
 * an already-agreed ECDH shared secret: activates Secure Messaging, sends
 * the embedded terminal certificate (PSO:VERIFY CERTIFICATE), proves
 * possession of the corresponding private key (EXTERNAL AUTHENTICATE,
 * signature construction verified byte-for-byte via live dynamic
 * instrumentation -- see ETOKEN_FIPS_SM_NOTES.md), and completes the
 * card->terminal direction (INTERNAL AUTHENTICATE) WITHOUT verifying the
 * card's response signature: this driver has no Gemalto CVCA root to check
 * it against, so the resulting channel is authenticated in the
 * terminal->card direction only. That is a known, documented limitation,
 * not an oversight.
 *
 * Only implemented for the P-256 case (priv->ma_point_len == 65); other
 * curves aren't supported since the certificate/private key were only
 * extracted for P-256.
 *
 * On success, Secure Messaging (card->sm_ctx) is left ACTIVE so the caller
 * can proceed with normal file access, transparently SM-wrapped from here
 * on. On failure, any partially-started SM is torn back down.
 */
static int
idprime_ecc_ma_mutual_auth(sc_card_t *card, idprime_private_data_t *priv)
{
	/* SSC starts at 1 (not 0): verified via live gdb hook of the SSC-increment
	 * helper (see ETOKEN_FIPS_SM_NOTES.md section 9.5) -- its first call (our
	 * idprime_sm_pre_transmit(), before the very first SM-wrapped command)
	 * returns 2, meaning the pre-call value was already 1. */
	static const u8 ssc_init[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	static const u8 mse_cert_verify_data[] = {0x83, 0x01, 0x01, 0x95, 0x01, 0x80};
	static const u8 mse_int_auth_data[] = {0x84, 0x01, 0x02, 0x95, 0x01, 0x80};
	u8 mse_ext_auth_data[3 + sizeof(idprime_p256_ma_terminal_id) + 3];
	/* zero-initialized: idprime_ecc_ma_key_agreement() only fills these
	 * conditionally (host_point_len/card_point_len >= 33), which GCC can't
	 * prove always holds here even though callers only reach this point
	 * after confirming priv->ma_point_len == 65, causing a false-positive
	 * -Wmaybe-uninitialized under LTO. */
	u8 host_x[32] = {0}, card_x[32] = {0};
	u8 *z = NULL;
	size_t zlen = 0;
	struct sc_apdu apdu;
	u8 rbuf[256];
	u8 hash_input[sizeof(host_x) + sizeof(idprime_p256_ma_terminal_id) + 8 +
			sizeof(card_x) + sizeof(idprime_p256_domain_params)];
	u8 digest[32];
	u8 sig[64];
	u8 rnd_icc[8];
	u8 ext_auth_data[sizeof(idprime_p256_ma_terminal_id) + 64];
	u8 rnd_ifd[8];
	u8 int_auth_resp[128];
	u8 check_applet_resp[32];
	size_t off;
	int r;

	if (priv->ma_point_len != 65) {
		sc_log(card->ctx, "Mutual authentication only implemented for P-256 MA keys");
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = idprime_ecc_ma_key_agreement(card, priv, &z, &zlen, host_x, card_x);
	if (r != SC_SUCCESS)
		return r;

	r = idprime_sm_start(card, z, zlen, priv->sm_key_len, ssc_init);
	sc_mem_clear(z, zlen);
	free(z);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Failed to start Secure Messaging: %s", sc_strerror(r));
		return r;
	}

	/* MSE:SET AT for digital signature / certificate verification */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB6);
	apdu.data = mse_cert_verify_data;
	apdu.datalen = apdu.lc = sizeof(mse_cert_verify_data);
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "MSE:SET AT (cert verify) failed: %s", sc_strerror(r));
		goto err;
	}

	/* PSO: VERIFY CERTIFICATE */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x00, 0xBE);
	apdu.data = idprime_p256_ma_cert;
	apdu.datalen = apdu.lc = sizeof(idprime_p256_ma_cert);
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "PSO:VERIFY CERTIFICATE failed: %s", sc_strerror(r));
		goto err;
	}

	/* MSE:SET AT for EXTERNAL AUTHENTICATE, carrying our terminal ID (CHR) */
	off = 0;
	mse_ext_auth_data[off++] = 0x83;
	mse_ext_auth_data[off++] = sizeof(idprime_p256_ma_terminal_id);
	memcpy(mse_ext_auth_data + off, idprime_p256_ma_terminal_id, sizeof(idprime_p256_ma_terminal_id));
	off += sizeof(idprime_p256_ma_terminal_id);
	mse_ext_auth_data[off++] = 0x95;
	mse_ext_auth_data[off++] = 0x01;
	mse_ext_auth_data[off++] = 0x80;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xA4);
	apdu.data = mse_ext_auth_data;
	apdu.datalen = apdu.lc = off;
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "MSE:SET AT (external auth) failed: %s", sc_strerror(r));
		goto err;
	}

	/* GET CHALLENGE for RND.ICC. Empirically the proprietary driver uses
	 * CLA 0x80 here (0x8C once SM-wrapped) instead of the usual 0x00
	 * (0x0C wrapped) elsewhere -- reason unknown, but verified against a
	 * live capture, so replicated as-is. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x84, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rnd_icc);
	apdu.le = sizeof(rnd_icc);
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS || apdu.resplen != sizeof(rnd_icc)) {
		sc_log(card->ctx, "GET CHALLENGE failed: %s", sc_strerror(r));
		if (r == SC_SUCCESS)
			r = SC_ERROR_WRONG_LENGTH;
		goto err;
	}
	memcpy(rnd_icc, rbuf, sizeof(rnd_icc));

	/* Build and sign the EXTERNAL AUTHENTICATE digest:
	 *   SHA256(hostX || terminalID || RND.ICC || cardX || domainParams)
	 * Verified via live signature verification against the card's own
	 * public key -- see ETOKEN_FIPS_SM_NOTES.md section 7. */
	off = 0;
	memcpy(hash_input + off, host_x, sizeof(host_x));
	off += sizeof(host_x);
	memcpy(hash_input + off, idprime_p256_ma_terminal_id, sizeof(idprime_p256_ma_terminal_id));
	off += sizeof(idprime_p256_ma_terminal_id);
	memcpy(hash_input + off, rnd_icc, sizeof(rnd_icc));
	off += sizeof(rnd_icc);
	memcpy(hash_input + off, card_x, sizeof(card_x));
	off += sizeof(card_x);
	memcpy(hash_input + off, idprime_p256_domain_params, sizeof(idprime_p256_domain_params));
	off += sizeof(idprime_p256_domain_params);
	SHA256(hash_input, off, digest);

	r = idprime_ecc_ma_sign_digest(card->ctx, digest, sig);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Failed to sign EXTERNAL AUTHENTICATE digest");
		goto err;
	}

	memcpy(ext_auth_data, idprime_p256_ma_terminal_id, sizeof(idprime_p256_ma_terminal_id));
	memcpy(ext_auth_data + sizeof(idprime_p256_ma_terminal_id), sig, sizeof(sig));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x82, 0x00, 0x00);
	apdu.data = ext_auth_data;
	apdu.datalen = apdu.lc = sizeof(ext_auth_data);
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "EXTERNAL AUTHENTICATE failed: %s", sc_strerror(r));
		goto err;
	}
	sc_log(card->ctx, "EXTERNAL AUTHENTICATE succeeded -- terminal authenticated to the card");

	/* MSE:SET AT for INTERNAL AUTHENTICATE, selecting the card's own MA
	 * key (key reference 2, the same one probed in idprime_probe_ecc_ma()) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xA4);
	apdu.data = mse_int_auth_data;
	apdu.datalen = apdu.lc = sizeof(mse_int_auth_data);
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "MSE:SET AT (internal auth) failed: %s", sc_strerror(r));
		goto err;
	}

	/* INTERNAL AUTHENTICATE: challenge the card with our own random
	 * RND.IFD. The card's response (its own signature, proving it holds
	 * the card-side MA private key) is deliberately NOT verified -- see
	 * the function comment above. */
	if (RAND_bytes(rnd_ifd, sizeof(rnd_ifd)) != 1) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x88, 0x00, 0x00);
	apdu.data = rnd_ifd;
	apdu.datalen = apdu.lc = sizeof(rnd_ifd);
	apdu.resp = int_auth_resp;
	apdu.resplen = sizeof(int_auth_resp);
	apdu.le = sizeof(int_auth_resp);
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "INTERNAL AUTHENTICATE failed: %s", sc_strerror(r));
		goto err;
	}
	sc_log(card->ctx, "INTERNAL AUTHENTICATE succeeded (card responded, signature not verified) "
			  "-- Secure Messaging established");

	/* The handshake messages above use a trivial small-integer SSC (starting
	 * at 1). Right as the handshake completes, the real driver switches to a
	 * fresh SSC seeded from RND.ICC||RND.IFD for every command from here on
	 * -- confirmed via live gdb hook of SM_AES_MAC's raw SSC argument
	 * against the real driver, see ETOKEN_FIPS_SM_NOTES.md. Skipping this
	 * desyncs the SSC starting with the very next command. */
	r = idprime_sm_reseed_ssc(card, rnd_icc, rnd_ifd);
	if (r != SC_SUCCESS)
		goto err;

	/* Mirrors idp_checkAppletEx(renew=0), which the real driver always
	 * performs as the last step of idp_openSM_ECC_MAV() before returning.
	 * This isn't optional bookkeeping: every SM-protected APDU advances the
	 * card's SSC, so skipping this command here would leave our SSC one
	 * full round trip behind the card's, and every subsequent SM command
	 * would then fail MAC verification. The response (a proprietary status
	 * blob followed by the applet AID) isn't otherwise used. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xA6, 0x00, 0x00);
	apdu.resp = check_applet_resp;
	apdu.resplen = sizeof(check_applet_resp);
	/* The card is strict about this Le value (like GET CHALLENGE above) --
	 * it must be exactly 0x15/21, matching every captured real session. */
	apdu.le = 0x15;
	r = sc_transmit_apdu(card, &apdu);
	if (r == SC_SUCCESS)
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Post-authentication applet check failed: %s", sc_strerror(r));
		goto err;
	}

	/* We're now sitting authenticated inside the IDPrime AID; the card
	 * rejects a redundant re-select of it, see idprime_select_idprime(). */
	priv->sm_authenticated = 1;

	return SC_SUCCESS;

err:
	sc_sm_stop(card);
	return r;
}

#endif /* defined(ENABLE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L */

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
	/* Assigned early (rather than at the end of this function, as before)
	 * so that idprime_select_idprime() can reach priv->sm_authenticated
	 * via card->drv_data while the rest of idprime_init() below is still
	 * running. Safe on any early failure return in this function: init()
	 * failing means sc_connect_card() calls sc_card_free() rather than
	 * card->ops->finish(), and sc_card_free() never touches drv_data. */
	card->drv_data = priv;

	/* Detect whether this applet requires the proprietary EC-based Mutual
	 * Authentication / Secure Messaging channel. Cards without the MA
	 * reference key are driven exactly as before. Cards that have it get
	 * their idp_maType/idp_isFIPS/idp_isFullSM state mirrored into priv;
	 * cards that require full SM go through the mutual-authentication
	 * handshake so the rest of this function (container map, index file,
	 * etc.) can proceed transparently over the now-active SM channel. */
	r = idprime_probe_ecc_ma(card, priv);
	if (r != SC_SUCCESS) {
		idprime_free_private_data(priv);
		LOG_FUNC_RETURN(card->ctx, r);
	}
	if (priv->ma_point_len > 0) {
		idprime_get_applet_fips_config(card, priv);
		idprime_get_ecc_full_sm(card, priv);
		if (priv->full_sm) {
			sc_log(card->ctx, "Card requires full Secure Messaging (is_fips=%d fips_identify=%d "
					  "sm_key_len=%u) -- performing mutual authentication",
					priv->is_fips,
					priv->fips_identify, priv->sm_key_len);
#if defined(ENABLE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
			r = idprime_ecc_ma_mutual_auth(card, priv);
#else
			r = SC_ERROR_NOT_SUPPORTED;
#endif
			if (r != SC_SUCCESS) {
				sc_log(card->ctx, "Mutual authentication failed: %s", sc_strerror(r));
				idprime_free_private_data(priv);
				LOG_FUNC_RETURN(card->ctx, r);
			}
		}
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

	switch (card->type) {
	case SC_CARD_TYPE_IDPRIME_3810:
		card->name = "Gemalto IDPrime 3810";
		break;
	case SC_CARD_TYPE_IDPRIME_830:
		card->name = "Gemalto IDPrime MD 830";
		break;
	case SC_CARD_TYPE_IDPRIME_930:
	case SC_CARD_TYPE_IDPRIME_930_PLUS:
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
	switch (card->type) {
	case SC_CARD_TYPE_IDPRIME_930_PLUS:
	case SC_CARD_TYPE_IDPRIME_940:
		_sc_card_add_rsa_alg(card, 3072, flags, 0);
		/* fallthrough */
	case SC_CARD_TYPE_IDPRIME_930:
		_sc_card_add_rsa_alg(card, 4096, flags, 0);
		/* fallthrough */
	case SC_CARD_TYPE_IDPRIME_840:
		/* Set up algorithm info for EC */
		flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
		if (card->type == SC_CARD_TYPE_IDPRIME_930_PLUS || card->type == SC_CARD_TYPE_IDPRIME_940) {
			flags |= SC_ALGORITHM_ECDH_CDH_RAW;
		}
		ext_flags = SC_ALGORITHM_EXT_EC_F_P
			| SC_ALGORITHM_EXT_EC_ECPARAMETERS
			| SC_ALGORITHM_EXT_EC_NAMEDCURVE
			| SC_ALGORITHM_EXT_EC_UNCOMPRESES
			;
		_sc_card_add_ec_alg(card, 256, flags, ext_flags, NULL);
		_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);
		_sc_card_add_ec_alg(card, 521, flags, ext_flags, NULL);
		break;
	default:
		break;
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
	case SC_SEC_OPERATION_DERIVE:
		priv->current_op = SC_ALGORITHM_EC;
		new_env.flags &= ~SC_SEC_ENV_ALG_REF_PRESENT;
		break;
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
		priv->current_op = SC_ALGORITHM_RSA;
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
	iso7816_fixup_transceive_length(card, &apdu);

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
	idprime_private_data_t *priv;

	if (card == NULL || crgram == NULL || out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);
	priv = card->drv_data;
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

	sbuf[0] = priv->current_op == SC_ALGORITHM_EC ? 0x00 : 0x81; /* padding indicator byte, 0x81 = Proprietary, 0x00 = No further indication  */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	iso7816_fixup_transceive_length(card, &apdu);
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
