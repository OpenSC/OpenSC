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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "internal.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifdef ENABLE_ZLIB
#include "compression.h"
#endif

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
	{ "3b:7f:96:00:00:80:31:80:65:b0:84:41:3d:f6:12:0f:fe:82:90:00",
	  "ff:ff:00:ff:ff:ff:ff:ff:ff:ff:00:00:00:00:ff:ff:ff:ff:ff:ff",
	  "Gemalto IDPrime MD 8840, 3840, 3810, 840 and 830 Cards",
	  SC_CARD_TYPE_IDPRIME_GENERIC, 0, NULL },
};

static const sc_path_t idprime_path = {
	"", 0,
	0, 0, SC_PATH_TYPE_DF_NAME,
	{ "\xA0\x00\x00\x00\x18\x80\x00\x00\x00\x06\x62", 11 }
};

/* data structures to store meta data about IDPrime objects */
typedef struct idprime_object {
	int fd;
	unsigned char key_reference;
	u8 df[2];
	unsigned short length;
} idprime_object_t;

/*
 * IDPrime private data per card state
 */
typedef struct idprime_private_data {
	u8 *cache_buf;			/* cached version of the currently selected file */
	size_t cache_buf_len;		/* length of the cached selected file */
	int cached;			/* is the cached selected file valid */
	size_t file_size;		/* this is real file size since IDPrime is quite strict about lengths */
	list_t pki_list;		/* list of pki containers */
	idprime_object_t *pki_current;	/* current pki object _ctl function */
	int tinfo_present;		/* Token Info Label object is present*/
	u8 tinfo_df[2];			/* DF of object with Token Info Label */
} idprime_private_data_t;

/* For SimCList autocopy, we need to know the size of the data elements */
static size_t idprime_list_meter(const void *el) {
	return sizeof(idprime_object_t);
}

void idprime_free_private_data(idprime_private_data_t *priv)
{
	free(priv->cache_buf);
	list_destroy(&priv->pki_list);
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

/* This select some index file, which is useful for enumerating other files
 * on the card */
static int idprime_select_index(sc_card_t *card)
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
	sc_format_path("0101", &index_path);
	r = iso_ops->select_file(card, &index_path, &file);
	if (r == SC_SUCCESS) {
		r = file->size;
	}
	sc_file_free(file);
	/* Ignore too large files */
	if (r > MAX_FILE_SIZE) {
		r = SC_ERROR_INVALID_DATA;
	}
	return r;
}

static int idprime_process_index(sc_card_t *card, idprime_private_data_t *priv, int length)
{
	u8 *buf = NULL;
	int r = SC_ERROR_OUT_OF_MEMORY;
	int i, num_entries;
	idprime_object_t new_object;

	buf = malloc(length);
	if (buf == NULL) {
		goto done;
	}

	r = iso_ops->read_binary(card, 0, buf, length, 0);
	if (r < 1) {
		r = SC_ERROR_WRONG_LENGTH;
		goto done;
	}

	/* First byte shows the number of entries, each of them 21 bytes long */
	num_entries = buf[0];
	if (r < num_entries*21 + 1) {
		r = SC_ERROR_INVALID_DATA;
		goto done;
	}
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
			new_object.fd++;
			if (card->type == SC_CARD_TYPE_IDPRIME_V2) {
				/* The key reference starts from 0x11 */
				new_object.key_reference = 0x10 + new_object.fd;
			} else {
				/* The key reference is one bigger than the value found here for some reason */
				new_object.key_reference = start[8] + 1;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found certificate with fd=%d, key_ref=%d",
				new_object.fd, new_object.key_reference);
			idprime_add_object_to_list(&priv->pki_list, &new_object);

		/* This looks like non-standard extension listing pkcs11 token info label in my card */
		} else if ((memcmp(&start[4], "tinfo", 6) == 0) && (memcmp(&start[12], "p11", 4) == 0)) {
			memcpy(priv->tinfo_df, new_object.df, sizeof(priv->tinfo_df));
			priv->tinfo_present = 1;
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Found p11/tinfo object");
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
	unsigned long flags;
	idprime_private_data_t *priv = NULL;
	struct sc_apdu apdu;
	u8 rbuf[CPLC_LENGTH];
	size_t rbuflen = sizeof(rbuf);

	/* We need to differentiate the OS version since they behave slightly differently */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xCA, 0x9F, 0x7F);
	apdu.resp = rbuf;
	apdu.resplen = rbuflen;
	apdu.le = rbuflen;
	r = sc_transmit_apdu(card, &apdu);
	card->type = SC_CARD_TYPE_IDPRIME_GENERIC;
	if (r == SC_SUCCESS && apdu.resplen == CPLC_LENGTH) {
		/* We are interested in the OS release level here */
		switch (rbuf[11]) {
		case 0x01:
			card->type = SC_CARD_TYPE_IDPRIME_V1;
			sc_log(card->ctx, "Detected IDPrime applet version 1");
			break;
		case 0x02:
			card->type = SC_CARD_TYPE_IDPRIME_V2;
			sc_log(card->ctx, "Detected IDPrime applet version 2");
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

	/* Now, select and process the index file */
	r = idprime_select_index(card);
	if (r <= 0) {
		LOG_FUNC_RETURN(card->ctx, r);
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Index file found");

	priv = idprime_new_private_data();
	if (!priv) {
		return SC_ERROR_OUT_OF_MEMORY;
	}

	r = idprime_process_index(card, priv, r);
	if (r != SC_SUCCESS) {
		idprime_free_private_data(priv);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	card->drv_data = priv;

	switch (card->type) {
	case SC_CARD_TYPE_IDPRIME_V1:
		card->name = "Gemalto IDPrime (OSv1)";
		break;
	case SC_CARD_TYPE_IDPRIME_V2:
		card->name = "Gemalto IDPrime (OSv2)";
		break;
	case SC_CARD_TYPE_IDPRIME_GENERIC:
	default:
		card->name = "Gemalto IDPrime (generic)";
		break;
	}
	card->cla = 0x00;

	/* Set up algorithm info. */
	flags = SC_ALGORITHM_RSA_PAD_PKCS1
		| SC_ALGORITHM_RSA_PAD_PSS
		| SC_ALGORITHM_RSA_PAD_OAEP
		/* SHA-1 mechanisms are not allowed in the card I have */
		| (SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_RSA_HASH_SHA512)
		| (SC_ALGORITHM_MGF1_SHA256 | SC_ALGORITHM_MGF1_SHA384 | SC_ALGORITHM_MGF1_SHA512)
		;

	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;

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

	r = idprime_select_index(card);
	return (r > 0);
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
	prkey_info->key_reference = (*entry)->key_reference;
	*entry = list_iterator_next(list);
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

	*tname = malloc(buf[1]);
	if (*tname == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	r = iso_ops->read_binary(card, 2, (unsigned char *)*tname, buf[1], 0);
	if (r < 1) {
		free(*tname);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	if ((*tname)[r-1] != '\0') {
		(*tname)[r-1] = '\0';
	}
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
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

#define HEADER_LEN 4

static int idprime_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	int r, len;
	idprime_private_data_t * priv = card->drv_data;
	u8 data[HEADER_LEN];
	size_t data_len = HEADER_LEN;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* forget any old cached values */
	if (priv->cache_buf) {
		free(priv->cache_buf);
		priv->cache_buf = NULL;
	}
	priv->cache_buf_len = 0;
	priv->cached = 0;

	r = iso_ops->select_file(card, in_path, file_out);
	if (r == SC_SUCCESS && priv && file_out != NULL) {
		/* Try to read first bytes of the file to fix FCI in case of
		 * compressed certififcate */
		len = iso_ops->read_binary(card, 0, data, data_len, 0);
		if (len == HEADER_LEN && data[0] == 0x01 && data[1] == 0x00) {
			/* Cache the real file size for the caching read_binary() */
			priv->file_size = (*file_out)->size;
			/* Fix the information in the file structure to not confuse upper layers */
			(*file_out)->size = (data[3]<<8) | data[2];
		}
	}
	/* Return the exit code of the select command */
	return r;
}

// used to read existing certificates
static int idprime_read_binary(sc_card_t *card, unsigned int offset,
	unsigned char *buf, size_t count, unsigned long flags)
{
	struct idprime_private_data *priv = card->drv_data;
	int r;
	int size;

	sc_log(card->ctx, "called; %"SC_FORMAT_LEN_SIZE_T"u bytes at offset %d",
		count, offset);

	if (!priv->cached && offset == 0) {
		// this function is called to read and uncompress the certificate
		u8 buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
		if (sizeof(buffer) < count) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
		}
		/* Read what was reported by FCI from select command */
		r = iso_ops->read_binary(card, 0, buffer, priv->file_size, flags);
		if (r < 0) {
			LOG_FUNC_RETURN(card->ctx, r);
		}
		if (r < 4) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_DATA);
		}
		if (buffer[0] == 1 && buffer[1] == 0) {
#ifdef ENABLE_ZLIB
			size_t expectedsize = buffer[2] + buffer[3] * 0x100;
			r = sc_decompress_alloc(&priv->cache_buf, &(priv->cache_buf_len),
				buffer+4, priv->file_size-4, COMPRESSION_AUTO);
			if (r != SC_SUCCESS) {
				sc_log(card->ctx, "Zlib error: %d", r);
				LOG_FUNC_RETURN(card->ctx, r);
			}
			if (priv->cache_buf_len != expectedsize) {
				sc_log(card->ctx,
					 "expected size: %"SC_FORMAT_LEN_SIZE_T"u real size: %"SC_FORMAT_LEN_SIZE_T"u",
					 expectedsize, priv->cache_buf_len);
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_DATA);
			}
#else
			sc_log(card->ctx, "compression not supported, no zlib");
			return SC_ERROR_NOT_SUPPORTED;
#endif /* ENABLE_ZLIB */
		} else {
			/* assuming uncompressed certificate */
			priv->cache_buf = malloc(r);
			if (priv->cache_buf == NULL) {
				return SC_ERROR_OUT_OF_MEMORY;
			}
			memcpy(priv->cache_buf, buffer, r);
			priv->cache_buf_len = r;
		}
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

	if (card == NULL || env == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* The card requires algorithm reference here */
	new_env = *env;
	new_env.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
	/* SHA-1 mechanisms are not allowed in the card I have available */
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_OAEP) {
			if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
				new_env.algorithm_ref = 0x1D;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
				new_env.algorithm_ref = 0x4D;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384) {
				new_env.algorithm_ref = 0x5D;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) {
				new_env.algorithm_ref = 0x6D;
			}
		} else { /* RSA-PKCS without hashing */
			new_env.algorithm_ref = 0x1A;
		}
		break;
	case SC_SEC_OPERATION_SIGN:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS) {
			if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
				new_env.algorithm_ref = 0x45;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384) {
				new_env.algorithm_ref = 0x55;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) {
				new_env.algorithm_ref = 0x65;
			}
		} else { /* RSA-PKCS */
			if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
				new_env.algorithm_ref = 0x42;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384) {
				new_env.algorithm_ref = 0x52;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) {
				new_env.algorithm_ref = 0x62;
			} else { /* RSA-PKCS without hashing */
				new_env.algorithm_ref = 0x02;
			}
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
	u8 sbuf[128]; /* For SHA-512 we need 64 + 2 bytes */
	u8 rbuf[4096]; /* needs work. for 3072 keys, needs 384+2 or so */
	size_t rbuflen = sizeof(rbuf);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* We should be signing hashes only so we should not reach this limit */
	if (datalen + 2 > sizeof(sbuf)) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	p = sbuf;
	*(p++) = 0x90;
	*(p++) = datalen;
	memcpy(p, data, datalen);
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
	if (apdu.resplen != datalen || memcmp(rbuf, data, datalen) != 0) {
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
		LOG_FUNC_RETURN(card->ctx, apdu.resplen);

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
		LOG_FUNC_RETURN(card->ctx, apdu.resplen);
	else
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
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

	return &idprime_drv;
}

struct sc_card_driver * sc_get_idprime_driver(void)
{
	return sc_get_driver();
}
