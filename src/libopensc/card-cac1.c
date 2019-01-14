/*
 * card-cac1.c: Support for legacy CAC-1
 * card-default.c: Support for cards with no driver
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005,2006,2007,2008,2009,2010 Douglas E. Engert <deengert@anl.gov>
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <thomas.harning@identityalliance.com>
 * Copyright (C) 2007, EMC, Russell Larner <rlarner@rsa.com>
 * Copyright (C) 2016 - 2018, Red Hat, Inc.
 *
 * CAC driver author: Robert Relyea <rrelyea@redhat.com>
 * Further work: Jakub Jelen <jjelen@redhat.com>
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
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#endif /* ENABLE_OPENSSL */

#include "internal.h"
#include "simpletlv.h"
#include "cardctl.h"
#ifdef ENABLE_ZLIB
#include "compression.h"
#endif
#include "iso7816.h"
#include "card-cac-common.h"

/*
 *  CAC hardware and APDU constants
 */
#define CAC_INS_GET_CERTIFICATE       0x36  /* CAC1 command to read a certificate */

/*
 * OLD cac read certificate, only use with CAC-1 card.
 */
static int cac_cac1_get_certificate(sc_card_t *card, u8 **out_buf, size_t *out_len)
{
	u8 buf[CAC_MAX_SIZE];
	u8 *out_ptr;
	size_t size = 0;
	size_t left = 0;
	size_t len, next_len;
	sc_apdu_t apdu;
	int r = SC_SUCCESS;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* get the size */
	size = left = *out_buf ? *out_len : sizeof(buf);
	out_ptr = *out_buf ? *out_buf : buf;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, CAC_INS_GET_CERTIFICATE, 0, 0 );
	next_len = MIN(left, 100);
	for (; left > 0; left -= len, out_ptr += len) {
		len = next_len;
		apdu.resp = out_ptr;
		apdu.le = len;
		apdu.resplen = left;
		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) {
			break;
		}
		if (apdu.resplen == 0) {
			r = SC_ERROR_INTERNAL;
			break;
		}
		/* in the old CAC-1, 0x63 means 'more data' in addition to 'pin failed' */
		if (apdu.sw1 != 0x63 || apdu.sw2 < 1)  {
			/* we've either finished reading, or hit an error, break */
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			left -= len;
			break;
		}
		next_len = MIN(left, apdu.sw2);
	}
	if (r < 0) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
	}
	r = size - left;
	if (*out_buf == NULL) {
		*out_buf = malloc(r);
		if (*out_buf == NULL) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,
				SC_ERROR_OUT_OF_MEMORY);
		}
		memcpy(*out_buf, buf, r);
	}
	*out_len = r;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

/*
 * Callers of this may be expecting a certificate,
 * select file will have saved the object type for us
 * as well as set that we want the cert from the object.
 */
static int cac_read_binary(sc_card_t *card, unsigned int idx,
		unsigned char *buf, size_t count, unsigned long flags)
{
	cac_private_data_t * priv = CAC_DATA(card);
	int r = 0;
	u8 *val = NULL;
	u8 *cert_ptr;
	size_t val_len;
	size_t len, cert_len;
	u8 cert_type;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* if we didn't return it all last time, return the remainder */
	if (priv->cached) {
		sc_log(card->ctx, 
			"returning cached value idx=%d count=%"SC_FORMAT_LEN_SIZE_T"u",
			idx, count);
		if (idx > priv->cache_buf_len) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_END_REACHED);
		}
		len = MIN(count, priv->cache_buf_len-idx);
		memcpy(buf, &priv->cache_buf[idx], len);
		LOG_FUNC_RETURN(card->ctx, len);
	}

	sc_log(card->ctx, 
		"clearing cache idx=%d count=%"SC_FORMAT_LEN_SIZE_T"u",
		idx, count);
	free(priv->cache_buf);
	priv->cache_buf = NULL;
	priv->cache_buf_len = 0;

	r = cac_cac1_get_certificate(card, &val, &val_len);
	if (r < 0)
		goto done;
	if (val_len < 1) {
		r = SC_ERROR_INVALID_DATA;
		goto done;
	}

	cert_type = val[0];
	cert_ptr = val + 1;
	cert_len = val_len - 1;

	/* if the info byte is 1, then the cert is compressed, decompress it */
	if ((cert_type & 0x3) == 1) {
#ifdef ENABLE_ZLIB
		r = sc_decompress_alloc(&priv->cache_buf, &priv->cache_buf_len,
			cert_ptr, cert_len, COMPRESSION_AUTO);
#else
		sc_log(card->ctx, "CAC compression not supported, no zlib");
		r = SC_ERROR_NOT_SUPPORTED;
#endif
		if (r)
			goto done;
		cert_ptr = val;
	} else if (cert_len > 0) {
		priv->cache_buf = malloc(cert_len);
		if (priv->cache_buf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		priv->cache_buf_len = cert_len;
		memcpy(priv->cache_buf, cert_ptr, cert_len);
	}

	/* OK we've read the data, now copy the required portion out to the callers buffer */
	priv->cached = 1;
	len = MIN(count, priv->cache_buf_len-idx);
	memcpy(buf, &priv->cache_buf[idx], len);
	r = len;
done:
	if (val)
		free(val);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * CAC cards use SC_PATH_SELECT_OBJECT_ID rather than SC_PATH_SELECT_FILE_ID. In order to use more
 * of the PKCS #15 structure, we call the selection SC_PATH_SELECT_FILE_ID, but we set p1 to 2 instead
 * of 0. Also cac1 does not do any FCI, but it doesn't understand not selecting it. It returns invalid INS
 * if it doesn't like anything about the select, so we always 'request' FCI for CAC1
 *
 * The rest is just copied from iso7816_select_file
 */
static int cac_select_file_by_type(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen, pathtype;
	struct sc_file *file = NULL;
	cac_private_data_t * priv = CAC_DATA(card);

	assert(card != NULL && in_path != NULL);
	ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;
	pathtype = in_path->type;

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		"path=%s, path->value=%s path->type=%d (%x)",
		sc_print_path(in_path),
		sc_dump_hex(in_path->value, in_path->len),
		in_path->type, in_path->type);
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "file_out=%p index=%d count=%d\n",
		file_out, in_path->index, in_path->count);

	/* Sigh, iso7816_select_file expects paths to keys to have specific
	 * formats. There is no override. We have to add some bytes to the
	 * path to make it happy.
	 * We only need to do this for private keys.
	 */
	if ((pathlen > 2) && (pathlen <= 4) && memcmp(path, "\x3F\x00", 2) == 0) {
		path += 2;
		pathlen -= 2;
	}


	/* CAC has multiple different type of objects that aren't PKCS #15. When we read
	 * them we need convert them to something PKCS #15 would understand. Find the object
	 * and object type here:
	 */
	if (priv) { /* don't record anything if we haven't been initialized yet */
		/* forget any old cached values */
		if (priv->cache_buf) {
			free(priv->cache_buf);
			priv->cache_buf = NULL;
		}
		priv->cache_buf_len = 0;
		priv->cached = 0;
	}

	if (in_path->aid.len) {
		if (!pathlen) {
			memcpy(path, in_path->aid.value, in_path->aid.len);
			pathlen = in_path->aid.len;
			pathtype = SC_PATH_TYPE_DF_NAME;
		} else {
			/* First, select the application */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"select application" );
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0);
			apdu.data = in_path->aid.value;
			apdu.datalen = in_path->aid.len;
			apdu.lc = in_path->aid.len;

			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_RET(ctx, r, "APDU transmit failed");
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r)
				LOG_FUNC_RETURN(ctx, r);

		}
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);

	switch (pathtype) {
	/* ideally we would had SC_PATH_TYPE_OBJECT_ID and add code to the iso7816 select.
	 * Unfortunately we'd also need to update the caching code as well. For now just
	 * use FILE_ID and change p1 here */
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 2;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);
	apdu.le = sc_get_max_recv_size(card) < 256 ? sc_get_max_recv_size(card) : 256;
	apdu.p2 = 0x00;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	if (file_out == NULL) {
		/* For some cards 'SELECT' can be only with request to return FCI/FCP. */
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (apdu.sw1 == 0x6A && apdu.sw2 == 0x86)   {
			apdu.p2 = 0x00;
			apdu.resplen = sizeof(buf);
			if (sc_transmit_apdu(card, &apdu) == SC_SUCCESS)
				r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		}
		if (apdu.sw1 == 0x61)
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		LOG_FUNC_RETURN(ctx, r);
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		LOG_FUNC_RETURN(ctx, r);

	/* CAC cards never return FCI, fake one */
	file = sc_file_new();
	if (file == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	file->path = *in_path;
	file->size = CAC_MAX_SIZE; /* we don't know how big, just give a large size until we can read the file */

	*file_out = file;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);

}

static int cac_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	return cac_select_file_by_type(card, in_path, file_out);
}

static int cac_finish(sc_card_t *card)
{
	cac_private_data_t * priv = CAC_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (priv) {
		cac_free_private_data(priv);
	}
	return SC_SUCCESS;
}


/* select a CAC pki applet by index */
static int cac_select_pki_applet(sc_card_t *card, int index)
{
	sc_path_t applet_path = cac_cac_pki_obj.path;
	applet_path.aid.value[applet_path.aid.len-1] = index;
	return cac_select_file_by_type(card, &applet_path, NULL);
}

/*
 *  Find the first existing CAC applet. If none found, then this isn't a CAC
 */
static int cac_find_first_pki_applet(sc_card_t *card, int *index_out)
{
	int r, i;

	for (i = 0; i < MAX_CAC_SLOTS; i++) {
		r = cac_select_pki_applet(card, i);
		if (r == SC_SUCCESS) {
			u8 data[2];
			sc_apdu_t apdu;

			/* Try to read first two bytes of the buffer to
			 * make sure it is not just malfunctioning card
			 */
			sc_format_apdu(card, &apdu, SC_APDU_CASE_2,
				CAC_INS_GET_CERTIFICATE, 0x00, 0x00);
			apdu.le = 0x02;
			apdu.resplen = 2;
			apdu.resp = data;
			r = sc_transmit_apdu(card, &apdu);
			/* SW1 = 0x63 means more data in CAC1 */
			if (r == SC_SUCCESS && apdu.sw1 != 0x63)
				continue;

			*index_out = i;
			return SC_SUCCESS;
		}
	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}

static int cac_populate_cac1(sc_card_t *card, int index, cac_private_data_t *priv)
{
	int r, i;
	cac_object_t pki_obj = cac_cac_pki_obj;
	u8 buf[100];
	u8 *val;
	size_t val_len;

	/* populate PKI objects */
	for (i = index; i < MAX_CAC_SLOTS; i++) {
		r = cac_select_pki_applet(card, i);
		if (r == SC_SUCCESS) {
			pki_obj.name = get_cac_label(i);
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				"CAC: pki_object found, cert_next=%d (%s)",
				i, pki_obj.name);
			pki_obj.path.aid.value[pki_obj.path.aid.len-1] = i;
			pki_obj.fd = i+1; /* don't use id of zero */
			cac_add_object_to_list(&priv->pki_list, &pki_obj);
		}
	}

	/*
	 * create a cuid to simulate the cac 2 cuid.
	 */
	priv->cuid = cac_cac_cuid;
	/* create a serial number by hashing the first 100 bytes of the
	 * first certificate on the card */
	r = cac_select_pki_applet(card, index);
	if (r < 0) {
		return r; /* shouldn't happen unless the card has been removed or is malfunctioning */
	}
	val = buf;
	val_len = sizeof(buf);
	r = cac_cac1_get_certificate(card, &val, &val_len);
	if (r >= 0) {
		priv->cac_id = malloc(20);
		if (priv->cac_id == NULL) {
			return SC_ERROR_OUT_OF_MEMORY;
		}
#ifdef ENABLE_OPENSSL
		SHA1(val, val_len, priv->cac_id);
		priv->cac_id_len = 20;
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_VERBOSE,
			"cuid", priv->cac_id, priv->cac_id_len);
#else
		sc_log(card->ctx, "OpenSSL Required");
		return SC_ERROR_NOT_SUPPORTED;
#endif /* ENABLE_OPENSSL */
	}
	return SC_SUCCESS;
}

/*
 * Look for a CAC card. If it exists, initialize our data structures
 */
static int cac_find_and_initialize(sc_card_t *card, int initialize)
{
	int r, index;
	cac_private_data_t *priv = NULL;

	/* already initialized? */
	if (card->drv_data) {
		return SC_SUCCESS;
	}

	/* is this a CAC Alt token without any accompanying structures */
	r = cac_find_first_pki_applet(card, &index);
	if (r == SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "PKI applet found, is bare CAC-1");
		if (!initialize) /* match card only */
			return r;

		if (!priv) {
			priv = cac_new_private_data();
			if (!priv)
				return SC_ERROR_OUT_OF_MEMORY;
		}
		card->drv_data = priv; /* needed for the read_binary() */
		r = cac_populate_cac1(card, index, priv);
		if (r == SC_SUCCESS) {
			card->type = SC_CARD_TYPE_CAC_I;
			return r;
		}
		card->drv_data = NULL; /* reset on failure */
	}
	if (priv) {
		cac_free_private_data(priv);
	}
	return r;
}


/* NOTE: returns a bool, 1 card matches, 0 it does not */
static int cac_match_card(sc_card_t *card)
{
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* Since we send an APDU, the card's logout function may be called...
	 * however it may be in dirty memory */
	card->ops->logout = NULL;

	r = cac_find_and_initialize(card, 0);
	return (r == SC_SUCCESS); /* never match */
}


static int cac_init(sc_card_t *card)
{
	int r;
	unsigned long flags;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = cac_find_and_initialize(card, 1);
	if (r < 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}
	flags = SC_ALGORITHM_RSA_RAW;

	_sc_card_add_rsa_alg(card, 1024, flags, 0); /* mandatory */
	_sc_card_add_rsa_alg(card, 2048, flags, 0); /* optional */
	_sc_card_add_rsa_alg(card, 3072, flags, 0); /* optional */

	card->caps |= SC_CARD_CAP_RNG | SC_CARD_CAP_ISO7816_PIN_INFO;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static struct sc_card_operations cac_ops;

static struct sc_card_driver cac1_drv = {
	"Common Access Card (CAC 1)",
	"cac1",
	&cac_ops,
	NULL, 0, NULL
};

static struct sc_card_driver * sc_get_driver(void)
{
	/* Inherit most of the things from the CAC driver */
	struct sc_card_driver *cac_drv = sc_get_cac_driver();

	cac_ops = *cac_drv->ops;
	cac_ops.match_card = cac_match_card;
	cac_ops.init = cac_init;
	cac_ops.finish = cac_finish;

	cac_ops.select_file =  cac_select_file; /* need to record object type */
	cac_ops.read_binary = cac_read_binary;

	return &cac1_drv;
}


struct sc_card_driver * sc_get_cac1_driver(void)
{
	return sc_get_driver();
}
