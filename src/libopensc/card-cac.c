/*
 * card-cac.c: Support for CAC from NIST SP800-73
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
#define CAC_MAX_CHUNK_SIZE 240
#define CAC_INS_SIGN_DECRYPT          0x42  /* A crypto operation */
#define CAC_INS_READ_FILE             0x52  /* read a TL or V file */
#define CAC_INS_GET_ACR               0x4c
#define CAC_INS_GET_PROPERTIES        0x56
#define CAC_P1_STEP    0x80
#define CAC_P1_FINAL   0x00
#define CAC_FILE_TAG    1
#define CAC_FILE_VALUE  2
/* TAGS in a TL file */
#define CAC_TAG_CERTIFICATE           0x70
#define CAC_TAG_CERTINFO              0x71
#define CAC_TAG_MSCUID                0x72
#define CAC_TAG_CUID                  0xF0
#define CAC_TAG_CC_VERSION_NUMBER     0xF1
#define CAC_TAG_GRAMMAR_VERION_NUMBER 0xF2
#define CAC_TAG_CARDURL               0xF3
#define CAC_TAG_PKCS15                0xF4
#define CAC_TAG_ACCESS_CONTROL        0xF6
#define CAC_TAG_DATA_MODEL            0xF5
#define CAC_TAG_CARD_APDU             0xF7
#define CAC_TAG_REDIRECTION           0xFA
#define CAC_TAG_CAPABILITY_TUPLES     0xFB
#define CAC_TAG_STATUS_TUPLES         0xFC
#define CAC_TAG_NEXT_CCC              0xFD
#define CAC_TAG_ERROR_CODES           0xFE
#define CAC_TAG_APPLET_FAMILY         0x01
#define CAC_TAG_NUMBER_APPLETS        0x94
#define CAC_TAG_APPLET_ENTRY          0x93
#define CAC_TAG_APPLET_AID            0x92
#define CAC_TAG_APPLET_INFORMATION    0x01
#define CAC_TAG_NUMBER_OF_OBJECTS     0x40
#define CAC_TAG_TV_BUFFER             0x50
#define CAC_TAG_PKI_OBJECT            0x51
#define CAC_TAG_OBJECT_ID             0x41
#define CAC_TAG_BUFFER_PROPERTIES     0x42
#define CAC_TAG_PKI_PROPERTIES        0x43

#define CAC_APP_TYPE_GENERAL          0x01
#define CAC_APP_TYPE_SKI              0x02
#define CAC_APP_TYPE_PKI              0x04

#define CAC_ACR_ACR                   0x00
#define CAC_ACR_APPLET_OBJECT         0x10
#define CAC_ACR_AMP                   0x20
#define CAC_ACR_SERVICE               0x21

/* hardware data structures (returned in the CCC) */
/* part of the card_url */
typedef struct cac_access_profile {
	u8 GCACR_listID;
	u8 GCACR_readTagListACRID;
	u8 GCACR_updatevalueACRID;
	u8 GCACR_readvalueACRID;
	u8 GCACR_createACRID;
	u8 GCACR_deleteACRID;
	u8 CryptoACR_listID;
	u8 CryptoACR_getChallengeACRID;
	u8 CryptoACR_internalAuthenicateACRID;
	u8 CryptoACR_pkiComputeACRID;
	u8 CryptoACR_readTagListACRID;
	u8 CryptoACR_updatevalueACRID;
	u8 CryptoACR_readvalueACRID;
	u8 CryptoACR_createACRID;
	u8 CryptoACR_deleteACRID;
} cac_access_profile_t;

/* part of the card url */
typedef struct cac_access_key_info {
	u8	keyFileID[2];
	u8	keynumber;
} cac_access_key_info_t;

typedef struct cac_card_url {
	u8 rid[5];
	u8 cardApplicationType;
	u8 objectID[2];
	u8 applicationID[2];
	cac_access_profile_t accessProfile;
	u8 pinID;			     /* not used for VM cards */
	cac_access_key_info_t accessKeyInfo; /* not used for VM cards */
	u8 keyCryptoAlgorithm;               /* not used for VM cards */
} cac_card_url_t;

#define CAC_MAX_OBJECTS 16

typedef struct {
	/* OID has two bytes */
	unsigned char oid[2];
	/* Format is NOT SimpleTLV? */
	unsigned char simpletlv;
	/* Is certificate object and private key is initialized */
	unsigned char privatekey;
} cac_properties_object_t;

typedef struct {
	unsigned int num_objects;
	cac_properties_object_t objects[CAC_MAX_OBJECTS];
} cac_properties_t;

/*
 * Flags for Current Selected Object Type
 *   CAC files are TLV files, with TL and V separated. For generic
 *   containers we reintegrate the TL anv V portions into a single
 *   file to read. Certs are also TLV files, but pkcs15 wants the
 *   actual certificate. At select time we know the patch which tells
 *   us what time of files we want to read. We remember that type
 *   so that read_binary can do the appropriate processing.
 */
#define CAC_OBJECT_TYPE_CERT		1
#define CAC_OBJECT_TYPE_TLV_FILE	4
#define CAC_OBJECT_TYPE_GENERIC		5

/*
 * Set up the normal CAC paths
 */
#define CAC_2_RID "\xA0\x00\x00\x01\x16"

static const sc_path_t cac_ACA_Path = {
	"", 0,
	0,0,SC_PATH_TYPE_DF_NAME,
	{ CAC_TO_AID(CAC_1_RID "\x10\x00") }
};

static const sc_path_t cac_CCC_Path = {
	"", 0,
	0,0,SC_PATH_TYPE_DF_NAME,
	{ CAC_TO_AID(CAC_2_RID "\xDB\x00") }
};

/*
 *  CAC general objects defined in 4.3.1.2 of CAC Applet Developer Guide Version 1.0.
 *   doubles as a source for CAC-2 labels.
 */
static const cac_object_t cac_objects[] = {
	{ "Person Instance", 0x200, { { 0 }, 0, 0, 0, SC_PATH_TYPE_DF_NAME,
		{ CAC_TO_AID(CAC_1_RID "\x02\x00") }}},
	{ "Personnel", 0x201, { { 0 }, 0, 0, 0, SC_PATH_TYPE_DF_NAME,
		{ CAC_TO_AID(CAC_1_RID "\x02\x01") }}},
	{ "Benefits", 0x202, { { 0 }, 0, 0, 0, SC_PATH_TYPE_DF_NAME,
		{ CAC_TO_AID(CAC_1_RID "\x02\x02") }}},
	{ "Other Benefits", 0x203, { { 0 }, 0, 0, 0, SC_PATH_TYPE_DF_NAME,
		{ CAC_TO_AID(CAC_1_RID "\x02\x03") }}},
	{ "PKI Credential", 0x2FD, { { 0 }, 0, 0, 0, SC_PATH_TYPE_DF_NAME,
		{ CAC_TO_AID(CAC_1_RID "\x02\xFD") }}},
	{ "PKI Certificate", 0x2FE, { { 0 }, 0, 0, 0, SC_PATH_TYPE_DF_NAME,
		{ CAC_TO_AID(CAC_1_RID "\x02\xFE") }}},
};

static const int cac_object_count = sizeof(cac_objects)/sizeof(cac_objects[0]);

/*
 * use the object id to find our object info on the object in our CAC-1 list
 */
static const cac_object_t *cac_find_obj_by_id(unsigned short object_id)
{
	int i;

	for (i = 0; i < cac_object_count; i++) {
		if (cac_objects[i].fd == object_id) {
			return &cac_objects[i];
		}
	}
	return NULL;
}

/*
 * Lookup the path in the pki list to see if it is a cert path
 */
static int cac_is_cert(cac_private_data_t * priv, const sc_path_t *in_path)
{
	cac_object_t test_obj;
	test_obj.path = *in_path;
	test_obj.path.index = 0;
	test_obj.path.count = 0;

	return (list_contains(&priv->pki_list, &test_obj) != 0);
}

/*
 * Send a command and receive data.
 *
 * A caller may provide a buffer, and length to read. If not provided,
 * an internal 4096 byte buffer is used, and a copy is returned to the
 * caller. that need to be freed by the caller.
 *
 * modelled after a similar function in card-piv.c
 */

static int cac_apdu_io(sc_card_t *card, int ins, int p1, int p2,
	const u8 * sendbuf, size_t sendbuflen, u8 ** recvbuf,
	size_t * recvbuflen)
{
	int r;
	sc_apdu_t apdu;
	u8 rbufinitbuf[CAC_MAX_SIZE];
	u8 *rbuf;
	size_t rbuflen;
	unsigned int apdu_case = SC_APDU_CASE_1;


	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx, 
		 "%02x %02x %02x %"SC_FORMAT_LEN_SIZE_T"u : %"SC_FORMAT_LEN_SIZE_T"u %"SC_FORMAT_LEN_SIZE_T"u\n",
		 ins, p1, p2, sendbuflen, card->max_send_size,
		 card->max_recv_size);

	rbuf = rbufinitbuf;
	rbuflen = sizeof(rbufinitbuf);

	/* if caller provided a buffer and length */
	if (recvbuf && *recvbuf && recvbuflen && *recvbuflen) {
		rbuf = *recvbuf;
		rbuflen = *recvbuflen;
	}

	if (recvbuf) {
		if (sendbuf)
			apdu_case = SC_APDU_CASE_4_SHORT;
		else
			apdu_case = SC_APDU_CASE_2_SHORT;
	} else if (sendbuf)
		apdu_case = SC_APDU_CASE_3_SHORT;


	sc_format_apdu(card, &apdu, apdu_case, ins, p1, p2);

	apdu.lc = sendbuflen;
	apdu.datalen = sendbuflen;
	apdu.data = sendbuf;

	if (recvbuf) {
		apdu.resp = rbuf;
		apdu.le = (rbuflen > 255) ? 255 : rbuflen;
		apdu.resplen = rbuflen;
	} else {
		 apdu.resp =  rbuf;
		 apdu.le = 0;
		 apdu.resplen = 0;
	}

	sc_log(card->ctx, 
		 "calling sc_transmit_apdu flags=%lx le=%"SC_FORMAT_LEN_SIZE_T"u, resplen=%"SC_FORMAT_LEN_SIZE_T"u, resp=%p",
		 apdu.flags, apdu.le, apdu.resplen, apdu.resp);

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);

	sc_log(card->ctx, 
		 "result r=%d apdu.resplen=%"SC_FORMAT_LEN_SIZE_T"u sw1=%02x sw2=%02x",
		 r, apdu.resplen, apdu.sw1, apdu.sw2);
	if (r < 0) {
		sc_log(card->ctx, "Transmit failed");
		goto err;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (r < 0) {
		sc_log(card->ctx,  "Card returned error ");
		goto err;
	}

	if (recvbuflen) {
		if (recvbuf && *recvbuf == NULL) {
			*recvbuf =  malloc(apdu.resplen);
			if (*recvbuf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
			memcpy(*recvbuf, rbuf, apdu.resplen);
		}
		*recvbuflen =  apdu.resplen;
		r = *recvbuflen;
	}

err:
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Get ACR of currently ACA applet identified by the  acr_type
 * 5.3.3.5 Get ACR APDU
 */
static int
cac_get_acr(sc_card_t *card, int acr_type, u8 **out_buf, size_t *out_len)
{
	u8 *out = NULL;
	/* XXX assuming it will not be longer than 255 B */
	size_t len = 256;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* for simplicity we support only ACR without arguments now */
	if (acr_type != 0x00 && acr_type != 0x10
	    && acr_type != 0x20 && acr_type != 0x21) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = cac_apdu_io(card, CAC_INS_GET_ACR, acr_type, 0, NULL, 0, &out, &len);
	if (len == 0) {
		r = SC_ERROR_FILE_NOT_FOUND;
	}
	if (r < 0)
		goto fail;

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
	    "got %"SC_FORMAT_LEN_SIZE_T"u bytes out=%p", len, out);

	*out_len = len;
	*out_buf = out;
	return SC_SUCCESS;

fail:
	if (out)
		free(out);
	*out_buf = NULL;
	*out_len = 0;
	return r;
}

/*
 * Read a CAC TLV file. Parameters specify if the TLV file is TL (Tag/Length) file or a V (value) file
 */
#define HIGH_BYTE_OF_SHORT(x) (((x)>> 8) & 0xff)
#define LOW_BYTE_OF_SHORT(x) ((x) & 0xff)
static int cac_read_file(sc_card_t *card, int file_type, u8 **out_buf, size_t *out_len)
{
	u8 params[2];
	u8 count[2];
	u8 *out = NULL;
	u8 *out_ptr;
	size_t offset = 0;
	size_t size = 0;
	size_t left = 0;
	size_t len;
	int r;

	params[0] = file_type;
	params[1] = 2;

	/* get the size */
	len = sizeof(count);
	out_ptr = count;
	r = cac_apdu_io(card, CAC_INS_READ_FILE, 0, 0, &params[0], sizeof(params), &out_ptr, &len);
	if (len == 0) {
		r = SC_ERROR_FILE_NOT_FOUND;
	}
	if (r < 0)
		goto fail;

	left = size = lebytes2ushort(count);
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		 "got %"SC_FORMAT_LEN_SIZE_T"u bytes out_ptr=%p count&=%p count[0]=0x%02x count[1]=0x%02x, len=0x%04"SC_FORMAT_LEN_SIZE_T"x (%"SC_FORMAT_LEN_SIZE_T"u)",
		 len, out_ptr, &count, count[0], count[1], size, size);
	out = out_ptr = malloc(size);
	if (out == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto fail;
	}
	for (offset += 2; left > 0; offset += len, left -= len, out_ptr += len) {
		len = MIN(left, CAC_MAX_CHUNK_SIZE);
		params[1] = len;
		r = cac_apdu_io(card, CAC_INS_READ_FILE, HIGH_BYTE_OF_SHORT(offset), LOW_BYTE_OF_SHORT(offset),
						&params[0], sizeof(params), &out_ptr, &len);
		/* if there is no data, assume there is no file */
		if (len == 0) {
			r = SC_ERROR_FILE_NOT_FOUND;
		}
		if (r < 0) {
			goto fail;
		}
	}
	*out_len = size;
	*out_buf = out;
	return SC_SUCCESS;
fail:
	if (out)
		free(out);
	*out_len = 0;
	return r;
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
	u8 *tl = NULL, *val = NULL;
	const u8 *tl_ptr, *val_ptr, *tl_start;
	u8 *tlv_ptr;
	const u8 *cert_ptr;
	size_t tl_len, val_len, tlv_len;
	size_t len, tl_head_len, cert_len;
	u8 cert_type, tag;

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
	if (priv->cache_buf) {
		free(priv->cache_buf);
		priv->cache_buf = NULL;
		priv->cache_buf_len = 0;
	}


	if (priv->object_type <= 0)
		 LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	r = cac_read_file(card, CAC_FILE_TAG, &tl, &tl_len);
	if (r < 0)  {
		goto done;
	}

	r = cac_read_file(card, CAC_FILE_VALUE, &val, &val_len);
	if (r < 0)
		goto done;

	switch (priv->object_type) {
	case CAC_OBJECT_TYPE_TLV_FILE:
		tlv_len = tl_len + val_len;
		priv->cache_buf = malloc(tlv_len);
		if (priv->cache_buf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		priv->cache_buf_len = tlv_len;

		for (tl_ptr = tl, val_ptr=val, tlv_ptr = priv->cache_buf;
				tl_len >= 2 && tlv_len > 0;
				val_len -= len, tlv_len -= len, val_ptr += len, tlv_ptr += len) {
			/* get the tag and the length */
			tl_start = tl_ptr;
			r = sc_simpletlv_read_tag(&tl_ptr, tl_len, &tag, &len);
			if (r != SC_SUCCESS && r != SC_ERROR_TLV_END_OF_CONTENTS)
				break;
			tl_head_len = (tl_ptr - tl_start);
			sc_simpletlv_put_tag(tag, len, tlv_ptr, tlv_len, &tlv_ptr);
			tlv_len -= tl_head_len;
			tl_len -= tl_head_len;

			/* don't crash on bad data */
			if (val_len < len) {
				sc_log(card->ctx, "Received too long value %"SC_FORMAT_LEN_SIZE_T"u, "
				    "while only %"SC_FORMAT_LEN_SIZE_T"u left. Truncating", len, val_len);
				len = val_len;
			}
			/* if we run out of return space, truncate */
			if (tlv_len < len) {
				len = tlv_len;
			}
			memcpy(tlv_ptr, val_ptr, len);
		}
		break;

	case CAC_OBJECT_TYPE_CERT:
		/* read file */
		sc_log(card->ctx, 
			 " obj= cert_file, val_len=%"SC_FORMAT_LEN_SIZE_T"u (0x%04"SC_FORMAT_LEN_SIZE_T"x)",
			 val_len, val_len);
		cert_len = 0;
		cert_ptr = NULL;
		cert_type = 0;
		for (tl_ptr = tl, val_ptr = val; tl_len >= 2;
		    val_len -= len, val_ptr += len, tl_len -= tl_head_len) {
			tl_start = tl_ptr;
			r = sc_simpletlv_read_tag(&tl_ptr, tl_len, &tag, &len);
			if (r != SC_SUCCESS && r != SC_ERROR_TLV_END_OF_CONTENTS)
				break;
			tl_head_len = tl_ptr - tl_start;

			/* incomplete value */
			if (val_len < len) {
				sc_log(card->ctx, "Read incomplete value %"SC_FORMAT_LEN_SIZE_T"u, "
				    "while only %"SC_FORMAT_LEN_SIZE_T"u left", len, val_len);
				break;
			}

			if (tag == CAC_TAG_CERTIFICATE) {
				cert_len = len;
				cert_ptr = val_ptr;
			}
			if (tag == CAC_TAG_CERTINFO) {
				if ((len >= 1) && (val_len >=1)) {
					cert_type = *val_ptr;
				}
			}
			if (tag == CAC_TAG_MSCUID) {
				sc_log_hex(card->ctx, "MSCUID", val_ptr, len);
			}
		}
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
		} else if (cert_len > 0) {
			priv->cache_buf = malloc(cert_len);
			if (priv->cache_buf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto done;
			}
			priv->cache_buf_len = cert_len;
			memcpy(priv->cache_buf, cert_ptr, cert_len);
		} else {
			sc_log(card->ctx, "Can't read zero-length certificate");
			goto done;
		}
		break;
	case CAC_OBJECT_TYPE_GENERIC:
		/* TODO
		 * We have some two buffers in unknown encoding that we
		 * need to present in PKCS#15 layer.
		 */
	default:
		/* Unknown object type */
		sc_log(card->ctx, "Unknown object type: %x", priv->object_type);
		r = SC_ERROR_INTERNAL;
		goto done;
	}

	/* OK we've read the data, now copy the required portion out to the callers buffer */
	priv->cached = 1;
	len = MIN(count, priv->cache_buf_len-idx);
	memcpy(buf, &priv->cache_buf[idx], len);
	r = len;
done:
	if (tl)
		free(tl);
	if (val)
		free(val);
	LOG_FUNC_RETURN(card->ctx, r);
}

/* CAC driver is read only */
static int cac_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

/* initialize getting a list and return the number of elements in the list */
static int cac_get_init_and_get_count(list_t *list, cac_object_t **entry, int *countp)
{
	*countp = list_size(list);
	list_iterator_start(list);
	*entry = list_iterator_next(list);
	return SC_SUCCESS;
}

/* finalize the list iterator */
static int cac_final_iterator(list_t *list)
{
	list_iterator_stop(list);
	return SC_SUCCESS;
}

/* fill in the obj_info for the current object on the list and advance to the next object */
static int cac_fill_object_info(list_t *list, cac_object_t **entry, sc_pkcs15_data_info_t *obj_info)
{
	memset(obj_info, 0, sizeof(sc_pkcs15_data_info_t));
	if (*entry == NULL) {
		return SC_ERROR_FILE_END_REACHED;
	}

	obj_info->path = (*entry)->path;
	obj_info->path.count = CAC_MAX_SIZE-1; /* read something from the object */
	obj_info->id.value[0] = ((*entry)->fd >> 8) & 0xff;
	obj_info->id.value[1] = (*entry)->fd & 0xff;
	obj_info->id.len = 2;
	strncpy(obj_info->app_label, (*entry)->name, SC_PKCS15_MAX_LABEL_SIZE-1);
	*entry = list_iterator_next(list);
	return SC_SUCCESS;
}

static int cac_get_serial_nr_from_CUID(sc_card_t* card, sc_serial_number_t* serial)
{
	cac_private_data_t * priv = CAC_DATA(card);

	LOG_FUNC_CALLED(card->ctx);
        if (card->serialnr.len)   {
                *serial = card->serialnr;
                LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
        }
	if (priv->cac_id_len) {
		serial->len = MIN(priv->cac_id_len, SC_MAX_SERIALNR);
		memcpy(serial->value, priv->cac_id, serial->len);
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);
}

static int cac_get_ACA_path(sc_card_t *card, sc_path_t *path)
{
	cac_private_data_t * priv = CAC_DATA(card);

	LOG_FUNC_CALLED(card->ctx);
	if (priv->aca_path) {
		*path = *priv->aca_path;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int cac_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	cac_private_data_t * priv = CAC_DATA(card);

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "cmd=%ld ptr=%p", cmd, ptr);

	if (priv == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	switch(cmd) {
		case SC_CARDCTL_CAC_GET_ACA_PATH:
			return cac_get_ACA_path(card, (sc_path_t *) ptr);
		case SC_CARDCTL_GET_SERIALNR:
			return cac_get_serial_nr_from_CUID(card, (sc_serial_number_t *) ptr);
		case SC_CARDCTL_CAC_INIT_GET_GENERIC_OBJECTS:
			return cac_get_init_and_get_count(&priv->general_list, &priv->general_current, (int *)ptr);
		case SC_CARDCTL_CAC_INIT_GET_CERT_OBJECTS:
			return cac_get_init_and_get_count(&priv->pki_list, &priv->pki_current, (int *)ptr);
		case SC_CARDCTL_CAC_GET_NEXT_GENERIC_OBJECT:
			return cac_fill_object_info(&priv->general_list, &priv->general_current, (sc_pkcs15_data_info_t *)ptr);
		case SC_CARDCTL_CAC_GET_NEXT_CERT_OBJECT:
			return cac_fill_object_info(&priv->pki_list, &priv->pki_current, (sc_pkcs15_data_info_t *)ptr);
		case SC_CARDCTL_CAC_FINAL_GET_GENERIC_OBJECTS:
			return cac_final_iterator(&priv->general_list);
		case SC_CARDCTL_CAC_FINAL_GET_CERT_OBJECTS:
			return cac_final_iterator(&priv->pki_list);
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

static int cac_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	/* CAC requires 8 byte response */
	u8 rbuf[8];
	u8 *rbufp = &rbuf[0];
	size_t out_len = sizeof rbuf;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = cac_apdu_io(card, 0x84, 0x00, 0x00, NULL, 0, &rbufp, &out_len);
	LOG_TEST_RET(card->ctx, r, "Could not get challenge");

	if (len < out_len) {
		out_len = len;
	}
	memcpy(rnd, rbuf, out_len);

	LOG_FUNC_RETURN(card->ctx, (int) out_len);
}

static int cac_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx, 
		 "flags=%08lx op=%d alg=%d algf=%08x algr=%08x kr0=%02x, krfl=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 env->flags, env->operation, env->algorithm,
		 env->algorithm_flags, env->algorithm_ref, env->key_ref[0],
		 env->key_ref_len);

	if (env->algorithm != SC_ALGORITHM_RSA) {
		 r = SC_ERROR_NO_CARD_SUPPORT;
	}


	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}


static int cac_restore_security_env(sc_card_t *card, int se_num)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int cac_rsa_op(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	int r;
	u8 *outp, *rbuf;
	size_t rbuflen, outplen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx, 
		 "datalen=%"SC_FORMAT_LEN_SIZE_T"u outlen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 datalen, outlen);

	outp = out;
	outplen = outlen;

	/* Not strictly necessary. This code requires the caller to have selected the correct PKI container
	 * and authenticated to that container with the verifyPin command... All of this under the reader lock.
	 * The PKCS #15 higher level driver code does all this correctly (it's the same for all cards, just
	 * different sets of APDU's that need to be called), so this call is really a little bit of paranoia */
	r = sc_lock(card);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, r);


	rbuf = NULL;
	rbuflen = 0;
	for (; datalen > CAC_MAX_CHUNK_SIZE; data += CAC_MAX_CHUNK_SIZE, datalen -= CAC_MAX_CHUNK_SIZE) {
		r = cac_apdu_io(card, CAC_INS_SIGN_DECRYPT, CAC_P1_STEP,  0,
			data, CAC_MAX_CHUNK_SIZE, &rbuf, &rbuflen);
		if (r < 0) {
			break;
		}
		if (rbuflen != 0) {
			int n = MIN(rbuflen, outplen);
			memcpy(outp,rbuf, n);
			outp += n;
			outplen -= n;
		}
		free(rbuf);
		rbuf = NULL;
		rbuflen = 0;
	}
	if (r < 0) {
		goto err;
	}
	rbuf = NULL;
	rbuflen = 0;
	r = cac_apdu_io(card, CAC_INS_SIGN_DECRYPT, CAC_P1_FINAL, 0, data, datalen, &rbuf, &rbuflen);
	if (r < 0) {
		goto err;
	}
	if (rbuflen != 0) {
		int n = MIN(rbuflen, outplen);
		memcpy(outp,rbuf, n);
		/*outp += n;     unused */
		outplen -= n;
	}
	free(rbuf);
	rbuf = NULL;
	r = outlen-outplen;

err:
	sc_unlock(card);
	if (r < 0) {
		sc_mem_clear(out, outlen);
	}
	if (rbuf) {
		free(rbuf);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int cac_compute_signature(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, cac_rsa_op(card, data, datalen, out, outlen));
}

static int cac_decipher(sc_card_t *card,
					 const u8 * data, size_t datalen,
					 u8 * out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, cac_rsa_op(card, data, datalen, out, outlen));
}

static int cac_parse_properties_object(sc_card_t *card, u8 type,
    const u8 *data, size_t data_len, cac_properties_object_t *object)
{
	size_t len;
	const u8 *val, *val_end;
	u8 tag;
	int parsed = 0;

	if (data_len < 11)
		return -1;

	/* Initilize: non-PKI applet */
	object->privatekey = 0;

	val = data;
	val_end = data + data_len;
	for (; val < val_end; val += len) {
		/* get the tag and the length */
		if (sc_simpletlv_read_tag(&val, val_end - val, &tag, &len) != SC_SUCCESS)
			break;

		switch (tag) {
		case CAC_TAG_OBJECT_ID:
			if (len != 2) {
				sc_log(card->ctx, "TAG: Object ID: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Object ID = 0x%02x 0x%02x", val[0], val[1]);
			memcpy(&object->oid, val, 2);
			parsed++;
			break;

		case CAC_TAG_BUFFER_PROPERTIES:
			if (len != 5) {
				sc_log(card->ctx, "TAG: Buffer Properties: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			/* First byte is "Type of Tag Supported" */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Buffer Properties: Type of Tag Supported = 0x%02x",
			    val[0]);
			object->simpletlv = val[0];
			parsed++;
			break;

		case CAC_TAG_PKI_PROPERTIES:
			/* 4th byte is "Private Key Initialized" */
			if (len != 4) {
				sc_log(card->ctx, "TAG: PKI Properties: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			if (type != CAC_TAG_PKI_OBJECT) {
				sc_log(card->ctx, "TAG: PKI Properties outside of PKI Object");
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: PKI Properties: Private Key Initialized = 0x%02x",
			    val[2]);
			object->privatekey = val[2];
			parsed++;
			break;

		default:
			/* ignore tags we don't understand */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Unknown (0x%02x)",tag );
			break;
		}
	}
	if (parsed < 2)
		return SC_ERROR_INVALID_DATA;

	return SC_SUCCESS;
}

static int cac_get_properties(sc_card_t *card, cac_properties_t *prop)
{
	u8 *rbuf = NULL;
	size_t rbuflen = 0, len;
	const u8 *val, *val_end;
	u8 tag;
	size_t i = 0;
	int r;
	prop->num_objects = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = cac_apdu_io(card, CAC_INS_GET_PROPERTIES, 0x01, 0x00, NULL, 0,
		&rbuf, &rbuflen);
	if (r < 0)
		return r;

	val = rbuf;
	val_end = val + rbuflen;
	for (; val < val_end; val += len) {
		/* get the tag and the length */
		if (sc_simpletlv_read_tag(&val, val_end - val, &tag, &len) != SC_SUCCESS)
			break;

		switch (tag) {
		case CAC_TAG_APPLET_INFORMATION:
			if (len != 5) {
				sc_log(card->ctx, "TAG: Applet Information: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Applet Information: Family: 0x%0x", val[0]);
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "     Applet Version: 0x%02x 0x%02x 0x%02x 0x%02x",
			    val[1], val[2], val[3], val[4]);
			break;

		case CAC_TAG_NUMBER_OF_OBJECTS:
			if (len != 1) {
				sc_log(card->ctx, "TAG: Num objects: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Num objects = %hhd", *val);
			/* make sure we do not overrun buffer */
			prop->num_objects = MIN(val[0], CAC_MAX_OBJECTS);
			break;

		case CAC_TAG_TV_BUFFER:
			if (len != 17) {
				sc_log(card->ctx, "TAG: TV Object: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: TV Object nr. %"SC_FORMAT_LEN_SIZE_T"u", i);
			if (i >= CAC_MAX_OBJECTS) {
				free(rbuf);
				return SC_SUCCESS;
			}

			if (cac_parse_properties_object(card, tag, val, len,
			    &prop->objects[i]) == SC_SUCCESS)
				i++;
			break;

		case CAC_TAG_PKI_OBJECT:
			if (len != 17) {
				sc_log(card->ctx, "TAG: PKI Object: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: PKI Object nr. %"SC_FORMAT_LEN_SIZE_T"u", i);
			if (i >= CAC_MAX_OBJECTS) {
				free(rbuf);
				return SC_SUCCESS;
			}

			if (cac_parse_properties_object(card, tag, val, len,
			    &prop->objects[i]) == SC_SUCCESS)
				i++;
			break;

		default:
			/* ignore tags we don't understand */
			sc_log(card->ctx, "TAG: Unknown (0x%02x), len=%"
			    SC_FORMAT_LEN_SIZE_T"u", tag, len);
			break;
		}
	}
	free(rbuf);
	/* sanity */
	if (i != prop->num_objects)
		sc_log(card->ctx, "The announced number of objects (%u) "
		    "did not match reality (%"SC_FORMAT_LEN_SIZE_T"u)",
		    prop->num_objects, i);
	prop->num_objects = i;

	return SC_SUCCESS;
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
		if (pathlen > 2) {
			path += 2;
			pathlen -= 2;
		}
	}


	/* CAC has multiple different type of objects that aren't PKCS #15. When we read
	 * them we need convert them to something PKCS #15 would understand. Find the object
	 * and object type here:
	 */
	if (priv) { /* don't record anything if we haven't been initialized yet */
		priv->object_type = CAC_OBJECT_TYPE_GENERIC;
		if (cac_is_cert(priv, in_path)) {
			priv->object_type = CAC_OBJECT_TYPE_CERT;
		}

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

	if (file_out != NULL) {
		apdu.p2 = 0;		/* first record, return FCI */
	}
	else {
		apdu.p2 = 0x0C;
	}

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

	/* This needs to come after the applet selection */
	if (priv && in_path->len >= 2) {
		/* get applet properties to know if we can treat the
		 * buffer as SimpleLTV and if we have PKI applet.
		 *
		 * Do this only if we select applets for reading
		 * (not during driver initialization)
		 */
		cac_properties_t prop;
		size_t i = -1;

		r = cac_get_properties(card, &prop);
		if (r == SC_SUCCESS) {
			for (i = 0; i < prop.num_objects; i++) {
				sc_log(card->ctx, "Searching for our OID: 0x%02x 0x%02x = 0x%02x 0x%02x",
				    prop.objects[i].oid[0], prop.objects[i].oid[1],
					in_path->value[0], in_path->value[1]);
				if (memcmp(prop.objects[i].oid,
				    in_path->value, 2) == 0)
					break;
			}
		}
		if (i < prop.num_objects) {
			if (prop.objects[i].privatekey)
				priv->object_type = CAC_OBJECT_TYPE_CERT;
			else if (prop.objects[i].simpletlv == 0)
				priv->object_type = CAC_OBJECT_TYPE_TLV_FILE;
		}
	}

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


/* select the Card Capabilities Container on CAC-2 */
static int cac_select_CCC(sc_card_t *card)
{
	return cac_select_file_by_type(card, &cac_CCC_Path, NULL);
}

/* Select ACA in non-standard location */
static int cac_select_ACA(sc_card_t *card)
{
	return cac_select_file_by_type(card, &cac_ACA_Path, NULL);
}

static int cac_path_from_cardurl(sc_card_t *card, sc_path_t *path, cac_card_url_t *val, int len)
{
	if (len < 10) {
		return SC_ERROR_INVALID_DATA;
	}
	sc_mem_clear(path, sizeof(sc_path_t));
	memcpy(path->aid.value, &val->rid, sizeof(val->rid));
	memcpy(&path->aid.value[5], val->applicationID, sizeof(val->applicationID));
	path->aid.len = sizeof(val->rid) + sizeof(val->applicationID);
	memcpy(path->value, val->objectID, sizeof(val->objectID));
	path->len = sizeof(val->objectID);
	path->type = SC_PATH_TYPE_FILE_ID;
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		 "path->aid=%x %x %x %x %x %x %x  len=%"SC_FORMAT_LEN_SIZE_T"u, path->value = %x %x len=%"SC_FORMAT_LEN_SIZE_T"u path->type=%d (%x)",
		 path->aid.value[0], path->aid.value[1], path->aid.value[2],
		 path->aid.value[3], path->aid.value[4], path->aid.value[5],
		 path->aid.value[6], path->aid.len, path->value[0],
		 path->value[1], path->len, path->type, path->type);
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		 "rid=%x %x %x %x %x  len=%"SC_FORMAT_LEN_SIZE_T"u appid= %x %x len=%"SC_FORMAT_LEN_SIZE_T"u objid= %x %x len=%"SC_FORMAT_LEN_SIZE_T"u",
		 val->rid[0], val->rid[1], val->rid[2], val->rid[3],
		 val->rid[4], sizeof(val->rid), val->applicationID[0],
		 val->applicationID[1], sizeof(val->applicationID),
		 val->objectID[0], val->objectID[1], sizeof(val->objectID));

	return SC_SUCCESS;
}

static int cac_parse_aid(sc_card_t *card, cac_private_data_t *priv, const u8 *aid, int aid_len)
{
	cac_object_t new_object;
	cac_properties_t prop;
	size_t i;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* Search for PKI applets (7 B). Ignore generic objects for now */
	if (aid_len != 7 || (memcmp(aid, CAC_1_RID "\x01", 6) != 0
	    && memcmp(aid, CAC_1_RID "\x00", 6) != 0))
		return SC_SUCCESS;

	sc_mem_clear(&new_object.path, sizeof(sc_path_t));
	memcpy(new_object.path.aid.value, aid, aid_len);
	new_object.path.aid.len = aid_len;

	/* Call without OID set will just select the AID without subseqent
	 * OID selection, which we need to figure out just now
	 */
	cac_select_file_by_type(card, &new_object.path, NULL);
	r = cac_get_properties(card, &prop);
	if (r < 0)
		return SC_ERROR_INTERNAL;

	for (i = 0; i < prop.num_objects; i++) {
		/* don't fail just because we have more certs than we can support */
		if (priv->cert_next >= MAX_CAC_SLOTS)
			return SC_SUCCESS;

		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		    "ACA: pki_object found, cert_next=%d (%s), privkey=%d",
		    priv->cert_next, get_cac_label(priv->cert_next),
		    prop.objects[i].privatekey);

		/* If the private key is not initialized, we can safely
		 * ignore this object here, but increase the pointer to follow
		 * the certificate labels
		 */
		if (!prop.objects[i].privatekey) {
			priv->cert_next++;
			continue;
		}

		/* OID here has always 2B */
		memcpy(new_object.path.value, &prop.objects[i].oid, 2);
		new_object.path.len = 2;
		new_object.path.type = SC_PATH_TYPE_FILE_ID;
		new_object.name = get_cac_label(priv->cert_next);
		new_object.fd = priv->cert_next+1;
		cac_add_object_to_list(&priv->pki_list, &new_object);
		priv->cert_next++;
	}

	return SC_SUCCESS;
}

static int cac_parse_cardurl(sc_card_t *card, cac_private_data_t *priv, cac_card_url_t *val, int len)
{
	cac_object_t new_object;
	const cac_object_t *obj;
	unsigned short object_id;
	int r;

	r = cac_path_from_cardurl(card, &new_object.path, val, len);
	if (r != SC_SUCCESS) {
		return r;
	}
	switch (val->cardApplicationType) {
	case CAC_APP_TYPE_PKI:
		/* we don't want to overflow the cac_label array. This test could
		 * go way if we create a label function that will create a unique label
		 * from a cert index.
		 */
		if (priv->cert_next >= MAX_CAC_SLOTS)
			break; /* don't fail just because we have more certs than we can support */
		new_object.name = get_cac_label(priv->cert_next);
		new_object.fd = priv->cert_next+1;
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"CARDURL: pki_object found, cert_next=%d (%s),", priv->cert_next, new_object.name);
		cac_add_object_to_list(&priv->pki_list, &new_object);
		priv->cert_next++;
		break;
	case CAC_APP_TYPE_GENERAL:
		object_id = bebytes2ushort(val->objectID);
		obj = cac_find_obj_by_id(object_id);
		if (obj == NULL)
			break; /* don't fail just because we don't recognize the object */
		new_object.name = obj->name;
		new_object.fd = 0;
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"CARDURL: gen_object found, objectID=%x (%s),", object_id, new_object.name);
		cac_add_object_to_list(&priv->general_list, &new_object);
		break;
	case CAC_APP_TYPE_SKI:
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"CARDURL: ski_object found");
	break;
	default:
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"CARDURL: unknown object_object found (type=0x%02x)", val->cardApplicationType);
		/* don't fail just because there is an unknown object in the CCC */
		break;
	}
	return SC_SUCCESS;
}

static int cac_parse_cuid(sc_card_t *card, cac_private_data_t *priv, cac_cuid_t *val, size_t len)
{
	size_t card_id_len;

	if (len < sizeof(cac_cuid_t)) {
		return SC_ERROR_INVALID_DATA;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "gsc_rid=%s", sc_dump_hex(val->gsc_rid, sizeof(val->gsc_rid)));
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "manufacture id=%x", val->manufacturer_id);
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "cac_type=%d", val->card_type);
	card_id_len = len - (&val->card_id - (u8 *)val);
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		 "card_id=%s (%"SC_FORMAT_LEN_SIZE_T"u)",
		 sc_dump_hex(&val->card_id, card_id_len),
		 card_id_len);
	priv->cuid = *val;
	priv->cac_id = malloc(card_id_len);
	if (priv->cac_id == NULL) {
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(priv->cac_id, &val->card_id, card_id_len);
	priv->cac_id_len = card_id_len;
	return SC_SUCCESS;
}
static int cac_process_CCC(sc_card_t *card, cac_private_data_t *priv);

static int cac_parse_CCC(sc_card_t *card, cac_private_data_t *priv, const u8 *tl,
						 size_t tl_len, u8 *val, size_t val_len)
{
	size_t len = 0;
	const u8 *tl_end = tl + tl_len;
	const u8 *val_end = val + val_len;
	sc_path_t new_path;
	int r;


	for (; (tl < tl_end) && (val< val_end); val += len) {
		/* get the tag and the length */
		u8 tag;
		r = sc_simpletlv_read_tag(&tl, tl_end - tl, &tag, &len);
		if (r != SC_SUCCESS && r != SC_ERROR_TLV_END_OF_CONTENTS) {
			sc_log(card->ctx, "Failed to parse tag from buffer");
			break;
		}
		if (val + len > val_end) {
			sc_log(card->ctx, "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
			break;
		}
		switch (tag) {
		case CAC_TAG_CUID:
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"TAG:CUID");
			r = cac_parse_cuid(card, priv, (cac_cuid_t *)val, len);
			if (r < 0)
				return r;
			break;
		case CAC_TAG_CC_VERSION_NUMBER:
			if (len != 1) {
				sc_log(card->ctx, "TAG: CC Version: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			/* ignore the version numbers for now */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				"TAG: CC Version = 0x%02x", *val);
			break;
		case CAC_TAG_GRAMMAR_VERION_NUMBER:
			if (len != 1) {
				sc_log(card->ctx, "TAG: Grammar Version: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			/* ignore the version numbers for now */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				"TAG: Grammar Version = 0x%02x", *val);
			break;
		case CAC_TAG_CARDURL:
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"TAG:CARDURL");
			r = cac_parse_cardurl(card, priv, (cac_card_url_t *)val, len);
			if (r < 0)
				return r;
			break;
		/*
		 * The following are really for file systems cards. This code only cares about CAC VM cards
		 */
		case CAC_TAG_PKCS15:
			if (len != 1) {
				sc_log(card->ctx, "TAG: PKCS15: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			/* TODO should verify that this is '0'. If it's not
			 * zero, we should drop out of here and let the PKCS 15
			 * code handle this card */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"TAG: PKCS15 = 0x%02x", *val);
			break;
		case CAC_TAG_DATA_MODEL:
			if (len != 1) {
				sc_log(card->ctx, "TAG: Registered Data Model Number: "
				    "Invalid length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"TAG: Registered Data Model Number (0x%02x)", *val);
			break;
		case CAC_TAG_CARD_APDU:
		case CAC_TAG_CAPABILITY_TUPLES:
		case CAC_TAG_STATUS_TUPLES:
		case CAC_TAG_REDIRECTION:
		case CAC_TAG_ERROR_CODES:
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"TAG: FSSpecific(0x%02x)", tag);
			break;
		case CAC_TAG_ACCESS_CONTROL:
			/* TODO handle access control later */
			sc_log_hex(card->ctx, "TAG:ACCESS Control", val, len);
			break;
		case CAC_TAG_NEXT_CCC:
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"TAG:NEXT CCC");
			r = cac_path_from_cardurl(card, &new_path, (cac_card_url_t *)val, len);
			if (r < 0)
				return r;

			r = cac_select_file_by_type(card, &new_path, NULL);
			if (r < 0)
				return r;

			r = cac_process_CCC(card, priv);
			if (r < 0)
				return r;
			break;
		default:
			/* ignore tags we don't understand */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,"TAG:Unknown (0x%02x)",tag );
			break;
		}
	}
	return SC_SUCCESS;
}

static int cac_process_CCC(sc_card_t *card, cac_private_data_t *priv)
{
	u8 *tl = NULL, *val = NULL;
	size_t tl_len, val_len;
	int r;


	r = cac_read_file(card, CAC_FILE_TAG, &tl, &tl_len);
	if (r < 0)
		goto done;

	r = cac_read_file(card, CAC_FILE_VALUE, &val, &val_len);
	if (r < 0)
		goto done;

	r = cac_parse_CCC(card, priv, tl, tl_len, val, val_len);
done:
	if (tl)
		free(tl);
	if (val)
		free(val);
	return r;
}

/* Service Applet Table (Table 5-21) should list all the applets on the
 * card, which is a good start if we don't have CCC
 */
static int cac_parse_ACA_service(sc_card_t *card, cac_private_data_t *priv,
    const u8 *val, size_t val_len)
{
	size_t len = 0;
	const u8 *val_end = val + val_len;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	for (; val < val_end; val += len) {
		/* get the tag and the length */
		u8 tag;
		if (sc_simpletlv_read_tag(&val, val_end - val, &tag, &len) != SC_SUCCESS)
			break;

		switch (tag) {
		case CAC_TAG_APPLET_FAMILY:
			if (len != 5) {
				sc_log(card->ctx, "TAG: Applet Information: "
				    "bad length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Applet Information: Family: 0x%02x", val[0]);
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "     Applet Version: 0x%02x 0x%02x 0x%02x 0x%02x",
			    val[1], val[2], val[3], val[4]);
			break;
		case CAC_TAG_NUMBER_APPLETS:
			if (len != 1) {
				sc_log(card->ctx, "TAG: Num applets: "
				    "bad length %"SC_FORMAT_LEN_SIZE_T"u", len);
				break;
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Num applets = %hhd", *val);
			break;
		case CAC_TAG_APPLET_ENTRY:
			/* Make sure we match the outer length */
			if (len < 3 || val[2] != len - 3) {
				sc_log(card->ctx, "TAG: Applet Entry: "
				    "bad length (%"SC_FORMAT_LEN_SIZE_T
				    "u) or length of internal buffer", len);
				break;
			}
			sc_debug_hex(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Applet Entry: AID", val + 3, val[2]);
			/* This is SimpleTLV prefixed with applet ID (1B) */
			r = cac_parse_aid(card, priv, val + 3, val[2]);
			if (r < 0)
				return r;
			break;
		default:
			/* ignore tags we don't understand */
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "TAG: Unknown (0x%02x)", tag);
			break;
		}
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
			/* Try to read first two bytes of the buffer to
			 * make sure it is not just malfunctioning card
			 */
			u8 params[2] = {CAC_FILE_TAG, 2};
			u8 data[2], *out_ptr = data;
			size_t len = 2;
			r = cac_apdu_io(card, CAC_INS_READ_FILE, 0, 0,
			    &params[0], sizeof(params), &out_ptr, &len);
			if (r != 2)
				continue;

			*index_out = i;
			return SC_SUCCESS;
		}
	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}

/*
 * This emulates CCC for Alt tokens, that do not come with CCC nor ACA applets
 */
static int cac_populate_cac_alt(sc_card_t *card, int index, cac_private_data_t *priv)
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
			    "CAC: pki_object found, cert_next=%d (%s),", i, pki_obj.name);
			pki_obj.path.aid.value[pki_obj.path.aid.len-1] = i;
			pki_obj.fd = i+1; /* don't use id of zero */
			cac_add_object_to_list(&priv->pki_list, &pki_obj);
		}
	}

	/* populate non-PKI objects */
	for (i=0; i < cac_object_count; i++) {
		r = cac_select_file_by_type(card, &cac_objects[i].path, NULL);
		if (r == SC_SUCCESS) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			    "CAC: obj_object found, cert_next=%d (%s),",
			    i, cac_objects[i].name);
			cac_add_object_to_list(&priv->general_list, &cac_objects[i]);
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
	val_len = cac_read_binary(card, 0, val, sizeof(buf), 0);
	if (val_len > 0) {
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

static int cac_process_ACA(sc_card_t *card, cac_private_data_t *priv)
{
	int r;
	u8 *val = NULL;
	size_t val_len;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* Assuming ACA is already selected */
	r = cac_get_acr(card, CAC_ACR_SERVICE, &val, &val_len);
	if (r < 0)
		goto done;

	r = cac_parse_ACA_service(card, priv, val, val_len);
        if (r == SC_SUCCESS) {
		priv->aca_path = malloc(sizeof(sc_path_t));
		if (!priv->aca_path) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		memcpy(priv->aca_path, &cac_ACA_Path, sizeof(sc_path_t));
	}
done:
	if (val)
		free(val);
	LOG_FUNC_RETURN(card->ctx, r);
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

	/* is this a CAC-2 specified in NIST Interagency Report 6887 -
	 * "Government Smart Card Interoperability Specification v2.1 July 2003" */
	r = cac_select_CCC(card);
	if (r == SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "CCC found, is CAC-2");
		if (!initialize) /* match card only */
			return r;

		priv = cac_new_private_data();
		if (!priv)
			return SC_ERROR_OUT_OF_MEMORY;
		r = cac_process_CCC(card, priv);
		if (r == SC_SUCCESS) {
			card->type = SC_CARD_TYPE_CAC_II;
			card->drv_data = priv;
			return r;
		}
	}

	/* Even some ALT tokens can be missing CCC so we should try with ACA */
	r = cac_select_ACA(card);
	if (r == SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "ACA found, is CAC-2 without CCC");
		if (!initialize) /* match card only */
			return r;

		if (!priv) {
			priv = cac_new_private_data();
			if (!priv)
				return SC_ERROR_OUT_OF_MEMORY;
		}
		r = cac_process_ACA(card, priv);
		if (r == SC_SUCCESS) {
			card->type = SC_CARD_TYPE_CAC_II;
			card->drv_data = priv;
			return r;
		}
	}

	/* is this a CAC Alt token without any accompanying structures */
	r = cac_find_first_pki_applet(card, &index);
	if (r == SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "PKI applet found, is bare CAC Alt");
		if (!initialize) /* match card only */
			return r;

		if (!priv) {
			priv = cac_new_private_data();
			if (!priv)
				return SC_ERROR_OUT_OF_MEMORY;
		}
		card->drv_data = priv; /* needed for the read_binary() */
		r = cac_populate_cac_alt(card, index, priv);
		if (r == SC_SUCCESS) {
			card->type = SC_CARD_TYPE_CAC_II;
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

static int cac_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	/* CAC, like PIV needs Extra validation of (new) PIN during
	 * a PIN change request, to ensure it's not outside the
	 * FIPS 201 4.1.6.1 (numeric only) and * FIPS 140-2
	 * (6 character minimum) requirements.
	 */
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (data->cmd == SC_PIN_CMD_CHANGE) {
		int i = 0;
		if (data->pin2.len < 6) {
			return SC_ERROR_INVALID_PIN_LENGTH;
		}
		for(i=0; i < data->pin2.len; ++i) {
			if (!isdigit(data->pin2.data[i])) {
				return SC_ERROR_INVALID_DATA;
			}
		}
	}

	return  iso_drv->ops->pin_cmd(card, data, tries_left);
}

static struct sc_card_operations cac_ops;

static struct sc_card_driver cac_drv = {
	"Common Access Card (CAC)",
	"cac",
	&cac_ops,
	NULL, 0, NULL
};

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	cac_ops = *iso_drv->ops;
	cac_ops.match_card = cac_match_card;
	cac_ops.init = cac_init;
	cac_ops.finish = cac_finish;

	cac_ops.select_file =  cac_select_file; /* need to record object type */
	cac_ops.get_challenge = cac_get_challenge;
	cac_ops.read_binary = cac_read_binary;
	cac_ops.write_binary = cac_write_binary;
	cac_ops.set_security_env = cac_set_security_env;
	cac_ops.restore_security_env = cac_restore_security_env;
	cac_ops.compute_signature = cac_compute_signature;
	cac_ops.decipher =  cac_decipher;
	cac_ops.card_ctl = cac_card_ctl;
	cac_ops.pin_cmd = cac_pin_cmd;

	return &cac_drv;
}


struct sc_card_driver * sc_get_cac_driver(void)
{
	return sc_get_driver();
}
