/*
 * card-skeid4.c: Support for (IDEMIA Cosmo) cards issued as identity documents in Slovakia
 *
 * Copyright (C) 2023 Juraj Šarinay <juraj@sarinay.com>
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

#include <string.h>
#include <stdlib.h>
#include "internal.h"

#include "iso7816.h"
#include "asn1.h"

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations skeid4_ops;
static struct sc_card_driver skeid4_drv = {
	"Slovak eID card v4",
	"skeid4",
	&skeid4_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table skeid4_atrs[] = {
  /* Slovak eID v4 - Cosmo 9.2 */
  {"3b:df:96:ff:81:b1:fe:45:1f:87:00:31:b9:64:09:37:72:13:73:84:01:e0:00:00:00:00", NULL, NULL, SC_CARD_TYPE_SKEID_V4, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

/* private data */
typedef struct skeid4_data {
	const sc_security_env_t * sec_env;
} skeid4_data_t;

#define SKEID4_KNOWN_URL_LEN 46
#define SKEID4_URL_OFFSET 25

static int skeid4_known_url(sc_card_t * card)
{
	const char *known_url = "http://www.minv.sk/cif/cif-sk-eid-v4-cosmo.xml";
	unsigned char buf[SKEID4_KNOWN_URL_LEN];

	sc_path_t path;
	sc_format_path("3F002F01", &path);
	int r = sc_select_file(card, &path, NULL);

	int bytes_read = sc_read_binary(card, SKEID4_URL_OFFSET, buf, SKEID4_KNOWN_URL_LEN, 0);

	r = SC_ERROR_WRONG_CARD;

	if (bytes_read == SKEID4_KNOWN_URL_LEN && !memcmp(buf, known_url, SKEID4_KNOWN_URL_LEN))
		r = SC_SUCCESS;
	return r;
}


static int skeid4_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, skeid4_atrs, &card->type) != SC_SUCCESS || skeid4_known_url(card) != SC_SUCCESS)
		return 0;

	sc_log(card->ctx,  "Slovak eID card v4 (Cosmo 9.2)");

	return 1;
}

static int skeid4_init(sc_card_t *card)
{
	skeid4_data_t * priv = NULL;
	const unsigned long flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	priv = calloc(1, sizeof(skeid4_data_t));
	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	card->drv_data = priv;

	card->name = "Slovak eID v4 (Cosmo)";
	card->type = SC_CARD_TYPE_SKEID_V4;
	card->cla = 0x00;

	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO | SC_CARD_CAP_APDU_EXT;

	r = _sc_card_add_rsa_alg(card, 3072, flags, 0);

	LOG_FUNC_RETURN(card->ctx, r);
}

static int skeid4_finish(sc_card_t *card)
{
	int r = 0;

	if (card == NULL )
		return 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* free priv data */
	if (card->drv_data) { /* priv */
		free(card->drv_data);
		card->drv_data = NULL;
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int skeid4_set_security_env(sc_card_t *card,
		const sc_security_env_t *env,
		int se_num)
{
	struct sc_apdu apdu;
	u8 sbuf[6];
	u8 *p;
	int r;
	u8 algo_ref;

	skeid4_data_t * priv = (skeid4_data_t *)card->drv_data;

	if (card == NULL || env == NULL || env->key_ref_len != 1) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);

	if (env->operation == SC_SEC_OPERATION_DECIPHER) {
		apdu.p2 = 0xB8;
		algo_ref = 0x1A;
	}
	else if (env->operation != SC_SEC_OPERATION_SIGN)
		return SC_ERROR_INVALID_ARGUMENTS;
	else if (*env->key_ref == 0x60) {
		apdu.p2 = 0xA4;
		algo_ref = 2;
	}
	else {
		apdu.p2 = 0xB6;
		algo_ref = 0x42;
	}

	p = sbuf;

	*p++ = 0x84; /* key reference */
	*p++ = 1;
	*p++ = *env->key_ref;

	*p++ = 0x80;	/* algorithm reference */
	*p++ = 0x01;
	*p++ = algo_ref;

	apdu.lc = 6;
	apdu.datalen = 6;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		sc_log(card->ctx, "%s: APDU transmit failed", sc_strerror(r));
		goto err;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
		sc_log(card->ctx, "%s: Card returned error", sc_strerror(r));
		goto err;
	}

	priv->sec_env = env ;
	r = SC_SUCCESS;
err:
	return r;
}

static int skeid4_select_file(struct sc_card *card, const struct sc_path *in_path, struct sc_file **file_out)
{
	// adapted from iso7816_select_file

	struct sc_context *ctx;
	struct sc_apdu apdu;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	const unsigned char *path;
	int r, pathlen, pathtype;
	int select_mf = 0;
	struct sc_file *file = NULL;
	const u8 *buffer;
	size_t buffer_len;
	unsigned int cla, tag;

	if (card == NULL || in_path == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	ctx = card->ctx;
	path = in_path->value;
	pathlen = in_path->len;
	pathtype = in_path->type;

	if (in_path->aid.len || pathtype == SC_PATH_TYPE_FROM_CURRENT || pathtype == SC_PATH_TYPE_FILE_ID) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);

	switch (pathtype) {
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
		        apdu.p1 = 2;
			if (pathlen == 2) {	/* only 3F00 supplied */
				select_mf = 1;
				break;
			}
			path += 2;
			pathlen -= 2;
		}
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_2_SHORT;
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL && !select_mf) {
		apdu.p2 = 0;		/* return FCI */
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = sc_get_max_recv_size(card) < 256 ? sc_get_max_recv_size(card) : 256;
	}
	else {
		apdu.p2 = 0x0C;		/* return nothing */
		apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r || !file_out)
		LOG_FUNC_RETURN(ctx, r);

	if (select_mf)   {
		/* SELECT MF was called with P2 == 0x0C */
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		*file_out = file;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	if (apdu.resplen < 2 ||
		(apdu.resp[0] != ISO7816_TAG_FCI && apdu.resp[0] !=ISO7816_TAG_FCP))
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	file = sc_file_new();
	if (file == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	file->path = *in_path;
	if (card->ops->process_fci == NULL) {
		sc_file_free(file);
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	buffer = apdu.resp;
	r = sc_asn1_read_tag(&buffer, apdu.resplen, &cla, &tag, &buffer_len);
	if (r == SC_SUCCESS)
		card->ops->process_fci(card, file, buffer, buffer_len);
	*file_out = file;

	return SC_SUCCESS;
}

static int
skeid4_compute_signature(struct sc_card *card,
		const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;

	// SHA-256 DigestInfo
	u8 prepended_data[51] = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

	if (card == NULL || data == NULL || out == NULL ||
	    ((datalen != 32 + 19 || memcmp(data, prepended_data, 19)) && datalen != 32))
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	skeid4_data_t * priv = (skeid4_data_t *)card->drv_data;

	// depending on the key, the operation is either PSE or INTERNAL AUTHENTICATE
	if (*priv->sec_env->key_ref != 0x60) {
		sc_log(card->ctx, "qualified signature requested, performing PSE.");
		const u8 * data_sans_digestinfo;

		data_sans_digestinfo = data;
		if (datalen == 51)
		  data_sans_digestinfo = data + 19;
		// INS: 0x88  PERFORM SECURITY OPERATION

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x2A, 0x9E, 0x9A);

		apdu.data = data_sans_digestinfo;
		apdu.lc = 32;
		apdu.datalen = 32;
	}
	else {
		sc_log(card->ctx, "advanced signature requested, performing INTERNAL AUTHENTICATE.");
		const u8 * data_with_digestinfo;

		if (datalen == 32) {
		// prepend SHA256 DigestInfo
			memcpy(prepended_data + 19, data, 32);
			data_with_digestinfo = prepended_data;
		}
		else data_with_digestinfo = data;

		// INS: 0x88  INTERNAL AUTHENTICATE

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x88, 0, 0);

		apdu.data = data_with_digestinfo;
		apdu.lc = 51;
		apdu.datalen = 51;
	}

	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = 0;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, apdu.resplen);

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
skeid4_decipher(struct sc_card *card,
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
	       "skeid4 decipher: in-len %"SC_FORMAT_LEN_SIZE_T"u, out-len %"SC_FORMAT_LEN_SIZE_T"u",
	       crgram_len, outlen);

	sbuf = malloc(crgram_len + 1);
	if (sbuf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x2A, 0x80, 0x86);
	apdu.resp    = out;
	apdu.resplen = outlen;
	apdu.le      = 0;

	sbuf[0] = 0x81; /* padding indicator byte: 0x81 proprietary */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;

	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, crgram_len);
	free(sbuf);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, apdu.resplen);
	else
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

struct sc_card_driver * sc_get_skeid4_driver(void)
{
	if (iso_ops == NULL) iso_ops = sc_get_iso7816_driver()->ops;
	skeid4_ops = *iso_ops;
	skeid4_ops.match_card = skeid4_match_card;
	skeid4_ops.init = skeid4_init;
	skeid4_ops.finish = skeid4_finish;
	skeid4_ops.set_security_env = skeid4_set_security_env;
	skeid4_ops.select_file = skeid4_select_file;
	skeid4_ops.compute_signature = skeid4_compute_signature;
	skeid4_ops.decipher = skeid4_decipher;
	return &skeid4_drv;
}
