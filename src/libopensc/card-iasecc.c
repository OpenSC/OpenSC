/*
 * card-iasecc.c: Support for IAS/ECC smart cards
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@gmail.com>
 *			OpenTrust <www.opentrust.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "opensc.h"
#include "sc-ossl-compat.h"
/* #include "sm.h" */
#include "pkcs15.h"
/* #include "hash-strings.h" */
#include "gp.h"

#include "iasecc.h"

#define IASECC_CARD_DEFAULT_FLAGS ( 0			\
		| SC_ALGORITHM_ONBOARD_KEY_GEN		\
		| SC_ALGORITHM_RSA_PAD_ISO9796		\
		| SC_ALGORITHM_RSA_PAD_PKCS1		\
		| SC_ALGORITHM_RSA_HASH_NONE		\
		| SC_ALGORITHM_RSA_HASH_SHA1		\
		| SC_ALGORITHM_RSA_HASH_SHA256)

#define IASECC_CARD_DEFAULT_CAPS ( 0 			\
		| SC_CARD_CAP_RNG			\
		| SC_CARD_CAP_APDU_EXT			\
		| SC_CARD_CAP_USE_FCI_AC		\
		| SC_CARD_CAP_ISO7816_PIN_INFO)

/* generic iso 7816 operations table */
static const struct sc_card_operations *iso_ops = NULL;

/* our operations table with overrides */
static struct sc_card_operations iasecc_ops;

static struct sc_card_driver iasecc_drv = {
	"IAS-ECC",
	"iasecc",
	&iasecc_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table iasecc_known_atrs[] = {
	{ "3B:7F:96:00:00:00:31:B8:64:40:70:14:10:73:94:01:80:82:90:00",
	  "FF:FF:FF:FF:FF:FF:FF:FE:FF:FF:00:00:FF:FF:FF:FF:FF:FF:FF:FF",
		"IAS/ECC Gemalto", SC_CARD_TYPE_IASECC_GEMALTO,  0, NULL },
        { "3B:DD:00:00:81:31:FE:45:80:F9:A0:00:00:00:77:01:08:00:07:90:00:00",
	  "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00",
		"IAS/ECC v1.0.1 Oberthur", SC_CARD_TYPE_IASECC_OBERTHUR,  0, NULL },
	{ "3B:7D:13:00:00:4D:44:57:2D:49:41:53:2D:43:41:52:44:32", NULL,
		"IAS/ECC v1.0.1 Sagem MDW-IAS-CARD2", SC_CARD_TYPE_IASECC_SAGEM,  0, NULL },
	{ "3B:7F:18:00:00:00:31:B8:64:50:23:EC:C1:73:94:01:80:82:90:00", NULL,
		"IAS/ECC v1.0.1 Sagem ypsID S3", SC_CARD_TYPE_IASECC_SAGEM,  0, NULL },
	{ "3B:DF:96:00:80:31:FE:45:00:31:B8:64:04:1F:EC:C1:73:94:01:80:82:90:00:EC", NULL,
		"IAS/ECC Morpho MinInt - Agent Card", SC_CARD_TYPE_IASECC_MI, 0, NULL },
	{ "3B:DF:18:FF:81:91:FE:1F:C3:00:31:B8:64:0C:01:EC:C1:73:94:01:80:82:90:00:B3", NULL,
		"IAS/ECC v1.0.1 Amos", SC_CARD_TYPE_IASECC_AMOS, 0, NULL },
	{ "3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:02:04:03:55:00:02:34", NULL,
		"IAS/ECC v1.0.1 Amos", SC_CARD_TYPE_IASECC_AMOS, 0, NULL },
	{ "3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:01:0B:03:52:00:05:38", NULL,
		"IAS/ECC v1.0.1 Amos", SC_CARD_TYPE_IASECC_AMOS, 0, NULL },
	{
		.atr     = "3B:AC:00:40:2A:00:12:25:00:64:80:00:03:10:00:90:00",
		.atrmask = "FF:00:00:00:00:FF:FF:FF:FF:FF:FF:00:00:00:FF:FF:FF",
		.name = "IAS/ECC CPx",
		.type = SC_CARD_TYPE_IASECC_CPX,
	},
	{
		.atr     = "2B:8F:80:01:00:31:B8:64:04:B0:EC:C1:73:94:01:80:82:90:00:0E",
		.atrmask = "FF:FF:FF:FF:FF:FF:FF:FF:00:00:FF:C0:FF:FF:FF:FF:FF:FF:FF:FF",
		.name = "IAS/ECC CPxCL",
		.type = SC_CARD_TYPE_IASECC_CPXCL,
	},
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_aid OberthurIASECC_AID = {
	{0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00}, 16
};

static struct sc_aid MIIASECC_AID = {
	{ 0x4D, 0x49, 0x4F, 0x4D, 0x43, 0x54}, 6
};

struct iasecc_pin_status  {
	unsigned char sha1[SHA_DIGEST_LENGTH];
	unsigned char reference;

	struct iasecc_pin_status *next;
	struct iasecc_pin_status *prev;
};

struct iasecc_pin_status *checked_pins = NULL;

/* Any absent field is set to -1, except scbs, which is always present */
struct iasecc_pin_policy {
	int min_length;
	int max_length;
	int stored_length;
	int tries_maximum;
	int tries_remaining;
	unsigned char scbs[IASECC_MAX_SCBS];
};

static int iasecc_select_file(struct sc_card *card, const struct sc_path *path, struct sc_file **file_out);
static int iasecc_process_fci(struct sc_card *card, struct sc_file *file, const unsigned char *buf, size_t buflen);
static int iasecc_get_serialnr(struct sc_card *card, struct sc_serial_number *serial);
static int iasecc_sdo_get_data(struct sc_card *card, struct iasecc_sdo *sdo);
static int iasecc_pin_get_policy (struct sc_card *card, struct sc_pin_cmd_data *data, struct iasecc_pin_policy *pin);
static int iasecc_pin_get_status(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left);
static int iasecc_pin_get_info(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left);
static int iasecc_check_update_pin(struct sc_pin_cmd_data *data, struct sc_pin_cmd_pin *pin);
static void iasecc_set_pin_padding(struct sc_pin_cmd_data *data, struct sc_pin_cmd_pin *pin,
				   size_t pad_len);
static int iasecc_pin_merge_policy(struct sc_card *card, struct sc_pin_cmd_data *data,
				   struct sc_pin_cmd_pin *pin, struct iasecc_pin_policy *policy);
static int iasecc_get_free_reference(struct sc_card *card, struct iasecc_ctl_get_free_reference *ctl_data);
static int iasecc_sdo_put_data(struct sc_card *card, struct iasecc_sdo_update *update);

#ifdef ENABLE_SM
static int _iasecc_sm_read_binary(struct sc_card *card, unsigned int offs, unsigned char *buf, size_t count);
static int _iasecc_sm_update_binary(struct sc_card *card, unsigned int offs, const unsigned char *buff, size_t count);
#endif

static int
iasecc_chv_cache_verified(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_pin_status *pin_status = NULL, *current = NULL;

	LOG_FUNC_CALLED(ctx);

	for(current = checked_pins; current; current = current->next)
		if (current->reference == pin_cmd->pin_reference)
			break;

	if (current)   {
		sc_log(ctx, "iasecc_chv_cache_verified() current PIN-%i", current->reference);
		pin_status = current;
	}
	else   {
		pin_status = calloc(1, sizeof(struct iasecc_pin_status));
		if (!pin_status)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot callocate PIN status info");
		sc_log(ctx, "iasecc_chv_cache_verified() allocated %p", pin_status);
	}

	pin_status->reference = pin_cmd->pin_reference;
	if (pin_cmd->pin1.data)
		SHA1(pin_cmd->pin1.data, pin_cmd->pin1.len, pin_status->sha1);
	else
		memset(pin_status->sha1, 0, SHA_DIGEST_LENGTH);

	sc_log_hex(ctx, "iasecc_chv_cache_verified() sha1(PIN)", pin_status->sha1, SHA_DIGEST_LENGTH);

	if (!current)   {
		if (!checked_pins)   {
			checked_pins = pin_status;
		}
		else   {
		checked_pins->prev = pin_status;
			pin_status->next = checked_pins;
			checked_pins = pin_status;
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_chv_cache_clean(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_pin_status *current = NULL;

	LOG_FUNC_CALLED(ctx);

	for(current = checked_pins; current; current = current->next)
		if (current->reference == pin_cmd->pin_reference)
			break;

	if (!current)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);


	if (current->next && current->prev)   {
		current->prev->next = current->next;
		current->next->prev = current->prev;
	}
	else if (!current->prev)   {
		checked_pins = current->next;
	}
	else if (!current->next && current->prev)   {
		current->prev->next = NULL;
	}

	free(current);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static struct iasecc_pin_status *
iasecc_chv_cache_is_verified(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_pin_status *current = NULL;
	unsigned char data_sha1[SHA_DIGEST_LENGTH];

	LOG_FUNC_CALLED(ctx);

	if (pin_cmd->pin1.data)
		SHA1(pin_cmd->pin1.data, pin_cmd->pin1.len, data_sha1);
	else
		memset(data_sha1, 0, SHA_DIGEST_LENGTH);
	sc_log_hex(ctx, "data_sha1: %s", data_sha1, SHA_DIGEST_LENGTH);

	for(current = checked_pins; current; current = current->next)
		if (current->reference == pin_cmd->pin_reference)
			break;

	if (current && !memcmp(data_sha1, current->sha1, SHA_DIGEST_LENGTH))   {
		sc_log(ctx, "PIN-%i status 'verified'", pin_cmd->pin_reference);
		return current;
	}

	sc_log(ctx, "PIN-%i status 'not verified'", pin_cmd->pin_reference);
	return NULL;
}


static int
iasecc_select_mf(struct sc_card *card, struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *mf_file = NULL;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (file_out)
		*file_out = NULL;

	memset(&path, 0, sizeof(struct sc_path));
	if (!card->ef_atr || !card->ef_atr->aid.len)   {
		struct sc_apdu apdu;
		unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];

		/* ISO 'select' command fails when not FCP data returned */
		sc_format_path("3F00", &path);
		path.type = SC_PATH_TYPE_FILE_ID;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
		apdu.lc = path.len;
		apdu.data = path.value;
		apdu.datalen = path.len;
		apdu.resplen = sizeof(apdu_resp);
		apdu.resp = apdu_resp;

		/* TODO: this might be obsolete now that 0x0c (no data) is default for p2 */
		if (card->type == SC_CARD_TYPE_IASECC_MI2)
			apdu.p2 = 0x04;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, rv, "Cannot select MF");
	}
	else   {
		memset(&path, 0, sizeof(path));
		path.type = SC_PATH_TYPE_DF_NAME;
		memcpy(path.value, card->ef_atr->aid.value, card->ef_atr->aid.len);
		path.len = card->ef_atr->aid.len;
		rv = iasecc_select_file(card, &path, file_out);
		LOG_TEST_RET(ctx, rv, "Unable to ROOT selection");
	}

	/* Ignore the FCP of the MF, because:
	 * - some cards do not return it;
	 * - there is not need of it -- create/delete of the files in MF is not envisaged.
	 */
	mf_file = sc_file_new();
	if (mf_file == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate MF file");
	mf_file->type = SC_FILE_TYPE_DF;
	mf_file->path = path;

	if (card->cache.valid) {
		sc_file_free(card->cache.current_df);
	}
	card->cache.current_df = NULL;

	if (card->cache.valid) {
		sc_file_free(card->cache.current_ef);
	}
	card->cache.current_ef = NULL;

	sc_file_dup(&card->cache.current_df, mf_file);
	card->cache.valid = 1;

	if (file_out && *file_out == NULL)
		*file_out = mf_file;
	else
		sc_file_free(mf_file);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_select_aid(struct sc_card *card, struct sc_aid *aid, unsigned char *out, size_t *out_len)
{
	struct sc_apdu apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	LOG_FUNC_CALLED(card->ctx);

	/* Select application (deselect previously selected application) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = aid->len;
	apdu.data = aid->value;
	apdu.datalen = aid->len;
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Cannot select AID");

	if (*out_len < apdu.resplen)
		LOG_TEST_RET(card->ctx, SC_ERROR_BUFFER_TOO_SMALL, "Cannot select AID");
	memcpy(out, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int
iasecc_match_card(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int i;

	i = _sc_match_atr(card, iasecc_known_atrs, &card->type);
	if (i < 0)   {
		sc_log(ctx, "card not matched");
		return 0;
	}

	sc_log(ctx, "'%s' card matched", iasecc_known_atrs[i].name);
	return 1;
}


static int iasecc_parse_ef_atr(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *pdata = (struct iasecc_private_data *) card->drv_data;
	struct iasecc_version *version = &pdata->version;
	struct iasecc_io_buffer_sizes *sizes = &pdata->max_sizes;
	int rv;

	LOG_FUNC_CALLED(ctx);
	rv = sc_parse_ef_atr(card);
	LOG_TEST_RET(ctx, rv, "MF selection error");

	if (card->ef_atr->pre_issuing_len < 4)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid pre-issuing data");

	version->ic_manufacturer =	card->ef_atr->pre_issuing[0];
	version->ic_type =		card->ef_atr->pre_issuing[1];
	version->os_version =		card->ef_atr->pre_issuing[2];
	version->iasecc_version =	card->ef_atr->pre_issuing[3];
	sc_log(ctx, "EF.ATR: IC manufacturer/type %X/%X, OS/IasEcc versions %X/%X",
		version->ic_manufacturer, version->ic_type, version->os_version, version->iasecc_version);

	if (card->ef_atr->issuer_data_len < 16)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid issuer data");

	sizes->send =	 card->ef_atr->issuer_data[2] * 0x100 + card->ef_atr->issuer_data[3];
	sizes->send_sc = card->ef_atr->issuer_data[6] * 0x100 + card->ef_atr->issuer_data[7];
	sizes->recv =	 card->ef_atr->issuer_data[10] * 0x100 + card->ef_atr->issuer_data[11];
	sizes->recv_sc = card->ef_atr->issuer_data[14] * 0x100 + card->ef_atr->issuer_data[15];

	sc_log(ctx,
		"EF.ATR: IO Buffer Size send/sc %"SC_FORMAT_LEN_SIZE_T"d/%"SC_FORMAT_LEN_SIZE_T"d "
		"recv/sc %"SC_FORMAT_LEN_SIZE_T"d/%"SC_FORMAT_LEN_SIZE_T"d",
		sizes->send, sizes->send_sc, sizes->recv, sizes->recv_sc);

	card->max_send_size = sizes->send;
	card->max_recv_size = sizes->recv;

	/* Most of the card producers interpret 'send' values as "maximum APDU data size".
	 * Oberthur strictly follows specification and interpret these values as "maximum APDU command size".
	 * Here we need 'data size'.
	 */
	if (card->max_send_size > 0xFF)
		card->max_send_size -= 5;

	sc_log(ctx,
	       "EF.ATR: max send/recv sizes %"SC_FORMAT_LEN_SIZE_T"X/%"SC_FORMAT_LEN_SIZE_T"X",
	       card->max_send_size, card->max_recv_size);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_init_gemalto(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	unsigned int flags;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	flags = IASECC_CARD_DEFAULT_FLAGS;

	card->caps = IASECC_CARD_DEFAULT_CAPS;

	sc_format_path("3F00", &path);
	if (SC_SUCCESS != sc_select_file(card, &path, NULL)) {
		/* Result ignored*/
		sc_log(card->ctx, "Warning, MF select failed");
	}

	rv = iasecc_parse_ef_atr(card);
	sc_log(ctx, "rv %i", rv);
	if (rv == SC_ERROR_FILE_NOT_FOUND)   {
		sc_log(ctx, "Select MF");
		rv = iasecc_select_mf(card, NULL);
		sc_log(ctx, "rv %i", rv);
		LOG_TEST_RET(ctx, rv, "MF selection error");

		rv = iasecc_parse_ef_atr(card);
		sc_log(ctx, "rv %i", rv);
	}
	sc_log(ctx, "rv %i", rv);
	LOG_TEST_RET(ctx, rv, "Cannot read/parse EF.ATR");

	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_oberthur_match(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *hist = card->reader->atr_info.hist_bytes;

	LOG_FUNC_CALLED(ctx);

	if (*hist != 0x80 || ((*(hist+1)&0xF0) != 0xF0))
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);

	sc_log_hex(ctx, "AID in historical_bytes", hist + 2, *(hist+1) & 0x0F);

	if (memcmp(hist + 2, OberthurIASECC_AID.value, *(hist+1) & 0x0F))
		LOG_FUNC_RETURN(ctx, SC_ERROR_RECORD_NOT_FOUND);

	if (!card->ef_atr)
		card->ef_atr = calloc(1, sizeof(struct sc_ef_atr));
	if (!card->ef_atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(card->ef_atr->aid.value, OberthurIASECC_AID.value, OberthurIASECC_AID.len);
	card->ef_atr->aid.len = OberthurIASECC_AID.len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_init_oberthur(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned int flags;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	flags = IASECC_CARD_DEFAULT_FLAGS;

	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	card->caps = IASECC_CARD_DEFAULT_CAPS;

	iasecc_parse_ef_atr(card);

	/* if we fail to select CM, */
	if (gp_select_card_manager(card)) {
		gp_select_isd_rid(card);
	}

	rv = iasecc_oberthur_match(card);
	LOG_TEST_RET(ctx, rv, "unknown Oberthur's IAS/ECC card");

	rv = iasecc_select_mf(card, NULL);
	LOG_TEST_RET(ctx, rv, "MF selection error");

	rv = iasecc_parse_ef_atr(card);
	LOG_TEST_RET(ctx, rv, "EF.ATR read or parse error");

	sc_log(ctx, "EF.ATR(aid:'%s')", sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len));
	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_mi_match(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned char resp[0x100];
	size_t resp_len;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	resp_len = sizeof(resp);
	rv = iasecc_select_aid(card, &MIIASECC_AID, resp, &resp_len);
	LOG_TEST_RET(ctx, rv, "IASECC: failed to select MI IAS/ECC applet");

	if (!card->ef_atr)
		card->ef_atr = calloc(1, sizeof(struct sc_ef_atr));
	if (!card->ef_atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(card->ef_atr->aid.value, MIIASECC_AID.value, MIIASECC_AID.len);
	card->ef_atr->aid.len = MIIASECC_AID.len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_init_amos_or_sagem(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned int flags;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	flags = IASECC_CARD_DEFAULT_FLAGS;

	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	card->caps = IASECC_CARD_DEFAULT_CAPS;

	if (card->type == SC_CARD_TYPE_IASECC_MI)   {
		rv = iasecc_mi_match(card);
		if (rv)
			card->type = SC_CARD_TYPE_IASECC_MI2;
		else
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	rv = iasecc_parse_ef_atr(card);
	if (rv == SC_ERROR_FILE_NOT_FOUND)   {
		rv = iasecc_select_mf(card, NULL);
		LOG_TEST_RET(ctx, rv, "MF selection error");

		rv = iasecc_parse_ef_atr(card);
	}
	LOG_TEST_RET(ctx, rv, "IASECC: ATR parse failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

inline static int
iasecc_is_cpx(const struct sc_card *card)
{
	switch(card->type) {
		case SC_CARD_TYPE_IASECC_CPX:
		case SC_CARD_TYPE_IASECC_CPXCL:
			return 1;
		default:
			return 0;
	}

	return 0;
}

static int
iasecc_init_cpx(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned int flags;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	card->caps = IASECC_CARD_DEFAULT_CAPS;

	flags = IASECC_CARD_DEFAULT_FLAGS;

	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	rv = iasecc_parse_ef_atr(card);
	if (rv)
		sc_invalidate_cache(card); /* avoid memory leakage */
	LOG_TEST_RET(ctx, rv, "Parse EF.ATR");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_init(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *private_data = NULL;
	int rv = SC_ERROR_NO_CARD_SUPPORT;
	void *old_drv_data = card->drv_data;

	LOG_FUNC_CALLED(ctx);
	private_data = (struct iasecc_private_data *) calloc(1, sizeof(struct iasecc_private_data));
	if (private_data == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	card->cla  = 0x00;
	card->drv_data = private_data;

	if (card->type == SC_CARD_TYPE_IASECC_GEMALTO)
		rv = iasecc_init_gemalto(card);
	else if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR)
		rv = iasecc_init_oberthur(card);
	else if (card->type == SC_CARD_TYPE_IASECC_SAGEM)
		rv = iasecc_init_amos_or_sagem(card);
	else if (card->type == SC_CARD_TYPE_IASECC_AMOS)
		rv = iasecc_init_amos_or_sagem(card);
	else if (card->type == SC_CARD_TYPE_IASECC_MI)
		rv = iasecc_init_amos_or_sagem(card);
	else if (iasecc_is_cpx(card))
		rv = iasecc_init_cpx(card);
	else {
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_INVALID_CARD, "");
	}


	if (!rv)   {
		if (card->ef_atr && card->ef_atr->aid.len)   {
			struct sc_path path;

			memset(&path, 0, sizeof(struct sc_path));
			path.type = SC_PATH_TYPE_DF_NAME;
			memcpy(path.value, card->ef_atr->aid.value, card->ef_atr->aid.len);
			path.len = card->ef_atr->aid.len;

			rv = iasecc_select_file(card, &path, NULL);
			sc_log(ctx, "Select ECC ROOT with the AID from EF.ATR: rv %i", rv);
			LOG_TEST_GOTO_ERR(ctx, rv, "Select EF.ATR AID failed");
		}

		iasecc_get_serialnr(card, NULL);
	}

#ifdef ENABLE_SM
	card->sm_ctx.ops.read_binary = _iasecc_sm_read_binary;
	card->sm_ctx.ops.update_binary = _iasecc_sm_update_binary;
#endif

	if (!rv && card->ef_atr && card->ef_atr->aid.len)   {
		sc_log(ctx, "EF.ATR(aid:'%s')", sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len));
	}

err:
	if (rv < 0) {
		free(private_data);
		card->drv_data = old_drv_data;
	} else {
		free(old_drv_data);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_read_binary(struct sc_card *card, unsigned int offs,
		unsigned char *buf, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_read_binary(card:%p) offs %i; count %"SC_FORMAT_LEN_SIZE_T"u",
	       card, offs, count);
	if (offs > 0x7fff) {
		sc_log(ctx, "invalid EF offset: 0x%X > 0x7FFF", offs);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, (offs >> 8) & 0x7F, offs & 0xFF);
	apdu.le = count < 0x100 ? count : 0x100;
	apdu.resplen = count;
	apdu.resp = buf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_read_binary() failed");
	sc_log(ctx,
	       "iasecc_read_binary() apdu.resplen %"SC_FORMAT_LEN_SIZE_T"u",
	       apdu.resplen);

	if (apdu.resplen == IASECC_READ_BINARY_LENGTH_MAX && apdu.resplen < count)   {
		rv = iasecc_read_binary(card, offs + apdu.resplen, buf + apdu.resplen, count - apdu.resplen, flags);
		if (rv != SC_ERROR_WRONG_LENGTH)   {
			LOG_TEST_RET(ctx, rv, "iasecc_read_binary() read tail failed");
			apdu.resplen += rv;
		}
	}

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}


static int
iasecc_erase_binary(struct sc_card *card, unsigned int offs, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *tmp = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_erase_binary(card:%p) count %"SC_FORMAT_LEN_SIZE_T"u",
	       card, count);
	if (!count)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "'ERASE BINARY' failed: invalid size to erase");

	tmp = malloc(count);
	if (!tmp)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate temporary buffer");
	memset(tmp, 0xFF, count);

	rv = sc_update_binary(card, offs, tmp, count, flags);
	free(tmp);

	LOG_FUNC_RETURN(ctx, rv);
}


#if ENABLE_SM
static int
_iasecc_sm_read_binary(struct sc_card *card, unsigned int offs,
		unsigned char *buff, size_t count)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_sm_read_binary() card:%p offs:%i count:%"SC_FORMAT_LEN_SIZE_T"u ",
	       card, offs, count);
	if (offs > 0x7fff)
		LOG_TEST_RET(ctx, SC_ERROR_OFFSET_TOO_LARGE, "Invalid arguments");

	if (count == 0)
		return 0;

	sc_print_cache(card);

	if (card->cache.valid && card->cache.current_ef)   {
		entry = sc_file_get_acl_entry(card->cache.current_ef, SC_AC_OP_READ);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "iasecc_sm_read() 'READ' ACL not present");

		sc_log(ctx, "READ method/reference %X/%X", entry->method, entry->key_ref);
		if ((entry->method == SC_AC_SCB) && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
			unsigned char se_num = entry->key_ref & IASECC_SCB_METHOD_MASK_REF;

			rv = iasecc_sm_read_binary(card, se_num, offs, buff, count);
			LOG_FUNC_RETURN(ctx, rv);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
_iasecc_sm_update_binary(struct sc_card *card, unsigned int offs,
		const unsigned char *buff, size_t count)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	int rv;

	if (count == 0)
		return SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_sm_read_binary() card:%p offs:%i count:%"SC_FORMAT_LEN_SIZE_T"u ",
	       card, offs, count);
	sc_print_cache(card);

	if (card->cache.valid && card->cache.current_ef)   {
		entry = sc_file_get_acl_entry(card->cache.current_ef, SC_AC_OP_UPDATE);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "iasecc_sm_update() 'UPDATE' ACL not present");

		sc_log(ctx, "UPDATE method/reference %X/%X", entry->method, entry->key_ref);
		if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
			unsigned char se_num = entry->key_ref & IASECC_SCB_METHOD_MASK_REF;

			rv = iasecc_sm_update_binary(card, se_num, offs, buff, count);
			LOG_FUNC_RETURN(ctx, rv);
		}
	}

	LOG_FUNC_RETURN(ctx, 0);
}
#endif


static int
iasecc_emulate_fcp(struct sc_context *ctx, struct sc_apdu *apdu)
{
	unsigned char dummy_df_fcp[] = {
		0x62,0xFF,
			0x82,0x01,0x38,
			0x8A,0x01,0x05,
			0xA1,0x04,0x8C,0x02,0x02,0x00,
			0x84,0xFF,
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	};

	LOG_FUNC_CALLED(ctx);

	if (apdu->p1 != 0x04)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "FCP emulation supported only for the DF-NAME selection type");
	if (apdu->datalen > 16)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid DF-NAME length");
	if (apdu->resplen < apdu->datalen + 16)
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "not enough space for FCP data");

	memcpy(dummy_df_fcp + 16, apdu->data, apdu->datalen);
	dummy_df_fcp[15] = apdu->datalen;
	dummy_df_fcp[1] = apdu->datalen + 14;
	memcpy(apdu->resp, dummy_df_fcp, apdu->datalen + 16);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/* TODO: redesign using of cache
 * TODO: do not keep intermediate results in 'file_out' argument */
static int
iasecc_select_file(struct sc_card *card, const struct sc_path *path,
		 struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path lpath;
	int cache_valid = card->cache.valid, df_from_cache = 0;
	int rv, ii;

	LOG_FUNC_CALLED(ctx);
	memcpy(&lpath, path, sizeof(struct sc_path));
	if (file_out)
		*file_out = NULL;

	sc_log(ctx,
	       "iasecc_select_file(card:%p) path.len %"SC_FORMAT_LEN_SIZE_T"u; path.type %i; aid_len %"SC_FORMAT_LEN_SIZE_T"u",
	       card, path->len, path->type, path->aid.len);
	sc_log(ctx, "iasecc_select_file() path:%s", sc_print_path(path));

	sc_print_cache(card);
	if ((!iasecc_is_cpx(card)) &&
	    (card->type != SC_CARD_TYPE_IASECC_GEMALTO) &&
	    (path->type != SC_PATH_TYPE_DF_NAME
			&& lpath.len >= 2
			&& lpath.value[0] == 0x3F && lpath.value[1] == 0x00))   {
		sc_log(ctx, "EF.ATR(aid:'%s')", card->ef_atr ? sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len) : "");

		rv = iasecc_select_mf(card, file_out);
		LOG_TEST_RET(ctx, rv, "MF selection error");

		memmove(&lpath.value[0], &lpath.value[2], lpath.len - 2);
		lpath.len -=  2;
	}

	if (lpath.aid.len)	{
		struct sc_file *file = NULL;
		struct sc_path ppath;

		sc_log(ctx,
		       "iasecc_select_file() select parent AID:%p/%"SC_FORMAT_LEN_SIZE_T"u",
		       lpath.aid.value, lpath.aid.len);
		sc_log(ctx, "iasecc_select_file() select parent AID:%s", sc_dump_hex(lpath.aid.value, lpath.aid.len));
		memset(&ppath, 0, sizeof(ppath));
		memcpy(ppath.value, lpath.aid.value, lpath.aid.len);
		ppath.len = lpath.aid.len;
		ppath.type = SC_PATH_TYPE_DF_NAME;

		if (card->cache.valid && card->cache.current_df
				&& card->cache.current_df->path.len == lpath.aid.len
				&& !memcmp(card->cache.current_df->path.value, lpath.aid.value, lpath.aid.len))
			df_from_cache = 1;

		rv = iasecc_select_file(card, &ppath, &file);
		LOG_TEST_GOTO_ERR(ctx, rv, "select AID path failed");

		if (file_out) {
			sc_file_free(*file_out);
			*file_out = file;
		} else {
			sc_file_free(file);
		}

		if (lpath.type == SC_PATH_TYPE_DF_NAME)
			lpath.type = SC_PATH_TYPE_FROM_CURRENT;
	}

	if (lpath.type == SC_PATH_TYPE_PATH)
		lpath.type = SC_PATH_TYPE_FROM_CURRENT;

	if (!lpath.len) {
		if (file_out) {
			sc_file_free(*file_out);
			*file_out = NULL;
		}
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	sc_print_cache(card);

	if (card->cache.valid && card->cache.current_df && lpath.type == SC_PATH_TYPE_DF_NAME
			&& card->cache.current_df->path.len == lpath.len
			&& !memcmp(card->cache.current_df->path.value, lpath.value, lpath.len))   {
		sc_log(ctx, "returns current DF path %s", sc_print_path(&card->cache.current_df->path));
		if (file_out) {
			sc_file_free(*file_out);
			sc_file_dup(file_out, card->cache.current_df);
		}

		sc_print_cache(card);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	do   {
		struct sc_apdu apdu;
		struct sc_file *file = NULL;
		unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
		int pathlen = lpath.len;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);

		if (card->type != SC_CARD_TYPE_IASECC_GEMALTO
				&& card->type != SC_CARD_TYPE_IASECC_OBERTHUR
				&& card->type != SC_CARD_TYPE_IASECC_SAGEM
				&& card->type != SC_CARD_TYPE_IASECC_AMOS
				&& card->type != SC_CARD_TYPE_IASECC_MI
				&& card->type != SC_CARD_TYPE_IASECC_MI2
				&& !iasecc_is_cpx(card)) {
			rv = SC_ERROR_NOT_SUPPORTED;
			LOG_TEST_GOTO_ERR(ctx, rv, "Unsupported card");
		}

		if (lpath.type == SC_PATH_TYPE_FILE_ID)   {
			apdu.p1 = 0x02;
			if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR)
				apdu.p1 = 0x01;
			if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR ||
			    card->type == SC_CARD_TYPE_IASECC_AMOS ||
			    card->type == SC_CARD_TYPE_IASECC_MI ||
			    card->type == SC_CARD_TYPE_IASECC_MI2 ||
			    card->type == SC_CARD_TYPE_IASECC_GEMALTO ||
			    iasecc_is_cpx(card)
			    )   {
				apdu.p2 = 0x04;
			}
		}
		else if (lpath.type == SC_PATH_TYPE_FROM_CURRENT)  {
			apdu.p1 = 0x09;
			if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR ||
			    card->type == SC_CARD_TYPE_IASECC_AMOS ||
			    card->type == SC_CARD_TYPE_IASECC_MI ||
			    card->type == SC_CARD_TYPE_IASECC_MI2 ||
			    card->type == SC_CARD_TYPE_IASECC_GEMALTO ||
			    iasecc_is_cpx(card)) {
				apdu.p2 = 0x04;
			}
		}
		else if (lpath.type == SC_PATH_TYPE_PARENT)   {
			apdu.p1 = 0x03;
			pathlen = 0;
			apdu.cse = SC_APDU_CASE_2_SHORT;
		}
		else if (lpath.type == SC_PATH_TYPE_DF_NAME)   {
			apdu.p1 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_AMOS ||
			    card->type == SC_CARD_TYPE_IASECC_MI2 ||
			    card->type == SC_CARD_TYPE_IASECC_OBERTHUR ||
			    card->type == SC_CARD_TYPE_IASECC_GEMALTO ||
			    iasecc_is_cpx(card)) {
				apdu.p2 = 0x04;
			}
		}
		else   {
			sc_log(ctx, "Invalid PATH type: 0x%X", lpath.type);
			rv = SC_ERROR_NOT_SUPPORTED;
			LOG_TEST_GOTO_ERR(ctx, rv, "iasecc_select_file() invalid PATH type");
		}

		for (ii=0; ii<2; ii++)   {
			apdu.lc = pathlen;
			apdu.data = lpath.value;
			apdu.datalen = pathlen;

			apdu.resp = rbuf;
			apdu.resplen = sizeof(rbuf);
			apdu.le = 256;

			rv = sc_transmit_apdu(card, &apdu);
			LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
			rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (rv == SC_ERROR_INCORRECT_PARAMETERS &&
					lpath.type == SC_PATH_TYPE_DF_NAME && apdu.p2 == 0x00)   {
				sc_log(ctx, "Warning: SC_ERROR_INCORRECT_PARAMETERS for SC_PATH_TYPE_DF_NAME, try again with P2=0x0C");
				apdu.p2 = 0x0C;
				continue;
			}

			if (ii)   {
				/* 'SELECT AID' do not returned FCP. Try to emulate. */
				apdu.resplen = sizeof(rbuf);
				rv = iasecc_emulate_fcp(ctx, &apdu);
				LOG_TEST_GOTO_ERR(ctx, rv, "Failed to emulate DF FCP");
			}

			break;
		}

		/*
		 * Using of the cached DF and EF can cause problems in the multi-thread environment.
		 * FIXME: introduce config. option that invalidates this cache outside the locked card session,
		 *        (or invent something else)
		 */
		if (rv == SC_ERROR_FILE_NOT_FOUND && cache_valid && df_from_cache)   {
			sc_invalidate_cache(card);
			sc_log(ctx, "iasecc_select_file() file not found, retry without cached DF");
			if (file_out) {
				sc_file_free(*file_out);
				*file_out = NULL;
			}
			rv = iasecc_select_file(card, path, file_out);
			LOG_FUNC_RETURN(ctx, rv);
		}

		LOG_TEST_GOTO_ERR(ctx, rv, "iasecc_select_file() check SW failed");

		sc_log(ctx,
		       "iasecc_select_file() apdu.resp %"SC_FORMAT_LEN_SIZE_T"u",
		       apdu.resplen);
		if (apdu.resplen)   {
			sc_log(ctx, "apdu.resp %02X:%02X:%02X...", apdu.resp[0], apdu.resp[1], apdu.resp[2]);

			switch (apdu.resp[0]) {
			case 0x62:
			case 0x6F:
				file = sc_file_new();
				if (file == NULL) {
					if (file_out) {
						sc_file_free(*file_out);
						*file_out = NULL;
					}
					LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
				}
				file->path = lpath;

				rv = iasecc_process_fci(card, file, apdu.resp, apdu.resplen);
				if (rv) {
					sc_file_free(file);
					if (file_out) {
						sc_file_free(*file_out);
						*file_out = NULL;
					}
					LOG_FUNC_RETURN(ctx, rv);
				}
				break;
			default:
				if (file_out) {
					sc_file_free(*file_out);
					*file_out = NULL;
				}
				LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
			}

			sc_log(ctx, "FileType %i", file->type);
			if (file->type == SC_FILE_TYPE_DF)   {
				if (card->cache.valid) {
					sc_file_free(card->cache.current_df);
				}
				card->cache.current_df = NULL;

				sc_file_dup(&card->cache.current_df, file);
				card->cache.valid = 1;
			}
			else   {
				if (card->cache.valid) {
					sc_file_free(card->cache.current_ef);
				}

				card->cache.current_ef = NULL;

				sc_file_dup(&card->cache.current_ef, file);
				card->cache.valid = 1;
			}

			if (file_out)   {
				sc_file_free(*file_out);
				*file_out = file;
			}
			else   {
				sc_file_free(file);
			}
		}
		else if (lpath.type == SC_PATH_TYPE_DF_NAME)   {
			sc_file_free(card->cache.current_df);
			card->cache.current_df = NULL;

			sc_file_free(card->cache.current_ef);
			card->cache.current_ef = NULL;

			card->cache.valid = 1;
		}
	} while(0);

	sc_print_cache(card);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
err:
	if (file_out) {
		sc_file_free(*file_out);
		*file_out = NULL;
	}
	return rv;
}


static int
iasecc_process_fci(struct sc_card *card, struct sc_file *file,
		 const unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	size_t taglen, offs, ii;
	int rv;
	const unsigned char *acls = NULL, *tag = NULL;
	unsigned char mask;
	unsigned char ops_DF[7] = {
		SC_AC_OP_DELETE, 0xFF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE, 0xFF, SC_AC_OP_CREATE, 0xFF
	};
	unsigned char ops_EF[7] = {
		SC_AC_OP_DELETE, 0xFF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE, 0xFF, SC_AC_OP_UPDATE, SC_AC_OP_READ
	};

	LOG_FUNC_CALLED(ctx);

	tag = sc_asn1_find_tag(ctx,  buf, buflen, 0x6F, &taglen);
	sc_log(ctx, "processing FCI: 0x6F tag %p", tag);
	if (tag != NULL) {
		sc_log(ctx, "  FCP length %"SC_FORMAT_LEN_SIZE_T"u", taglen);
		buf = tag;
		buflen = taglen;
	}

	tag = sc_asn1_find_tag(ctx,  buf, buflen, 0x62, &taglen);
	sc_log(ctx, "processing FCI: 0x62 tag %p", tag);
	if (tag != NULL) {
		sc_log(ctx, "  FCP length %"SC_FORMAT_LEN_SIZE_T"u", taglen);
		buf = tag;
		buflen = taglen;
	}

	rv = iso_ops->process_fci(card, file, buf, buflen);
	LOG_TEST_RET(ctx, rv, "ISO parse FCI failed");
/*
	Gemalto:  6F 19 80 02 02 ED 82 01 01 83 02 B0 01 88 00	8C 07 7B 17 17 17 17 17 00 8A 01 05 90 00
	Sagem:    6F 17 62 15 80 02 00 7D 82 01 01                   8C 02 01 00 83 02 2F 00 88 01 F0 8A 01 05 90 00
	Oberthur: 62 1B 80 02 05 DC 82 01 01 83 02 B0 01 88 00 A1 09 8C 07 7B 17 FF 17 17 17 00 8A 01 05 90 00
*/

	sc_log(ctx, "iasecc_process_fci() type %i; let's parse file ACLs", file->type);
	tag = sc_asn1_find_tag(ctx, buf, buflen, IASECC_DOCP_TAG_ACLS, &taglen);
	if (tag)
		acls = sc_asn1_find_tag(ctx, tag, taglen, IASECC_DOCP_TAG_ACLS_CONTACT, &taglen);
	else
		acls = sc_asn1_find_tag(ctx, buf, buflen, IASECC_DOCP_TAG_ACLS_CONTACT, &taglen);

	if (!acls)   {
		sc_log(ctx,
		       "ACLs not found in data(%"SC_FORMAT_LEN_SIZE_T"u) %s",
		       buflen, sc_dump_hex(buf, buflen));
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "ACLs tag missing");
	}

	sc_log(ctx, "ACLs(%"SC_FORMAT_LEN_SIZE_T"u) '%s'", taglen,
	       sc_dump_hex(acls, taglen));
	mask = 0x40, offs = 1;
	for (ii = 0; ii < 7; ii++, mask /= 2)  {
		unsigned char op = file->type == SC_FILE_TYPE_DF ? ops_DF[ii] : ops_EF[ii];

		/* avoid any access to acls[offs] beyond the taglen */
		if (offs >= taglen) {
			sc_log(ctx, "Warning: Invalid offset reached during ACL parsing");
			break;
		}
		if (!(mask & acls[0]))
			continue;

		sc_log(ctx, "ACLs mask 0x%X, offs %"SC_FORMAT_LEN_SIZE_T"u, op 0x%X, acls[offs] 0x%X", mask, offs, op, acls[offs]);
		if (op == 0xFF)   {
			;
		}
		else if (acls[offs] == 0)   {
			sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);
		}
		else if (acls[offs] == 0xFF)   {
			sc_file_add_acl_entry(file, op, SC_AC_NEVER, 0);
		}
		else if ((acls[offs] & IASECC_SCB_METHOD_MASK) == IASECC_SCB_METHOD_USER_AUTH)   {
			sc_file_add_acl_entry(file, op, SC_AC_SEN, acls[offs] & IASECC_SCB_METHOD_MASK_REF);
		}
		else if (acls[offs] & IASECC_SCB_METHOD_MASK)   {
			sc_file_add_acl_entry(file, op, SC_AC_SCB, acls[offs]);
		}
		else   {
			sc_log(ctx, "Warning: non supported SCB method: %X", acls[offs]);
			sc_file_add_acl_entry(file, op, SC_AC_NEVER, 0);
		}

		offs++;
	}

	LOG_FUNC_RETURN(ctx, 0);
}


static int
iasecc_fcp_encode(struct sc_card *card, struct sc_file *file, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	unsigned char buf[0x80], type;
	unsigned char  ops[7] = {
		SC_AC_OP_DELETE, 0xFF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE, 0xFF, SC_AC_OP_UPDATE, SC_AC_OP_READ
	};
	unsigned char smbs[8];
	size_t ii, offs = 0, amb, mask, nn_smb;

	LOG_FUNC_CALLED(ctx);

	if (file->type == SC_FILE_TYPE_DF)
		type = IASECC_FCP_TYPE_DF;
	else
		type = IASECC_FCP_TYPE_EF;

	buf[offs++] = IASECC_FCP_TAG_SIZE;
	buf[offs++] = 2;
	buf[offs++] = (file->size >> 8) & 0xFF;
	buf[offs++] = file->size & 0xFF;

	buf[offs++] = IASECC_FCP_TAG_TYPE;
	buf[offs++] = 1;
	buf[offs++] = type;

	buf[offs++] = IASECC_FCP_TAG_FID;
	buf[offs++] = 2;
	buf[offs++] = (file->id >> 8) & 0xFF;
	buf[offs++] = file->id & 0xFF;

	buf[offs++] = IASECC_FCP_TAG_SFID;
	buf[offs++] = 0;

	amb = 0, mask = 0x40, nn_smb = 0;
	for (ii = 0; ii < sizeof(ops); ii++, mask >>= 1) {
		const struct sc_acl_entry *entry;

		if (ops[ii]==0xFF)
			continue;

		entry = sc_file_get_acl_entry(file, ops[ii]);
		if (!entry)
			continue;

		sc_log(ctx, "method %X; reference %X", entry->method, entry->key_ref);
		if (entry->method == SC_AC_NEVER)
			continue;
		else if (entry->method == SC_AC_NONE)
			smbs[nn_smb++] = 0x00;
		else if (entry->method == SC_AC_CHV)
			smbs[nn_smb++] = entry->key_ref | IASECC_SCB_METHOD_USER_AUTH;
		else if (entry->method == SC_AC_SEN)
			smbs[nn_smb++] = entry->key_ref | IASECC_SCB_METHOD_USER_AUTH;
		else if (entry->method == SC_AC_SCB)
			smbs[nn_smb++] = entry->key_ref;
		else if (entry->method == SC_AC_PRO)
			smbs[nn_smb++] = entry->key_ref | IASECC_SCB_METHOD_SM;
		else
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non supported AC method");

		amb |= mask;
		sc_log(ctx,
		       "%"SC_FORMAT_LEN_SIZE_T"u: AMB %"SC_FORMAT_LEN_SIZE_T"X; nn_smb %"SC_FORMAT_LEN_SIZE_T"u",
		       ii, amb, nn_smb);
	}

	/* TODO: Encode contactless ACLs and life cycle status for all IAS/ECC cards */
	if (card->type == SC_CARD_TYPE_IASECC_SAGEM ||
			card->type == SC_CARD_TYPE_IASECC_AMOS )  {
		unsigned char status = 0;

		buf[offs++] = IASECC_FCP_TAG_ACLS;
		buf[offs++] = 2*(2 + 1 + nn_smb);

		buf[offs++] = IASECC_FCP_TAG_ACLS_CONTACT;
		buf[offs++] = nn_smb + 1;
		buf[offs++] = amb;
		memcpy(buf + offs, smbs, nn_smb);
		offs += nn_smb;

		/* Same ACLs for contactless */
		buf[offs++] = IASECC_FCP_TAG_ACLS_CONTACTLESS;
		buf[offs++] = nn_smb + 1;
		buf[offs++] = amb;
		memcpy(buf + offs, smbs, nn_smb);
		offs += nn_smb;

		if (file->status == SC_FILE_STATUS_ACTIVATED)
			status = 0x05;
		else if (file->status == SC_FILE_STATUS_CREATION)
			status = 0x01;

		if (status)   {
			buf[offs++] = 0x8A;
			buf[offs++] = 0x01;
			buf[offs++] = status;
		}
	}
	else   {
		buf[offs++] = IASECC_FCP_TAG_ACLS;
		buf[offs++] = 2 + 1 + nn_smb;

		buf[offs++] = IASECC_FCP_TAG_ACLS_CONTACT;
		buf[offs++] = nn_smb + 1;
		buf[offs++] = amb;
		memcpy(buf + offs, smbs, nn_smb);
		offs += nn_smb;
	}

	if (out)   {
		if (out_len < offs)
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small to encode FCP");
		memcpy(out, buf, offs);
	}

	LOG_FUNC_RETURN(ctx, offs);
}


static int
iasecc_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	const struct sc_acl_entry *entry = NULL;
	unsigned char sbuf[0x100];
	size_t sbuf_len;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_print_cache(card);

	if (file->type != SC_FILE_TYPE_WORKING_EF)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Creation of the file with of this type is not supported");

	sbuf_len = iasecc_fcp_encode(card, file, sbuf + 2, sizeof(sbuf)-2);
	LOG_TEST_RET(ctx, sbuf_len, "FCP encode error");

	sbuf[0] = IASECC_FCP_TAG;
	sbuf[1] = sbuf_len;

	if (card->cache.valid && card->cache.current_df)   {
		entry = sc_file_get_acl_entry(card->cache.current_df, SC_AC_OP_CREATE);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "iasecc_create_file() 'CREATE' ACL not present");

		sc_log(ctx, "iasecc_create_file() 'CREATE' method/reference %X/%X", entry->method, entry->key_ref);
		sc_log(ctx, "iasecc_create_file() create data: '%s'", sc_dump_hex(sbuf, sbuf_len + 2));
		if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
                        rv = iasecc_sm_create_file(card, entry->key_ref & IASECC_SCB_METHOD_MASK_REF, sbuf, sbuf_len + 2);
                        LOG_TEST_RET(ctx, rv, "iasecc_create_file() SM create file error");

                        rv = iasecc_select_file(card, &file->path, NULL);
                        LOG_FUNC_RETURN(ctx, rv);

		}
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0, 0);
	apdu.data = sbuf;
	apdu.datalen = sbuf_len + 2;
	apdu.lc = sbuf_len + 2;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_create_file() create file error");

	rv = iasecc_select_file(card, &file->path, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot select newly created file");

	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_get_challenge(struct sc_card *card, u8 * rnd, size_t len)
{
	/* As IAS/ECC cannot handle other data length than 0x08 */
	u8 rbuf[8];
	size_t out_len;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = iso_ops->get_challenge(card, rbuf, sizeof rbuf);
	LOG_TEST_RET(card->ctx, r, "GET CHALLENGE cmd failed");

	if (len < (size_t) r) {
		out_len = len;
	} else {
		out_len = (size_t) r;
	}
	memcpy(rnd, rbuf, out_len);

	LOG_FUNC_RETURN(card->ctx, (int) out_len);
}


static int
iasecc_logout(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!card->ef_atr || !card->ef_atr->aid.len)
		return SC_SUCCESS;

	memset(&path, 0, sizeof(struct sc_path));
	path.type = SC_PATH_TYPE_DF_NAME;
	memcpy(path.value, card->ef_atr->aid.value, card->ef_atr->aid.len);
	path.len = card->ef_atr->aid.len;

	rv = iasecc_select_file(card, &path, NULL);
	sc_log(ctx, "Select ECC ROOT with the AID from EF.ATR: rv %i", rv);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_finish(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *private_data = (struct iasecc_private_data *)card->drv_data;
	struct iasecc_se_info *se_info = private_data->se_info, *next;

	LOG_FUNC_CALLED(ctx);

	while (se_info)   {
		sc_file_free(se_info->df);
		next = se_info->next;
		free(se_info);
		se_info = next;
	}

	free(card->drv_data);
	card->drv_data = NULL;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	struct sc_apdu apdu;
	struct sc_file *file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_print_cache(card);

	rv = iasecc_select_file(card, path, &file);
	if (rv == SC_ERROR_FILE_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	LOG_TEST_RET(ctx, rv, "Cannot select file to delete");

	entry = sc_file_get_acl_entry(file, SC_AC_OP_DELETE);
	if (!entry)
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "Cannot delete file: no 'DELETE' acl");

	sc_log(ctx, "DELETE method/reference %X/%X", entry->method, entry->key_ref);
	if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
		unsigned char se_num = entry->key_ref & IASECC_SCB_METHOD_MASK_REF;
		rv = iasecc_sm_delete_file(card, se_num, file->id);
	}
	else   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "Delete file failed");

		if (card->cache.valid) {
			sc_file_free(card->cache.current_ef);
		}
		card->cache.current_ef = NULL;
	}

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	if (sw1 == 0x62 && sw2 == 0x82)
		return SC_SUCCESS;

	return iso_ops->check_sw(card, sw1, sw2);
}


static unsigned
iasecc_get_algorithm(struct sc_context *ctx, const struct sc_security_env *env,
		unsigned operation, unsigned mechanism)
{
    const struct sc_supported_algo_info *info = NULL;
    int ii;

    if (!env)
        return 0;

    for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS && env->supported_algos[ii].reference; ii++)
        if ((env->supported_algos[ii].operations & operation)
			&& (env->supported_algos[ii].mechanism == mechanism))
            break;

    if (ii < SC_MAX_SUPPORTED_ALGORITHMS && env->supported_algos[ii].reference)   {
        info = &env->supported_algos[ii];
        sc_log(ctx, "found IAS/ECC algorithm %X:%X:%X:%X",
			info->reference, info->mechanism, info->operations, info->algo_ref);
    }
    else   {
        sc_log(ctx, "cannot find IAS/ECC algorithm (operation:%X,mechanism:%X)", operation, mechanism);
    }

    return info ? info->algo_ref : 0;
}


static int
iasecc_se_cache_info(struct sc_card *card, struct iasecc_se_info *se)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info *se_info = NULL, *si = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	se_info = calloc(1, sizeof(struct iasecc_se_info));
	if (!se_info)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SE info allocation error");
	memcpy(se_info, se, sizeof(struct iasecc_se_info));

	if (card->cache.valid && card->cache.current_df)   {
		sc_file_dup(&se_info->df, card->cache.current_df);
		if (se_info->df == NULL)   {
			free(se_info);
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");
		}
	}

	rv = iasecc_docp_copy(ctx, &se->docp, &se_info->docp);
	if (rv < 0)   {
		free(se_info->df);
		free(se_info);
		LOG_TEST_RET(ctx, rv, "Cannot make copy of DOCP");
	}

	if (!prv->se_info)   {
		prv->se_info = se_info;
	}
	else    {
		for (si = prv->se_info; si->next; si = si->next)
			;
		si->next = se_info;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_se_get_info_from_cache(struct sc_card *card, struct iasecc_se_info *se)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info *si = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	for(si = prv->se_info; si; si = si->next)   {
		if (si->reference != se->reference)
			continue;
		if (!(card->cache.valid && card->cache.current_df) && si->df)
			continue;
		if (card->cache.valid && card->cache.current_df && !si->df)
			continue;
		if (card->cache.valid && card->cache.current_df && si->df)
			if (memcmp(&card->cache.current_df->path, &si->df->path, sizeof(struct sc_path)))
				continue;
		break;
	}

	if (!si)
		return SC_ERROR_OBJECT_NOT_FOUND;

	memcpy(se, si, sizeof(struct iasecc_se_info));

	if (si->df)   {
		sc_file_dup(&se->df, si->df);
		if (se->df == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");
	}

	rv = iasecc_docp_copy(ctx, &si->docp, &se->docp);
	LOG_TEST_RET(ctx, rv, "Cannot make copy of DOCP");

	LOG_FUNC_RETURN(ctx, rv);
}


int
iasecc_se_get_info(struct sc_card *card, struct iasecc_se_info *se)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[0x100];
	unsigned char sbuf_iasecc[10] = {
		0x4D, 0x08, IASECC_SDO_TEMPLATE_TAG, 0x06,
		IASECC_SDO_TAG_HEADER, IASECC_SDO_CLASS_SE | IASECC_OBJECT_REF_LOCAL,
		se->reference & 0x3F,
		0x02, IASECC_SDO_CLASS_SE, 0x80
	};
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (iasecc_is_cpx(card)) {
		rv = iasecc_select_mf(card, NULL);
		LOG_TEST_RET(ctx, rv, "MF invalid");
	}

	if (se->reference > IASECC_SE_REF_MAX)
                LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = iasecc_se_get_info_from_cache(card, se);
	if (rv == SC_ERROR_OBJECT_NOT_FOUND)   {
		sc_log(ctx, "No SE#%X info in cache, try to use 'GET DATA'", se->reference);

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x3F, 0xFF);
		apdu.data = sbuf_iasecc;
		apdu.datalen = sizeof(sbuf_iasecc);
		apdu.lc = apdu.datalen;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = sizeof(rbuf);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "get SE data  error");

		rv = iasecc_se_parse(card, apdu.resp, apdu.resplen, se);
		LOG_TEST_RET(ctx, rv, "cannot parse SE data");

		rv = iasecc_se_cache_info(card, se);
		LOG_TEST_RET(ctx, rv, "failed to put SE data into cache");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo sdo;
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	unsigned algo_ref;
	struct sc_apdu apdu;
	unsigned sign_meth, sign_ref, auth_meth, auth_ref, aflags;
	unsigned char cse_crt_at[] = {
		0x84, 0x01, 0xFF,
		0x80, 0x01, IASECC_ALGORITHM_RSA_PKCS
	};
	unsigned char cse_crt_dst[] = {
		0x84, 0x01, 0xFF,
		0x80, 0x01, (IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA1)
	};
	unsigned char cse_crt_ht[] = {
		0x80, 0x01, IASECC_ALGORITHM_SHA1
	};
	unsigned char cse_crt_ct[] = {
		0x84, 0x01, 0xFF,
		0x80, 0x01, (IASECC_ALGORITHM_RSA_PKCS_DECRYPT | IASECC_ALGORITHM_SHA1)
	};
	int rv, operation = env->operation;

	/* TODO: take algorithm references from 5032, not from header file. */
	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_set_security_env(card:%p) operation 0x%X; senv.algorithm 0x%X, senv.algorithm_ref 0x%X",
			card, env->operation, env->algorithm, env->algorithm_ref);

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = IASECC_SDO_CLASS_RSA_PRIVATE;
	sdo.sdo_ref  = env->key_ref[0] & ~IASECC_OBJECT_REF_LOCAL;
	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_RET(ctx, rv, "Cannot get RSA PRIVATE SDO data");

	/* To made by iasecc_sdo_convert_to_file() */
	prv->key_size = *(sdo.docp.size.value + 0) * 0x100 + *(sdo.docp.size.value + 1);
	sc_log(ctx, "prv->key_size 0x%"SC_FORMAT_LEN_SIZE_T"X", prv->key_size);

	rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_PSO_COMPUTE_SIGNATURE, &sign_meth, &sign_ref);
	LOG_TEST_RET(ctx, rv, "Cannot convert SC_AC_OP_SIGN acl");

	rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_INTERNAL_AUTHENTICATE, &auth_meth, &auth_ref);
	LOG_TEST_RET(ctx, rv, "Cannot convert SC_AC_OP_INT_AUTH acl");

	aflags = env->algorithm_flags;

	if (!(aflags & SC_ALGORITHM_RSA_PAD_PKCS1))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Only supported signature with PKCS1 padding");

	if (operation == SC_SEC_OPERATION_SIGN)   {
		if (!(aflags & (SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA256)))   {
			sc_log(ctx, "CKM_RSA_PKCS asked -- use 'AUTHENTICATE' sign operation instead of 'SIGN'");
			operation = SC_SEC_OPERATION_AUTHENTICATE;
		}
		else if (sign_meth == SC_AC_NEVER)   {
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "PSO_DST not allowed for this key");
		}
	}

	if (operation == SC_SEC_OPERATION_SIGN)   {
		prv->op_method = sign_meth;
		prv->op_ref = sign_ref;
	}
	else if (operation == SC_SEC_OPERATION_AUTHENTICATE)   {
		if (auth_meth == SC_AC_NEVER)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_ALLOWED, "INTERNAL_AUTHENTICATE is not allowed for this key");

		prv->op_method = auth_meth;
		prv->op_ref = auth_ref;
	}

	sc_log(ctx, "senv.algorithm 0x%X, senv.algorithm_ref 0x%X", env->algorithm, env->algorithm_ref);
	sc_log(ctx,
	       "se_num %i, operation 0x%X, algorithm 0x%X, algorithm_ref 0x%X, flags 0x%X; key size %"SC_FORMAT_LEN_SIZE_T"u",
	       se_num, operation, env->algorithm, env->algorithm_ref,
	       env->algorithm_flags, prv->key_size);
	switch (operation)  {
	case SC_SEC_OPERATION_SIGN:
		if (!(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1))
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Need RSA_PKCS1 specified");

		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)   {
			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_HASH, CKM_SHA256);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports HASH:SHA256");

			cse_crt_ht[2] = algo_ref; /* IASECC_ALGORITHM_SHA2 */

			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_SHA256_RSA_PKCS);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:SHA1_RSA_PKCS");

			cse_crt_dst[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
			cse_crt_dst[5] = algo_ref;   /* IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA2 */
		}
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)   {
			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_HASH,  CKM_SHA_1);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports HASH:SHA1");

			cse_crt_ht[2] = algo_ref;	/* IASECC_ALGORITHM_SHA1 */

			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_SHA1_RSA_PKCS);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:SHA1_RSA_PKCS");

			cse_crt_dst[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
			cse_crt_dst[5] = algo_ref;   /* IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA1 */
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Need RSA_HASH_SHA[1,256] specified");
		}

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_HT);
		apdu.data = cse_crt_ht;
		apdu.datalen = sizeof(cse_crt_ht);
		apdu.lc = sizeof(cse_crt_ht);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "MSE restore error");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_DST);
		apdu.data = cse_crt_dst;
		apdu.datalen = sizeof(cse_crt_dst);
		apdu.lc = sizeof(cse_crt_dst);
		break;
	case SC_SEC_OPERATION_AUTHENTICATE:
		algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_RSA_PKCS);
		if (!algo_ref)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Application do not supports SIGNATURE:RSA_PKCS");

		cse_crt_at[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
		cse_crt_at[5] = algo_ref;	/* IASECC_ALGORITHM_RSA_PKCS */

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_AT);
		apdu.data = cse_crt_at;
		apdu.datalen = sizeof(cse_crt_at);
		apdu.lc = sizeof(cse_crt_at);
		break;
	case SC_SEC_OPERATION_DECIPHER:
		rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_PSO_DECRYPT, &prv->op_method, &prv->op_ref);
		LOG_TEST_RET(ctx, rv, "Cannot convert SC_AC_OP_PSO_DECRYPT acl");
		algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_DECIPHER,  CKM_RSA_PKCS);
		if (!algo_ref)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Application do not supports DECIPHER:RSA_PKCS");

		cse_crt_ct[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
		cse_crt_ct[5] = algo_ref;	/* IASECC_ALGORITHM_RSA_PKCS_DECRYPT | IASECC_ALGORITHM_SHA1 */

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_CT);
		apdu.data = cse_crt_ct;
		apdu.datalen = sizeof(cse_crt_ct);
		apdu.lc = sizeof(cse_crt_ct);
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "MSE restore error");

	prv->security_env = *env;
	prv->security_env.operation = operation;

	LOG_FUNC_RETURN(ctx, 0);
}


static int
iasecc_chv_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd, unsigned char *scbs,
		  int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	unsigned char scb = scbs[IASECC_ACLS_CHV_VERIFY];
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%i,scb:%X)", pin_cmd->pin_reference, pin_cmd->pin1.len,
	       scb);

	if (scb & IASECC_SCB_METHOD_SM) {
		rv = iasecc_sm_pin_verify(card, scb & IASECC_SCB_METHOD_MASK_REF, pin_cmd, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	}

	rv = iso_ops->pin_cmd(card, pin_cmd, tries_left);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_se_at_to_chv_reference(struct sc_card *card, unsigned reference,
		unsigned *chv_reference)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info se;
	struct sc_crt crt;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SE reference %i", reference);

	if (reference > IASECC_SE_REF_MAX)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(&se, 0, sizeof(se));
	se.reference = reference;

	rv = iasecc_se_get_info(card, &se);
	LOG_TEST_RET(ctx, rv, "SDO get data error");

	memset(&crt, 0, sizeof(crt));
	crt.tag = IASECC_CRT_TAG_AT;
	crt.usage = IASECC_UQB_AT_USER_PASSWORD;

	rv = iasecc_se_get_crt(card, &se, &crt);
	LOG_TEST_RET(ctx, rv, "no authentication template for USER PASSWORD");

	if (chv_reference)
		*chv_reference = crt.refs[0];

	sc_file_free(se.df);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_get_status(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data info;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "PIN type is not supported for status");

	memset(&info, 0, sizeof(info));
	info.cmd = SC_PIN_CMD_GET_INFO;
	info.pin_type = data->pin_type;
	info.pin_reference = data->pin_reference;

	rv = iso_ops->pin_cmd(card, &info, tries_left);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN info");

	data->pin1.max_tries = info.pin1.max_tries;
	data->pin1.tries_left = info.pin1.tries_left;
	data->pin1.logged_in = info.pin1.logged_in;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_verify(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	unsigned type = data->pin_type;
	unsigned reference = data->pin_reference;
	struct sc_pin_cmd_data pin_cmd;
	struct iasecc_pin_policy policy;
	int tries_before_verify = -1;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "Verify PIN(type:%X,ref:%i,data(len:%i,%p)",
	       type, reference, data->pin1.len, data->pin1.data);

	if (type == SC_AC_AUT)   {
		rv =  iasecc_sm_external_authentication(card, reference, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	}

	if (type == SC_AC_SCB)   {
		if (reference & IASECC_SCB_METHOD_USER_AUTH)   {
			type = SC_AC_SEN;
			reference = reference & IASECC_SCB_METHOD_MASK_REF;
		}
	}

	if (type == SC_AC_SEN)   {
		type = SC_AC_CHV;
		rv = iasecc_se_at_to_chv_reference(card, reference,  &reference);
		LOG_TEST_RET(ctx, rv, "SE AT to CHV reference error");
	}

	if (type != SC_AC_CHV)   {
		sc_log(ctx, "Do not try to verify non CHV PINs");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	pin_cmd = *data;
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.pin_reference = reference;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;

	rv = iasecc_pin_get_status(card, &pin_cmd, tries_left);
	if (data->pin1.data && !data->pin1.len)
		LOG_FUNC_RETURN(ctx, rv);

	if (!rv)   {
		if (pin_cmd.pin1.logged_in == SC_PIN_STATE_LOGGED_IN)
			if (iasecc_chv_cache_is_verified(card, &pin_cmd))
				LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}
	else if (rv != SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)   {
		LOG_FUNC_RETURN(ctx, rv);
	}

	iasecc_chv_cache_clean(card, &pin_cmd);

	rv = iasecc_pin_merge_policy(card, &pin_cmd, &pin_cmd.pin1, &policy);
	LOG_TEST_RET(ctx, rv, "Failed to update PIN1 info");

	/* PIN-pads work best with fixed-size lengths. Use PIN padding when length is available. */
	if (pin_cmd.flags & SC_PIN_CMD_USE_PINPAD) {
		tries_before_verify = pin_cmd.pin1.tries_left;
		if (policy.stored_length > 0)
			iasecc_set_pin_padding(&pin_cmd, &pin_cmd.pin1, policy.stored_length);
	}

	rv = iasecc_chv_verify(card, &pin_cmd, policy.scbs, tries_left);

	/*
	 * Detect and log PIN-pads which don't handle variable-length PIN - special case where they
	 * forward the CHV verify command with Lc = 0 to the card, without updating Lc. An IAS-ECC
	 * card responds to this command by returning the number of attempts left, without
	 * decreasing the counter.
	 */
	if ((pin_cmd.flags & SC_PIN_CMD_USE_PINPAD) && !(pin_cmd.flags & SC_PIN_CMD_NEED_PADDING)) {
		if (rv == SC_ERROR_PIN_CODE_INCORRECT && pin_cmd.pin1.tries_left == tries_before_verify) {
			SC_TEST_RET(ctx, SC_LOG_DEBUG_VERBOSE, rv,
				    "PIN-pad reader does not support variable-length PIN");
		}
	}

	LOG_TEST_RET(ctx, rv, "PIN CHV verification error");

	rv = iasecc_chv_cache_verified(card, &pin_cmd);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_get_policy (struct sc_card *card, struct sc_pin_cmd_data *data, struct iasecc_pin_policy *pin)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *save_current_df = NULL, *save_current_ef = NULL;
	struct iasecc_sdo sdo;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pin_get_policy(card:%p)", card);

	if (data->pin_type != SC_AC_CHV)   {
		sc_log(ctx, "PIN policy only available for CHV type");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (card->cache.valid && card->cache.current_df)   {
		sc_file_dup(&save_current_df, card->cache.current_df);
		if (save_current_df == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			sc_log(ctx, "Cannot duplicate current DF file");
			goto err;
		}
	}

	if (card->cache.valid && card->cache.current_ef)   {
		sc_file_dup(&save_current_ef, card->cache.current_ef);
		if (save_current_ef == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			sc_log(ctx, "Cannot duplicate current EF file");
			goto err;
		}
	}

	if (!(data->pin_reference & IASECC_OBJECT_REF_LOCAL) && card->cache.valid && card->cache.current_df) {
		sc_format_path("3F00", &path);
		path.type = SC_PATH_TYPE_FILE_ID;
		rv = iasecc_select_file(card, &path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Unable to select MF");
	}

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = IASECC_SDO_CLASS_CHV;

	sdo.sdo_ref = data->pin_reference & ~IASECC_OBJECT_REF_LOCAL;

	sc_log(ctx, "iasecc_pin_get_policy() reference %i", sdo.sdo_ref);

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get SDO PIN data");

	if (sdo.docp.acls_contact.size == 0) {
		rv = SC_ERROR_INVALID_DATA;
		sc_log(ctx, "Extremely strange ... there is no ACLs");
		goto err;
	}

	sc_log(ctx,
	       "iasecc_pin_get_policy() sdo.docp.size.size %"SC_FORMAT_LEN_SIZE_T"u",
	       sdo.docp.size.size);

	memcpy(pin->scbs, sdo.docp.scbs, sizeof(pin->scbs));

	pin->min_length = (sdo.data.chv.size_min.value ? *sdo.data.chv.size_min.value : -1);
	pin->max_length = (sdo.data.chv.size_max.value ? *sdo.data.chv.size_max.value : -1);
	pin->tries_maximum = (sdo.docp.tries_maximum.value ? *sdo.docp.tries_maximum.value : -1);
	pin->tries_remaining = (sdo.docp.tries_remaining.value ? *sdo.docp.tries_remaining.value : -1);
	if (sdo.docp.size.value && sdo.docp.size.size <= sizeof(int)) {
		unsigned int n = 0;
		unsigned int i;
		for (i=0; i<sdo.docp.size.size; i++)
			n = (n << 8) + *(sdo.docp.size.value + i);
		pin->stored_length = n;
	} else {
		pin->stored_length = -1;
	}

	sc_log(ctx, "PIN policy: size max/min %i/%i, tries max/left %i/%i",
	       pin->max_length, pin->min_length, pin->tries_maximum, pin->tries_remaining);
	iasecc_sdo_free_fields(card, &sdo);

	if (save_current_df)   {
		sc_log(ctx, "iasecc_pin_get_policy() restore current DF");
		rv = iasecc_select_file(card, &save_current_df->path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot return to saved DF");
	}

	if (save_current_ef)   {
		sc_log(ctx, "iasecc_pin_get_policy() restore current EF");
		rv = iasecc_select_file(card, &save_current_ef->path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot return to saved EF");
	}

err:
	sc_file_free(save_current_df);
	sc_file_free(save_current_ef);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_get_info(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_pin_policy policy;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pin_get_info(card:%p)", card);

	/*
	 * Get PIN status first and thereafter update with info from PIN policy, when available.
	 * The first one is typically used for the PIN verification status and number of remaining
	 * tries, and the second one for the maximum tries. If a field is present in both, the
	 * policy takes precedence.
	 */
	rv = iasecc_pin_get_status(card, data, tries_left);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN status");

	rv = iasecc_pin_get_policy(card, data, &policy);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN policy");

	/*
	 * We only care about the tries_xxx fields in the PIN policy, since the other ones are not
	 * commonly expected or used in a SC_PIN_CMD_GET_INFO response.	Note that max_tries is
	 * always taken from the policy, since it is never expected to be available in status (it
	 * is set to -1 when not available in policy).
	 */
	data->pin1.max_tries = policy.tries_maximum;
	if (policy.tries_remaining >= 0)
		data->pin1.tries_left = policy.tries_remaining;

	if (tries_left)
		*tries_left = data->pin1.tries_left;

	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * Check PIN and update flags. We reject empty PINs (where data is non-NULL but length is 0) due
 * to their non-obvious meaning in verification/change/unblock. We also need to update the
 * SC_PIN_CMD_USE_PINPAD flag depending on the PIN being available or not (where data is NULL means
 * that PIN is not available). Unfortunately we can not rely on the flag provided by the caller due
 * to its ambiguous use. The approach here is to assume pin-pad input when the PIN data is NULL,
 * otherwise not.
 */
static int iasecc_check_update_pin(struct sc_pin_cmd_data *data, struct sc_pin_cmd_pin *pin)
{
	if ((!pin->data && pin->len) || (pin->data && !pin->len))
		return SC_ERROR_INVALID_ARGUMENTS;

	if (pin->data)
		data->flags &= ~SC_PIN_CMD_USE_PINPAD;
	else
		data->flags |= SC_PIN_CMD_USE_PINPAD;

	return SC_SUCCESS;
}


/* Enable PIN padding with 0xff as the padding character, unless already enabled */
static void iasecc_set_pin_padding(struct sc_pin_cmd_data *data, struct sc_pin_cmd_pin *pin,
				   size_t pad_len)
{
	if (data->flags & SC_PIN_CMD_NEED_PADDING)
		return;

	pin->pad_length = pad_len;
	pin->pad_char = 0xff;
	data->flags |= SC_PIN_CMD_NEED_PADDING;
}


/*
 * Retrieve the PIN policy and combine it with the existing fields in an intelligent way. This is
 * needed since we may be called with existing settings, typically from the PKCS #15 layer. We use
 * the IAS-ECC card-level PIN settings as complementary.
 */
static int
iasecc_pin_merge_policy(struct sc_card *card, struct sc_pin_cmd_data *data,
			struct sc_pin_cmd_pin *pin, struct iasecc_pin_policy *policy)
{
	struct sc_context *ctx = card->ctx;
	size_t pad_len = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pin_merge_policy(card:%p)", card);

	rv = iasecc_check_update_pin(data, pin);
	LOG_TEST_RET(ctx, rv, "Invalid PIN");

	rv = iasecc_pin_get_policy(card, data, policy);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN policy");

	/* Some cards obviously use the min/max length fields to signal PIN padding */
	if (policy->min_length > 0 && policy->min_length == policy->max_length) {
		pad_len = policy->min_length;
		policy->min_length = 0;
	}

	/* Take the most limited values of min/max lengths */
	if (policy->min_length > 0 && (size_t) policy->min_length > pin->min_length)
		pin->min_length = policy->min_length;
	if (policy->max_length > 0 && (!pin->max_length || (size_t) policy->max_length < pin->max_length))
		pin->max_length = policy->max_length;

	/* Set PIN padding if needed and not already set by the caller */
	if (pad_len)
		iasecc_set_pin_padding(data, pin, pad_len);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_keyset_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo_update update;
	struct iasecc_sdo sdo;
	unsigned scb;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change keyset(ref:%i,lengths:%i)", data->pin_reference, data->pin2.len);
	if (!data->pin2.data || data->pin2.len < 32)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Needs at least 32 bytes for a new keyset value");

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = IASECC_SDO_CLASS_KEYSET;
	sdo.sdo_ref  = data->pin_reference;

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_RET(ctx, rv, "Cannot get keyset data");

	if (sdo.docp.acls_contact.size == 0)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Bewildered ... there are no ACLs");
	scb = sdo.docp.scbs[IASECC_ACLS_KEYSET_PUT_DATA];
	iasecc_sdo_free_fields(card, &sdo);

	sc_log(ctx, "SCB:0x%X", scb);
	if (!(scb & IASECC_SCB_METHOD_SM))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Other then protected by SM, the keyset change is not supported");

	memset(&update, 0, sizeof(update));
	update.magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
	update.sdo_class = sdo.sdo_class;
	update.sdo_ref = sdo.sdo_ref;

	update.fields[0].parent_tag = IASECC_SDO_KEYSET_TAG;
	update.fields[0].tag = IASECC_SDO_KEYSET_TAG_MAC;
	/* FIXME is it safe to modify the const value here? */
	update.fields[0].value = (unsigned char *) data->pin2.data;
	update.fields[0].size = 16;

	update.fields[1].parent_tag = IASECC_SDO_KEYSET_TAG;
	update.fields[1].tag = IASECC_SDO_KEYSET_TAG_ENC;
	/* FIXME is it safe to modify the const value here? */
	update.fields[1].value = (unsigned char *) data->pin2.data + 16;
	update.fields[1].size = 16;

	rv = iasecc_sm_sdo_update(card, (scb & IASECC_SCB_METHOD_MASK_REF), &update);
	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * The PIN change function can handle different PIN-pad input combinations for the old and new
 * PINs:
 *   OLD PIN:   NEW PIN:     DESCRIPTION:
 *   Available  Available    No input.
 *   Available  Absent       Only new PIN is input.
 *   Absent     Available    Both PINs are input (due to limitations in IAS-ECC)
 *   Absent     Absent       Both PINs are input.
 */
static int
iasecc_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	struct iasecc_pin_policy policy;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change PIN(ref:%i,type:0x%X,lengths:%i/%i)",
	       data->pin_reference, data->pin_type, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)   {
		sc_log(ctx, "Can not change non-CHV PINs");
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	/*
	 * Verify the original PIN. This would normally not be needed since it is implicitly done
	 * by the card when executing a PIN change command. But we must go through our verification
	 * function in order to handle secure messaging setup, if enabled for the PIN. The
	 * verification is skipped for PIN-pads (which do not work with SM anyway), to avoid the
	 * user having to enter the PIN twice.
	 */
	pin_cmd = *data;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;

	rv = iasecc_pin_merge_policy(card, &pin_cmd, &pin_cmd.pin1, &policy);
	LOG_TEST_RET(ctx, rv, "Failed to update PIN1 info");

	if (!(pin_cmd.flags & SC_PIN_CMD_USE_PINPAD)) {
		rv = iasecc_chv_verify(card, &pin_cmd, policy.scbs, tries_left);
		LOG_TEST_RET(ctx, rv, "PIN CHV verification error");
	}

	/*
	 * To keep things simple, assume that we can use the same PIN parameters for the new PIN as
	 * for the old one, ignoring the ones specified by the caller, with the exception of the
	 * PIN prompt and the PIN data itself. Note that the old PIN is re-verified since the
	 * IAS-ECC specification has no implicit verification for the PIN change command. This also
	 * forces us to always use PIN-pad for the second PIN if the first one was input on a
	 * PIN-pad.
	 */
	pin_cmd.cmd = SC_PIN_CMD_CHANGE;
	pin_cmd.pin2 = pin_cmd.pin1;
	pin_cmd.pin2.prompt = data->pin2.prompt;
	if (pin_cmd.flags & SC_PIN_CMD_USE_PINPAD) {
		pin_cmd.pin2.data = NULL;
		pin_cmd.pin2.len = 0;
	} else {
		pin_cmd.pin2.data = data->pin2.data;
		pin_cmd.pin2.len = data->pin2.len;
	}

	rv = iasecc_check_update_pin(&pin_cmd, &pin_cmd.pin2);
	LOG_TEST_RET(ctx, rv, "Invalid PIN2");

	rv = iso_ops->pin_cmd(card, &pin_cmd, tries_left);
	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * The PIN unblock function can handle different PIN-pad input combinations for the PUK and the new
 * PIN:
 *   PUK:       NEW PIN:     DESCRIPTION:
 *   Available  Available    No input.
 *   Available  Absent       Only new PIN is input.
 *   Absent     Available    Only PUK is input.
 *   Absent     Absent       Both PUK and new PIN are input.
 */
static int
iasecc_pin_reset(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	unsigned char scb;
	struct sc_pin_cmd_data pin_cmd;
	struct iasecc_pin_policy policy;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Reset PIN(ref:%i,lengths:%i/%i)", data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unblock procedure can be used only with the PINs of type CHV");

	rv = iasecc_pin_get_policy(card, data, &policy);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN policy");

	scb = policy.scbs[IASECC_ACLS_CHV_RESET];
	do   {
		unsigned need_all = scb & IASECC_SCB_METHOD_NEED_ALL ? 1 : 0;
		unsigned char se_num = scb & IASECC_SCB_METHOD_MASK_REF;

		if (scb & IASECC_SCB_METHOD_USER_AUTH)   {
			pin_cmd = *data;
			if (pin_cmd.puk_reference)   {
				sc_log(ctx, "Verify PIN with CHV %X", pin_cmd.puk_reference);
				pin_cmd.pin_type = SC_AC_CHV;
				pin_cmd.pin_reference = pin_cmd.puk_reference;
			} else   {
				sc_log(ctx, "Verify PIN in SE %X", se_num);
				pin_cmd.pin_type = SC_AC_SEN;
				pin_cmd.pin_reference = se_num;
			}
			rv = iasecc_pin_verify(card, &pin_cmd, tries_left);
			LOG_TEST_RET(ctx, rv, "iasecc_pin_reset() verify PUK error");

			if (!need_all)
				break;
		}

		if (scb & IASECC_SCB_METHOD_SM)   {
			rv = iasecc_sm_pin_reset(card, se_num, data);
			LOG_FUNC_RETURN(ctx, rv);
		}

		if (scb & IASECC_SCB_METHOD_EXT_AUTH)   {
			rv =  iasecc_sm_external_authentication(card, data->pin_reference, tries_left);
			LOG_TEST_RET(ctx, rv, "iasecc_pin_reset() external authentication error");
		}
	} while(0);

	/* Use iso 7816 layer for unblock, with implicit pin for PIN1 and the new PIN for PIN2 */
	pin_cmd = *data;
	pin_cmd.cmd = SC_PIN_CMD_UNBLOCK;
	pin_cmd.flags |= SC_PIN_CMD_IMPLICIT_CHANGE;
	pin_cmd.pin1.len = 0;

	rv = iasecc_pin_merge_policy(card, &pin_cmd, &pin_cmd.pin2, &policy);
	LOG_TEST_RET(ctx, rv, "Failed to update PIN2 info");

	rv = iso_ops->pin_cmd(card, &pin_cmd, tries_left);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pin_cmd() cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%i, PIN-2 %p:%i",
			data->cmd, data->pin_type, data->pin_reference,
			data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);

	switch (data->cmd)   {
	case SC_PIN_CMD_VERIFY:
		rv = iasecc_pin_verify(card, data, tries_left);
		break;
	case SC_PIN_CMD_CHANGE:
		if (data->pin_type == SC_AC_AUT)
			rv = iasecc_keyset_change(card, data, tries_left);
		else
			rv = iasecc_pin_change(card, data, tries_left);
		break;
	case SC_PIN_CMD_UNBLOCK:
		rv = iasecc_pin_reset(card, data, tries_left);
		break;
	case SC_PIN_CMD_GET_INFO:
		rv = iasecc_pin_get_info(card, data, tries_left);
		break;
	default:
		sc_log(ctx, "Other pin commands not supported yet: 0x%X", data->cmd);
		rv = SC_ERROR_NOT_SUPPORTED;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	struct sc_context *ctx = card->ctx;
	struct sc_iin *iin = &card->serialnr.iin;
	struct sc_apdu apdu;
	unsigned char rbuf[0xC0];
	size_t ii, offs, len;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (card->serialnr.len)
		goto end;

	memset(&card->serialnr, 0, sizeof(card->serialnr));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x80 | IASECC_SFI_EF_SN, 0);
	apdu.le = sizeof(rbuf);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Get 'serial number' data failed");

	if (apdu.resplen < 2 || rbuf[0] != ISO7812_PAN_SN_TAG || rbuf[1] > (apdu.resplen-2))
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "serial number parse error");
	len = rbuf[1];

	iin->mii = (rbuf[2] >> 4) & 0x0F;

	iin->country = 0;
	for (ii=5; ii<8; ii++)   {
		iin->country *= 10;
		iin->country += (rbuf[ii/2] >> ((ii & 0x01) ? 0 : 4)) & 0x0F;
	}

	iin->issuer_id = 0;
	for (ii=8; ii<10; ii++)   {
		iin->issuer_id *= 10;
		iin->issuer_id += (rbuf[ii/2] >> (ii & 0x01 ? 0 : 4)) & 0x0F;
	}

	/* Copy the serial number from the last 8 bytes (at most) */
	offs = len > 8 ? len - 8 : 0;
	if (card->type == SC_CARD_TYPE_IASECC_SAGEM)   {
		/* 5A 0A 92 50 00 20 10 10 25 00 01 3F */
		/*            00 02 01 01 02 50 00 13  */
		for (ii=0; ii < len - offs; ii++)
			*(card->serialnr.value + ii) = ((rbuf[ii + offs + 1] & 0x0F) << 4)
				+ ((rbuf[ii + offs + 2] & 0xF0) >> 4) ;
		card->serialnr.len = ii;
	}
	else   {
		for (ii=0; ii < len - offs; ii++)
			*(card->serialnr.value + ii) = rbuf[ii + offs + 2];
		card->serialnr.len = ii;
	}

	do  {
		char txt[0x200];

		for (ii=0;ii<card->serialnr.len;ii++)
			sprintf(txt + ii*2, "%02X", *(card->serialnr.value + ii));

		sc_log(ctx, "serial number '%s'; mii %i; country %i; issuer_id %li", txt, iin->mii, iin->country, iin->issuer_id);
	} while(0);

end:
	if (serial)
		memcpy(serial, &card->serialnr, sizeof(*serial));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_create(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char *data = NULL, sdo_class = sdo->sdo_class;
	struct iasecc_sdo_update update;
	struct iasecc_extended_tlv *field = NULL;
	int rv = SC_ERROR_NOT_SUPPORTED, data_len;

	LOG_FUNC_CALLED(ctx);
	if (sdo->magic != SC_CARDCTL_IASECC_SDO_MAGIC)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid SDO data");

	sc_log(ctx, "iasecc_sdo_create(card:%p) %02X%02X%02X", card,
			IASECC_SDO_TAG_HEADER, sdo->sdo_class | 0x80, sdo->sdo_ref);

	data_len = iasecc_sdo_encode_create(ctx, sdo, &data);
	LOG_TEST_RET(ctx, data_len, "iasecc_sdo_create() cannot encode SDO create data");
	sc_log(ctx, "iasecc_sdo_create() create data(%i):%s", data_len, sc_dump_hex(data, data_len));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
	apdu.data = data;
	apdu.datalen = data_len;
	apdu.lc = data_len;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_sdo_create() SDO put data error");

	memset(&update, 0, sizeof(update));
	update.magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
	update.sdo_class = sdo->sdo_class;
	update.sdo_ref = sdo->sdo_ref;

	if (sdo_class == IASECC_SDO_CLASS_RSA_PRIVATE)   {
		update.fields[0] = sdo->data.prv_key.compulsory;
		update.fields[0].parent_tag = IASECC_SDO_PRVKEY_TAG;
		field = &sdo->data.prv_key.compulsory;
	}
	else if (sdo_class == IASECC_SDO_CLASS_RSA_PUBLIC)   {
		update.fields[0] = sdo->data.pub_key.compulsory;
		update.fields[0].parent_tag = IASECC_SDO_PUBKEY_TAG;
		field = &sdo->data.pub_key.compulsory;
	}
	else if (sdo_class == IASECC_SDO_CLASS_KEYSET)   {
		update.fields[0] = sdo->data.keyset.compulsory;
		update.fields[0].parent_tag = IASECC_SDO_KEYSET_TAG;
		field = &sdo->data.keyset.compulsory;
	}

	if (update.fields[0].value && !update.fields[0].on_card)   {
		rv = iasecc_sdo_put_data(card, &update);
		LOG_TEST_RET(ctx, rv, "failed to update 'Compulsory usage' data");

		if (field)
			field->on_card = 1;
	}

	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

/* Oberthur's specific */
static int
iasecc_sdo_delete(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char data[6] = {
		0x70, 0x04, 0xBF, 0xFF, 0xFF, 0x00
	};
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (sdo->magic != SC_CARDCTL_IASECC_SDO_MAGIC)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid SDO data");

	data[2] = IASECC_SDO_TAG_HEADER;
	data[3] = sdo->sdo_class | 0x80;
	data[4] = sdo->sdo_ref;
	sc_log(ctx, "delete SDO %02X%02X%02X", data[2], data[3], data[4]);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
	apdu.data = data;
	apdu.datalen = sizeof(data);
	apdu.lc = sizeof(data);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "delete SDO error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_sdo_put_data(struct sc_card *card, struct iasecc_sdo_update *update)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int ii, rv;

	LOG_FUNC_CALLED(ctx);
	if (update->magic != SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid SDO update data");

	for(ii=0; update->fields[ii].tag && ii < IASECC_SDO_TAGS_UPDATE_MAX; ii++)   {
		unsigned char *encoded = NULL;
		int encoded_len;

		encoded_len = iasecc_sdo_encode_update_field(ctx, update->sdo_class, update->sdo_ref,
							&update->fields[ii], &encoded);
		sc_log(ctx, "iasecc_sdo_put_data() encode[%i]; tag %X; encoded_len %i", ii, update->fields[ii].tag, encoded_len);
		LOG_TEST_RET(ctx, encoded_len, "Cannot encode update data");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
		apdu.data = encoded;
		apdu.datalen = encoded_len;
		apdu.lc = encoded_len;
		apdu.flags |= SC_APDU_FLAGS_CHAINING;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "SDO put data error");

		free(encoded);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_key_rsa_put_data(struct sc_card *card, struct iasecc_sdo_rsa_update *update)
{
	struct sc_context *ctx = card->ctx;
	unsigned char scb;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (update->sdo_prv_key)   {
		sc_log(ctx, "encode private rsa in %p", &update->update_prv);
		rv = iasecc_sdo_encode_rsa_update(card->ctx, update->sdo_prv_key, update->p15_rsa, &update->update_prv);
		LOG_TEST_RET(ctx, rv, "failed to encode update of RSA private key");
	}

	if (update->sdo_pub_key)   {
		sc_log(ctx, "encode public rsa in %p", &update->update_pub);
		if (card->type == SC_CARD_TYPE_IASECC_SAGEM)   {
			if (update->sdo_pub_key->data.pub_key.cha.value)   {
				free(update->sdo_pub_key->data.pub_key.cha.value);
				memset(&update->sdo_pub_key->data.pub_key.cha, 0, sizeof(update->sdo_pub_key->data.pub_key.cha));
			}
		}
		rv = iasecc_sdo_encode_rsa_update(card->ctx, update->sdo_pub_key, update->p15_rsa, &update->update_pub);
		LOG_TEST_RET(ctx, rv, "failed to encode update of RSA public key");
	}

	if (update->sdo_prv_key)   {
		sc_log(ctx, "reference of the private key to store: %X", update->sdo_prv_key->sdo_ref);

		if (update->sdo_prv_key->docp.acls_contact.size == 0)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "extremely strange ... there are no ACLs");

		scb = update->sdo_prv_key->docp.scbs[IASECC_ACLS_RSAKEY_PUT_DATA];
		sc_log(ctx, "'UPDATE PRIVATE RSA' scb 0x%X", scb);

		do   {
			unsigned all_conditions = scb & IASECC_SCB_METHOD_NEED_ALL ? 1 : 0;

			if ((scb & IASECC_SCB_METHOD_USER_AUTH) && !all_conditions)
				break;

			if (scb & IASECC_SCB_METHOD_EXT_AUTH)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Not yet");

			if (scb & IASECC_SCB_METHOD_SM)   {
#ifdef ENABLE_SM
				rv = iasecc_sm_rsa_update(card, scb & IASECC_SCB_METHOD_MASK_REF, update);
				LOG_FUNC_RETURN(ctx, rv);
#else
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
#endif
			}
		} while(0);

		rv = iasecc_sdo_put_data(card, &update->update_prv);
		LOG_TEST_RET(ctx, rv, "failed to update of RSA private key");
	}

	if (update->sdo_pub_key)   {
		sc_log(ctx, "reference of the public key to store: %X", update->sdo_pub_key->sdo_ref);

		rv = iasecc_sdo_put_data(card, &update->update_pub);
		LOG_TEST_RET(ctx, rv, "failed to update of RSA public key");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_tag_from_class(unsigned sdo_class)
{
	switch (sdo_class & ~IASECC_OBJECT_REF_LOCAL)   {
	case IASECC_SDO_CLASS_CHV:
		return IASECC_SDO_CHV_TAG;
	case IASECC_SDO_CLASS_RSA_PRIVATE:
		return IASECC_SDO_PRVKEY_TAG;
	case IASECC_SDO_CLASS_RSA_PUBLIC:
		return IASECC_SDO_PUBKEY_TAG;
	case IASECC_SDO_CLASS_SE:
		return IASECC_SDO_CLASS_SE;
	case IASECC_SDO_CLASS_KEYSET:
		return IASECC_SDO_KEYSET_TAG;
	}

	return -1;
}


static int
iasecc_sdo_get_tagged_data(struct sc_card *card, int sdo_tag, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[0x100];
	size_t offs = sizeof(sbuf) - 1;
	unsigned char rbuf[0x400];
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "sdo_tag=0x%x sdo_ref=0x%x sdo_class=0x%x", sdo_tag,
			sdo->sdo_ref, sdo->sdo_class);

	/* XXX: for the CPx, the SDO are available from some specific path */
	if (iasecc_is_cpx(card)) {
		struct sc_path path;
		char *path_str = NULL;
		switch(sdo_tag) {
			case IASECC_SDO_PRVKEY_TAG:
			/* APDU 00 CB 3F FF 0B 4D 09 70 07 BF 90 02 03 7F 48 80 */
			path_str = "3F00:0001";
			break;
			case IASECC_SDO_CHV_TAG:
			/* APDU 00 CB 3F FF 0B 4D 09 70 07 BF 81 01 03 7F 41 80 */
			path_str = "3F00";
			break;
			default:
			path_str = NULL;
			break;
		}
		if (path_str) {
			sc_log(ctx, "Warning: Enforce the path=%s", path_str);
			sc_format_path(path_str, &path);
			rv = iasecc_select_file(card, &path, NULL);
			LOG_TEST_RET(ctx, rv, "path error");
		}
	}

	sbuf[offs--] = 0x80;
	sbuf[offs--] = sdo_tag & 0xFF;
	if ((sdo_tag >> 8) & 0xFF)
		sbuf[offs--] = (sdo_tag >> 8) & 0xFF;
	sbuf[offs] = sizeof(sbuf) - offs - 1;
	offs--;

	sbuf[offs--] = sdo->sdo_ref & 0x9F;
	sbuf[offs--] = sdo->sdo_class | IASECC_OBJECT_REF_LOCAL;
	sbuf[offs--] = IASECC_SDO_TAG_HEADER;

	sbuf[offs] = sizeof(sbuf) - offs - 1;
	offs--;
	sbuf[offs--] = IASECC_SDO_TEMPLATE_TAG;

	sbuf[offs] = sizeof(sbuf) - offs - 1;
	offs--;
	sbuf[offs] = 0x4D;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x3F, 0xFF);
	apdu.data = sbuf + offs;
	apdu.datalen = sizeof(sbuf) - offs;
	apdu.lc = sizeof(sbuf) - offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x100;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "SDO get data error");

	rv = iasecc_sdo_parse(card, apdu.resp, apdu.resplen, sdo);
	LOG_TEST_RET(ctx, rv, "cannot parse SDO data");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_sdo_get_data(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	int rv, sdo_tag;

	LOG_FUNC_CALLED(ctx);

	sdo_tag = iasecc_sdo_tag_from_class(sdo->sdo_class);

	rv = iasecc_sdo_get_tagged_data(card, sdo_tag, sdo);
	/* When there is no public data 'GET DATA' returns error */
	if (rv != SC_ERROR_INCORRECT_PARAMETERS)
		LOG_TEST_RET(ctx, rv, "cannot parse ECC SDO data");

	rv = iasecc_sdo_get_tagged_data(card, IASECC_DOCP_TAG, sdo);
	LOG_TEST_RET(ctx, rv, "cannot parse ECC DOCP data");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_sdo_generate(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo_update update_pubkey;
	struct sc_apdu apdu;
	unsigned char scb, sbuf[5], rbuf[0x400], exponent[3] = {0x01, 0x00, 0x01};
	int offs = 0, rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);

	if (sdo->sdo_class != IASECC_SDO_CLASS_RSA_PRIVATE)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "For a moment, only RSA_PRIVATE class can be accepted for the SDO generation");

	if (sdo->docp.acls_contact.size == 0)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Bewildered ... there are no ACLs");

	scb = sdo->docp.scbs[IASECC_ACLS_RSAKEY_GENERATE];
	sc_log(ctx, "'generate RSA key' SCB 0x%X", scb);
	do   {
		unsigned all_conditions = scb & IASECC_SCB_METHOD_NEED_ALL ? 1 : 0;

		if (scb & IASECC_SCB_METHOD_USER_AUTH)
			if (!all_conditions)
				break;

		if (scb & IASECC_SCB_METHOD_EXT_AUTH)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Not yet");

		if (scb & IASECC_SCB_METHOD_SM)   {
			rv = iasecc_sm_rsa_generate(card, scb & IASECC_SCB_METHOD_MASK_REF, sdo);
                        LOG_FUNC_RETURN(ctx, rv);
		}
	} while(0);

	memset(&update_pubkey, 0, sizeof(update_pubkey));
	update_pubkey.magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
	update_pubkey.sdo_class = IASECC_SDO_CLASS_RSA_PUBLIC;
	update_pubkey.sdo_ref = sdo->sdo_ref;

	update_pubkey.fields[0].parent_tag = IASECC_SDO_PUBKEY_TAG;
	update_pubkey.fields[0].tag = IASECC_SDO_PUBKEY_TAG_E;
	update_pubkey.fields[0].value = exponent;
	update_pubkey.fields[0].size = sizeof(exponent);

	rv = iasecc_sdo_put_data(card, &update_pubkey);
	LOG_TEST_RET(ctx, rv, "iasecc_sdo_generate() update SDO public key failed");

	offs = 0;
	sbuf[offs++] = IASECC_SDO_TEMPLATE_TAG;
	sbuf[offs++] = 0x03;
	sbuf[offs++] = IASECC_SDO_TAG_HEADER;
	sbuf[offs++] = IASECC_SDO_CLASS_RSA_PRIVATE | IASECC_OBJECT_REF_LOCAL;
	sbuf[offs++] = sdo->sdo_ref & ~IASECC_OBJECT_REF_LOCAL;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x47, 0x00, 0x00);
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x100;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "SDO get data error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_get_chv_reference_from_se(struct sc_card *card, int *se_reference)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info se;
	struct sc_crt crt;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!se_reference)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid arguments");

	memset(&se, 0, sizeof(se));
	se.reference = *se_reference;

	rv = iasecc_se_get_info(card, &se);
	LOG_TEST_RET(ctx, rv, "get SE info error");

	memset(&crt, 0, sizeof(crt));
	crt.tag = IASECC_CRT_TAG_AT;
	crt.usage = IASECC_UQB_AT_USER_PASSWORD;

	rv = iasecc_se_get_crt(card, &se, &crt);
	LOG_TEST_RET(ctx, rv, "Cannot get 'USER PASSWORD' authentication template");

	sc_file_free(se.df);
	LOG_FUNC_RETURN(ctx, crt.refs[0]);
}


static int
iasecc_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo *sdo = (struct iasecc_sdo *) ptr;

	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return iasecc_get_serialnr(card, (struct sc_serial_number *)ptr);
	case SC_CARDCTL_IASECC_SDO_CREATE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_CREATE: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_create(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_DELETE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_DELETE: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_delete(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_PUT_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_PUT_DATA: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_put_data(card, (struct iasecc_sdo_update *) ptr);
	case SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA");
		return iasecc_sdo_key_rsa_put_data(card, (struct iasecc_sdo_rsa_update *) ptr);
	case SC_CARDCTL_IASECC_SDO_GET_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_GET_DATA: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_get_data(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_GENERATE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_GET_DATA: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_generate(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_GET_SE_INFO:
		sc_log(ctx, "CMD SC_CARDCTL_GET_SE_INFO: sdo_class %X", sdo->sdo_class);
		return iasecc_se_get_info(card, (struct iasecc_se_info *) ptr);
	case SC_CARDCTL_GET_CHV_REFERENCE_IN_SE:
		sc_log(ctx, "CMD SC_CARDCTL_GET_CHV_REFERENCE_IN_SE");
		return iasecc_get_chv_reference_from_se(card, (int *)ptr);
	case SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE");
		return iasecc_get_free_reference(card, (struct iasecc_ctl_get_free_reference *)ptr);
	}
	return SC_ERROR_NOT_SUPPORTED;
}


static int
iasecc_decipher(struct sc_card *card,
		const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[0x200];
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];
	size_t offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(card->ctx,
	       "crgram_len %"SC_FORMAT_LEN_SIZE_T"u;  outlen %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len, out_len);
	if (!out || !out_len || in_len > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	offs = 0;
	sbuf[offs++] = 0x81;
	memcpy(sbuf + offs, in, in_len);
	offs += in_len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = 256;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Card returned error");

	if (out_len > apdu.resplen)
		out_len = apdu.resplen;

	memcpy(out, apdu.resp, out_len);
	rv = out_len;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_qsign_data_sha1(struct sc_context *ctx, const unsigned char *in, size_t in_len,
				struct iasecc_qsign_data *out)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L

	int r = SC_ERROR_INTERNAL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_MD *md = NULL;
	SHA_CTX *md_data = NULL;
	unsigned int md_out_len;
	SHA_LONG pre_hash_Nl, *hh[5] = {NULL, NULL, NULL, NULL, NULL};
	int jj, ii;
	int hh_size = sizeof(SHA_LONG), hh_num = SHA_DIGEST_LENGTH / sizeof(SHA_LONG);

	LOG_FUNC_CALLED(ctx);

	if (!in || !in_len || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx,
	       "sc_pkcs15_get_qsign_data() input data length %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len);
	memset(out, 0, sizeof(struct iasecc_qsign_data));

	md = sc_evp_md(ctx, "SHA1");
	mdctx = EVP_MD_CTX_new();
	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		sc_log(ctx, "EVP_DigestInit_ex failed");
		goto err;
	}
	
	md_data = EVP_MD_CTX_md_data(mdctx);
	if (md_data == NULL) {
		sc_log(ctx, "Failed to find md_data");
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	if (EVP_DigestUpdate(mdctx, in, in_len) != 1) {
		sc_log(ctx, "EVP_DigestUpdate failed");
		goto err;
	}

	hh[0] = &md_data->h0;
	hh[1] = &md_data->h1;
	hh[2] = &md_data->h2;
	hh[3] = &md_data->h3;
	hh[4] = &md_data->h4;

	for (jj=0; jj<hh_num; jj++)
		for(ii=0; ii<hh_size; ii++)
			out->pre_hash[jj*hh_size + ii] = ((*hh[jj] >> 8*(hh_size-1-ii)) & 0xFF);
	out->pre_hash_size = SHA_DIGEST_LENGTH;
	sc_log(ctx, "Pre SHA1:%s", sc_dump_hex(out->pre_hash, out->pre_hash_size));

	pre_hash_Nl = md_data->Nl - (md_data->Nl % (sizeof(md_data->data) *8));
	for (ii=0; ii<hh_size; ii++)   {
		out->counter[ii] = (md_data->Nh >> 8*(hh_size-1-ii)) &0xFF;
		out->counter[hh_size+ii] = (pre_hash_Nl >> 8*(hh_size-1-ii)) &0xFF;
	}
	for (ii=0, out->counter_long=0; ii<(int)sizeof(out->counter); ii++)
		out->counter_long = out->counter_long*0x100 + out->counter[ii];
	sc_log(ctx, "Pre counter(%li):%s", out->counter_long, sc_dump_hex(out->counter, sizeof(out->counter)));

	if (md_data->num)   {
		memcpy(out->last_block, in + in_len - md_data->num, md_data->num);
		out->last_block_size = md_data->num;
		sc_log(ctx, "Last block(%"SC_FORMAT_LEN_SIZE_T"u):%s",
		       out->last_block_size,
		       sc_dump_hex(out->last_block, out->last_block_size));
	}

	if (EVP_DigestFinal_ex(mdctx, out->hash, &md_out_len) != 1) {
		sc_log(ctx, "EVP_DigestFinal_ex failed");
		goto err;
	}

	out->hash_size = SHA_DIGEST_LENGTH;
	sc_log(ctx, "Expected digest %s\n", sc_dump_hex(out->hash, out->hash_size));

	r = SC_SUCCESS;
	goto end;

err:
	if (ctx->debug > 0 && ctx->debug_file != 0)
		ERR_print_errors_fp(ctx->debug_file);
end:
	EVP_MD_CTX_free(mdctx);
	sc_evp_md_free(md);

	LOG_FUNC_RETURN(ctx, r);

#else /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
}


static int
iasecc_qsign_data_sha256(struct sc_context *ctx, const unsigned char *in, size_t in_len,
				struct iasecc_qsign_data *out)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L

	int r = SC_ERROR_INTERNAL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_MD *md = NULL;
	SHA256_CTX *md_data;
	unsigned int md_out_len;

	SHA_LONG pre_hash_Nl;
	int jj, ii;
	int hh_size = sizeof(SHA_LONG), hh_num = SHA256_DIGEST_LENGTH / sizeof(SHA_LONG);

	LOG_FUNC_CALLED(ctx);
	if (!in || !in_len || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx,
	       "sc_pkcs15_get_qsign_data() input data length %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len);
	memset(out, 0, sizeof(struct iasecc_qsign_data));

	md = sc_evp_md(ctx, "SHA256");
	mdctx = EVP_MD_CTX_new();
	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		sc_log(ctx, "EVP_DigestInit_ex failed");
		goto err;
	}

	md_data = EVP_MD_CTX_md_data(mdctx);
	if (md_data == NULL) {
		sc_log(ctx, "Failed to find md_data");
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	if (EVP_DigestUpdate(mdctx, in, in_len) != 1) {
		sc_log(ctx, "EVP_DigestUpdate failed");
		goto err;
	}

	for (jj=0; jj<hh_num; jj++)
		for(ii=0; ii<hh_size; ii++)
			out->pre_hash[jj*hh_size + ii] = ((md_data->h[jj] >> 8*(hh_size-1-ii)) & 0xFF);
	out->pre_hash_size = SHA256_DIGEST_LENGTH;
	sc_log(ctx, "Pre hash:%s", sc_dump_hex(out->pre_hash, out->pre_hash_size));

	pre_hash_Nl = md_data->Nl - (md_data->Nl % (sizeof(md_data->data) * 8));
	for (ii=0; ii<hh_size; ii++)   {
		out->counter[ii] = (md_data->Nh >> 8*(hh_size-1-ii)) &0xFF;
		out->counter[hh_size+ii] = (pre_hash_Nl >> 8*(hh_size-1-ii)) &0xFF;
	}
	for (ii=0, out->counter_long=0; ii<(int)sizeof(out->counter); ii++)
		out->counter_long = out->counter_long*0x100 + out->counter[ii];
	sc_log(ctx, "Pre counter(%li):%s", out->counter_long, sc_dump_hex(out->counter, sizeof(out->counter)));

	if (md_data->num)   {
		memcpy(out->last_block, in + in_len - md_data->num, md_data->num);
		out->last_block_size = md_data->num;
		sc_log(ctx, "Last block(%"SC_FORMAT_LEN_SIZE_T"u):%s",
		       out->last_block_size,
		       sc_dump_hex(out->last_block, out->last_block_size));
	}

	if (EVP_DigestFinal_ex(mdctx, out->hash, &md_out_len) != 1) {
		sc_log(ctx, "EVP_DigestFinal_ex failed");
		goto err;
	}

	out->hash_size = SHA256_DIGEST_LENGTH;
	sc_log(ctx, "Expected digest %s\n", sc_dump_hex(out->hash, out->hash_size));

	r = SC_SUCCESS;
	goto end;

err:
	if (ctx->debug > 0 && ctx->debug_file != 0)
		ERR_print_errors_fp(ctx->debug_file);
end:
	EVP_MD_CTX_free(mdctx);
	sc_evp_md_free(md);

	LOG_FUNC_RETURN(ctx, r);

#else /* OPENSSL_VERSION_NUMBER < 0x30000000L */
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
}


static int
iasecc_compute_signature_dst(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct iasecc_qsign_data qsign_data;
	struct sc_apdu apdu;
	size_t offs = 0, hash_len = 0;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_compute_signature_dst() input length %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len);
	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_SIGN");
	else if (!(prv->key_size & 0x1E0) || (prv->key_size & ~0x1E0))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key size for SC_SEC_OPERATION_SIGN");

	memset(&qsign_data, 0, sizeof(qsign_data));
	if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)   {
		rv = iasecc_qsign_data_sha1(card->ctx, in, in_len, &qsign_data);
	}
	else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)   {
		rv = iasecc_qsign_data_sha256(card->ctx, in, in_len, &qsign_data);
	}
	else
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Need RSA_HASH_SHA1 or RSA_HASH_SHA256 algorithm");
	LOG_TEST_RET(ctx, rv, "Cannot get QSign data");

	sc_log(ctx,
	       "iasecc_compute_signature_dst() hash_len %"SC_FORMAT_LEN_SIZE_T"u; key_size %"SC_FORMAT_LEN_SIZE_T"u",
	       hash_len, prv->key_size);

	memset(sbuf, 0, sizeof(sbuf));
	sbuf[offs++] = 0x90;
	if (qsign_data.counter_long)   {
		sbuf[offs++] = qsign_data.hash_size + 8;
		memcpy(sbuf + offs, qsign_data.pre_hash, qsign_data.pre_hash_size);
		offs += qsign_data.pre_hash_size;
		memcpy(sbuf + offs, qsign_data.counter, sizeof(qsign_data.counter));
		offs += sizeof(qsign_data.counter);
	}
	else   {
		sbuf[offs++] = 0;
	}

	sbuf[offs++] = 0x80;
	sbuf[offs++] = qsign_data.last_block_size;
	memcpy(sbuf + offs, qsign_data.last_block, qsign_data.last_block_size);
	offs += qsign_data.last_block_size;

	sc_log(ctx,
	       "iasecc_compute_signature_dst() offs %"SC_FORMAT_LEN_SIZE_T"u; OP(meth:%X,ref:%X)",
	       offs, prv->op_method, prv->op_ref);
	if (prv->op_method == SC_AC_SCB && (prv->op_ref & IASECC_SCB_METHOD_SM))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Not yet");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x90, 0xA0);
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Compute signature failed");

	sc_log(ctx, "iasecc_compute_signature_dst() partial hash OK");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.resp = rbuf;
	apdu.resplen = prv->key_size;
	apdu.le = prv->key_size;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Compute signature failed");

	sc_log(ctx,
	       "iasecc_compute_signature_dst() DST resplen %"SC_FORMAT_LEN_SIZE_T"u",
	       apdu.resplen);
	if (apdu.resplen > out_len)
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Result buffer too small for the DST signature");

	memcpy(out, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}


static int
iasecc_compute_signature_at(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct sc_apdu apdu;
	size_t offs = 0, sz = 0;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (env->operation != SC_SEC_OPERATION_AUTHENTICATE)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_AUTHENTICATE");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x00, 0x00);
	apdu.datalen = in_len;
	apdu.data = in;
	apdu.lc = in_len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x100;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Compute signature failed");

	do   {
		if (offs + apdu.resplen > out_len)
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small to return signature");

		memcpy(out + offs, rbuf, apdu.resplen);
		offs += apdu.resplen;

		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
			break;

		if (apdu.sw1 == 0x61)   {
			sz = apdu.sw2 == 0x00 ? 0x100 : apdu.sw2;
			rv = iso_ops->get_response(card, &sz, rbuf);
			LOG_TEST_RET(ctx, rv, "Get response error");

			apdu.resplen = rv;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "Impossible error: SW1 is not 0x90 neither 0x61");
		}

	} while(rv > 0);

	LOG_FUNC_RETURN(ctx, offs);
}


static int
iasecc_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx;
	struct iasecc_private_data *prv;
	struct sc_security_env *env;

	if (!card || !in || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->ctx;
	prv = (struct iasecc_private_data *) card->drv_data;
	env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "inlen %"SC_FORMAT_LEN_SIZE_T"u, outlen %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len, out_len);

	if (env->operation == SC_SEC_OPERATION_SIGN)
		return iasecc_compute_signature_dst(card, in, in_len, out,  out_len);
	else if (env->operation == SC_SEC_OPERATION_AUTHENTICATE)
		return iasecc_compute_signature_at(card, in, in_len, out,  out_len);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
iasecc_read_public_key(struct sc_card *card, unsigned type,
		struct sc_path *key_path, unsigned ref, unsigned size,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo sdo;
	struct sc_pkcs15_bignum bn[2];
	struct sc_pkcs15_pubkey_rsa rsa_key;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (type != SC_ALGORITHM_RSA)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sc_log(ctx, "read public kay(ref:%i;size:%i)", ref, size);

	memset(&bn, 0, sizeof bn);
	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = IASECC_SDO_CLASS_RSA_PUBLIC;
	sdo.sdo_ref  = ref & ~IASECC_OBJECT_REF_LOCAL;

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_GOTO_ERR(ctx, rv, "failed to read public key: cannot get RSA SDO data");

	if (out)
		*out = NULL;
	if (out_len)
		*out_len = 0;

	bn[0].data = (unsigned char *) malloc(sdo.data.pub_key.n.size);
	if (!bn[0].data)
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_OUT_OF_MEMORY, "failed to read public key: cannot allocate modulus");
	bn[0].len = sdo.data.pub_key.n.size;
	memcpy(bn[0].data, sdo.data.pub_key.n.value, sdo.data.pub_key.n.size);

	bn[1].data = (unsigned char *) malloc(sdo.data.pub_key.e.size);
	if (!bn[1].data)
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_OUT_OF_MEMORY, "failed to read public key: cannot allocate exponent");
	bn[1].len = sdo.data.pub_key.e.size;
	memcpy(bn[1].data, sdo.data.pub_key.e.value, sdo.data.pub_key.e.size);

	rsa_key.modulus = bn[0];
	rsa_key.exponent = bn[1];

	rv = sc_pkcs15_encode_pubkey_rsa(ctx, &rsa_key, out, out_len);
	LOG_TEST_GOTO_ERR(ctx, rv, "failed to read public key: cannot encode RSA public key");

	if (out && out_len)
		sc_log(ctx, "encoded public key: %s", sc_dump_hex(*out, *out_len));

err:
	if (bn[0].data)
		free(bn[0].data);
	if (bn[1].data)
		free(bn[1].data);

	iasecc_sdo_free_fields(card, &sdo);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_get_free_reference(struct sc_card *card, struct iasecc_ctl_get_free_reference *ctl_data)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo *sdo = NULL;
	int idx, rv;

	LOG_FUNC_CALLED(ctx);

	if ((ctl_data->key_size % 0x40) || ctl_data->index < 1 || (ctl_data->index > IASECC_OBJECT_REF_MAX))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "get reference for key(index:%i,usage:%X,access:%X)", ctl_data->index, ctl_data->usage, ctl_data->access);
	/* TODO: when looking for the slot for the signature keys, check also PSO_SIGNATURE ACL */
	for (idx = ctl_data->index; idx <= IASECC_OBJECT_REF_MAX; idx++)   {
		unsigned char sdo_tag[3] = {
			IASECC_SDO_TAG_HEADER, IASECC_OBJECT_REF_LOCAL | IASECC_SDO_CLASS_RSA_PRIVATE, idx
		};
		size_t sz;

		if (sdo)
			iasecc_sdo_free(card, sdo);

		rv = iasecc_sdo_allocate_and_parse(card, sdo_tag, 3, &sdo);
		LOG_TEST_RET(ctx, rv, "cannot parse SDO data");

		rv = iasecc_sdo_get_data(card, sdo);
		if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)   {
			iasecc_sdo_free(card, sdo);

			sc_log(ctx, "found empty key slot %i", idx);
			break;
		} else if (rv != SC_SUCCESS) {
			iasecc_sdo_free(card, sdo);

			sc_log(ctx, "get new key reference failed");
			LOG_FUNC_RETURN(ctx, rv);
		}

		sz = *(sdo->docp.size.value + 0) * 0x100 + *(sdo->docp.size.value + 1);
		sc_log(ctx,
		       "SDO(idx:%i) size %"SC_FORMAT_LEN_SIZE_T"u; key_size %"SC_FORMAT_LEN_SIZE_T"u",
		       idx, sz, ctl_data->key_size);

		if (sz != ctl_data->key_size / 8)   {
			sc_log(ctx,
			       "key index %i ignored: different key sizes %"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u",
			       idx, sz, ctl_data->key_size / 8);
			continue;
		}

		if (sdo->docp.non_repudiation.value)   {
			sc_log(ctx, "non repudiation flag %X", sdo->docp.non_repudiation.value[0]);
			if ((ctl_data->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) && !(*sdo->docp.non_repudiation.value))   {
				sc_log(ctx, "key index %i ignored: need non repudiation", idx);
				continue;
			}

			if (!(ctl_data->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) && *sdo->docp.non_repudiation.value)   {
				sc_log(ctx, "key index %i ignored: don't need non-repudiation", idx);
				continue;
			}
		}

		if (ctl_data->access & SC_PKCS15_PRKEY_ACCESS_LOCAL)   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_GENERATE] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: GENERATE KEY not allowed", idx);
				continue;
			}
		}
		else   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_PUT_DATA] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: PUT DATA not allowed", idx);
				continue;
			}
		}

		if ((ctl_data->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) && (ctl_data->usage & SC_PKCS15_PRKEY_USAGE_SIGN))   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_PSO_SIGN] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: PSO SIGN not allowed", idx);
				continue;
			}
		}
		else if (ctl_data->usage & SC_PKCS15_PRKEY_USAGE_SIGN)   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_INTERNAL_AUTH] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: INTERNAL AUTHENTICATE not allowed", idx);
				continue;
			}
		}

		if (ctl_data->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP))   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_PSO_DECIPHER] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: PSO DECIPHER not allowed", idx);
				continue;
			}
		}

		break;
	}

	ctl_data->index = idx;

	if (idx > IASECC_OBJECT_REF_MAX)
		LOG_FUNC_RETURN(ctx, SC_ERROR_DATA_OBJECT_NOT_FOUND);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (!iso_ops)
		iso_ops = iso_drv->ops;

	iasecc_ops = *iso_ops;

	iasecc_ops.match_card = iasecc_match_card;
	iasecc_ops.init = iasecc_init;
	iasecc_ops.finish = iasecc_finish;
	iasecc_ops.read_binary = iasecc_read_binary;
	/*	write_binary: ISO7816 implementation works	*/
	/*	update_binary: ISO7816 implementation works	*/
	iasecc_ops.erase_binary = iasecc_erase_binary;
	/*	resize_binary	*/
	/* 	read_record: Untested	*/
	/*	write_record: Untested	*/
	/*	append_record: Untested	*/
	/*	update_record: Untested	*/
	iasecc_ops.select_file = iasecc_select_file;
	/*	get_response: Untested	*/
	iasecc_ops.get_challenge = iasecc_get_challenge;
	iasecc_ops.logout = iasecc_logout;
	/*	restore_security_env	*/
	iasecc_ops.set_security_env = iasecc_set_security_env;
	iasecc_ops.decipher = iasecc_decipher;
	iasecc_ops.compute_signature = iasecc_compute_signature;
	iasecc_ops.create_file = iasecc_create_file;
	iasecc_ops.delete_file = iasecc_delete_file;
	/*	list_files	*/
	iasecc_ops.check_sw = iasecc_check_sw;
	iasecc_ops.card_ctl = iasecc_card_ctl;
	iasecc_ops.process_fci = iasecc_process_fci;
	/*	construct_fci: Not needed	*/
	iasecc_ops.pin_cmd = iasecc_pin_cmd;
	/*	get_data: Not implemented	*/
	/*	put_data: Not implemented	*/
	/*	delete_record: Not implemented	*/

	iasecc_ops.read_public_key = iasecc_read_public_key;

	return &iasecc_drv;
}

struct sc_card_driver *
sc_get_iasecc_driver(void)
{
	return sc_get_driver();
}

#else

/* we need to define the functions below to export them */
#include "errors.h"

int
iasecc_se_get_info()
{
	return SC_ERROR_NOT_SUPPORTED;
}

#endif /* ENABLE_OPENSSL */
