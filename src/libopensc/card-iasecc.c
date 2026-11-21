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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
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

/* ChipDoc Generic applet (IAS/ECC Generic applet on ChipDoc cards):
 * PKCS#1 type 1 padding and raw RSA are done by the card.  OpenSC builds the
 * DigestInfo and the card pads it; PSS and raw RSA use complete blocks. */
#define IASECC_CHIPDOC_GENERIC_RSA_FLAGS ( 0			\
		| SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01	\
		| SC_ALGORITHM_RSA_PAD_PSS		\
		| SC_ALGORITHM_RSA_RAW			\
		| SC_ALGORITHM_RSA_HASH_SHA1		\
		| SC_ALGORITHM_RSA_HASH_SHA224		\
		| SC_ALGORITHM_RSA_HASH_SHA256		\
		| SC_ALGORITHM_RSA_HASH_SHA384		\
		| SC_ALGORITHM_RSA_HASH_SHA512		\
		| SC_ALGORITHM_RSA_HASH_NONE)

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
	{ "3B:EA:00:00:81:31:FE:45:00:31:C1:73:C8:40:00:00:90:00:7A", NULL,
		"NXP ChipDoc (Generic applet)", SC_CARD_TYPE_IASECC_AMOS, 0, NULL },
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
static int iasecc_pin_get_status(struct sc_card *card, struct sc_pin_cmd_data *data);
static int iasecc_pin_get_info(struct sc_card *card, struct sc_pin_cmd_data *data);
static int iasecc_check_update_pin(struct sc_pin_cmd_data *data, struct sc_pin_cmd_pin *pin);
static void iasecc_set_pin_padding(struct sc_pin_cmd_data *data, struct sc_pin_cmd_pin *pin,
				   size_t pad_len);
static int iasecc_pin_merge_policy(struct sc_card *card, struct sc_pin_cmd_data *data,
				   struct sc_pin_cmd_pin *pin, struct iasecc_pin_policy *policy);
static int iasecc_get_free_reference(struct sc_card *card, struct iasecc_ctl_get_free_reference *ctl_data);
static int iasecc_sdo_put_data(struct sc_card *card, struct iasecc_sdo_update *update);

/* ChipDoc Generic applet (IAS/ECC Generic applet on ChipDoc cards) */
static int iasecc_chipdoc_generic_detect(struct sc_card *card);
static int iasecc_chipdoc_generic_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num);
static int iasecc_chipdoc_generic_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data);
static int iasecc_chipdoc_generic_compute_signature(struct sc_card *card, const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len);
static int iasecc_chipdoc_generic_compute_signature_pss(struct sc_card *card, const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len);
static int iasecc_chipdoc_generic_decipher(struct sc_card *card, const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len);
static int iasecc_chipdoc_generic_compute_signature_raw(struct sc_card *card, const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len);
static int iasecc_chipdoc_generic_sdo_get_tagged_data(struct sc_card *card, const unsigned char *req,
		size_t req_len, unsigned char *resp, size_t *resp_len);
static void iasecc_chipdoc_generic_sm_close(struct sc_card *card);

#ifdef ENABLE_SM
static int _iasecc_sm_read_binary(struct sc_card *card, unsigned int offs, unsigned char *buf, size_t count);
static int _iasecc_sm_update_binary(struct sc_card *card, unsigned int offs, const unsigned char *buff, size_t count);
#endif

void
sc_invalidate_cache(struct sc_card *card)
{
	if (card) {
		struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
		sc_file_free(prv->cache.current_ef);
		sc_file_free(prv->cache.current_df);
		memset(&prv->cache, 0, sizeof(prv->cache));
		prv->cache.valid = 0;
	}
}

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
		sc_log(ctx, "current PIN-%i", current->reference);
		pin_status = current;
	}
	else   {
		pin_status = calloc(1, sizeof(struct iasecc_pin_status));
		if (!pin_status)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot callocate PIN status info");
		sc_log(ctx, "allocated %p", pin_status);
	}

	pin_status->reference = pin_cmd->pin_reference;
	if (pin_cmd->pin1.data)
		SHA1(pin_cmd->pin1.data, pin_cmd->pin1.len, pin_status->sha1);
	else
		memset(pin_status->sha1, 0, SHA_DIGEST_LENGTH);

	sc_log_hex(ctx, "sha1(PIN)", pin_status->sha1, SHA_DIGEST_LENGTH);

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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
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

	sc_invalidate_cache(card);
	sc_file_dup(&prv->cache.current_df, mf_file);
	prv->cache.valid = 1;

	if (file_out && *file_out == NULL)
		*file_out = mf_file;
	else
		sc_file_free(mf_file);

	LOG_FUNC_RETURN(ctx, rv);
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

	sc_log(ctx, "EF.ATR: IO Buffer Size send/sc %zd/%zd recv/sc %zd/%zd",
			sizes->send, sizes->send_sc, sizes->recv, sizes->recv_sc);

	card->max_send_size = sizes->send;
	card->max_recv_size = sizes->recv;

	/* Most of the card producers interpret 'send' values as "maximum APDU data size".
	 * Oberthur strictly follows specification and interpret these values as "maximum APDU command size".
	 * Here we need 'data size'.
	 */
	if (card->max_send_size > 0xFF)
		card->max_send_size -= 5;

	sc_log(ctx, "EF.ATR: max send/recv sizes %zX/%zX", card->max_send_size, card->max_recv_size);

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
	size_t resp_len = sizeof(resp);
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	rv = iso7816_select_aid(card, MIIASECC_AID.value, MIIASECC_AID.len, resp, &resp_len);
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
		rv = SC_ERROR_INVALID_CARD;
		LOG_TEST_GOTO_ERR(ctx, rv, "");
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

		if (card->type == SC_CARD_TYPE_IASECC_AMOS)
			iasecc_chipdoc_generic_detect(card);
	}

#ifdef ENABLE_SM
	/* ChipDoc Generic uses its own SM implementation. */
	if (!private_data->chipdoc_generic)   {
		card->sm_ctx.ops.read_binary = _iasecc_sm_read_binary;
		card->sm_ctx.ops.update_binary = _iasecc_sm_update_binary;
	}
#endif

	if (!rv && card->ef_atr && card->ef_atr->aid.len)   {
		sc_log(ctx, "EF.ATR(aid:'%s')", sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len));
	}

err:
	if (rv < 0) {
		sc_invalidate_cache(card);
		free(private_data);
		card->drv_data = old_drv_data;
	} else {
		free(old_drv_data);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_read_binary(struct sc_card *card, unsigned int offs,
		unsigned char *buf, size_t count, unsigned long *flags)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_read_binary(card:%p) offs %i; count %zu", card, offs, count);
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
	LOG_TEST_RET(ctx, rv, "failed");
	sc_log(ctx, "apdu.resplen %zu", apdu.resplen);

	if (apdu.resplen == IASECC_READ_BINARY_LENGTH_MAX && apdu.resplen < count)   {
		rv = iasecc_read_binary(card, (int)(offs + apdu.resplen), buf + apdu.resplen, count - apdu.resplen, flags);
		if (rv != SC_ERROR_WRONG_LENGTH)   {
			LOG_TEST_RET(ctx, rv, "read tail failed");
			apdu.resplen += rv;
		}
	}

	LOG_FUNC_RETURN(ctx, (int)apdu.resplen);
}


static int
iasecc_erase_binary(struct sc_card *card, unsigned int offs, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *tmp = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_erase_binary(card:%p) count %zu", card, count);
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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "card:%p offs:%i count:%zu ", card, offs, count);
	if (offs > 0x7fff)
		LOG_TEST_RET(ctx, SC_ERROR_OFFSET_TOO_LARGE, "Invalid arguments");

	if (count == 0)
		return 0;

	if (prv->cache.valid && prv->cache.current_ef) {
		entry = sc_file_get_acl_entry(prv->cache.current_ef, SC_AC_OP_READ);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "'READ' ACL not present");

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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	int rv;

	if (count == 0)
		return SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "card:%p offs:%i count:%zu ", card, offs, count);

	if (prv->cache.valid && prv->cache.current_ef) {
		entry = sc_file_get_acl_entry(prv->cache.current_ef, SC_AC_OP_UPDATE);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "'UPDATE' ACL not present");

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
	apdu->resplen = apdu->datalen + 16;
	memcpy(apdu->resp, dummy_df_fcp, apdu->resplen);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/* TODO: redesign using of cache
 * TODO: do not keep intermediate results in 'file_out' argument */
static int
iasecc_select_file(struct sc_card *card, const struct sc_path *path,
		 struct sc_file **file_out)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct sc_path lpath;
	int rv, ii;

	LOG_FUNC_CALLED(ctx);
	memcpy(&lpath, path, sizeof(struct sc_path));
	if (file_out)
		*file_out = NULL;

	sc_log(ctx, "iasecc_select_file(card:%p) path.len %zu; path.type %i; aid_len %zu",
			card, path->len, path->type, path->aid.len);
	sc_log(ctx, "path:%s", sc_print_path(path));

	/* PINs are internal; AODF references CHV files 0001/0002 that don't exist
	 * in the applet DF, so ignore their selection. */
	if (prv->chipdoc_generic && path->type == SC_PATH_TYPE_FILE_ID && path->len == 2
			&& path->aid.len == 0 && path->value[0] == 0x00
			&& (path->value[1] == 0x01 || path->value[1] == 0x02))   {
		sc_log(ctx, "ChipDoc Generic: ignoring the selection of the PIN file %02X%02X",
				path->value[0], path->value[1]);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	if (prv->chipdoc_generic && prv->chipdoc_generic_ssc) {
		if (path->aid.len == 0 && prv->cache.current_df
				&& prv->cache.current_df->path.len == path->len
				&& !memcmp(prv->cache.current_df->path.value, path->value, path->len)) {
			sc_log(ctx, "ChipDoc Generic: \"%s\" is already selected", sc_print_path(path));
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		}
		sc_log(ctx, "ChipDoc Generic: leaving the selected DF, closing SM");
		iasecc_chipdoc_generic_sm_close(card);
	}

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

		sc_log(ctx, "select parent AID:%p/%zu", lpath.aid.value, lpath.aid.len);
		sc_log(ctx, "select parent AID:%s", sc_dump_hex(lpath.aid.value, lpath.aid.len));
		memset(&ppath, 0, sizeof(ppath));
		memcpy(ppath.value, lpath.aid.value, lpath.aid.len);
		ppath.len = lpath.aid.len;
		ppath.type = SC_PATH_TYPE_DF_NAME;

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

	do   {
		struct sc_apdu apdu;
		struct sc_file *file = NULL;
		unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
		size_t pathlen = lpath.len;

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
			LOG_TEST_GOTO_ERR(ctx, rv, "invalid PATH type");
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

		LOG_TEST_GOTO_ERR(ctx, rv, "check SW failed");

		sc_log(ctx, "apdu.resp %zu", apdu.resplen);
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
				sc_invalidate_cache(card);
				sc_file_dup(&prv->cache.current_df, file);
				prv->cache.valid = 1;
			}
			else   {
				sc_file_free(prv->cache.current_ef);
				sc_file_dup(&prv->cache.current_ef, file);
				prv->cache.valid = 1;
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
			sc_invalidate_cache(card);
			prv->cache.valid = 1;
		}
	} while(0);

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
		sc_log(ctx, "  FCP length %zu", taglen);
		buf = tag;
		buflen = taglen;
	}

	tag = sc_asn1_find_tag(ctx,  buf, buflen, 0x62, &taglen);
	sc_log(ctx, "processing FCI: 0x62 tag %p", tag);
	if (tag != NULL) {
		sc_log(ctx, "  FCP length %zu", taglen);
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

	sc_log(ctx, "type %i; let's parse file ACLs", file->type);
	tag = sc_asn1_find_tag(ctx, buf, buflen, IASECC_DOCP_TAG_ACLS, &taglen);
	if (tag)
		acls = sc_asn1_find_tag(ctx, tag, taglen, IASECC_DOCP_TAG_ACLS_CONTACT, &taglen);
	else
		acls = sc_asn1_find_tag(ctx, buf, buflen, IASECC_DOCP_TAG_ACLS_CONTACT, &taglen);

	if (!acls)   {
		sc_log(ctx, "ACLs not found in data(%zu) %s", buflen, sc_dump_hex(buf, buflen));
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "ACLs tag missing");
	}

	sc_log(ctx, "ACLs(%zu) '%s'", taglen, sc_dump_hex(acls, taglen));
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

		sc_log(ctx, "ACLs mask 0x%X, offs %zu, op 0x%X, acls[offs] 0x%X", mask, offs, op, acls[offs]);
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
	size_t ii, amb, offs = 0, mask, nn_smb;

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
		sc_log(ctx, "%zu: AMB %zX; nn_smb %zu", ii, amb, nn_smb);
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

	LOG_FUNC_RETURN(ctx, (int)offs);
}


static int
iasecc_create_file(struct sc_card *card, struct sc_file *file)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	const struct sc_acl_entry *entry = NULL;
	unsigned char sbuf[0x100];
	size_t sbuf_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (file->type != SC_FILE_TYPE_WORKING_EF)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Creation of the file with of this type is not supported");

	rv = iasecc_fcp_encode(card, file, sbuf + 2, sizeof(sbuf)-2);
	LOG_TEST_RET(ctx, rv, "FCP encode error");
	sbuf_len = rv;

	sbuf[0] = IASECC_FCP_TAG;
	sbuf[1] = sbuf_len;

	if (prv->cache.valid && prv->cache.current_df) {
		entry = sc_file_get_acl_entry(prv->cache.current_df, SC_AC_OP_CREATE);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "'CREATE' ACL not present");

		sc_log(ctx, "'CREATE' method/reference %X/%X", entry->method, entry->key_ref);
		sc_log(ctx, "create data: '%s'", sc_dump_hex(sbuf, sbuf_len + 2));
		if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
                        rv = iasecc_sm_create_file(card, entry->key_ref & IASECC_SCB_METHOD_MASK_REF, sbuf, sbuf_len + 2);
                        LOG_TEST_RET(ctx, rv, "SM create file error");

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
	LOG_TEST_RET(ctx, rv, "create file error");

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

	iasecc_chipdoc_generic_sm_close(card);

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

	iasecc_chipdoc_generic_sm_close(card);
	sc_invalidate_cache(card);

	while (se_info)   {
		sc_file_free(se_info->df);
		next = se_info->next;
		iasecc_docp_free_fields(&se_info->docp);
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

	rv = iasecc_select_file(card, path, &file);
	if (rv == SC_ERROR_FILE_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	LOG_TEST_RET(ctx, rv, "Cannot select file to delete");

	entry = sc_file_get_acl_entry(file, SC_AC_OP_DELETE);
	if (!entry) {
		sc_file_free(file);
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "Cannot delete file: no 'DELETE' acl");
	}

	sc_log(ctx, "DELETE method/reference %X/%X", entry->method, entry->key_ref);
	if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
		unsigned char se_num = entry->key_ref & IASECC_SCB_METHOD_MASK_REF;
		rv = iasecc_sm_delete_file(card, se_num, file->id);
		sc_file_free(file);
	}
	else   {
		struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
		sc_file_free(file);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "Delete file failed");

		if (prv->cache.valid) {
			sc_file_free(prv->cache.current_ef);
		}
		prv->cache.current_ef = NULL;
	}

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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info *se_info = NULL, *si = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	se_info = calloc(1, sizeof(struct iasecc_se_info));
	if (!se_info)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SE info allocation error");
	memcpy(se_info, se, sizeof(struct iasecc_se_info));

	if (prv->cache.valid && prv->cache.current_df) {
		sc_file_dup(&se_info->df, prv->cache.current_df);
		if (se_info->df == NULL)   {
			free(se_info);
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");
		}
	}

	rv = iasecc_docp_copy(ctx, &se->docp, &se_info->docp);
	if (rv < 0)   {
		free(se_info->df);
		iasecc_docp_free_fields(&se_info->docp);
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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info *si = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	for(si = prv->se_info; si; si = si->next)   {
		if (si->reference != se->reference)
			continue;
		if (!(prv->cache.valid && prv->cache.current_df) && si->df)
			continue;
		if (prv->cache.valid && prv->cache.current_df && !si->df)
			continue;
		if (prv->cache.valid && prv->cache.current_df && si->df)
			if (memcmp(&prv->cache.current_df->path, &si->df->path, sizeof(struct sc_path)))
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


/*
 * ChipDoc Generic applet.  Key operations use DF "Generic" with ISO 7816-4
 * SM (DH RFC 5114 group 22, 3DES retail MAC).  Key data and PIN
 * verification require that channel; the applet pads PKCS#1 v1.5 itself.
 */

static const unsigned char iasecc_chipdoc_generic_aid[] = IASECC_CHIPDOC_GENERIC_AID;

/* The Generic applet reports 63C7 after reset; the empty VERIFY probe is free. */
#define IASECC_CHIPDOC_GENERIC_PIN_MAX_TRIES 7

/* RFC 5114 group 22 (1024-bit MODP with 160-bit prime order subgroup) */
static const char iasecc_chipdoc_generic_dh_p[] =
	"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
	"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
	"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
	"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
	"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
	"DF1FB2BC2E4A4371";
static const char iasecc_chipdoc_generic_dh_g[] =
	"A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
	"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
	"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
	"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
	"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
	"855E6EEB22B3B2E5";
static const char iasecc_chipdoc_generic_dh_q[] =
	"F518AA8781A8DF278ABA4E7D64B7CB9D49462353";

static int
iasecc_chipdoc_generic_select_applet(struct sc_card *card)
{
	struct sc_path path;
	int rv;

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_DF_NAME;
	memcpy(path.value, iasecc_chipdoc_generic_aid, sizeof(iasecc_chipdoc_generic_aid));
	path.len = sizeof(iasecc_chipdoc_generic_aid);

	rv = iasecc_select_file(card, &path, NULL);
	LOG_TEST_RET(card->ctx, rv, "cannot select the ChipDoc Generic applet");

	return SC_SUCCESS;
}

/* Triple-DES EDE (24 byte key) in CBC mode without padding. */
static int
iasecc_chipdoc_generic_3des_cbc(const unsigned char *key, const unsigned char *iv,
		unsigned char *data, size_t len, int enc)
{
	EVP_CIPHER_CTX *cctx;
	int out_len = 0, rv = SC_SUCCESS;

	cctx = EVP_CIPHER_CTX_new();
	if (!cctx)
		return SC_ERROR_OUT_OF_MEMORY;

	if ((enc ? EVP_EncryptInit_ex(cctx, EVP_des_ede3_cbc(), NULL, key, iv)
		 : EVP_DecryptInit_ex(cctx, EVP_des_ede3_cbc(), NULL, key, iv)) != 1)   {
		EVP_CIPHER_CTX_free(cctx);
		return SC_ERROR_INTERNAL;
	}
	EVP_CIPHER_CTX_set_padding(cctx, 0);

	if ((enc ? EVP_EncryptUpdate(cctx, data, &out_len, data, (int)len)
		 : EVP_DecryptUpdate(cctx, data, &out_len, data, (int)len)) != 1
			|| (size_t)out_len != len)
		rv = SC_ERROR_INTERNAL;

	EVP_CIPHER_CTX_free(cctx);
	return rv;
}


static int
iasecc_chipdoc_generic_crypt(const unsigned char *kenc, unsigned char *data, size_t len, int enc)
{
	unsigned char key24[24], iv[8] = {0};

	memcpy(key24, kenc, 16);
	memcpy(key24 + 16, kenc, 8);

	return iasecc_chipdoc_generic_3des_cbc(key24, iv, data, len, enc);
}

/* Mandatory 0x80 + zero bytes padding (a full block is added when aligned). */
static size_t
iasecc_chipdoc_generic_pad2(const unsigned char *in, size_t in_len, unsigned char *out)
{
	size_t len = ((in_len / 8) + 1) * 8, i;

	if (in != out)
		memcpy(out, in, in_len);
	out[in_len] = 0x80;
	for (i = in_len + 1; i < len; i++)
		out[i] = 0x00;

	return len;
}

static size_t
iasecc_chipdoc_generic_unpad2(unsigned char *buf, size_t len)
{
	while (len > 0 && buf[len - 1] == 0x00)
		len--;
	if (len > 0 && buf[len - 1] == 0x80)
		len--;

	return len;
}

/* ISO 9797-1 MAC algorithm 3 ('retail MAC') with the 16 byte key K1|K2. */
static int
iasecc_chipdoc_generic_mac(const unsigned char *keys, const unsigned char *data, size_t len,
		unsigned char mac[8])
{
	unsigned char k24[24], iv[8] = {0}, phase1[8], block[8];
	unsigned char *tmp;
	size_t body_len;
	int rv;

	if (len < 16 || (len & 7))
		return SC_ERROR_INVALID_ARGUMENTS;

	body_len = len - 8;
	tmp = malloc(body_len);
	if (!tmp)
		return SC_ERROR_OUT_OF_MEMORY;

	/* phase 1: single DES CBC with K1 over all the blocks but the last one */
	memcpy(tmp, data, body_len);
	memcpy(k24, keys, 8);
	memcpy(k24 + 8, keys, 8);
	memcpy(k24 + 16, keys, 8);
	rv = iasecc_chipdoc_generic_3des_cbc(k24, iv, tmp, body_len, 1);
	if (rv == SC_SUCCESS)
		memcpy(phase1, tmp + body_len - 8, 8);
	free(tmp);
	if (rv != SC_SUCCESS)
		return rv;

	/* phase 2: 3DES EDE with K1|K2|K1 over the last block */
	memcpy(k24 + 8, keys + 8, 8);
	memcpy(block, data + len - 8, 8);
	rv = iasecc_chipdoc_generic_3des_cbc(k24, phase1, block, 8, 1);
	if (rv == SC_SUCCESS)
		memcpy(mac, block, 8);

	return rv;
}

/* Key derivation used by the applet: Kenc = SHA1(Z|01)[:16], Kmac = SHA1(Z|02)[:16] */
static int
iasecc_chipdoc_generic_kdf(const unsigned char *z, unsigned char *kenc, unsigned char *mack)
{
	static const unsigned char counter1[4] = {0x00, 0x00, 0x00, 0x01};
	static const unsigned char counter2[4] = {0x00, 0x00, 0x00, 0x02};
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	EVP_MD_CTX *mdctx;
	int rv = SC_SUCCESS;

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		return SC_ERROR_OUT_OF_MEMORY;

	if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) != 1
			|| EVP_DigestUpdate(mdctx, z, 128) != 1
			|| EVP_DigestUpdate(mdctx, counter1, sizeof(counter1)) != 1
			|| EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1
			|| digest_len < 16)   {
		rv = SC_ERROR_INTERNAL;
	} else   {
		memcpy(kenc, digest, 16);

		if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) != 1
				|| EVP_DigestUpdate(mdctx, z, 128) != 1
				|| EVP_DigestUpdate(mdctx, counter2, sizeof(counter2)) != 1
				|| EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1
				|| digest_len < 16)   {
			rv = SC_ERROR_INTERNAL;
		} else   {
			memcpy(mack, digest, 16);
		}
	}

	EVP_MD_CTX_free(mdctx);
	return rv;
}

static int
iasecc_chipdoc_generic_bn2bin(const BIGNUM *bn, unsigned char *buf, int buf_len)
{
	return BN_bn2binpad(bn, buf, buf_len) == buf_len ? SC_SUCCESS : SC_ERROR_INTERNAL;
}

static void
iasecc_chipdoc_generic_sm_close(struct sc_card *card)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;

	if (!prv || !prv->chipdoc_generic)
		return;

	memset(prv->chipdoc_generic_kenc, 0, sizeof(prv->chipdoc_generic_kenc));
	memset(prv->chipdoc_generic_mack, 0, sizeof(prv->chipdoc_generic_mack));
	prv->chipdoc_generic_ssc = 0;
}

static int
iasecc_card_reader_lock_obtained(struct sc_card *card, int was_reset)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;

	if (was_reset && prv && prv->chipdoc_generic) {
		sc_log(card->ctx, "reader reset: closing ChipDoc Generic SM");
		iasecc_chipdoc_generic_sm_close(card);
	}
	return SC_SUCCESS;
}

/* Open a secure messaging channel: DH key agreement + key derivation. */
static int
iasecc_chipdoc_generic_sm_open(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_apdu apdu;
	BIGNUM *p = NULL, *g = NULL, *q = NULL, *q1 = NULL;
	BIGNUM *x = NULL, *y = NULL, *yb = NULL, *z = NULL;
	BN_CTX *bn_ctx = NULL;
	unsigned char sbuf[0x100], rbuf[0x100];
	unsigned char ybuf[128], zbuf[128];
	size_t offs;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (prv->chipdoc_generic_ssc)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	iasecc_chipdoc_generic_sm_close(card);

	rv = iasecc_chipdoc_generic_select_applet(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "cannot select the ChipDoc Generic applet");

	bn_ctx = BN_CTX_new();
	p = BN_new(); g = BN_new(); q = BN_new(); q1 = BN_new();
	x = BN_new(); y = BN_new(); yb = BN_new(); z = BN_new();
	if (!bn_ctx || !p || !g || !q || !q1 || !x || !y || !yb || !z)   {
		rv = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	if (!BN_hex2bn(&p, iasecc_chipdoc_generic_dh_p)
			|| !BN_hex2bn(&g, iasecc_chipdoc_generic_dh_g)
			|| !BN_hex2bn(&q, iasecc_chipdoc_generic_dh_q))   {
		rv = SC_ERROR_INTERNAL;
		goto err;
	}

	if (!BN_sub(q1, q, BN_value_one())
			|| !BN_rand_range(x, q1)
			|| !BN_add_word(x, 1)
			|| !BN_mod_exp(y, g, x, p, bn_ctx))   {
		rv = SC_ERROR_INTERNAL;
		goto err;
	}
	rv = iasecc_chipdoc_generic_bn2bin(y, ybuf, sizeof(ybuf));
	if (rv != SC_SUCCESS)
		goto err;

	offs = 0;
	memcpy(sbuf + offs, "\x80\x01\x1B\x83\x01\x8E\x91\x81\x80", 9);
	offs += 9;
	memcpy(sbuf + offs, ybuf, sizeof(ybuf));
	offs += sizeof(ybuf);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xA6);
	apdu.lc = offs;
	apdu.datalen = offs;
	apdu.data = sbuf;
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "MSE SET AT transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "MSE SET AT failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x3F, 0xFF);
	memcpy(sbuf, "\x4D\x04\xA6\x02\x91\x00", 6);
	apdu.lc = 6;
	apdu.datalen = 6;
	apdu.data = sbuf;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "GET DATA transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "GET DATA failed");

	if (apdu.resplen != 134 || memcmp(rbuf, "\xA6\x81\x83", 3))   {
		sc_log(ctx, "unexpected card public key data (len %zu)", apdu.resplen);
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}

	if (!BN_bin2bn(rbuf + apdu.resplen - 128, 128, yb)
			|| BN_cmp(yb, BN_value_one()) <= 0 || BN_cmp(yb, p) >= 0
			|| !BN_mod_exp(z, yb, x, p, bn_ctx))   {
		rv = SC_ERROR_INTERNAL;
		goto err;
	}
	rv = iasecc_chipdoc_generic_bn2bin(z, zbuf, sizeof(zbuf));
	if (rv != SC_SUCCESS)
		goto err;

	rv = iasecc_chipdoc_generic_kdf(zbuf, prv->chipdoc_generic_kenc, prv->chipdoc_generic_mack);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM key derivation failed");

	prv->chipdoc_generic_ssc = 1;	/* the first SM message uses SSC 2 */

	rv = SC_SUCCESS;
err:
	BN_clear_free(p); BN_clear_free(g); BN_clear_free(q); BN_clear_free(q1);
	BN_clear_free(x); BN_clear_free(y); BN_clear_free(yb); BN_clear_free(z);
	BN_CTX_free(bn_ctx);
	memset(ybuf, 0, sizeof(ybuf));
	memset(zbuf, 0, sizeof(zbuf));
	if (rv != SC_SUCCESS)
		iasecc_chipdoc_generic_sm_close(card);
	LOG_FUNC_RETURN(ctx, rv);
}

#define IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE	0x300

static size_t
iasecc_chipdoc_generic_tlv(unsigned char *buf, size_t buf_size, unsigned tag,
		const unsigned char *val, size_t val_len)
{
	u8 *ptr = buf;

	if (sc_asn1_put_tag(tag, val, val_len, buf, buf_size, &ptr) != SC_SUCCESS)
		return 0;
	return (size_t)(ptr - buf);
}

/*
 * Send one SM command: 'cla' also goes into the MAC (chained PSO uses 0x1C);
 * data goes in DO87, do85 in DO85, optional DO97.  Return the decrypted
 * payloads and the inner status word.
 */
static int
iasecc_chipdoc_generic_sm_cmd(struct sc_card *card, unsigned cla,
		unsigned ins, unsigned p1, unsigned p2,
		const unsigned char *data, size_t data_len,
		const unsigned char *do85, size_t do85_len, int with_le,
		unsigned char *rdata, size_t *rdata_len,
		unsigned char *rdo85, size_t *rdo85_len,
		unsigned *sw_out)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_apdu apdu;
	unsigned char hdr[4], ssc[8], mac[8], rmac[8];
	unsigned char sbuf[IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE];
	unsigned char rbuf[IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE];
	unsigned char tmp[IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE];
	unsigned char fbuf[IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE];
	const unsigned char *do87_val = NULL, *do85_val = NULL;
	size_t offs, total, f_len, t_len, do87_vlen = 0, do85_vlen = 0;
	size_t i, tlv_len, tlv_hdr;
	unsigned long ssc_val;
	unsigned sw = 0;
	int rv = SC_ERROR_INTERNAL, has_mac = 0;

	LOG_FUNC_CALLED(ctx);

	if (!prv->chipdoc_generic_ssc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);


	offs = 0;
	if (data_len)   {
		if (data_len + 9 > sizeof(tmp))   {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			goto err;
		}
		t_len = iasecc_chipdoc_generic_pad2(data, data_len, tmp + 1);
		tmp[0] = 0x01;
		rv = iasecc_chipdoc_generic_crypt(prv->chipdoc_generic_kenc, tmp + 1, t_len, 1);
		if (rv != SC_SUCCESS)
			goto err;
		offs += iasecc_chipdoc_generic_tlv(sbuf + offs, sizeof(sbuf) - offs, IASECC_SM_DO_TAG_TCG, tmp, t_len + 1);
	}
	if (do85_len)   {
		if (do85_len + 8 > sizeof(tmp))   {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			goto err;
		}
		t_len = iasecc_chipdoc_generic_pad2(do85, do85_len, tmp);
		rv = iasecc_chipdoc_generic_crypt(prv->chipdoc_generic_kenc, tmp, t_len, 1);
		if (rv != SC_SUCCESS)
			goto err;
		offs += iasecc_chipdoc_generic_tlv(sbuf + offs, sizeof(sbuf) - offs, IASECC_SM_DO_TAG_TCG_ODD_INS, tmp, t_len);
	}
	if (with_le)   {
		sbuf[offs++] = IASECC_SM_DO_TAG_TLE;
		sbuf[offs++] = 0x01;
		sbuf[offs++] = 0x00;
	}

	/* command MAC: SSC || pad2(header) || pad2(data objects) */
	prv->chipdoc_generic_ssc++;
	ssc_val = prv->chipdoc_generic_ssc;
	for (i = 0; i < 8; i++)   {
		ssc[7 - i] = ssc_val & 0xFF;
		ssc_val >>= 8;
	}

	hdr[0] = cla;
	hdr[1] = ins;
	hdr[2] = p1;
	hdr[3] = p2;
	memcpy(tmp, ssc, 8);
	t_len = 8 + iasecc_chipdoc_generic_pad2(hdr, 4, tmp + 8);
	t_len += iasecc_chipdoc_generic_pad2(sbuf, offs, tmp + t_len);
	rv = iasecc_chipdoc_generic_mac(prv->chipdoc_generic_mack, tmp, t_len, mac);
	if (rv != SC_SUCCESS)
		goto err;

	offs += iasecc_chipdoc_generic_tlv(sbuf + offs, sizeof(sbuf) - offs, IASECC_SM_DO_TAG_TCC, mac, 8);


	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, ins, p1, p2);
	apdu.cla = cla;
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;	/* more data (if any) will be fetched with GET RESPONSE */

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM command transmit failed");

	/* sc_transmit_apdu() has already followed any 0x61xx with GET RESPONSE */
	total = apdu.resplen;

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)   {
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_GOTO_ERR(ctx, rv, "SM command failed");
	}


	prv->chipdoc_generic_ssc++;
	ssc_val = prv->chipdoc_generic_ssc;
	for (i = 0; i < 8; i++)   {
		ssc[7 - i] = ssc_val & 0xFF;
		ssc_val >>= 8;
	}

	offs = 0;
	f_len = 0;
	while (offs < total)   {
		const unsigned char *tlv = rbuf + offs;
		unsigned int tlv_cla, tlv_tag, tlv_id;

		rv = sc_asn1_read_tag(&tlv, total - offs, &tlv_cla, &tlv_tag, &tlv_len);
		if (rv != SC_SUCCESS || tlv == NULL)   {
			rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
			goto err;
		}
		tlv_hdr = (size_t)(tlv - (rbuf + offs));
		tlv_id = tlv_cla | tlv_tag;

		if (tlv_id == IASECC_CARD_ANSWER_TAG_MAC)   {
			if (tlv_len != 8)   {
				rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
				goto err;
			}
			memcpy(rmac, tlv, 8);
			has_mac = 1;
		} else   {
			memcpy(fbuf + f_len, rbuf + offs, tlv_hdr + tlv_len);
			f_len += tlv_hdr + tlv_len;
			if (tlv_id == IASECC_CARD_ANSWER_TAG_DATA)   {
				do87_val = tlv;
				do87_vlen = tlv_len;
			} else if (tlv_id == IASECC_SM_DO_TAG_TCG_ODD_INS)   {
				do85_val = tlv;
				do85_vlen = tlv_len;
			} else if (tlv_id == IASECC_CARD_ANSWER_TAG_SW)   {
				if (tlv_len != 2)   {
					rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
					goto err;
				}
				sw = (tlv[0] << 8) | tlv[1];
			}
		}

		offs += tlv_hdr + tlv_len;
	}

	if (!has_mac)   {
		sc_log(ctx, "no DO8E in the SM response");
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}

	memcpy(tmp, ssc, 8);
	t_len = 8 + iasecc_chipdoc_generic_pad2(fbuf, f_len, tmp + 8);
	rv = iasecc_chipdoc_generic_mac(prv->chipdoc_generic_mack, tmp, t_len, mac);
	if (rv != SC_SUCCESS)
		goto err;
	if (CRYPTO_memcmp(mac, rmac, 8) != 0)   {
		sc_log(ctx, "SM response MAC mismatch");
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}


	if (do87_val && rdata)   {
		if (!do87_vlen || do87_val[0] != 0x01 || (do87_vlen - 1) > sizeof(tmp))   {
			rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
			goto err;
		}
		t_len = do87_vlen - 1;
		memcpy(tmp, do87_val + 1, t_len);
		rv = iasecc_chipdoc_generic_crypt(prv->chipdoc_generic_kenc, tmp, t_len, 0);
		if (rv != SC_SUCCESS)
			goto err;
		t_len = iasecc_chipdoc_generic_unpad2(tmp, t_len);
		if (t_len > *rdata_len)   {
			rv = SC_ERROR_BUFFER_TOO_SMALL;
			goto err;
		}
		memcpy(rdata, tmp, t_len);
		*rdata_len = t_len;
	}
	if (do85_val && rdo85)   {
		if (do85_vlen > sizeof(tmp))   {
			rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
			goto err;
		}
		t_len = do85_vlen;
		memcpy(tmp, do85_val, t_len);
		rv = iasecc_chipdoc_generic_crypt(prv->chipdoc_generic_kenc, tmp, t_len, 0);
		if (rv != SC_SUCCESS)
			goto err;
		t_len = iasecc_chipdoc_generic_unpad2(tmp, t_len);
		if (t_len > *rdo85_len)   {
			rv = SC_ERROR_BUFFER_TOO_SMALL;
			goto err;
		}
		memcpy(rdo85, tmp, t_len);
		*rdo85_len = t_len;
	}

	if (sw_out)
		*sw_out = sw;

	rv = SC_SUCCESS;
err:
	memset(sbuf, 0, sizeof(sbuf));
	memset(tmp, 0, sizeof(tmp));
	memset(fbuf, 0, sizeof(fbuf));
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_chipdoc_generic_check_sw(unsigned sw, int *tries_left)
{
	if (sw == 0x9000)
		return SC_SUCCESS;

	if ((sw & 0xFFF0) == 0x63C0)   {
		if (tries_left)
			*tries_left = sw & 0x0F;
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	switch (sw)   {
	case 0x6982:
	case 0x6985:
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	case 0x6983:
		return SC_ERROR_AUTH_METHOD_BLOCKED;
	case 0x6A80:
	case 0x6A86:
		return SC_ERROR_INVALID_ARGUMENTS;
	case 0x6A88:
		return SC_ERROR_DATA_OBJECT_NOT_FOUND;
	}

	return SC_ERROR_CARD_CMD_FAILED;
}

/* Best effort: the card may be a plain IAS/ECC card. */
static int
iasecc_chipdoc_generic_detect(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_path path;
	/* TokenInfo may contain either applet marker. */
	static const unsigned char token_needle[5] = {'J', 'C', 'O', 'P', '3'};
	static const unsigned char chipdoc_needle[7] = {'C', 'h', 'i', 'p', 'D', 'o', 'c'};
	unsigned char buf[64];
	size_t i;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = iasecc_chipdoc_generic_select_applet(card);
	if (rv != SC_SUCCESS)   {
		sc_log(ctx, "ChipDoc Generic applet is not present: %i", rv);
		sc_invalidate_cache(card);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = 0x50;
	path.value[1] = 0x32;
	path.len = 2;

	rv = iasecc_select_file(card, &path, NULL);
	if (rv == SC_SUCCESS)
		rv = sc_read_binary(card, 0, buf, sizeof(buf), 0);
	if (rv > 0)   {
		for (i = 0; i + sizeof(token_needle) <= (size_t)rv; i++)   {
			if (!memcmp(buf + i, token_needle, sizeof(token_needle))
					|| (i + sizeof(chipdoc_needle) <= (size_t)rv
						&& !memcmp(buf + i, chipdoc_needle, sizeof(chipdoc_needle))))   {
				prv->chipdoc_generic = 1;
				sc_log(ctx, "ChipDoc marker detected in the Generic applet");
				break;
			}
		}
	}

	if (prv->chipdoc_generic)   {
		card->caps |= SC_CARD_CAP_RAW_RSA_DECIPHER;

		free(card->algorithms);
		card->algorithms = NULL;
		card->algorithm_count = 0;
		sc_log(ctx, "ChipDoc Generic applet detected: replacing the algorithm info");
		_sc_card_add_rsa_alg(card, 1024, IASECC_CHIPDOC_GENERIC_RSA_FLAGS, 0x10001);
		_sc_card_add_rsa_alg(card, 2048, IASECC_CHIPDOC_GENERIC_RSA_FLAGS, 0x10001);
	} else   {
		sc_log(ctx, "ChipDoc Generic applet not detected");
	}

	sc_invalidate_cache(card);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
iasecc_chipdoc_generic_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	unsigned ref;

	(void)se_num;
	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "ChipDoc Generic set security env: operation 0x%X, algorithm 0x%lX, flags 0x%lX, key_ref 0x%X",
			env->operation, env->algorithm, env->algorithm_flags, env->key_ref[0]);

	if (env->algorithm != SC_ALGORITHM_RSA)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS)   {
		unsigned long mgf = env->algorithm_flags & SC_ALGORITHM_MGF1_HASHES;

		/* PSS needs a complete block and exactly one MGF1 hash. */
		if (!mgf || (mgf & (mgf - 1)))
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	else if (!(env->algorithm_flags & (SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 |
			SC_ALGORITHM_RSA_RAW)))
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	if (env->operation != SC_SEC_OPERATION_SIGN &&
			env->operation != SC_SEC_OPERATION_DECIPHER)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	if (env->operation == SC_SEC_OPERATION_DECIPHER &&
			(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS))
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	ref = env->key_ref[0] & ~IASECC_OBJECT_REF_LOCAL;
	if (!ref || ref > IASECC_OBJECT_REF_MAX)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	prv->chipdoc_generic_key_ref = ref;
	prv->security_env = *env;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
iasecc_chipdoc_generic_pin_verify(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct sc_context *ctx = card->ctx;
	const unsigned char *pin;
	unsigned sw = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "ChipDoc Generic VERIFY(ref:%u; len:%zu)",
			data->pin_reference, data->pin1.len);

	if (data->pin1.len == 0 || data->pin1.len > 64 || !data->pin1.data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	pin = data->pin1.data + data->pin1.offset;

	rv = iasecc_chipdoc_generic_sm_open(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "cannot open SM session");

	rv = iasecc_chipdoc_generic_sm_cmd(card, 0x0C, 0x20, 0x00, data->pin_reference,
			pin, data->pin1.len, NULL, 0, 0,
			NULL, NULL, NULL, NULL, &sw);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM VERIFY failed");

	rv = iasecc_chipdoc_generic_check_sw(sw, &data->pin1.tries_left);
	LOG_TEST_GOTO_ERR(ctx, rv, "ChipDoc Generic VERIFY failed");

	rv = SC_SUCCESS;
err:
	if (rv != SC_SUCCESS)
		iasecc_chipdoc_generic_sm_close(card);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_chipdoc_generic_pin_get_info(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	/* CHV SDO DOCP: BF81 ref 1; 9A = max tries, 9B = remaining tries. */
	static const unsigned char get_chv_docp[] = {
		0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, 0x01, 0x02, 0xA0, 0x80
	};
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo sdo = {0};
	struct sc_apdu apdu;
	unsigned char resp[0x100];
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (data->pin_type != SC_AC_CHV || data->pin_reference != 0x01)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	/* The CHV SDO is in the MF/main IAS context, not in the Generic DF. */
	rv = iasecc_select_file(card, sc_get_mf_path(), NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "cannot select MF");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x3F, 0xFF);
	apdu.data = get_chv_docp;
	apdu.datalen = sizeof(get_chv_docp);
	apdu.lc = sizeof(get_chv_docp);
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = 0x00;
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "GET DATA refused by the card");

	sdo.sdo_class = IASECC_SDO_CLASS_CHV;
	sdo.sdo_ref = 0x01;
	rv = iasecc_sdo_parse(card, apdu.resp, apdu.resplen, &sdo);
	LOG_TEST_GOTO_ERR(ctx, rv, "cannot parse the CHV SDO");

	if (!sdo.docp.tries_maximum.value && !sdo.docp.tries_remaining.value) {
		rv = SC_ERROR_DATA_OBJECT_NOT_FOUND;
		goto err;
	}

	if (sdo.docp.tries_maximum.value)
		data->pin1.max_tries = *sdo.docp.tries_maximum.value;
	if (sdo.docp.tries_remaining.value)
		data->pin1.tries_left = *sdo.docp.tries_remaining.value;
	sc_log(ctx, "ChipDoc Generic CHV SDO: tries max/left %d/%d",
			data->pin1.max_tries, data->pin1.tries_left);
	rv = SC_SUCCESS;

err:
	iasecc_sdo_free_fields(card, &sdo);
	/* The SDO is read from MF; restore the Generic applet for key operations. */
	if (iasecc_chipdoc_generic_select_applet(card) != SC_SUCCESS)
		sc_log(ctx, "cannot restore the ChipDoc Generic applet");
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_chipdoc_generic_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	int rv;

	switch (data->cmd)   {
	case SC_PIN_CMD_VERIFY:
		rv = iasecc_chipdoc_generic_pin_verify(card, data);
		break;
	case SC_PIN_CMD_GET_INFO:
		if (data->pin_type != SC_AC_CHV || data->pin_reference != 0x01) {
			rv = SC_ERROR_NOT_SUPPORTED;
			break;
		}
		rv = iasecc_chipdoc_generic_pin_get_info(card, data);
		if (rv != SC_SUCCESS) {
			/* Fall back to the free empty VERIFY probe. */
			sc_log(card->ctx, "ChipDoc Generic CHV SDO unavailable (%s), using VERIFY probe",
					sc_strerror(rv));
			rv = iso_ops->pin_cmd(card, data);
			if (rv == SC_SUCCESS && data->pin1.max_tries <= 0)
				data->pin1.max_tries = IASECC_CHIPDOC_GENERIC_PIN_MAX_TRIES;
		}
		break;
	default:
		rv = SC_ERROR_NOT_SUPPORTED;
	}

	return rv;
}

static int
iasecc_chipdoc_generic_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	unsigned char selkey[6];
	unsigned char sig[512];
	unsigned char digestinfo[128];
	const unsigned char *sign_data = in;
	size_t sig_len = sizeof(sig);
	size_t sign_data_len = in_len;
	unsigned sw = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "ChipDoc Generic compute signature: key_ref 0x%X, in_len %zu",
			prv->chipdoc_generic_key_ref, in_len);

	if (!prv->chipdoc_generic_key_ref)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (prv->security_env.algorithm_flags & SC_ALGORITHM_RSA_RAW)
		return iasecc_chipdoc_generic_compute_signature_raw(card, in, in_len, out, out_len);
	if (prv->security_env.algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS)
		return iasecc_chipdoc_generic_compute_signature_pss(card, in, in_len, out, out_len);


	if (in_len == 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (prv->security_env.algorithm_flags & SC_ALGORITHM_RSA_HASHES)   {
		unsigned long hash = prv->security_env.algorithm_flags & SC_ALGORITHM_RSA_HASHES;

		/* INTERNAL AUTHENTICATE applies type-1 padding but not DigestInfo:
		 * add it here so the card pads a complete DigestInfo, not a bare digest. */
		sign_data_len = sizeof(digestinfo);
		rv = sc_pkcs1_encode(ctx, hash | SC_ALGORITHM_RSA_PAD_NONE, in, in_len,
				digestinfo, &sign_data_len, 0, NULL);
		LOG_TEST_RET(ctx, rv, "cannot build the DigestInfo");
		sign_data = digestinfo;
		sc_log(ctx, "ChipDoc Generic: sending %zu-byte DigestInfo", sign_data_len);
	}
	if (sign_data_len > 245)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = iasecc_chipdoc_generic_sm_open(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "cannot open SM session");


	selkey[0] = 0x80;					/* algorithm reference */
	selkey[1] = 0x01;
	selkey[2] = IASECC_ALGORITHM_RSA_PKCS;			/* RSA PKCS#1 */
	selkey[3] = 0x84;					/* key reference */
	selkey[4] = 0x01;
	selkey[5] = IASECC_OBJECT_REF_LOCAL | prv->chipdoc_generic_key_ref;

	rv = iasecc_chipdoc_generic_sm_cmd(card, 0x0C, 0x22, 0x41, 0xA4, selkey, sizeof(selkey), NULL, 0, 0,
			NULL, NULL, NULL, NULL, &sw);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM SET KEY failed");
	rv = iasecc_chipdoc_generic_check_sw(sw, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "SET KEY refused by the card");


	rv = iasecc_chipdoc_generic_sm_cmd(card, 0x0C, 0x88, 0x00, 0x00, sign_data, sign_data_len, NULL, 0, 1,
			sig, &sig_len, NULL, NULL, &sw);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM INTERNAL AUTHENTICATE failed");
	rv = iasecc_chipdoc_generic_check_sw(sw, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "INTERNAL AUTHENTICATE refused by the card");

	if (!sig_len || sig_len > out_len)   {
		rv = SC_ERROR_BUFFER_TOO_SMALL;
		goto err;
	}

	memcpy(out, sig, sig_len);
	rv = (int)sig_len;

err:
	if (rv < 0)
		iasecc_chipdoc_generic_sm_close(card);
	LOG_FUNC_RETURN(ctx, rv);
}

/* Run a complete raw-RSA block through MSE:SET DST and two chained PSOs. */
static int
iasecc_chipdoc_generic_raw_rsa(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	unsigned char mse[6];
	unsigned char stream[IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE];
	unsigned char rbuf[IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE];
	unsigned char odd[IASECC_CHIPDOC_GENERIC_SM_BUF_SIZE];
	size_t rlen = sizeof(rbuf), odd_len = sizeof(odd), split;
	unsigned sw = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!prv->security_env.key_size_bits)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	if (in_len != BYTES4BITS(prv->security_env.key_size_bits)
			|| in_len < 64 || in_len > 256)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	split = in_len - 27;
	stream[0] = 0x81;
	memcpy(stream + 1, in, split);

	rv = iasecc_chipdoc_generic_sm_open(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "cannot open SM session");

	mse[0] = 0x80;
	mse[1] = 0x01;
	mse[2] = 0x8C;
	mse[3] = 0x84;
	mse[4] = 0x01;
	mse[5] = IASECC_OBJECT_REF_LOCAL | prv->chipdoc_generic_key_ref;

	rv = iasecc_chipdoc_generic_sm_cmd(card, 0x0C, 0x22, 0x41, 0xB8, mse, sizeof(mse), NULL, 0, 0,
			NULL, NULL, NULL, NULL, &sw);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM MSE SET DST failed");
	rv = iasecc_chipdoc_generic_check_sw(sw, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "MSE SET DST refused by the card");

	rv = iasecc_chipdoc_generic_sm_cmd(card, 0x1C, 0x2A, 0x80, 0x86, stream, split + 1, NULL, 0, 0,
			NULL, NULL, NULL, NULL, &sw);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM PSO part 1 failed");
	rv = iasecc_chipdoc_generic_check_sw(sw, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "PSO part 1 refused by the card");

	rv = iasecc_chipdoc_generic_sm_cmd(card, 0x0C, 0x2A, 0x80, 0x86, in + split, in_len - split, NULL, 0, 1,
			rbuf, &rlen, odd, &odd_len, &sw);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM PSO part 2 failed");
	rv = iasecc_chipdoc_generic_check_sw(sw, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "PSO part 2 refused by the card");

	if (!rlen && odd_len)   {
		memcpy(rbuf, odd, odd_len);
		rlen = odd_len;
	}
	if (!rlen)   {
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}
	if (rlen > out_len)   {
		rv = SC_ERROR_BUFFER_TOO_SMALL;
		goto err;
	}

	memcpy(out, rbuf, rlen);
	rv = (int)rlen;

err:
	if (rv < 0)
		iasecc_chipdoc_generic_sm_close(card);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_chipdoc_generic_decipher(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;

	if (prv->security_env.operation != SC_SEC_OPERATION_DECIPHER
			|| !prv->chipdoc_generic_key_ref)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	return iasecc_chipdoc_generic_raw_rsa(card, in, in_len, out, out_len);
}

/* CKM_RSA_X_509: sign the caller's complete block as-is. */
static int
iasecc_chipdoc_generic_compute_signature_raw(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	return iasecc_chipdoc_generic_raw_rsa(card, in, in_len, out, out_len);
}

/* Build EMSA-PSS here (the applet adds no padding) and sign it as a raw block. */
static int
iasecc_chipdoc_generic_compute_signature_pss(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	static const struct {
		unsigned int algo;
		unsigned long flags;
	} hashes[] = {
		{ SC_ALGORITHM_RSA_HASH_SHA1,
			SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_MGF1_SHA1 },
		{ SC_ALGORITHM_RSA_HASH_SHA224,
			SC_ALGORITHM_RSA_HASH_SHA224 | SC_ALGORITHM_MGF1_SHA224 },
		{ SC_ALGORITHM_RSA_HASH_SHA256,
			SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_MGF1_SHA256 },
		{ SC_ALGORITHM_RSA_HASH_SHA384,
			SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_MGF1_SHA384 },
		{ SC_ALGORITHM_RSA_HASH_SHA512,
			SC_ALGORITHM_RSA_HASH_SHA512 | SC_ALGORITHM_MGF1_SHA512 },
	};
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	unsigned char em[512];
	unsigned char digest[64];
	unsigned long mgf, hash = 0;
	size_t em_len, digest_len;
	unsigned int algo = 0;
	size_t i;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!prv->security_env.key_size_bits)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	/* Sign-and-hash PSS input is DigestInfo-wrapped by the core; a bare
	 * digest would need external hashing, so refuse it. */
	digest_len = sizeof(digest);
	rv = sc_pkcs1_strip_digest_info_prefix(&algo, in, in_len, digest, &digest_len);
	if (rv != SC_SUCCESS)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	for (i = 0; i < sizeof(hashes)/sizeof(hashes[0]); i++)   {
		if (hashes[i].algo == algo)   {
			hash = hashes[i].flags;
			break;
		}
	}
	mgf = prv->security_env.algorithm_flags & SC_ALGORITHM_MGF1_HASHES;
	if (!hash || mgf != (hash & SC_ALGORITHM_MGF1_HASHES))
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	/* PSS salt length = hash length. */
	em_len = BYTES4BITS(prv->security_env.key_size_bits);
	if (em_len < 64 || em_len > 256)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	rv = sc_pkcs1_encode(ctx, SC_ALGORITHM_RSA_PAD_PSS | hash, digest, digest_len,
			em, &em_len, prv->security_env.key_size_bits, NULL);
	LOG_TEST_RET(ctx, rv, "cannot build the PSS encoded message");

	rv = iasecc_chipdoc_generic_raw_rsa(card, em, em_len, out, out_len);
	LOG_FUNC_RETURN(ctx, rv);
}

/* Some SDOs (e.g. the public key) are readable only inside SM. */
static int
iasecc_chipdoc_generic_sdo_get_tagged_data(struct sc_card *card, const unsigned char *req,
		size_t req_len, unsigned char *resp, size_t *resp_len)
{
	struct sc_context *ctx = card->ctx;
	unsigned char rdo85[0x400];
	size_t rdo85_len = sizeof(rdo85);
	unsigned sw = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = iasecc_chipdoc_generic_sm_open(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "cannot open SM session");

	rv = iasecc_chipdoc_generic_sm_cmd(card, 0x0C, 0xCB, 0x3F, 0xFF, NULL, 0, req, req_len, 1,
			NULL, NULL, rdo85, &rdo85_len, &sw);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM GET DATA failed");

	rv = iasecc_chipdoc_generic_check_sw(sw, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "GET DATA refused by the card");

	if (rdo85_len > *resp_len)   {
		rv = SC_ERROR_BUFFER_TOO_SMALL;
		goto err;
	}

	memcpy(resp, rdo85, rdo85_len);
	*resp_len = rdo85_len;
	rv = SC_SUCCESS;

err:
	if (rv != SC_SUCCESS)
		iasecc_chipdoc_generic_sm_close(card);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo sdo = {0};
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	unsigned algo_ref;
	struct sc_apdu apdu;
	unsigned sign_meth, sign_ref, auth_meth, auth_ref;
	unsigned long aflags;
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

	if (prv->chipdoc_generic)
		return iasecc_chipdoc_generic_set_security_env(card, env, se_num);

	/* TODO: take algorithm references from 5032, not from header file. */
	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_set_security_env(card:%p) operation 0x%X; senv.algorithm 0x%lX, senv.algorithm_ref 0x%lX",
			card, env->operation, env->algorithm, env->algorithm_ref);

	sdo.sdo_class = IASECC_SDO_CLASS_RSA_PRIVATE;
	sdo.sdo_ref  = env->key_ref[0] & ~IASECC_OBJECT_REF_LOCAL;
	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get RSA PRIVATE SDO data");

	if (sdo.docp.size.size < 2) {
		rv = SC_ERROR_INVALID_DATA;
		LOG_TEST_GOTO_ERR(ctx, rv, "Invalid RSA PRIVATE SDO data");
	}
	/* To made by iasecc_sdo_convert_to_file() */
	prv->key_size = *(sdo.docp.size.value + 0) * 0x100 + *(sdo.docp.size.value + 1);
	sc_log(ctx, "prv->key_size 0x%zX", prv->key_size);

	rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_PSO_COMPUTE_SIGNATURE, &sign_meth, &sign_ref);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot convert SC_AC_OP_SIGN acl");

	rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_INTERNAL_AUTHENTICATE, &auth_meth, &auth_ref);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot convert SC_AC_OP_INT_AUTH acl");

	aflags = env->algorithm_flags;

	if (!(aflags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01)) {
		rv = SC_ERROR_NOT_SUPPORTED;
		LOG_TEST_GOTO_ERR(ctx, rv, "Only supported signature with PKCS1 padding");
	}

	if (operation == SC_SEC_OPERATION_SIGN)   {
		if (!(aflags & (SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA256)))   {
			sc_log(ctx, "CKM_RSA_PKCS asked -- use 'AUTHENTICATE' sign operation instead of 'SIGN'");
			operation = SC_SEC_OPERATION_AUTHENTICATE;
		}
		else if (sign_meth == SC_AC_NEVER)   {
			rv = SC_ERROR_NOT_SUPPORTED;
			LOG_TEST_GOTO_ERR(ctx, rv, "PSO_DST not allowed for this key");
		}
	}

	if (operation == SC_SEC_OPERATION_SIGN)   {
		prv->op_method = sign_meth;
		prv->op_ref = sign_ref;
	}
	else if (operation == SC_SEC_OPERATION_AUTHENTICATE)   {
		if (auth_meth == SC_AC_NEVER) {
			rv = SC_ERROR_NOT_ALLOWED;
			LOG_TEST_GOTO_ERR(ctx, rv, "INTERNAL_AUTHENTICATE is not allowed for this key");
		}

		prv->op_method = auth_meth;
		prv->op_ref = auth_ref;
	}

	sc_log(ctx, "senv.algorithm 0x%lX, senv.algorithm_ref 0x%lX", env->algorithm, env->algorithm_ref);
	sc_log(ctx, "se_num %i, operation 0x%X, algorithm 0x%lX, algorithm_ref 0x%lX, flags 0x%lX; key size %zu",
			se_num, operation, env->algorithm, env->algorithm_ref, env->algorithm_flags, prv->key_size);
	switch (operation)  {
	case SC_SEC_OPERATION_SIGN:
		if (!(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01)) {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			LOG_TEST_GOTO_ERR(ctx, rv, "Need RSA_PKCS1 specified");
		}

		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)   {
			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_HASH, CKM_SHA256);
			if (!algo_ref) {
				rv = SC_ERROR_NOT_SUPPORTED;
				LOG_TEST_GOTO_ERR(ctx, rv, "Card application do not supports HASH:SHA256");
			}

			cse_crt_ht[2] = algo_ref; /* IASECC_ALGORITHM_SHA2 */

			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_SHA256_RSA_PKCS);
			if (!algo_ref) {
				rv = SC_ERROR_NOT_SUPPORTED;
				LOG_TEST_GOTO_ERR(ctx, rv, "Card application do not supports SIGNATURE:SHA1_RSA_PKCS");
			}

			cse_crt_dst[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
			cse_crt_dst[5] = algo_ref;   /* IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA2 */
		}
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)   {
			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_HASH,  CKM_SHA_1);
			if (!algo_ref) {
				rv = SC_ERROR_NOT_SUPPORTED;
				LOG_TEST_GOTO_ERR(ctx, rv, "Card application do not supports HASH:SHA1");
			}

			cse_crt_ht[2] = algo_ref;	/* IASECC_ALGORITHM_SHA1 */

			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_SHA1_RSA_PKCS);
			if (!algo_ref) {
				rv = SC_ERROR_NOT_SUPPORTED;
				LOG_TEST_GOTO_ERR(ctx, rv, "Card application do not supports SIGNATURE:SHA1_RSA_PKCS");
			}

			cse_crt_dst[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
			cse_crt_dst[5] = algo_ref;   /* IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA1 */
		}
		else   {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			LOG_TEST_GOTO_ERR(ctx, rv, "Need RSA_HASH_SHA[1,256] specified");
		}

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_HT);
		apdu.data = cse_crt_ht;
		apdu.datalen = sizeof(cse_crt_ht);
		apdu.lc = sizeof(cse_crt_ht);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_GOTO_ERR(ctx, rv, "MSE restore error");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_DST);
		apdu.data = cse_crt_dst;
		apdu.datalen = sizeof(cse_crt_dst);
		apdu.lc = sizeof(cse_crt_dst);
		break;
	case SC_SEC_OPERATION_AUTHENTICATE:
		algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_RSA_PKCS);
		if (!algo_ref) {
			rv = SC_ERROR_NOT_SUPPORTED;
			LOG_TEST_GOTO_ERR(ctx, rv, "Application do not supports SIGNATURE:RSA_PKCS");
		}

		cse_crt_at[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
		cse_crt_at[5] = algo_ref;	/* IASECC_ALGORITHM_RSA_PKCS */

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_AT);
		apdu.data = cse_crt_at;
		apdu.datalen = sizeof(cse_crt_at);
		apdu.lc = sizeof(cse_crt_at);
		break;
	case SC_SEC_OPERATION_DECIPHER:
		rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_PSO_DECRYPT, &prv->op_method, &prv->op_ref);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot convert SC_AC_OP_PSO_DECRYPT acl");
		algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_DECIPHER,  CKM_RSA_PKCS);
		if (!algo_ref) {
			rv = SC_ERROR_NOT_SUPPORTED;
			LOG_TEST_GOTO_ERR(ctx, rv, "Application do not supports DECIPHER:RSA_PKCS");
		}

		cse_crt_ct[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
		cse_crt_ct[5] = algo_ref;	/* IASECC_ALGORITHM_RSA_PKCS_DECRYPT | IASECC_ALGORITHM_SHA1 */

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_CT);
		apdu.data = cse_crt_ct;
		apdu.datalen = sizeof(cse_crt_ct);
		apdu.lc = sizeof(cse_crt_ct);
		break;
	default:
		rv = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "MSE restore error");

	prv->security_env = *env;
	prv->security_env.operation = operation;
	rv = 0;

err:
	iasecc_sdo_free_fields(card, &sdo);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_chv_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd, unsigned char *scbs)
{
	struct sc_context *ctx = card->ctx;
	unsigned char scb = scbs[IASECC_ACLS_CHV_VERIFY];
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%zu,scb:%X)", pin_cmd->pin_reference, pin_cmd->pin1.len, scb);

	if (scb & IASECC_SCB_METHOD_SM) {
		rv = iasecc_sm_pin_verify(card, scb & IASECC_SCB_METHOD_MASK_REF, pin_cmd);
		LOG_FUNC_RETURN(ctx, rv);
	}

	rv = iso_ops->pin_cmd(card, pin_cmd);
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
iasecc_pin_get_status(struct sc_card *card, struct sc_pin_cmd_data *data)
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

	rv = iso_ops->pin_cmd(card, &info);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN info");

	data->pin1.max_tries = info.pin1.max_tries;
	data->pin1.tries_left = info.pin1.tries_left;
	data->pin1.logged_in = info.pin1.logged_in;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_verify(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct sc_context *ctx = card->ctx;
	unsigned type = data->pin_type;
	unsigned reference = data->pin_reference;
	struct sc_pin_cmd_data pin_cmd;
	struct iasecc_pin_policy policy;
	int tries_before_verify = -1;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify PIN(type:%X,ref:%i,data(len:%zu,%p)",
			type, reference, data->pin1.len, data->pin1.data);

	if (type == SC_AC_AUT)   {
		rv =  iasecc_sm_external_authentication(card, reference, &data->pin1.tries_left);
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

	rv = iasecc_pin_get_status(card, &pin_cmd);
	if (data->pin1.data && !data->pin1.len)
		LOG_FUNC_RETURN(ctx, rv);

	if (!rv)   {
		if (pin_cmd.pin1.logged_in & SC_PIN_STATE_LOGGED_IN)
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

	rv = iasecc_chv_verify(card, &pin_cmd, policy.scbs);

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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct sc_file *save_current_df = NULL, *save_current_ef = NULL;
	struct iasecc_sdo sdo = {0};
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pin_get_policy(card:%p)", card);

	if (data->pin_type != SC_AC_CHV)   {
		rv = SC_ERROR_INVALID_ARGUMENTS;
		LOG_TEST_GOTO_ERR(ctx, rv, "PIN policy only available for CHV type");
	}

	if (prv->cache.valid && prv->cache.current_df) {
		sc_file_dup(&save_current_df, prv->cache.current_df);
		if (save_current_df == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			LOG_TEST_GOTO_ERR(ctx, rv, "Cannot duplicate current DF file");
		}
	}

	if (prv->cache.valid && prv->cache.current_ef) {
		sc_file_dup(&save_current_ef, prv->cache.current_ef);
		if (save_current_ef == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			LOG_TEST_GOTO_ERR(ctx, rv, "Cannot duplicate current EF file");
		}
	}

	if (!(data->pin_reference & IASECC_OBJECT_REF_LOCAL) && prv->cache.valid && prv->cache.current_df) {
		sc_format_path("3F00", &path);
		path.type = SC_PATH_TYPE_FILE_ID;
		rv = iasecc_select_file(card, &path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Unable to select MF");
	}

	sdo.sdo_class = IASECC_SDO_CLASS_CHV;

	sdo.sdo_ref = data->pin_reference & ~IASECC_OBJECT_REF_LOCAL;

	sc_log(ctx, "reference %i", sdo.sdo_ref);

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get SDO PIN data");

	if (sdo.docp.acls_contact.size == 0) {
		rv = SC_ERROR_INVALID_DATA;
		LOG_TEST_GOTO_ERR(ctx, rv, "Extremely strange ... there is no ACLs");
	}

	sc_log(ctx, "sdo.docp.size.size %zu", sdo.docp.size.size);

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

	if (save_current_df)   {
		sc_log(ctx, "restore current DF");
		rv = iasecc_select_file(card, &save_current_df->path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot return to saved DF");
	}

	if (save_current_ef)   {
		sc_log(ctx, "restore current EF");
		rv = iasecc_select_file(card, &save_current_ef->path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot return to saved EF");
	}

err:
	iasecc_sdo_free_fields(card, &sdo);
	sc_file_free(save_current_df);
	sc_file_free(save_current_ef);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_get_info(struct sc_card *card, struct sc_pin_cmd_data *data)
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
	rv = iasecc_pin_get_status(card, data);
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
iasecc_keyset_change(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo_update update = {0};
	struct iasecc_sdo sdo = {0};
	unsigned scb;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change keyset(ref:%i,lengths:%zu)", data->pin_reference, data->pin2.len);
	if (!data->pin2.data || data->pin2.len < 32)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Needs at least 32 bytes for a new keyset value");

	sdo.sdo_class = IASECC_SDO_CLASS_KEYSET;
	sdo.sdo_ref  = data->pin_reference;

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get keyset data");

	if (sdo.docp.acls_contact.size == 0) {
		rv = SC_ERROR_INVALID_DATA;
		LOG_TEST_GOTO_ERR(ctx, rv, "Bewildered ... there are no ACLs");
	}
	scb = sdo.docp.scbs[IASECC_ACLS_KEYSET_PUT_DATA];

	update.magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
	update.sdo_class = sdo.sdo_class;
	update.sdo_ref = sdo.sdo_ref;

	sc_log(ctx, "SCB:0x%X", scb);
	if (!(scb & IASECC_SCB_METHOD_SM)) {
		rv = SC_ERROR_NOT_SUPPORTED;
		LOG_TEST_GOTO_ERR(ctx, rv, "Other then protected by SM, the keyset change is not supported");
	}


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

err:
	iasecc_sdo_free_fields(card, &sdo);

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
iasecc_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	struct iasecc_pin_policy policy;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change PIN(ref:%i,type:0x%X,lengths:%zu/%zu)",
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
		rv = iasecc_chv_verify(card, &pin_cmd, policy.scbs);
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

	rv = iso_ops->pin_cmd(card, &pin_cmd);
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
iasecc_pin_reset(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct sc_context *ctx = card->ctx;
	unsigned char scb;
	struct sc_pin_cmd_data pin_cmd;
	struct iasecc_pin_policy policy;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Reset PIN(ref:%i,lengths:%zu/%zu)", data->pin_reference, data->pin1.len, data->pin2.len);

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
			rv = iasecc_pin_verify(card, &pin_cmd);
			LOG_TEST_RET(ctx, rv, "verify PUK error");

			if (!need_all)
				break;
		}

		if (scb & IASECC_SCB_METHOD_SM)   {
			rv = iasecc_sm_pin_reset(card, se_num, data);
			LOG_FUNC_RETURN(ctx, rv);
		}

		if (scb & IASECC_SCB_METHOD_EXT_AUTH)   {
			rv =  iasecc_sm_external_authentication(card, data->pin_reference, &data->pin1.tries_left);
			LOG_TEST_RET(ctx, rv, "external authentication error");
		}
	} while(0);

	/* Use iso 7816 layer for unblock, with implicit pin for PIN1 and the new PIN for PIN2 */
	pin_cmd = *data;
	pin_cmd.cmd = SC_PIN_CMD_UNBLOCK;
	pin_cmd.flags |= SC_PIN_CMD_IMPLICIT_CHANGE;
	pin_cmd.pin1.len = 0;

	rv = iasecc_pin_merge_policy(card, &pin_cmd, &pin_cmd.pin2, &policy);
	LOG_TEST_RET(ctx, rv, "Failed to update PIN2 info");

	rv = iso_ops->pin_cmd(card, &pin_cmd);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%zu, PIN-2 %p:%zu",
			data->cmd, data->pin_type, data->pin_reference,
			data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);

	if (prv->chipdoc_generic)
		LOG_FUNC_RETURN(ctx, iasecc_chipdoc_generic_pin_cmd(card, data));

	switch (data->cmd)   {
	case SC_PIN_CMD_VERIFY:
		rv = iasecc_pin_verify(card, data);
		break;
	case SC_PIN_CMD_CHANGE:
		if (data->pin_type == SC_AC_AUT)
			rv = iasecc_keyset_change(card, data);
		else
			rv = iasecc_pin_change(card, data);
		break;
	case SC_PIN_CMD_UNBLOCK:
		rv = iasecc_pin_reset(card, data);
		break;
	case SC_PIN_CMD_GET_INFO:
		rv = iasecc_pin_get_info(card, data);
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
	LOG_TEST_RET(ctx, data_len, "cannot encode SDO create data");
	sc_log(ctx, "create data(%i):%s", data_len, sc_dump_hex(data, data_len));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
	apdu.data = data;
	apdu.datalen = data_len;
	apdu.lc = data_len;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "SDO put data error");

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
		sc_log(ctx, "encode[%i]; tag %X; encoded_len %i", ii, update->fields[ii].tag, encoded_len);
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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
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

	if (prv->chipdoc_generic && sdo_tag != IASECC_DOCP_TAG) {
		size_t rlen = sizeof(rbuf);

		rv = iasecc_chipdoc_generic_sdo_get_tagged_data(card, sbuf + offs, sizeof(sbuf) - offs, rbuf, &rlen);
		LOG_TEST_RET(ctx, rv, "cannot read the ChipDoc Generic SDO data");

		rv = iasecc_sdo_parse(card, rbuf, rlen, sdo);
		LOG_TEST_RET(ctx, rv, "cannot parse the ChipDoc Generic SDO data");

		LOG_FUNC_RETURN(ctx, rv);
	}

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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	int rv, sdo_tag;

	LOG_FUNC_CALLED(ctx);

	sdo_tag = iasecc_sdo_tag_from_class(sdo->sdo_class);

	rv = iasecc_sdo_get_tagged_data(card, sdo_tag, sdo);
	/* The ChipDoc Generic applet has no separate DOCP data. */
	if (prv->chipdoc_generic)
		LOG_FUNC_RETURN(ctx, rv);
	/* GET DATA returns an error when there is no public data. */
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
	LOG_TEST_RET(ctx, rv, "update SDO public key failed");

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
	sc_log(card->ctx, "crgram_len %zu;  outlen %zu", in_len, out_len);
	if (!out || !out_len || in_len > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (((struct iasecc_private_data *)card->drv_data)->chipdoc_generic)
		return iasecc_chipdoc_generic_decipher(card, in, in_len, out, out_len);

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
	rv = (int)out_len;

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

	sc_log(ctx, "input data length %zu", in_len);
	memset(out, 0, sizeof(struct iasecc_qsign_data));

	md = sc_evp_md(ctx, "SHA1");
	mdctx = EVP_MD_CTX_new();
	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		sc_log_openssl(ctx);
		sc_log(ctx, "EVP_DigestInit_ex failed");
		goto end;
	}

	md_data = EVP_MD_CTX_md_data(mdctx);
	if (md_data == NULL) {
		sc_log_openssl(ctx);
		sc_log(ctx, "Failed to find md_data");
		r = SC_ERROR_NOT_SUPPORTED;
		goto end;
	}

	if (EVP_DigestUpdate(mdctx, in, in_len) != 1) {
		sc_log_openssl(ctx);
		sc_log(ctx, "EVP_DigestUpdate failed");
		goto end;
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
		sc_log(ctx, "Last block(%zu):%s", out->last_block_size,
				sc_dump_hex(out->last_block, out->last_block_size));
	}

	if (EVP_DigestFinal_ex(mdctx, out->hash, &md_out_len) != 1) {
		sc_log_openssl(ctx);
		sc_log(ctx, "EVP_DigestFinal_ex failed");
		goto end;
	}

	out->hash_size = SHA_DIGEST_LENGTH;
	sc_log(ctx, "Expected digest %s\n", sc_dump_hex(out->hash, out->hash_size));

	r = SC_SUCCESS;

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

	sc_log(ctx, "input data length %zu", in_len);
	memset(out, 0, sizeof(struct iasecc_qsign_data));

	md = sc_evp_md(ctx, "SHA256");
	mdctx = EVP_MD_CTX_new();
	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		sc_log_openssl(ctx);
		sc_log(ctx, "EVP_DigestInit_ex failed");
		goto end;
	}

	md_data = EVP_MD_CTX_md_data(mdctx);
	if (md_data == NULL) {
		sc_log_openssl(ctx);
		sc_log(ctx, "Failed to find md_data");
		r = SC_ERROR_NOT_SUPPORTED;
		goto end;
	}

	if (EVP_DigestUpdate(mdctx, in, in_len) != 1) {
		sc_log_openssl(ctx);
		sc_log(ctx, "EVP_DigestUpdate failed");
		goto end;
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
		sc_log(ctx, "Last block(%zu):%s", out->last_block_size,
				sc_dump_hex(out->last_block, out->last_block_size));
	}

	if (EVP_DigestFinal_ex(mdctx, out->hash, &md_out_len) != 1) {
		sc_log_openssl(ctx);
		sc_log(ctx, "EVP_DigestFinal_ex failed");
		goto end;
	}

	out->hash_size = SHA256_DIGEST_LENGTH;
	sc_log(ctx, "Expected digest %s\n", sc_dump_hex(out->hash, out->hash_size));

	r = SC_SUCCESS;

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
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct iasecc_qsign_data qsign_data;
	struct sc_apdu apdu;
	size_t offs = 0, hash_len = 0;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "input length %zu", in_len);
	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_SIGN");
	else if (!(prv->key_size & 0x1E0) || (prv->key_size & ~0x1E0))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key size for SC_SEC_OPERATION_SIGN");
	if (sizeof(rbuf) < prv->key_size)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

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

	sc_log(ctx, "hash_len %zu; key_size %zu", hash_len, prv->key_size);

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

	sc_log(ctx, "offs %zu; OP(meth:%X,ref:%X)",
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

	sc_log(ctx, "partial hash OK");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.resp = rbuf;
	apdu.resplen = prv->key_size;
	apdu.le = prv->key_size;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Compute signature failed");

	sc_log(ctx, "DST resplen %zu", apdu.resplen);
	if (apdu.resplen > out_len)
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Result buffer too small for the DST signature");

	memcpy(out, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(ctx, (int)apdu.resplen);
}


static int
iasecc_compute_signature_at(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *)card->drv_data;
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

	LOG_FUNC_RETURN(ctx, (int)offs);
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
	prv = (struct iasecc_private_data *)card->drv_data;
	env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "inlen %zu, outlen %zu", in_len, out_len);

	if (prv->chipdoc_generic)
		return iasecc_chipdoc_generic_compute_signature(card, in, in_len, out, out_len);

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
	if (!bn[0].data) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_TEST_GOTO_ERR(ctx, rv, "failed to read public key: cannot allocate modulus");
	}
	bn[0].len = sdo.data.pub_key.n.size;
	memcpy(bn[0].data, sdo.data.pub_key.n.value, sdo.data.pub_key.n.size);

	bn[1].data = (unsigned char *) malloc(sdo.data.pub_key.e.size);
	if (!bn[1].data) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_TEST_GOTO_ERR(ctx, rv, "failed to read public key: cannot allocate exponent");
	}
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

	LOG_FUNC_RETURN(ctx, rv);
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

		iasecc_sdo_free(card, sdo);
		sdo = NULL;

		rv = iasecc_sdo_allocate_and_parse(card, sdo_tag, 3, &sdo);
		LOG_TEST_RET(ctx, rv, "cannot parse SDO data");

		rv = iasecc_sdo_get_data(card, sdo);
		if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)   {
			sc_log(ctx, "found empty key slot %i", idx);
			break;
		} else if (rv != SC_SUCCESS) {
			iasecc_sdo_free(card, sdo);

			sc_log(ctx, "get new key reference failed");
			LOG_FUNC_RETURN(ctx, rv);
		}

		if (sdo->docp.size.size < 2)
			continue;
		sz = *(sdo->docp.size.value + 0) * 0x100 + *(sdo->docp.size.value + 1);
		sc_log(ctx, "SDO(idx:%i) size %zu; key_size %zu", idx, sz, ctl_data->key_size);

		if (sz != ctl_data->key_size / 8)   {
			sc_log(ctx, "key index %i ignored: different key sizes %zu/%zu",
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

	iasecc_sdo_free(card, sdo);

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
	iasecc_ops.card_reader_lock_obtained = iasecc_card_reader_lock_obtained;

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
