/*
 * iasecc.h Support for IAS/ECC smart cards
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "common/compat_strlcpy.h"

#include "sm.h"
#include "iasecc.h"
#include "authentic.h"


#ifdef ENABLE_SM

static int
sm_save_sc_context (struct sc_card *card, struct sm_info *sm_info)
{
	struct sc_context *ctx;
	struct sc_card_cache *cache;

	if (!card || !sm_info)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->ctx;
	cache = &card->cache;

	sc_log(ctx, "SM save context: cache(valid:%i,current_df:%p)", cache->valid, cache->current_df);
	if (cache->valid && cache->current_df)   {
		sm_info->current_path_df = cache->current_df->path;
		if (cache->current_df->path.type == SC_PATH_TYPE_DF_NAME)   {
			if (cache->current_df->path.aid.len)   {
				sm_info->current_aid = cache->current_df->path.aid;
			}
			else   {
				memcpy(sm_info->current_aid.value, cache->current_df->path.value, cache->current_df->path.len);
				sm_info->current_aid.len = cache->current_df->path.len;
			}
		}
	}

	if (cache->valid && cache->current_ef)
		sm_info->current_path_ef = cache->current_ef->path;

	return SC_SUCCESS;
}


static int
sm_restore_sc_context(struct sc_card *card, struct sm_info *sm_info)
{
	int rv = SC_SUCCESS;

	if (sm_info->current_path_df.type == SC_PATH_TYPE_DF_NAME && sm_info->current_path_df.len)
		rv = sc_select_file(card, &sm_info->current_path_df, NULL);

	if (sm_info->current_path_ef.len && rv == SC_SUCCESS)
		rv = sc_select_file(card, &sm_info->current_path_ef, NULL);

	memset(&sm_info->current_path_df, 0, sizeof(sm_info->current_path_df));
	memset(&sm_info->current_path_ef, 0, sizeof(sm_info->current_path_ef));

	return rv;
}

static int
iasecc_sm_transmit_apdus(struct sc_card *card, struct sc_remote_data *rdata,
		unsigned char *out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_remote_apdu *rapdu = rdata->data;
	int rv = SC_SUCCESS, offs = 0;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_transmit_apdus() rdata-length %i", rdata->length);

	while (rapdu)   {
		sc_log(ctx, "iasecc_sm_transmit_apdus() rAPDU flags 0x%lX", rapdu->apdu.flags);
		rv = sc_transmit_apdu(card, &rapdu->apdu);
		LOG_TEST_RET(ctx, rv, "iasecc_sm_transmit_apdus() failed to execute r-APDU");
		rv = sc_check_sw(card, rapdu->apdu.sw1, rapdu->apdu.sw2);
		if (rv < 0 && !(rapdu->flags & SC_REMOTE_APDU_FLAG_NOT_FATAL))
			LOG_TEST_RET(ctx, rv, "iasecc_sm_transmit_apdus() fatal error %i");

		if (out && out_len && (rapdu->flags & SC_REMOTE_APDU_FLAG_RETURN_ANSWER))   {
			int len = rapdu->apdu.resplen > (*out_len - offs) ? (*out_len - offs) : rapdu->apdu.resplen;

			memcpy(out + offs, rapdu->apdu.resp, len);
			offs += len;
			/* TODO: decode and gather data answers */
		}

		rapdu = rapdu->next;
	}

	if (out_len)
		*out_len = offs;

	LOG_FUNC_RETURN(ctx, rv);
}


/* Big TODO: do SM release in all handles, clean the saved card context -- current DF, EF, etc. */
static int
sm_release (struct sc_card *card, struct sc_remote_data *rdata,
		unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sm_info *sm_info = &card->sm_ctx.info;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!card->sm_ctx.module.ops.finalize)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = card->sm_ctx.module.ops.finalize(ctx, sm_info, rdata, out, out_len);

	sm_restore_sc_context(card, sm_info);
	LOG_FUNC_RETURN(ctx, rv);
}
#endif


int
iasecc_sm_external_authentication(struct sc_card *card, unsigned skey_ref, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sm_cwa_session *cwa_session = &sm_info->session.cwa;
	struct sc_remote_data rdata;
	struct sc_apdu apdu;
	unsigned char sbuf[0x100];
	int rv, offs;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_external_authentication(): SKey ref %i", skey_ref);

	if (card->sm_ctx.sm_mode == SM_MODE_NONE)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Cannot do 'External Authentication' without SM activated ");

	strlcpy(sm_info->config_section, card->sm_ctx.config_section, sizeof(sm_info->config_section));
	sm_info->cmd = SM_CMD_EXTERNAL_AUTH;
	sm_info->serialnr = card->serialnr;
	sm_info->card_type = card->type;
	sm_info->sm_type = SM_TYPE_CWA14890;
	cwa_session->params.crt_at.usage = IASECC_UQB_AT_EXTERNAL_AUTHENTICATION;
	cwa_session->params.crt_at.algo = IASECC_ALGORITHM_ROLE_AUTH;
	cwa_session->params.crt_at.refs[0] = skey_ref;

	offs = 0;
	sbuf[offs++] = IASECC_CRT_TAG_ALGO;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = IASECC_ALGORITHM_ROLE_AUTH;
	sbuf[offs++] = IASECC_CRT_TAG_REFERENCE;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = skey_ref;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x81, 0xA4);
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_external_authentication(): APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_external_authentication(): set SE error");

	rv = sc_get_challenge(card, cwa_session->card_challenge, sizeof(cwa_session->card_challenge));
	LOG_TEST_RET(ctx, rv, "iasecc_sm_external_authentication(): set SE error");

	sc_remote_data_init(&rdata);

	if (!card->sm_ctx.module.ops.initialize)
		LOG_TEST_RET(ctx, SC_ERROR_SM_NOT_INITIALIZED, "No SM module");
	rv = card->sm_ctx.module.ops.initialize(ctx, sm_info, &rdata);
	LOG_TEST_RET(ctx, rv, "SM: INITIALIZE failed");

	sc_log(ctx, "sm_iasecc_external_authentication(): rdata length %i\n", rdata.length);

	rv = iasecc_sm_transmit_apdus (card, &rdata, NULL, 0);
	if (rv == SC_ERROR_PIN_CODE_INCORRECT && tries_left)
		*tries_left = (rdata.data + rdata.length - 1)->apdu.sw2 & 0x0F;
	LOG_TEST_RET(ctx, rv, "sm_iasecc_external_authentication(): execute failed");

	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of SM and External Authentication");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


#ifdef ENABLE_SM
static int
iasecc_sm_se_mutual_authentication(struct sc_card *card, unsigned se_num)
{
	struct sc_context *ctx = card->ctx;
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct iasecc_se_info se;
	struct sc_crt *crt =  &sm_info->session.cwa.params.crt_at;
	struct sc_apdu apdu;
	unsigned char sbuf[0x100];
	int rv, offs;

	memset(&se, 0, sizeof(se));

	se.reference = se_num;
	crt->usage = IASECC_UQB_AT_MUTUAL_AUTHENTICATION;
	crt->tag = IASECC_CRT_TAG_AT;

	rv = iasecc_se_get_info(card, &se);
	LOG_TEST_RET(ctx, rv, "Get SE info error");

	rv = iasecc_se_get_crt(card, &se, crt);
	LOG_TEST_RET(ctx, rv, "Cannot get authentication CRT");

	sc_file_free(se.df);

	/* MSE SET Mutual Authentication SK scheme */
	offs = 0;
	sbuf[offs++] = IASECC_CRT_TAG_ALGO;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = crt->algo;
	sbuf[offs++] = IASECC_CRT_TAG_REFERENCE;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = crt->refs[0];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xC1, 0xA4);
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "SM set SE mutual auth.: APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "SM set SE mutual auth.: set SE error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_sm_get_challenge(struct sc_card *card, unsigned char *out, size_t len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	sc_log(ctx, "SM get challenge: length %"SC_FORMAT_LEN_SIZE_T"u", len);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x84, 0, 0);
	apdu.le = len;
	apdu.resplen = len;
	apdu.resp = rbuf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Command failed");

	memcpy(out, rbuf, apdu.resplen);

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}
#endif


int
iasecc_sm_initialize(struct sc_card *card, unsigned se_num, unsigned cmd)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sm_cwa_session *cwa_session = &sm_info->session.cwa;
	struct sc_remote_data rdata;
	int rv;

	LOG_FUNC_CALLED(ctx);

	strlcpy(sm_info->config_section, card->sm_ctx.config_section, sizeof(sm_info->config_section));
	sm_info->cmd = cmd;
	sm_info->serialnr = card->serialnr;
	sm_info->card_type = card->type;
	sm_info->sm_type = SM_TYPE_CWA14890;

	rv = iasecc_sm_se_mutual_authentication(card, se_num);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_initialize() MUTUAL AUTHENTICATION failed");

	rv = iasecc_sm_get_challenge(card, cwa_session->card_challenge, SM_SMALL_CHALLENGE_LEN);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_initialize() GET CHALLENGE failed");

	sc_remote_data_init(&rdata);

	rv = sm_save_sc_context(card, sm_info);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_initialize() cannot save current context");

	if (!card->sm_ctx.module.ops.initialize)
		LOG_TEST_RET(ctx, SC_ERROR_SM_NOT_INITIALIZED, "iasecc_sm_initialize() no SM module");
	rv = card->sm_ctx.module.ops.initialize(ctx, sm_info, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_initialize() INITIALIZE failed");


	if (rdata.length == 1)   {
		rdata.data->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;
		rdata.data->apdu.flags &= ~SC_APDU_FLAGS_NO_GET_RESP;
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "TODO: SM init with more then one APDU");
	}

	cwa_session->mdata_len = sizeof(cwa_session->mdata);
	rv = iasecc_sm_transmit_apdus (card, &rdata, cwa_session->mdata, &cwa_session->mdata_len);
	if (rv == SC_ERROR_PIN_CODE_INCORRECT)
		sc_log(ctx, "SM initialization failed, %i tries left", (rdata.data + rdata.length - 1)->apdu.sw2 & 0x0F);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_initialize() transmit APDUs failed");

	rdata.free(&rdata);

	sc_log(ctx, "MA data(len:%"SC_FORMAT_LEN_SIZE_T"u) '%s'",
	       cwa_session->mdata_len,
	       sc_dump_hex(cwa_session->mdata, cwa_session->mdata_len));
	if (cwa_session->mdata_len != 0x48)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "iasecc_sm_initialize() invalid MUTUAL AUTHENTICATE result data");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


#ifdef ENABLE_SM
static int
iasecc_sm_cmd(struct sc_card *card, struct sc_remote_data *rdata)
{
#define AUTH_SM_APDUS_MAX 12
#define ENCODED_APDUS_MAX_LENGTH (AUTH_SM_APDUS_MAX * (SC_MAX_APDU_BUFFER_SIZE * 2 + 64) + 32)
	struct sc_context *ctx = card->ctx;
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sm_cwa_session *session = &sm_info->session.cwa;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!card->sm_ctx.module.ops.get_apdus)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	rv =  card->sm_ctx.module.ops.get_apdus(ctx, sm_info, session->mdata, session->mdata_len, rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_cmd() 'GET APDUS' failed");

	sc_log(ctx, "iasecc_sm_cmd() %i remote APDUs to transmit", rdata->length);
	for (rapdu = rdata->data; rapdu; rapdu = rapdu->next)   {
		struct sc_apdu *apdu = &rapdu->apdu;

		sc_log(ctx,
		       "iasecc_sm_cmd() apdu->ins:0x%X, resplen %"SC_FORMAT_LEN_SIZE_T"u",
		       apdu->ins, apdu->resplen);
		if (!apdu->ins)
			break;
		rv = sc_transmit_apdu(card, apdu);
		if (rv < 0)   {
			sc_log(ctx, "iasecc_sm_cmd() APDU transmit error rv:%i", rv);
			break;
		}

		rv = sc_check_sw(card, apdu->sw1, apdu->sw2);
		if (rv < 0 && !(rapdu->flags & SC_REMOTE_APDU_FLAG_NOT_FATAL))   {
			sc_log(ctx, "iasecc_sm_cmd() APDU error rv:%i", rv);
			break;
		}
		sc_log(ctx,
		       "iasecc_sm_cmd() apdu->resplen %"SC_FORMAT_LEN_SIZE_T"u",
		       apdu->resplen);
	}

	LOG_FUNC_RETURN(ctx, rv);
}
#endif


int
iasecc_sm_rsa_generate(struct sc_card *card, unsigned se_num, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_rsa_generate() SE#%i, SDO(class:%X,ref:%X)", se_num, sdo->sdo_class, sdo->sdo_ref);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_RSA_GENERATE);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_rsa_generate() SM initialize failed");

	sm_info->cmd_data = sdo;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_rsa_generate() SM cmd failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_rsa_generate() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


int
iasecc_sm_rsa_update(struct sc_card *card, unsigned se_num, struct iasecc_sdo_rsa_update *udata)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM update RSA: SE#: 0x%X, SDO(class:0x%X:ref:%X)", se_num,
			udata->sdo_prv_key->sdo_class, udata->sdo_prv_key->sdo_ref);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_RSA_UPDATE);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_rsa_update() SM initialize failed");

	sm_info->cmd_data = udata;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_rsa_update() SM cmd failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_rsa_update() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


int
iasecc_sm_pin_verify(struct sc_card *card, unsigned se_num, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_pin_verify() SE#%i, PIN(ref:%i,len:%i)", se_num, data->pin_reference, data->pin1.len);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_PIN_VERIFY);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_verify() SM INITIALIZE failed");

	sm_info->cmd_data = data;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	if (rv && rdata.length && tries_left)
		if (rdata.data->apdu.sw1 == 0x63 && (rdata.data->apdu.sw2 & 0xF0) == 0xC0)
			*tries_left = rdata.data->apdu.sw2 & 0x0F;

	LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_verify() SM 'PIN VERIFY' failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_verify() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


int
iasecc_sm_sdo_update(struct sc_card *card, unsigned se_num, struct iasecc_sdo_update *update)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_sdo_update() SE#%i, SDO(class:0x%X,ref:%i)", se_num, update->sdo_class, update->sdo_ref);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_SDO_UPDATE);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_sdo_update() SM INITIALIZE failed");

	sc_log(ctx, "current DF '%s'", sc_print_path(&sm_info->current_path_df));

	sm_info->cmd_data = update;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_sdo_update() SM 'SDO UPDATE' failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_sdo_update() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


int
iasecc_sm_pin_reset(struct sc_card *card, unsigned se_num, struct sc_pin_cmd_data *data)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sm_pin_reset() SE#%i, PIN(ref:%i,len:%i)", se_num, data->pin_reference, data->pin2.len);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_PIN_RESET);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_reset() SM INITIALIZE failed");

	sm_info->cmd_data = data;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_reset() SM 'PIN RESET' failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_pin_reset() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


int
iasecc_sm_create_file(struct sc_card *card, unsigned se_num, unsigned char *fcp, size_t fcp_len)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	struct iasecc_sm_cmd_create_file cmd_data;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_sm_create_file() SE#%i, fcp(%"SC_FORMAT_LEN_SIZE_T"u) '%s'",
	       se_num, fcp_len, sc_dump_hex(fcp, fcp_len));

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_FILE_CREATE);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_create_file() SM INITIALIZE failed");

	cmd_data.data = fcp;
	cmd_data.size = fcp_len;
	sm_info->cmd_data = &cmd_data;

	sc_remote_data_init(&rdata);
	rv= iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_create_file() SM 'UPDATE BINARY' failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_create_file() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}

int
iasecc_sm_read_binary(struct sc_card *card, unsigned se_num, size_t offs, unsigned char *buff, size_t count)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	struct iasecc_sm_cmd_update_binary cmd_data;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "SM read binary: acl:%X, offs:%"SC_FORMAT_LEN_SIZE_T"u, count:%"SC_FORMAT_LEN_SIZE_T"u",
	       se_num, offs, count);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_FILE_READ);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_read_binary() SM INITIALIZE failed");

	cmd_data.offs = offs;
	cmd_data.count = count;
	sm_info->cmd_data = &cmd_data;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_read_binary() SM 'READ BINARY' failed");

	sc_log(ctx, "IAS/ECC decode answer() rdata length %i", rdata.length);

	rv = sm_release (card, &rdata, buff, count);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_read_binary() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


int
iasecc_sm_update_binary(struct sc_card *card, unsigned se_num, size_t offs,
		const unsigned char *buff, size_t count)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	struct iasecc_sm_cmd_update_binary cmd_data;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "SM update binary: acl:%X, offs:%"SC_FORMAT_LEN_SIZE_T"u, count:%"SC_FORMAT_LEN_SIZE_T"u",
	       se_num, offs, count);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_FILE_UPDATE);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_update_binary() SM INITIALIZE failed");

	cmd_data.offs = offs;
	cmd_data.count = count;
	cmd_data.data = buff;
	sm_info->cmd_data = &cmd_data;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_update_binary() SM 'UPDATE BINARY' failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_update_binary() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, count);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


int
iasecc_sm_delete_file(struct sc_card *card, unsigned se_num, unsigned int file_id)
{
	struct sc_context *ctx = card->ctx;
#ifdef ENABLE_SM
	struct sm_info *sm_info = &card->sm_ctx.info;
	struct sc_remote_data rdata;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM delete file: SE#:%X, file-id:%X", se_num, file_id);

	rv = iasecc_sm_initialize(card, se_num, SM_CMD_FILE_DELETE);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_delete_file() SM INITIALIZE failed");

	sm_info->cmd_data = (void *)(uintptr_t)file_id;

	sc_remote_data_init(&rdata);
	rv = iasecc_sm_cmd(card, &rdata);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_delete_file() SM 'FILE DELETE' failed");

	rv = sm_release (card, &rdata, NULL, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_sm_delete_file() SM release failed");

	rdata.free(&rdata);
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


