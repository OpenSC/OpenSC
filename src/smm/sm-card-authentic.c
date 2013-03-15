/*
 * sm-authentic.c: Secure Messaging procedures specific to Oberthur's card
 * 		'COSMO v7' with PKI applet 'AuthentIC v3.1'
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include "libopensc/opensc.h"
#include "libopensc/log.h"
#if 0
#include "libopensc/hash-strings.h"
#endif

#include "sm-module.h"

static int
sm_oberthur_diversify_keyset(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *idata, size_t idata_len)
{
	struct sm_gp_session *gp_session = &sm_info->session.gp;
	struct sm_gp_keyset *gp_keyset = &sm_info->session.gp.gp_keyset;
	unsigned char master_key[16] = {
		0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
	};
	unsigned char *keys[3] = {
		gp_keyset->enc,
		gp_keyset->mac,
		gp_keyset->kek
	};
	unsigned char key_buff[16];
	unsigned char *tmp;
	int rv = 0, ii, tmp_len;

	if (gp_keyset->kmc_len == 48)   {
		for (ii=0; ii<3; ii++)
			memcpy(keys[ii], gp_keyset->kmc + 16*ii, 16);
	}
	else if (gp_keyset->kmc_len == 16 || gp_keyset->kmc_len == 0)   {
		if (gp_keyset->kmc_len == 16)
			memcpy(master_key, gp_keyset->kmc, 16);
		sc_log(ctx, "KMC: %s", sc_dump_hex(master_key, sizeof(master_key)));
		for (ii=0; ii<3; ii++)   {
			key_buff[0] = key_buff[8] = 0;
			key_buff[1] = key_buff[9] = 0;
			key_buff[2] = key_buff[10] = *(idata + 6);
			key_buff[3] = key_buff[11] = *(idata + 7);
			key_buff[4] = key_buff[12] = *(idata + 8);
			key_buff[5] = key_buff[13] = *(idata + 9);
			key_buff[6] = 0xF0,  key_buff[14] = 0x0F;
			key_buff[7] = key_buff[15] = ii+1;

			sc_log(ctx, "key_buf:%s", sc_dump_hex(key_buff, 16));

			rv = sm_encrypt_des_ecb3(master_key, key_buff, sizeof(key_buff), &tmp, &tmp_len);
			LOG_TEST_RET(ctx, rv, "GP init session: cannot derivate key");

			memcpy(keys[ii], tmp, sizeof(gp_keyset->enc));
			free(tmp);
		}
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "GP init session: invalid KMC data");
	}

	if (!rv && ctx)   {
		char dump_buf[2048];

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL,
				gp_session->card_challenge, sizeof(gp_session->card_challenge), dump_buf, sizeof(dump_buf));
		sc_log(ctx, "Card challenge: %s", dump_buf);

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL,
				gp_session->host_challenge, sizeof(gp_session->host_challenge), dump_buf, sizeof(dump_buf));
		sc_log(ctx, "Host challenge: %s", dump_buf);

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, gp_keyset->enc, sizeof(gp_keyset->enc), dump_buf, sizeof(dump_buf));
		sc_log(ctx, "ENC: %s", dump_buf);

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, gp_keyset->mac, sizeof(gp_keyset->mac), dump_buf, sizeof(dump_buf));
		sc_log(ctx, "MAC: %s", dump_buf);

		sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, gp_keyset->kek, sizeof(gp_keyset->kek), dump_buf, sizeof(dump_buf));
		sc_log(ctx, "KEK: %s", dump_buf);
	}

	return rv;

}


static int
sm_authentic_encode_apdu(struct sc_context *ctx, struct sm_info *sm_info)
{
	struct sc_apdu *apdu = (struct sc_apdu *) sm_info->cmd_data;
	int rv = SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM encode APDU: offset:");

	rv = sm_gp_securize_apdu(ctx, sm_info, NULL, apdu);
	LOG_TEST_RET(ctx, rv, "SM encode APDU: securize error");

	LOG_FUNC_RETURN(ctx, rv);
}


#if 0
static int
sm_authentic_get_apdu_read_binary(struct sc_context *ctx, struct sm_info *sm_info,
		char *init_data, struct sc_remote_apdu **rapdus)
{
	struct sm_info_read_binary *rb = &sm_info->cmd_params.read_binary;
	size_t offs = rb->offset, size = rb->size;
	int rv = SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'READ BINARY' APDUs: offset:%i,size:%i", offs, size);
	while (size)   {
		int sz = size > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : size;
		struct sc_remote_apdu *rapdu = NULL;

		rv = sc_remote_apdu_allocate(rapdus, &rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'READ BINARY' APDUs: cannot allocate remote apdu");

		rapdu->apdu.cse = SC_APDU_CASE_2_SHORT;
		rapdu->apdu.cla = 0x00;
		rapdu->apdu.ins = 0xB0;
		rapdu->apdu.p1 = (offs>>8)&0xFF;
		rapdu->apdu.p2 = offs&0xFF;
		rapdu->apdu.resplen = sz;
		rapdu->apdu.le = sz;

		rv = sm_gp_securize_apdu(ctx, sm_info, init_data, &rapdu->apdu);
		LOG_TEST_RET(ctx, rv, "SM get 'READ BINARY' APDUs: securize error");

		offs += sz;
		size -= sz;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_authentic_get_apdu_update_binary(struct sc_context *ctx, struct sm_info *sm_info,
		char *init_data, struct sc_remote_apdu **rapdus)
{
	struct sm_info_update_binary *ub = &sm_info->cmd_params.update_binary;
	size_t offs = ub->offset, size = ub->size, data_offs = 0;
	int rv = SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'UPDATE BINARY' APDUs: offset:%i,size:%i", offs, size);
	while (size)   {
		int sz = size > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : size;
		struct sc_remote_apdu *rapdu = NULL;

		rv = sc_remote_apdu_allocate(rapdus, &rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: cannot allocate remote apdu");

		rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
		rapdu->apdu.cla = 0x00;
		rapdu->apdu.ins = 0xD6;
		rapdu->apdu.p1 = (offs>>8)&0xFF;
		rapdu->apdu.p2 = offs&0xFF;
		memcpy((unsigned char *)rapdu->apdu.data, ub->data + data_offs, sz);
		rapdu->apdu.datalen = sz;
		rapdu->apdu.lc = sz;

		rv = sm_gp_securize_apdu(ctx, sm_info, init_data, &rapdu->apdu);
		LOG_TEST_RET(ctx, rv, "SM get 'READ BINARY' APDUs: securize error");

		offs += sz;
		data_offs += sz;
		size -= sz;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_authentic_get_apdu_create_file(struct sc_context *ctx, struct sm_info *sm_info,
		char *init_data, struct sc_remote_apdu **rapdus)
{
	struct sm_info_create_file *cf = &sm_info->cmd_params.create_file;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'CREATE FILE' APDU: FCP(%i) %p", cf->fcp_len, cf->fcp);

	rv = sc_remote_apdu_allocate(rapdus, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'CREATE FILE' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0xE0;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0x00;
	memcpy((unsigned char *)rapdu->apdu.data, cf->fcp, cf->fcp_len);
	rapdu->apdu.datalen = cf->fcp_len;
	rapdu->apdu.lc = cf->fcp_len;

	rv = sm_gp_securize_apdu(ctx, sm_info, init_data, &rapdu->apdu);
	LOG_TEST_RET(ctx, rv, "SM get 'CREATE FILE' APDU: securize error");

	LOG_FUNC_RETURN(ctx, rv);
}
#endif

static int
sm_authentic_get_apdu_release(struct sc_context *ctx, struct sm_info *sm_info,
		char *init_data, struct sc_remote_data *rdata)
{
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'SM RELEASE' APDU");

	if (!rdata || !rdata->alloc)
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "SM get 'SM RELEASE' APDU: invalid remote data");

	rv = rdata->alloc(rdata, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'SM RELEASE' APDU: cannot allocate remote apdu");

	rapdu->apdu.cse = SC_APDU_CASE_1;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x20;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0xC0;

	rv = sm_gp_securize_apdu(ctx, sm_info, init_data, &rapdu->apdu);
	LOG_TEST_RET(ctx, rv, "SM get 'SM RELEASE' APDUs: securize error");

	LOG_FUNC_RETURN(ctx, rv);
}


int
sm_authentic_get_apdus(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len, struct sc_remote_data *rdata,
		int release_sm)
{
	int rv = 0;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get APDUs: rdata:%p, init_len:%i", rdata, init_len);
	sc_log(ctx, "SM get APDUs: serial %s", sc_dump_hex(sm_info->serialnr.value, sm_info->serialnr.len));

	if (init_data)   {
		rv = sm_gp_external_authentication(ctx, sm_info, init_data, init_len, rdata, sm_oberthur_diversify_keyset);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: cannot authenticate card");
	}

	switch (sm_info->cmd)  {
#if 0
	case SM_CMD_FILE_READ:
		rv = sm_authentic_get_apdu_read_binary(ctx, sm_info, init_data, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: add 'READ BINARY' failed");
		break;
	case SM_CMD_FILE_UPDATE:
		rv = sm_authentic_get_apdu_update_binary(ctx, sm_info, init_data, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: add 'UPDATE BINARY' failed");
		break;
	case SM_CMD_FILE_CREATE:
		rv = sm_authentic_get_apdu_create_file(ctx, sm_info, init_data, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: add 'FILE CREATE' failed");
		break;
	case SM_CMD_PIN_VERIFY:
		rv = sm_authentic_get_apdu_verify_pin(ctx, sm_info, init_data, &rapdus);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: add 'VERIFY PIN' failed");
		break;
	case SM_CMD_PIN_RESET:
		break;
	case SM_CMD_PIN_CREATE:
		break;
	case SM_CMD_RSA_GENERATE:
		break;
	case SM_CMD_RSA_UPDATE:
		break;
#endif
	case SM_CMD_APDU_TRANSMIT:
		rv = sm_authentic_encode_apdu(ctx, sm_info);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: cannot encode APDU");
		break;
	case SM_CMD_INITIALIZE:
		break;
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported SM command");
	}

#if 0
	if (release_sm)   {
		rv = sm_authentic_get_apdu_release(ctx, sm_info, init_data, init_len, out, out_num);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: add 'release' failed");

		sm_gp_close_session(ctx, &sm_info->session.gp);
	}
#endif
	LOG_FUNC_RETURN(ctx, rv);
}
