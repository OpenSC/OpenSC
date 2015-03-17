/*
 * sm-iasecc.c: Secure Messaging procedures specific to IAS/ECC card
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *					  OpenTrust <www.opentrust.com>
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

#include <openssl/des.h>

#include "libopensc/opensc.h"
#include "libopensc/sm.h"
#include "libopensc/log.h"
#include "libopensc/asn1.h"
#include "libopensc/iasecc.h"
#include "libopensc/iasecc-sdo.h"
#include "sm-module.h"

static const struct sc_asn1_entry c_asn1_iasecc_sm_data_object[4] = {
	{ "encryptedData", 	SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 7,	SC_ASN1_OPTIONAL,	NULL, NULL },
	{ "commandStatus", 	SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 0x19,	0, 			NULL, NULL },
	{ "ticket", 		SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 0x0E,	0, 			NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int
sm_iasecc_get_apdu_read_binary(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct iasecc_sm_cmd_update_binary *cmd_data = (struct iasecc_sm_cmd_update_binary *)sm_info->cmd_data;
	size_t offs, data_offs = 0;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);
	if (!cmd_data || !cmd_data->data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

        if (!rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get 'READ BINARY' APDUs: offset:%i,size:%i", cmd_data->offs, cmd_data->count);
	offs = cmd_data->offs;
	while (cmd_data->count > data_offs)   {
		int sz = (cmd_data->count - data_offs) > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : (cmd_data->count - data_offs);
		struct sc_remote_apdu *rapdu = NULL;

 		rv = rdata->alloc(rdata, &rapdu);
	        LOG_TEST_RET(ctx, rv, "SM get 'READ BINARY' APDUs: cannot allocate remote APDU");

		rapdu->apdu.cse = SC_APDU_CASE_2_SHORT;
		rapdu->apdu.cla = 0x00;
		rapdu->apdu.ins = 0xB0;
		rapdu->apdu.p1 = (offs >> 8) & 0xFF;
		rapdu->apdu.p2 = offs & 0xFF;
		rapdu->apdu.le = sz;
		/* 'resplen' is set by remote apdu allocation procedure */

		rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: securize APDU error");

		rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

		offs += sz;
		data_offs += sz;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_update_binary(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct iasecc_sm_cmd_update_binary *cmd_data = (struct iasecc_sm_cmd_update_binary *)sm_info->cmd_data;
	size_t offs, data_offs = 0;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);
	if (!cmd_data || !cmd_data->data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

        if (!rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get 'UPDATE BINARY' APDUs: offset:%i,size:%i", cmd_data->offs, cmd_data->count);
	offs = cmd_data->offs;
	while (data_offs < cmd_data->count)   {
		int sz = (cmd_data->count - data_offs) > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : (cmd_data->count - data_offs);
		struct sc_remote_apdu *rapdu = NULL;

 		rv = rdata->alloc(rdata, &rapdu);
	        LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: cannot allocate remote APDU");

		rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
		rapdu->apdu.cla = 0x00;
		rapdu->apdu.ins = 0xD6;
		rapdu->apdu.p1 = (offs >> 8) & 0xFF;
		rapdu->apdu.p2 = offs & 0xFF;
		memcpy((unsigned char *)rapdu->apdu.data, cmd_data->data + data_offs, sz);
		rapdu->apdu.datalen = sz;
		rapdu->apdu.lc = sz;

		/** 99 02 SW   8E 08 MAC **/
		rapdu->apdu.le = 0x0E;

		rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
		LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: securize APDU error");

		rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

		offs += sz;
		data_offs += sz;
	}

	LOG_FUNC_RETURN(ctx, rv);
}

/* TODO: reduce name of functions */
static int
sm_iasecc_get_apdu_create_file(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct iasecc_sm_cmd_create_file *cmd_data = (struct iasecc_sm_cmd_create_file *)sm_info->cmd_data;
	struct sc_remote_apdu *rapdu = NULL;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	if (!cmd_data || !cmd_data->data || !rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get 'CREATE FILE' APDU: FCP(%i) %s", cmd_data->size, sc_dump_hex(cmd_data->data,cmd_data->size));

 	rv = rdata->alloc(rdata, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: cannot allocate remote APDU");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0xE0;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0x00;
	memcpy((unsigned char *)rapdu->apdu.data, cmd_data->data, cmd_data->size);
	rapdu->apdu.datalen = cmd_data->size;
	rapdu->apdu.lc = cmd_data->size;

	/** 99 02 SW   8E 08 MAC **/
	rapdu->apdu.le = 0x0E;

	rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: securize APDU error");

	rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_delete_file(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	unsigned int file_id = (unsigned int)sm_info->cmd_data;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'DELETE FILE' APDU: file-id %04X", file_id);

	if (!file_id)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

        if (!rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

 	rv = rdata->alloc(rdata, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'DELETE FILE' APDUs: cannot allocate remote APDU");

	rapdu->apdu.cse = SC_APDU_CASE_1;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0xE4;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0x00;

	/** 99 02 SW   8E 08 MAC **/
	rapdu->apdu.le = 0x0E;

	rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'DELETE FILE' APDUs: securize APDU error");

	rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_verify_pin(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct sc_pin_cmd_data *pin_data = (struct sc_pin_cmd_data *)sm_info->cmd_data;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!pin_data || !rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get 'VERIFY PIN' APDU: ", pin_data->pin_reference);

 	rv = rdata->alloc(rdata, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'VERIFY PIN' APDUs: cannot allocate remote APDU");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x20;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = pin_data->pin_reference & ~IASECC_OBJECT_REF_GLOBAL;
	if (pin_data->pin1.len > SM_MAX_DATA_SIZE)
		LOG_TEST_RET(ctx, rv, "SM get 'VERIFY PIN' APDU: invelid PIN size");

	memcpy((unsigned char *)rapdu->apdu.data, pin_data->pin1.data, pin_data->pin1.len);
	rapdu->apdu.datalen = pin_data->pin1.len;
	rapdu->apdu.lc = pin_data->pin1.len;

	/** 99 02 SW   8E 08 MAC **/
	rapdu->apdu.le = 0x0E;

	rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'VERIFY PIN' APDUs: securize APDU error");

	rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_reset_pin(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct sc_pin_cmd_data *pin_data = (struct sc_pin_cmd_data *)sm_info->cmd_data;
	struct sc_remote_apdu *rapdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!pin_data || !rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get 'RESET PIN' APDU; reference %i", pin_data->pin_reference);

 	rv = rdata->alloc(rdata, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'RESET PIN' APDUs: cannot allocate remote APDU");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x2C;
	rapdu->apdu.p2 = pin_data->pin_reference & ~IASECC_OBJECT_REF_GLOBAL;
	if (pin_data->pin2.len)   {
		if (pin_data->pin2.len > SM_MAX_DATA_SIZE)
			LOG_TEST_RET(ctx, rv, "SM get 'RESET PIN' APDU: invalid PIN size");

		rapdu->apdu.p1 = 0x02;
		memcpy((unsigned char *)rapdu->apdu.data, pin_data->pin2.data, pin_data->pin2.len);
		rapdu->apdu.datalen = pin_data->pin2.len;
		rapdu->apdu.lc = pin_data->pin2.len;
	}
	else   {
		rapdu->apdu.p1 = 0x03;
	}

	/** 99 02 SW   8E 08 MAC **/
	rapdu->apdu.le = 0x0E;

	rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'RESET PIN' APDUs: securize APDU error");

	rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_sdo_update(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct iasecc_sdo_update *update = (struct iasecc_sdo_update *)sm_info->cmd_data;
	int rv = SC_ERROR_INVALID_ARGUMENTS, ii;

	LOG_FUNC_CALLED(ctx);
	if (!update)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
        if (!rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM get 'SDO UPDATE' APDU, SDO(class:0x%X,ref:%i)", update->sdo_class, update->sdo_ref);
	for (ii=0; update->fields[ii].tag && ii < IASECC_SDO_TAGS_UPDATE_MAX; ii++)   {
		unsigned char *encoded = NULL;
		size_t encoded_len, offs;

		encoded_len = iasecc_sdo_encode_update_field(ctx, update->sdo_class, update->sdo_ref, &update->fields[ii], &encoded);
		LOG_TEST_RET(ctx, encoded_len, "SM get 'SDO UPDATE' APDU: encode component error");

		sc_log(ctx, "SM IAS/ECC get APDUs: encoded component '%s'", sc_dump_hex(encoded, encoded_len));

		for (offs = 0; offs < encoded_len; )   {
			int len = (encoded_len - offs) > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : (encoded_len - offs);
			struct sc_remote_apdu *rapdu = NULL;

		 	rv = rdata->alloc(rdata, &rapdu);
	        	LOG_TEST_RET(ctx, rv, "SM get 'SDO UPDATE' APDUs: cannot allocate remote APDU");

			rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
			rapdu->apdu.cla = len + offs < encoded_len ? SC_APDU_FLAGS_CHAINING : 0x00;
			rapdu->apdu.ins = 0xDB;
			rapdu->apdu.p1 = 0x3F;
			rapdu->apdu.p2 = 0xFF;
			memcpy((unsigned char *)rapdu->apdu.data, encoded + offs, len);
			rapdu->apdu.datalen = len;
			rapdu->apdu.lc = len;

			/** 99 02 SW   8E 08 MAC **/
			rapdu->apdu.le = 0x0E;

			rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
			LOG_TEST_RET(ctx, rv, "SM get 'SDO UPDATE' APDUs: securize APDU error");

			rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

			offs += len;
		}
		free(encoded);
	}
	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_generate_rsa(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct iasecc_sdo *sdo = (struct iasecc_sdo *)sm_info->cmd_data;
	struct sc_remote_apdu *rapdu = NULL;
	unsigned char put_exponent_data[14] = {
		0x70, 0x0C,
			IASECC_SDO_TAG_HEADER, IASECC_SDO_CLASS_RSA_PUBLIC | 0x80, sdo->sdo_ref & 0x7F, 0x08,
					0x7F, 0x49, 0x05, 0x82, 0x03, 0x01, 0x00, 0x01
	};
	unsigned char generate_data[5] = {
		0x70, 0x03,
			IASECC_SDO_TAG_HEADER, IASECC_SDO_CLASS_RSA_PRIVATE | 0x80, sdo->sdo_ref & 0x7F
	};
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM get 'GENERATE RSA' APDU: SDO(class:%X,reference:%X)", sdo->sdo_class, sdo->sdo_ref);

        if (!rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* Put Exponent */
 	rv = rdata->alloc(rdata, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: cannot allocate remote APDU");

	rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0xDB;
	rapdu->apdu.p1 = 0x3F;
	rapdu->apdu.p2 = 0xFF;
	memcpy((unsigned char *)rapdu->apdu.data, put_exponent_data, sizeof(put_exponent_data));
	rapdu->apdu.datalen = sizeof(put_exponent_data);
	rapdu->apdu.lc = sizeof(put_exponent_data);

	/** 99 02 SW   8E 08 MAC **/
	rapdu->apdu.le = 0x0E;

	rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: securize APDU error");

	rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

	/* Generate Key */
 	rv = rdata->alloc(rdata, &rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: cannot allocate remote APDU");

	rapdu->apdu.cse = SC_APDU_CASE_4_SHORT;
	rapdu->apdu.cla = 0x00;
	rapdu->apdu.ins = 0x47;
	rapdu->apdu.p1 = 0x00;
	rapdu->apdu.p2 = 0x00;
	memcpy((unsigned char *)rapdu->apdu.data, generate_data, sizeof(generate_data));
	rapdu->apdu.datalen = sizeof(generate_data);
	rapdu->apdu.lc = sizeof(generate_data);

	rapdu->apdu.le = 0x100;

	rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
	LOG_TEST_RET(ctx, rv, "SM get 'UPDATE BINARY' APDUs: securize APDU error");

	rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sm_iasecc_get_apdu_update_rsa(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct iasecc_sdo_rsa_update *cmd_data = (struct iasecc_sdo_rsa_update *)sm_info->cmd_data;
	struct iasecc_sdo_update *to_update[2] = {NULL, NULL};
	int rv = 0, ii = 0, jj = 0;

	LOG_FUNC_CALLED(ctx);
	if (cmd_data->update_prv.sdo_class)   {
		to_update[ii++] = &cmd_data->update_prv;
		sc_log(ctx, "SM get 'UPDATE RSA' APDU: SDO(class:%X,ref:%X)", cmd_data->update_prv.sdo_class, cmd_data->update_prv.sdo_ref);
	}

	if (cmd_data->update_pub.sdo_class)   {
		to_update[ii++] = &cmd_data->update_pub;
		sc_log(ctx, "SM get 'UPDATE RSA' APDU: SDO(class:%X,ref:%X)", cmd_data->update_pub.sdo_class, cmd_data->update_pub.sdo_ref);
	}

	for (jj=0;jj<2 && to_update[jj];jj++)   {
		for (ii=0; to_update[jj]->fields[ii].tag && ii < IASECC_SDO_TAGS_UPDATE_MAX; ii++)   {
			unsigned char *encoded = NULL;
			size_t encoded_len, offs;

			sc_log(ctx, "SM IAS/ECC get APDUs: component(num %i:%i) class:%X, ref:%X", jj, ii,
					to_update[jj]->sdo_class, to_update[jj]->sdo_ref);

			encoded_len = iasecc_sdo_encode_update_field(ctx, to_update[jj]->sdo_class, to_update[jj]->sdo_ref,
						&to_update[jj]->fields[ii], &encoded);
			LOG_TEST_RET(ctx, encoded_len, "SM get 'UPDATE RSA' APDU: cannot encode key component");

			sc_log(ctx, "SM IAS/ECC get APDUs: component encoded %s", sc_dump_hex(encoded, encoded_len));

			for (offs = 0; offs < encoded_len; )   {
				int len = (encoded_len - offs) > SM_MAX_DATA_SIZE ? SM_MAX_DATA_SIZE : (encoded_len - offs);
				struct sc_remote_apdu *rapdu = NULL;

		 		rv = rdata->alloc(rdata, &rapdu);
	        		LOG_TEST_RET(ctx, rv, "SM get 'UPDATE RSA' APDUs: cannot allocate remote APDU");

				rapdu->apdu.cse = SC_APDU_CASE_3_SHORT;
				rapdu->apdu.cla = len + offs < encoded_len ? 0x10 : 0x00;
				rapdu->apdu.ins = 0xDB;
				rapdu->apdu.p1 = 0x3F;
				rapdu->apdu.p2 = 0xFF;
				memcpy((unsigned char *)rapdu->apdu.data, encoded + offs, len);
				rapdu->apdu.datalen = len;
				rapdu->apdu.lc = len;

				/** 99 02 SW   8E 08 MAC **/
				rapdu->apdu.le = 0x0E;

				rv = sm_cwa_securize_apdu(ctx, sm_info, rapdu);
		                LOG_TEST_RET(ctx, rv, "SM get 'UPDATE RSA' APDUs: securize APDU error");

				rapdu->flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;

				offs += len;
			}
			free(encoded);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sm_iasecc_get_apdus(struct sc_context *ctx, struct sm_info *sm_info,
	       unsigned char *init_data, size_t init_len, struct sc_remote_data *rdata, int release_sm)
{
	struct sm_cwa_session *cwa_session = &sm_info->session.cwa;
	struct sm_cwa_keyset *cwa_keyset = &sm_info->session.cwa.cwa_keyset;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM IAS/ECC get APDUs: init_len:%i", init_len);
	sc_log(ctx, "SM IAS/ECC get APDUs: rdata:%p", rdata);
	sc_log(ctx, "SM IAS/ECC get APDUs: serial %s", sc_dump_hex(sm_info->serialnr.value, sm_info->serialnr.len));

	rv = sm_cwa_decode_authentication_data(ctx, cwa_keyset, cwa_session, init_data);
	LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: decode authentication data error");

	rv = sm_cwa_init_session_keys(ctx, cwa_session, cwa_session->params.crt_at.algo);
	LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: cannot get session keys");

	sc_log(ctx, "SKENC %s", sc_dump_hex(cwa_session->session_enc, sizeof(cwa_session->session_enc)));
	sc_log(ctx, "SKMAC %s", sc_dump_hex(cwa_session->session_mac, sizeof(cwa_session->session_mac)));
	sc_log(ctx, "SSC   %s", sc_dump_hex(cwa_session->ssc, sizeof(cwa_session->ssc)));

	switch (sm_info->cmd)  {
	case SM_CMD_FILE_READ:
		rv = sm_iasecc_get_apdu_read_binary(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'READ BINARY' failed");
		break;
	case SM_CMD_FILE_UPDATE:
		rv = sm_iasecc_get_apdu_update_binary(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'UPDATE BINARY' failed");
		break;
	case SM_CMD_FILE_CREATE:
		rv = sm_iasecc_get_apdu_create_file(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'CREATE FILE' failed");
		break;
	case SM_CMD_FILE_DELETE:
		rv = sm_iasecc_get_apdu_delete_file(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'DELETE FILE' failed");
		break;
	case SM_CMD_PIN_RESET:
		rv = sm_iasecc_get_apdu_reset_pin(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'RESET PIN' failed");
		break;
	case SM_CMD_RSA_GENERATE:
		rv = sm_iasecc_get_apdu_generate_rsa(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'GENERATE RSA' failed");
		break;
	case SM_CMD_RSA_UPDATE:
		rv = sm_iasecc_get_apdu_update_rsa(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'UPDATE RSA' failed");
		break;
	case SM_CMD_SDO_UPDATE:
		rv = sm_iasecc_get_apdu_sdo_update(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'SDO UPDATE' failed");
		break;
	case SM_CMD_PIN_VERIFY:
		rv = sm_iasecc_get_apdu_verify_pin(ctx, sm_info, rdata);
		LOG_TEST_RET(ctx, rv, "SM IAS/ECC get APDUs: 'RAW APDU' failed");
		break;
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported SM command");
	}

	if (release_sm)   {
		/* Apparently useless for this card */
	}

	LOG_FUNC_RETURN(ctx, rv);
}


int
sm_iasecc_decode_card_data(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata,
		unsigned char *out, size_t out_len)
{
	struct sm_cwa_session *session_data = &sm_info->session.cwa;
	struct sc_asn1_entry asn1_iasecc_sm_data_object[4];
	struct sc_remote_apdu *rapdu = NULL;
	int rv, offs = 0;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "IAS/ECC decode answer() rdata length %i, out length %i", rdata->length, out_len);
        for (rapdu = rdata->data; rapdu; rapdu = rapdu->next)   {
                unsigned char *decrypted;
                size_t decrypted_len;
		unsigned char resp_data[SC_MAX_APDU_BUFFER_SIZE];
		size_t resp_len = sizeof(resp_data);
		unsigned char status[2] = {0, 0};
		size_t status_len = sizeof(status);
		unsigned char ticket[8];
		size_t ticket_len = sizeof(ticket);

		sc_log(ctx, "IAS/ECC decode response(%i) %s", rapdu->apdu.resplen, sc_dump_hex(rapdu->apdu.resp, rapdu->apdu.resplen));

		sc_copy_asn1_entry(c_asn1_iasecc_sm_data_object, asn1_iasecc_sm_data_object);
		sc_format_asn1_entry(asn1_iasecc_sm_data_object + 0, resp_data, &resp_len, 0);
		sc_format_asn1_entry(asn1_iasecc_sm_data_object + 1, status, &status_len, 0);
		sc_format_asn1_entry(asn1_iasecc_sm_data_object + 2, ticket, &ticket_len, 0);

        	rv = sc_asn1_decode(ctx, asn1_iasecc_sm_data_object, rapdu->apdu.resp, rapdu->apdu.resplen, NULL, NULL);
		LOG_TEST_RET(ctx, rv, "IAS/ECC decode answer(s): ASN1 decode error");

		sc_log(ctx, "IAS/ECC decode response() SW:%02X%02X, MAC:%s", status[0], status[1], sc_dump_hex(ticket, ticket_len));
		if (status[0] != 0x90 || status[1] != 0x00)
			continue;

		if (asn1_iasecc_sm_data_object[0].flags & SC_ASN1_PRESENT)   {
			sc_log(ctx, "IAS/ECC decode answer() object present");
			if (resp_data[0] != 0x01)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "IAS/ECC decode answer(s): invalid encrypted data format");

			decrypted_len = sizeof(decrypted);
			rv = sm_decrypt_des_cbc3(ctx, session_data->session_enc, &resp_data[1], resp_len - 1,
					&decrypted, &decrypted_len);
			LOG_TEST_RET(ctx, rv, "IAS/ECC decode answer(s): cannot decrypt card answer data");

			sc_log(ctx, "IAS/ECC decrypted data(%i) %s", decrypted_len, sc_dump_hex(decrypted, decrypted_len));
			while(*(decrypted + decrypted_len - 1) == 0x00)
			       decrypted_len--;
			if (*(decrypted + decrypted_len - 1) != 0x80)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "IAS/ECC decode answer(s): invalid card data padding ");
			decrypted_len--;

			if (out && out_len)   {
				if (out_len < offs + decrypted_len)
					LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "IAS/ECC decode answer(s): unsufficient output buffer size");

				memcpy(out + offs, decrypted, decrypted_len);

				offs += decrypted_len;
				sc_log(ctx, "IAS/ECC decode card answer(s): out_len/offs %i/%i", out_len, offs);
			}

			free(decrypted);
		}
	}

	LOG_FUNC_RETURN(ctx, offs);
}
