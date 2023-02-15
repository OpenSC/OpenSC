/*
 * sm-cwa14890.c: Procedures related to Secure Messaging according to the CWA-14890
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

int
sm_cwa_get_mac(struct sc_context *ctx, unsigned char *key, sm_des_cblock *icv,
			unsigned char *in, int in_len, sm_des_cblock *out, int force_padding)
{
	unsigned char padding[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char *buf;

	LOG_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_SM, "sm_cwa_get_mac() data length %i", in_len);

	buf = malloc(in_len + 8);
	if (!buf)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	sc_debug(ctx, SC_LOG_DEBUG_SM, "sm_cwa_get_mac() in_data(%i) %s", in_len, sc_dump_hex(in, in_len));
	memcpy(buf, in, in_len);
	memcpy(buf + in_len, padding, 8);

	if (force_padding)
		in_len = ((in_len + 8) / 8) * 8;
	else
		in_len = ((in_len + 7) / 8) * 8;

	sc_debug(ctx, SC_LOG_DEBUG_SM, "sm_cwa_get_mac() data to MAC(%i) %s", in_len, sc_dump_hex(buf, in_len));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "sm_cwa_get_mac() ICV %s", sc_dump_hex((unsigned char *)icv, 8));

	DES_cbc_cksum_3des_emv96(ctx, buf, out, in_len, key, icv);

	free(buf);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sm_cwa_encode_external_auth_data(struct sc_context *ctx, struct sm_cwa_session *session_data,
		unsigned char *out, size_t out_len)
{
	if (out_len < 16)
		return SC_ERROR_BUFFER_TOO_SMALL;

	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.RND %s", sc_dump_hex(session_data->ifd.rnd, 8));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.SN  %s", sc_dump_hex(session_data->ifd.sn, 8));

	memcpy(out + 0, session_data->icc.rnd, 8);
	memcpy(out + 8, session_data->icc.sn, 8);

	return 16;
}


int
sm_cwa_encode_mutual_auth_data(struct sc_context *ctx, struct sm_cwa_session *session_data,
		unsigned char *out, size_t out_len)
{
	if (out_len < 64)
		return SC_ERROR_BUFFER_TOO_SMALL;

	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.RND %s", sc_dump_hex(session_data->ifd.rnd, 8));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.SN  %s", sc_dump_hex(session_data->ifd.sn, 8));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.K   %s", sc_dump_hex(session_data->ifd.k, 32));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "ICC.RND %s", sc_dump_hex(session_data->icc.rnd, 8));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "ICC.SN  %s", sc_dump_hex(session_data->icc.sn, 8));

	memcpy(out + 0, session_data->ifd.rnd, 8);
	memcpy(out + 8, session_data->ifd.sn, 8);
	memcpy(out + 16, session_data->icc.rnd, 8);
	memcpy(out + 24, session_data->icc.sn, 8);
	memcpy(out + 32, session_data->ifd.k, 32);

	return 64;
}


int
sm_cwa_decode_authentication_data(struct sc_context *ctx, struct sm_cwa_keyset *keyset,
		struct sm_cwa_session *session_data, unsigned char *auth_data)
{
	sm_des_cblock icv = {0, 0, 0, 0, 0, 0, 0, 0};
	sm_des_cblock cblock;
	unsigned char *decrypted = NULL;
	size_t decrypted_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(icv, 0, sizeof(icv));
	rv = sm_cwa_get_mac(ctx, keyset->mac, &icv, session_data->mdata, 0x40, &cblock, 1);
	LOG_TEST_RET(ctx, rv, "Decode authentication data:  sm_ecc_get_mac failed");
	sc_debug(ctx, SC_LOG_DEBUG_SM, "MAC:%s", sc_dump_hex(cblock, sizeof(cblock)));

	if(memcmp(session_data->mdata + 0x40, cblock, 8))
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_AUTHENTICATION_FAILED);

	rv = sm_decrypt_des_cbc3(ctx, keyset->enc, session_data->mdata, session_data->mdata_len, &decrypted, &decrypted_len);
	LOG_TEST_RET(ctx, rv, "sm_ecc_decode_auth_data() DES CBC3 decrypt error");

	sc_debug(ctx, SC_LOG_DEBUG_SM,
	       "sm_ecc_decode_auth_data() decrypted(%"SC_FORMAT_LEN_SIZE_T"u) %s",
	       decrypted_len, sc_dump_hex(decrypted, decrypted_len));

	if (memcmp(decrypted, session_data->icc.rnd, 8)) {
		free(decrypted);
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	if (memcmp(decrypted + 8, session_data->icc.sn, 8)) {
		free(decrypted);
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	if (memcmp(decrypted + 16, session_data->ifd.rnd, 8)) {
		free(decrypted);
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	if (memcmp(decrypted + 24, session_data->ifd.sn, 8)) {
		free(decrypted);
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	memcpy(session_data->icc.k, decrypted + 32, 32);

	free(decrypted);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sm_cwa_init_session_keys(struct sc_context *ctx, struct sm_cwa_session *session_data,
		unsigned char mechanism)
{
	unsigned char xored[36];
	unsigned char buff[SHA256_DIGEST_LENGTH];
	int ii;

	memset(xored, 0, sizeof(xored));

	for (ii=0; ii<32; ii++)
		xored[ii] = session_data->ifd.k[ii] ^ session_data->icc.k[ii];

	sc_debug(ctx, SC_LOG_DEBUG_SM, "K_IFD %s", sc_dump_hex(session_data->ifd.k, 32));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "K_ICC %s", sc_dump_hex(session_data->icc.k, 32));

	if (mechanism == IASECC_ALGORITHM_SYMMETRIC_SHA1)   {
		xored[35] = 0x01;
		sc_debug(ctx, SC_LOG_DEBUG_SM, "XOR for SkEnc %s", sc_dump_hex(xored, 36));
		SHA1(xored, 36, buff);
		memcpy(&session_data->session_enc[0], buff, sizeof(session_data->session_enc));

		xored[35] = 0x02;
		sc_debug(ctx, SC_LOG_DEBUG_SM, "XOR for SkMac %s", sc_dump_hex(xored, 36));
		SHA1(xored, 36, buff);
		memcpy(&session_data->session_mac[0], buff, sizeof(session_data->session_mac));
	}
	else if (mechanism == IASECC_ALGORITHM_SYMMETRIC_SHA256)   {
		xored[35] = 0x01;
		SHA256(xored, 36, buff);
		memcpy(&session_data->session_enc[0], buff, sizeof(session_data->session_enc));

		xored[35] = 0x02;
		SHA256(xored, 36, buff);
		memcpy(&session_data->session_mac[0], buff, sizeof(session_data->session_mac));
	}
	else   {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memcpy(session_data->ssc + 0, session_data->icc.rnd + 4, 4);
	memcpy(session_data->ssc + 4, session_data->ifd.rnd + 4, 4);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sm_cwa_initialize(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata)
{
	struct sm_cwa_session *cwa_session = &sm_info->session.cwa;
	struct sm_cwa_keyset *cwa_keyset = &sm_info->session.cwa.cwa_keyset;
	struct sc_serial_number sn = sm_info->serialnr;
	size_t icc_sn_len = sizeof(cwa_session->icc.sn);
	struct sc_remote_apdu *new_rapdu = NULL;
	struct sc_apdu *apdu = NULL;
	unsigned char buf[0x100], *encrypted = NULL;
	size_t encrypted_len;
	sm_des_cblock icv = {0, 0, 0, 0, 0, 0, 0, 0}, cblock;
	int rv, offs;

	LOG_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM IAS/ECC initialize: serial %s", sc_dump_hex(sm_info->serialnr.value, sm_info->serialnr.len));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM IAS/ECC initialize: card challenge %s", sc_dump_hex(cwa_session->card_challenge, 8));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM IAS/ECC initialize: current_df_path %s", sc_print_path(&sm_info->current_path_df));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM IAS/ECC initialize: CRT_AT reference 0x%X", cwa_session->params.crt_at.refs[0]);

	if (!rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = rdata->alloc(rdata, &new_rapdu);
	LOG_TEST_RET(ctx, rv, "SM GP decode card answer: cannot allocate remote APDU");
	apdu = &new_rapdu->apdu;

	memcpy(&cwa_session->icc.rnd[0], cwa_session->card_challenge, 8);

	if (sn.len > icc_sn_len)
		memcpy(&cwa_session->icc.sn[0], &sn.value[sn.len - icc_sn_len], icc_sn_len);
	else
		memcpy(&cwa_session->icc.sn[icc_sn_len - sn.len], &sn.value[0], sn.len);

	if (sm_info->cmd == SM_CMD_EXTERNAL_AUTH)   {
		offs = sm_cwa_encode_external_auth_data(ctx, cwa_session, buf, sizeof(buf));
		if (offs != 0x10)
			LOG_FUNC_RETURN(ctx, offs);
	}
	else   {
		offs = sm_cwa_encode_mutual_auth_data(ctx, cwa_session, buf, sizeof(buf));
		if (offs != 0x40)
			LOG_FUNC_RETURN(ctx, offs);
	}

	sc_debug(ctx, SC_LOG_DEBUG_SM, "S(%i) %s", offs, sc_dump_hex(buf, offs));

	rv = sm_encrypt_des_cbc3(ctx, cwa_keyset->enc, buf, offs, &encrypted, &encrypted_len, 1);
	LOG_TEST_RET(ctx, rv, "_encrypt_des_cbc3() failed");

	sc_debug(ctx, SC_LOG_DEBUG_SM, "ENCed(%"SC_FORMAT_LEN_SIZE_T"u) %s", encrypted_len,
	       sc_dump_hex(encrypted, encrypted_len));

	memcpy(buf, encrypted, encrypted_len);
	offs = encrypted_len;

	rv = sm_cwa_get_mac(ctx, cwa_keyset->mac, &icv, buf, offs, &cblock, 1);
	LOG_TEST_GOTO_ERR(ctx, rv, "sm_ecc_get_mac() failed");
	sc_debug(ctx, SC_LOG_DEBUG_SM, "MACed(%"SC_FORMAT_LEN_SIZE_T"u) %s", sizeof(cblock),
	       sc_dump_hex(cblock, sizeof(cblock)));

	apdu->cse = SC_APDU_CASE_4_SHORT;
	apdu->cla = 0x00;
	apdu->ins = 0x82;
	apdu->p1 =  0x00;
	apdu->p2 =  0x00;
	apdu->lc =  encrypted_len + sizeof(cblock);
	apdu->le = encrypted_len + sizeof(cblock);
	apdu->datalen = encrypted_len + sizeof(cblock);
	memcpy(new_rapdu->sbuf, encrypted, encrypted_len);
	memcpy(new_rapdu->sbuf + encrypted_len, cblock, sizeof(cblock));
	rv = SC_SUCCESS;

err:
	free(encrypted);
	LOG_FUNC_RETURN(ctx, rv);
}


int
sm_cwa_securize_apdu(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu *rapdu)
{
	struct sm_cwa_session *session_data = &sm_info->session.cwa;
	struct sc_apdu *apdu = &rapdu->apdu;
	unsigned char sbuf[0x400];
	sm_des_cblock cblock, icv;
	unsigned char *encrypted = NULL, edfb_data[0x200], mac_data[0x200];
	size_t encrypted_len, edfb_len = 0, mac_len = 0, offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_SM,
	       "securize APDU (cla:%X,ins:%X,p1:%X,p2:%X,data(%"SC_FORMAT_LEN_SIZE_T"u):%p)",
	       apdu->cla, apdu->ins, apdu->p1, apdu->p2, apdu->datalen,
	       apdu->data);

	sm_incr_ssc(session_data->ssc, sizeof(session_data->ssc));

	rv = sm_encrypt_des_cbc3(ctx, session_data->session_enc, apdu->data, apdu->datalen, &encrypted, &encrypted_len, 0);
	LOG_TEST_RET(ctx, rv, "securize APDU: DES CBC3 encryption failed");
	sc_debug(ctx, SC_LOG_DEBUG_SM, "encrypted data (len:%"SC_FORMAT_LEN_SIZE_T"u, %s)",
	       encrypted_len, sc_dump_hex(encrypted, encrypted_len));

	offs = 0;
	if (apdu->ins & 0x01)   {
		edfb_data[offs++] = IASECC_SM_DO_TAG_TCG_ODD_INS;
		if (encrypted_len + 1 > 0x7F)
			edfb_data[offs++] = 0x81;
		edfb_data[offs++] = encrypted_len;
	}
	else   {
		edfb_data[offs++] = IASECC_SM_DO_TAG_TCG_EVEN_INS;
		if (encrypted_len + 1 > 0x7F)
			edfb_data[offs++] = 0x81;
		edfb_data[offs++] = encrypted_len + 1;
		edfb_data[offs++] = 0x01;
	}
	memcpy(edfb_data + offs, encrypted, encrypted_len);
	offs += encrypted_len;
	edfb_len = offs;
	sc_debug(ctx, SC_LOG_DEBUG_SM, "securize APDU: EDFB(len:%"SC_FORMAT_LEN_SIZE_T"u,%s)",
	       edfb_len, sc_dump_hex(edfb_data, edfb_len));

	free(encrypted);
	encrypted = NULL;

	offs = 0;
	memcpy(mac_data + offs, session_data->ssc, 8);
	offs += 8;
	mac_data[offs++] = apdu->cla | 0x0C;
	mac_data[offs++] = apdu->ins;
	mac_data[offs++] = apdu->p1;
	mac_data[offs++] = apdu->p2;
	mac_data[offs++] = 0x80;
	mac_data[offs++] = 0x00;
	mac_data[offs++] = 0x00;
	mac_data[offs++] = 0x00;

	memcpy(mac_data + offs, edfb_data, edfb_len);
	offs += edfb_len;

	/* if (apdu->le)   { */
		mac_data[offs++] = IASECC_SM_DO_TAG_TLE;
		mac_data[offs++] = 1;
		mac_data[offs++] = apdu->le;
	/* } */

	mac_len = offs;
	sc_debug(ctx, SC_LOG_DEBUG_SM, "securize APDU: MAC data(len:%"SC_FORMAT_LEN_SIZE_T"u,%s)",
	       mac_len, sc_dump_hex(mac_data, mac_len));

	memset(icv, 0, sizeof(icv));
	rv = sm_cwa_get_mac(ctx, session_data->session_mac, &icv, mac_data, mac_len, &cblock, 0);
	LOG_TEST_RET(ctx, rv, "securize APDU: MAC calculation error");
	sc_debug(ctx, SC_LOG_DEBUG_SM, "securize APDU: MAC:%s", sc_dump_hex(cblock, sizeof(cblock)));

	offs = 0;
	if (edfb_len)   {
		memcpy(sbuf + offs, edfb_data, edfb_len);
		offs += edfb_len;
	}

	/* if (apdu->le)   { */
		sbuf[offs++] = IASECC_SM_DO_TAG_TLE;
		sbuf[offs++] = 1;
		sbuf[offs++] = apdu->le;
	/* } */

	sbuf[offs++] = IASECC_SM_DO_TAG_TCC;
	sbuf[offs++] = 8;
	memcpy(sbuf + offs, cblock, 8);
	offs += 8;
	sc_debug(ctx, SC_LOG_DEBUG_SM, "securize APDU: SM data(len:%"SC_FORMAT_LEN_SIZE_T"u,%s)",
	       offs, sc_dump_hex(sbuf, offs));

	if (offs > sizeof(rapdu->sbuf))
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "securize APDU: buffer too small for encrypted data");

	apdu->cse = SC_APDU_CASE_4_SHORT;
	apdu->cla |= 0x0C;
	apdu->lc = offs;
	apdu->datalen = offs;
	memcpy((unsigned char *)apdu->data, sbuf, offs);

	sm_incr_ssc(session_data->ssc, sizeof(session_data->ssc));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
