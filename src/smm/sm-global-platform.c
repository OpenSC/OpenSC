/*
 * sm-global-platform.c: Global Platform related procedures
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

#include <openssl/des.h>
#include <openssl/rand.h>

#include "libopensc/opensc.h"
#include "libopensc/sm.h"
#include "libopensc/log.h"
#include "libopensc/asn1.h"

#include "sm-module.h"

static const struct sc_asn1_entry c_asn1_authentic_card_response[4] = {
	{ "number",	SC_ASN1_INTEGER,        SC_ASN1_TAG_INTEGER,    0, NULL, NULL },
	{ "status",	SC_ASN1_INTEGER,        SC_ASN1_TAG_INTEGER,    0, NULL, NULL },
	{ "data",       SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 2 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_card_response[2] = {
	{ "cardResponse", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int
sm_gp_decode_card_answer(struct sc_context *ctx, struct sc_remote_data *rdata, unsigned char *out, size_t out_len)
{
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


int
sm_gp_initialize(struct sc_context *ctx, struct sm_info *sm_info,  struct sc_remote_data *rdata)
{
	struct sc_serial_number sn = sm_info->serialnr;
	struct sm_gp_session *gp_session = &sm_info->session.gp;
	struct sm_gp_keyset *gp_keyset = &sm_info->session.gp.gp_keyset;
	struct sc_remote_apdu *new_rapdu = NULL;
	struct sc_apdu *apdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM GP initialize: serial:%s", sc_dump_hex(sn.value, sn.len));
	sc_log(ctx, "SM GP initialize: current_df_path %s", sc_print_path(&sm_info->current_path_df));
	sc_log(ctx, "SM GP initialize: KMC length %i", gp_keyset->kmc_len);

	if (!rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = rdata->alloc(rdata, &new_rapdu);
	LOG_TEST_RET(ctx, rv, "SM GP decode card answer: cannot allocate remote APDU");
	apdu = &new_rapdu->apdu;

	rv = RAND_bytes(gp_session->host_challenge, SM_SMALL_CHALLENGE_LEN);
	if (!rv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_RAND_FAILED);

	apdu->cse = SC_APDU_CASE_4_SHORT;
	apdu->cla = 0x80;
	apdu->ins = 0x50;
	apdu->p1 = 0x0;
	apdu->p2 = 0x0;
	apdu->lc = SM_SMALL_CHALLENGE_LEN;
	apdu->le = 0x1C;
	apdu->datalen = SM_SMALL_CHALLENGE_LEN;
	memcpy(&new_rapdu->sbuf[0], gp_session->host_challenge, SM_SMALL_CHALLENGE_LEN);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static unsigned char *
sc_gp_get_session_key(struct sc_context *ctx, struct sm_gp_session *gp_session,
		unsigned char *key)
{
	int out_len;
	unsigned char *out;
	unsigned char deriv[16];

	memcpy(deriv,		gp_session->card_challenge + 4,	4);
	memcpy(deriv + 4,	gp_session->host_challenge,	4);
	memcpy(deriv + 8,	gp_session->card_challenge,	4);
	memcpy(deriv + 12,	gp_session->host_challenge + 4,	4);

	if (sm_encrypt_des_ecb3(key, deriv, 16, &out, &out_len))   {
		if (ctx)
			sc_log(ctx, "SM GP get session key: des_ecb3 encryption error");
		free(out);
		return NULL;
	}
	else if (out==NULL  || out_len!=16)   {
		if (ctx)
			sc_log(ctx, "SM GP get session key: des_ecb3 encryption error: out(%p,len:%i)", out, out_len);
		if (out)
			free(out);
		return NULL;
	}

	return out;
}


int
sm_gp_get_cryptogram(unsigned char *session_key,
		unsigned char *left, unsigned char *right,
		unsigned char *out, int out_len)
{
	unsigned char block[24];
	DES_cblock kk,k2;
	DES_key_schedule ks,ks2;
	DES_cblock cksum={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	if (out_len!=8)
		return SC_ERROR_INVALID_ARGUMENTS;

	memcpy(block + 0, left, 8);
	memcpy(block + 8, right, 8);
	memcpy(block + 16, "\x80\0\0\0\0\0\0\0",8);

	memcpy(&kk, session_key, 8);
	memcpy(&k2, session_key + 8, 8);
	DES_set_key_unchecked(&kk,&ks);
	DES_set_key_unchecked(&k2,&ks2);
	DES_cbc_cksum_3des(block,&cksum, sizeof(block),&ks,&ks2,&cksum);

	memcpy(out, cksum, 8);

	return 0;
}


int
sm_gp_get_mac(unsigned char *key, DES_cblock *icv,
		unsigned char *in, int in_len, DES_cblock *out)
{
	int len;
	unsigned char *block;
	DES_cblock kk, k2;
	DES_key_schedule ks,ks2;

	block = malloc(in_len + 8);
	if (!block)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(block, in, in_len);
	memcpy(block + in_len, "\x80\0\0\0\0\0\0\0", 8);
	len = in_len + 8;
	len -= (len%8);

	memcpy(&kk, key, 8);
	memcpy(&k2, key + 8, 8);
	DES_set_key_unchecked(&kk,&ks);
	DES_set_key_unchecked(&k2,&ks2);

	DES_cbc_cksum_3des(block, out, len ,&ks, &ks2, icv);

	free(block);
	return 0;
}


static int
sm_gp_parse_init_data(struct sc_context *ctx, struct sm_gp_session *gp_session,
		unsigned char *init_data, size_t init_len)
{
	struct sm_gp_keyset *gp_keyset = &gp_session->gp_keyset;

	if(init_len != 0x1C)
		return SC_ERROR_INVALID_DATA;

	gp_keyset->version = *(init_data + 10);
	gp_keyset->index = *(init_data + 11);
	memcpy(gp_session->card_challenge, init_data + 12, SM_SMALL_CHALLENGE_LEN);

	return SC_SUCCESS;
}


static int
sm_gp_init_session(struct sc_context *ctx, struct sm_gp_session *gp_session,
		unsigned char *adata, size_t adata_len)
{
	struct sm_gp_keyset *gp_keyset = &gp_session->gp_keyset;
	unsigned char cksum[8];
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!adata || adata_len < 8)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "SM GP init session: auth.data %s", sc_dump_hex(adata, 8));

	gp_session->session_enc = sc_gp_get_session_key(ctx, gp_session, gp_keyset->enc);
	gp_session->session_mac = sc_gp_get_session_key(ctx, gp_session, gp_keyset->mac);
	gp_session->session_kek = sc_gp_get_session_key(ctx, gp_session, gp_keyset->kek);
	if (!gp_session->session_enc || !gp_session->session_mac || !gp_session->session_kek)
		LOG_TEST_RET(ctx, SC_ERROR_SM_NO_SESSION_KEYS, "SM GP init session: get session keys error");
	memcpy(gp_session->session_kek, gp_keyset->kek, 16);

	sc_log(ctx, "SM GP init session: session ENC: %s", sc_dump_hex(gp_session->session_enc, 16));
	sc_log(ctx, "SM GP init session: session MAC: %s", sc_dump_hex(gp_session->session_mac, 16));
	sc_log(ctx, "SM GP init session: session KEK: %s", sc_dump_hex(gp_session->session_kek, 16));

	memset(cksum, 0, sizeof(cksum));
	rv = sm_gp_get_cryptogram(gp_session->session_enc, gp_session->host_challenge, gp_session->card_challenge, cksum, sizeof(cksum));
	LOG_TEST_RET(ctx, rv, "SM GP init session: cannot get cryptogram");

	sc_log(ctx, "SM GP init session: cryptogram: %s", sc_dump_hex(cksum, 8));
	if (memcmp(cksum, adata, adata_len))
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_AUTHENTICATION_FAILED);

	sc_log(ctx, "SM GP init session: card authenticated");
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


void
sm_gp_close_session(struct sc_context *ctx, struct sm_gp_session *gp_session)
{
	free(gp_session->session_enc);
	free(gp_session->session_mac);
	free(gp_session->session_kek);
}


int
sm_gp_external_authentication(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len, struct sc_remote_data *rdata,
		int (*diversify_keyset)(struct sc_context *ctx,
				struct sm_info *sm_info,
				unsigned char *idata, size_t idata_len))
{
	struct sc_remote_apdu *new_rapdu = NULL;
	struct sc_apdu *apdu = NULL;
	unsigned char host_cryptogram[8], raw_apdu[SC_MAX_APDU_BUFFER_SIZE];
	struct sm_gp_session *gp_session = &sm_info->session.gp;
	DES_cblock mac;
	int rv, offs = 0;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info || !init_data || !rdata || !rdata->alloc)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (init_len != 0x1C)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "SM GP authentication: invalid auth data length");

	rv = sm_gp_parse_init_data(ctx, gp_session, init_data, init_len);
	LOG_TEST_RET(ctx, rv, "SM GP authentication: 'INIT DATA' parse error");

	if (diversify_keyset)   {
		rv = (*diversify_keyset)(ctx, sm_info, init_data, init_len);
		LOG_TEST_RET(ctx, rv, "SM GP authentication: keyset diversification error");
	}

	rv = sm_gp_init_session(ctx, gp_session, init_data + 20, 8);
	LOG_TEST_RET(ctx, rv, "SM GP authentication: init session error");

	rv = sm_gp_get_cryptogram(gp_session->session_enc,
			gp_session->card_challenge, gp_session->host_challenge,
			host_cryptogram, sizeof(host_cryptogram));
	LOG_TEST_RET(ctx, rv, "SM GP authentication: get host cryptogram error");

	sc_log(ctx, "SM GP authentication: host_cryptogram:%s", sc_dump_hex(host_cryptogram, 8));

	rv = rdata->alloc(rdata, &new_rapdu);
	LOG_TEST_RET(ctx, rv, "SM GP authentication: cannot allocate remote APDU");
	apdu = &new_rapdu->apdu;

	offs = 0;
	apdu->cse = SC_APDU_CASE_3_SHORT;
	apdu->cla = raw_apdu[offs++] = 0x84;
	apdu->ins = raw_apdu[offs++] = 0x82;
	apdu->p1  = raw_apdu[offs++] = gp_session->params.level;
	apdu->p2  = raw_apdu[offs++] = 0;
	apdu->lc  = raw_apdu[offs++] = 0x10;
	apdu->datalen = 0x10;

	memcpy(raw_apdu + offs, host_cryptogram, 8);
	offs += 8;
	rv = sm_gp_get_mac(gp_session->session_mac, &gp_session->mac_icv, raw_apdu, offs, &mac);
	LOG_TEST_RET(ctx, rv, "SM GP authentication: get MAC error");

	memcpy(new_rapdu->sbuf, host_cryptogram, 8);
	memcpy(new_rapdu->sbuf + 8, mac, 8);
	memcpy(gp_session->mac_icv, mac, 8);

	LOG_FUNC_RETURN(ctx, 1);
}


static int
sm_gp_encrypt_command_data(struct sc_context *ctx, unsigned char *session_key,
		const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
	unsigned char *data = NULL;
	int rv, len;

	if (!out || !out_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "SM GP encrypt command data error");

	sc_log(ctx, "SM GP encrypt command data(len:%i,%p)", in_len, in);
	if (in==NULL || in_len==0)   {
		*out = NULL;
		*out_len = 0;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	len = in_len + 8;
	len -= (len%8);

	data = calloc(1, len);
	if (!data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	*data = in_len;
	memcpy(data + 1, in, in_len);

	rv = sm_encrypt_des_cbc3(ctx, session_key, data, in_len + 1, out, out_len, 1);
	free(data);
	LOG_TEST_RET(ctx, rv, "SM GP encrypt command data: encryption error");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sm_gp_securize_apdu(struct sc_context *ctx, struct sm_info *sm_info,
		char *init_data, struct sc_apdu *apdu)
{
	unsigned char  buff[SC_MAX_APDU_BUFFER_SIZE + 24];
	unsigned char *apdu_data = NULL;
	struct sm_gp_session *gp_session = &sm_info->session.gp;
	unsigned gp_level = sm_info->session.gp.params.level;
	unsigned gp_index = sm_info->session.gp.params.index;
	DES_cblock mac;
	unsigned char *encrypted = NULL;
	size_t encrypted_len = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);

	apdu_data = (unsigned char *)apdu->data;
	sc_log(ctx, "SM GP securize APDU(cse:%X,cla:%X,ins:%X,data(len:%i,%p),lc:%i,GP level:%X,GP index:%X",
				apdu->cse, apdu->cla, apdu->ins, apdu->datalen, apdu->data,
				apdu->lc, gp_level, gp_index);

	if (gp_level == 0 || (apdu->cla & 0x04))
		return 0;

	if (gp_level == SM_GP_SECURITY_MAC)   {
		if (apdu->datalen + 8 > SC_MAX_APDU_BUFFER_SIZE)
			LOG_TEST_RET(ctx, SC_ERROR_WRONG_LENGTH, "SM GP securize APDU: too much data");
	}
	else if (gp_level == SM_GP_SECURITY_ENC)   {
		if (!gp_session->session_enc)
			LOG_TEST_RET(ctx, SC_ERROR_SM_INVALID_SESSION_KEY, "SM GP securize APDU: no ENC session key found");

		if (sm_gp_encrypt_command_data(ctx, gp_session->session_enc, apdu->data, apdu->datalen, &encrypted, &encrypted_len))
			LOG_TEST_RET(ctx, SC_ERROR_SM_ENCRYPT_FAILED, "SM GP securize APDU: data encryption error");

		if (encrypted_len + 8 > SC_MAX_APDU_BUFFER_SIZE)
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "SM GP securize APDU: not enough place for encrypted data");

		sc_log(ctx, "SM GP securize APDU: encrypted length %i", encrypted_len);
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_SM_INVALID_LEVEL, "SM GP securize APDU: invalid SM level");
	}

	buff[0] = apdu->cla | 0x04;
	buff[1] = apdu->ins;
	buff[2] = apdu->p1;
	buff[3] = apdu->p2;
	buff[4] = apdu->lc + 8;

	memcpy(buff + 5, apdu_data, apdu->datalen);

	rv = sm_gp_get_mac(gp_session->session_mac, &gp_session->mac_icv, buff, 5 + apdu->datalen, &mac);
	LOG_TEST_RET(ctx, rv, "SM GP securize APDU: get MAC error");

	if (gp_level == SM_GP_SECURITY_MAC)   {
		memcpy(apdu_data + apdu->datalen, mac, 8);

		apdu->cla |= 0x04;
		apdu->datalen += 8;
		apdu->lc = apdu->datalen;

		if (apdu->cse==SC_APDU_CASE_2_SHORT)
			apdu->cse = SC_APDU_CASE_4_SHORT;
	}
	else if (gp_level == SM_GP_SECURITY_ENC)   {
		memcpy(apdu_data + encrypted_len, mac, 8);
		if (encrypted_len)
			memcpy(apdu_data, encrypted, encrypted_len);

		apdu->cla |= 0x04;
		apdu->datalen = encrypted_len + 8;
		apdu->lc = encrypted_len + 8;

		if (apdu->cse == SC_APDU_CASE_2_SHORT)
			apdu->cse = SC_APDU_CASE_4_SHORT;

		if (apdu->cse == SC_APDU_CASE_1)
			apdu->cse = SC_APDU_CASE_3_SHORT;

		free(encrypted);
	}

	memcpy(sm_info->session.gp.mac_icv, mac, 8);

	LOG_FUNC_RETURN(ctx, rv);
}


