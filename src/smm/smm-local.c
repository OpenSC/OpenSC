/*
 * smm-local.c: Secure Messaging 'local' module
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

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#include "libopensc/opensc.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "libopensc/iasecc.h"

#include "sm-module.h"

static int
sm_gp_config_get_keyset(struct sc_context *ctx, struct sm_info *sm_info)
{
	scconf_block *sm_conf_block = NULL, **blocks;
	struct sm_gp_keyset *gp_keyset = &sm_info->session.gp.gp_keyset;

	const char *kmc = NULL;
	unsigned char hex[48];
	size_t hex_len = sizeof(hex);
	int rv, ii;

	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM get KMC from config section '%s'", sm_info->config_section);
	for (ii = 0; ctx->conf_blocks[ii]; ii++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm_info->config_section);
		if (blocks) {
			sm_conf_block = blocks[0];
			free(blocks);
		}

		if (sm_conf_block)
			break;
	}

	kmc = scconf_get_str(sm_conf_block, "kmc", NULL);
	if (!kmc)
		return SC_ERROR_SM_KEYSET_NOT_FOUND;

	rv = sc_hex_to_bin(kmc, hex, &hex_len);
	if (rv)   {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get KMC: hex to bin failed for '%s'; error %i", kmc, rv);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM type:%X, KMC(%"SC_FORMAT_LEN_SIZE_T"u) %s",
			sm_info->sm_type, hex_len, sc_dump_hex(hex, hex_len));
	if (hex_len != 16 && hex_len != 48 )
		return SC_ERROR_INVALID_DATA;

	memcpy(gp_keyset->kmc, hex, hex_len);
	gp_keyset->kmc_len = hex_len;

	return SC_SUCCESS;
}


static int
sm_cwa_config_get_keyset(struct sc_context *ctx, struct sm_info *sm_info)
{
	struct sm_cwa_session *cwa_session = &sm_info->session.cwa;
	struct sm_cwa_keyset *cwa_keyset = &sm_info->session.cwa.cwa_keyset;
	scconf_block *sm_conf_block = NULL, **blocks;
	struct sc_crt *crt_at = &sm_info->session.cwa.params.crt_at;
	const char *value = NULL;
	char name[128];
	unsigned char hex[48];
	size_t hex_len = sizeof(hex);
	int rv, ii, ref = crt_at->refs[0] & IASECC_OBJECT_REF_MAX;

	for (ii = 0; ctx->conf_blocks[ii]; ii++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm_info->config_section);
		if (blocks) {
			sm_conf_block = blocks[0];
			free(blocks);
		}

		if (sm_conf_block)
			break;
	}

	sc_debug(ctx, SC_LOG_DEBUG_SM, "CRT(algo:%X,ref:%X)", crt_at->algo, crt_at->refs[0]);
	/* Keyset ENC */
	if (sm_info->current_aid.len && (crt_at->refs[0] & IASECC_OBJECT_REF_LOCAL))
		snprintf(name, sizeof(name), "keyset_%s_%02i_enc",
				sc_dump_hex(sm_info->current_aid.value, sm_info->current_aid.len), ref);
	else
		snprintf(name, sizeof(name), "keyset_%02i_enc", ref);
	value = scconf_get_str(sm_conf_block, name, NULL);
	if (!value)   {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
		return SC_ERROR_SM_KEYSET_NOT_FOUND;
	}

	sc_debug(ctx, SC_LOG_DEBUG_SM, "keyset::enc(%"SC_FORMAT_LEN_SIZE_T"u) %s", strlen(value),
			value);
	if (strlen(value) == 16)   {
		memcpy(cwa_keyset->enc, value, 16);
	}
	else   {
		hex_len = sizeof(hex);
		rv = sc_hex_to_bin(value, hex, &hex_len);
		if (rv)   {
			sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get %s: hex to bin failed for '%s'; error %i", name, value, rv);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}

		sc_debug(ctx, SC_LOG_DEBUG_SM, "ENC(%"SC_FORMAT_LEN_SIZE_T"u) %s", hex_len,
				sc_dump_hex(hex, hex_len));
		if (hex_len != 16)
			return SC_ERROR_INVALID_DATA;

		memcpy(cwa_keyset->enc, hex, hex_len);
	}
	sc_debug(ctx, SC_LOG_DEBUG_SM, "%s %s", name, sc_dump_hex(cwa_keyset->enc, 16));

	/* Keyset MAC */
	if (sm_info->current_aid.len && (crt_at->refs[0] & IASECC_OBJECT_REF_LOCAL))
		snprintf(name, sizeof(name), "keyset_%s_%02i_mac",
				sc_dump_hex(sm_info->current_aid.value, sm_info->current_aid.len), ref);
	else
		snprintf(name, sizeof(name), "keyset_%02i_mac", ref);
	value = scconf_get_str(sm_conf_block, name, NULL);
	if (!value)   {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
		return SC_ERROR_SM_KEYSET_NOT_FOUND;
	}

	sc_debug(ctx, SC_LOG_DEBUG_SM, "keyset::mac(%"SC_FORMAT_LEN_SIZE_T"u) %s", strlen(value),
			value);
	if (strlen(value) == 16)   {
		memcpy(cwa_keyset->mac, value, 16);
	}
	else   {
		hex_len = sizeof(hex);
		rv = sc_hex_to_bin(value, hex, &hex_len);
		if (rv)   {
			sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get '%s': hex to bin failed for '%s'; error %i", name, value, rv);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}

		sc_debug(ctx, SC_LOG_DEBUG_SM, "MAC(%"SC_FORMAT_LEN_SIZE_T"u) %s", hex_len,
				sc_dump_hex(hex, hex_len));
		if (hex_len != 16)
			return SC_ERROR_INVALID_DATA;

		memcpy(cwa_keyset->mac, hex, hex_len);
	}
	sc_debug(ctx, SC_LOG_DEBUG_SM, "%s %s", name, sc_dump_hex(cwa_keyset->mac, 16));

	cwa_keyset->sdo_reference = crt_at->refs[0];


	/* IFD parameters */
	//memset(cwa_session, 0, sizeof(struct sm_cwa_session));
	value = scconf_get_str(sm_conf_block, "ifd_serial", NULL);
	if (!value)
		return SC_ERROR_SM_IFD_DATA_MISSING;
	hex_len = sizeof(hex);
	rv = sc_hex_to_bin(value, hex, &hex_len);
	if (rv)   {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get 'ifd_serial': hex to bin failed for '%s'; error %i", value, rv);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	if (hex_len != sizeof(cwa_session->ifd.sn))   {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
				"SM get 'ifd_serial': invalid IFD serial length: %"SC_FORMAT_LEN_SIZE_T"u",
				hex_len);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	memcpy(cwa_session->ifd.sn, hex, hex_len);

	rv = RAND_bytes(cwa_session->ifd.rnd, 8);
	if (!rv)   {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Generate random error: %i", rv);
		return SC_ERROR_SM_RAND_FAILED;
	}

	rv = RAND_bytes(cwa_session->ifd.k, 32);
	if (!rv)   {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Generate random error: %i", rv);
		return SC_ERROR_SM_RAND_FAILED;
	}
	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.Serial: %s", sc_dump_hex(cwa_session->ifd.sn, sizeof(cwa_session->ifd.sn)));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.Rnd: %s", sc_dump_hex(cwa_session->ifd.rnd, sizeof(cwa_session->ifd.rnd)));
	sc_debug(ctx, SC_LOG_DEBUG_SM, "IFD.K: %s", sc_dump_hex(cwa_session->ifd.k, sizeof(cwa_session->ifd.k)));

	return SC_SUCCESS;
}

/** API of the external SM module */
/**
 * Initialize
 *
 * Read keyset from the OpenSC configuration file,
 * get and return the APDU(s) to initialize SM session.
 */
int
initialize(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *out)
{
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_debug(ctx, SC_LOG_DEBUG_SM, "Current AID: %s", sc_dump_hex(sm_info->current_aid.value, sm_info->current_aid.len));
	switch (sm_info->sm_type)   {
		case SM_TYPE_GP_SCP01:
			rv = sm_gp_config_get_keyset(ctx, sm_info);
			LOG_TEST_RET(ctx, rv, "SM gp configuration error");

			rv = sm_gp_initialize(ctx, sm_info, out);
			LOG_TEST_RET(ctx, rv, "SM gp initializing error");
			break;
		case SM_TYPE_CWA14890:
			rv = sm_cwa_config_get_keyset(ctx, sm_info);
			LOG_TEST_RET(ctx, rv, "SM iasecc configuration error");

			rv = sm_cwa_initialize(ctx, sm_info, out);
			LOG_TEST_RET(ctx, rv, "SM iasecc initializing error");
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported SM type");
	};

	LOG_FUNC_RETURN(ctx, rv);
}


/**
 * Get APDU(s)
 *
 * Get securized APDU(s) corresponding
 * to the asked command.
 */
int
get_apdus(struct sc_context *ctx, struct sm_info *sm_info, unsigned char *init_data, size_t init_len,
		struct sc_remote_data *out)
{
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	if (!sm_info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM get APDUs: out:%p", out);
	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM get APDUs: serial %s", sc_dump_hex(sm_info->serialnr.value, sm_info->serialnr.len));

	if (sm_info->card_type == SC_CARD_TYPE_OBERTHUR_AUTHENTIC_3_2)   {
		rv = sm_authentic_get_apdus(ctx, sm_info, init_data, init_len, out, 1);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: failed for AuthentIC");
	}
	else if (sm_info->card_type/10*10 == SC_CARD_TYPE_IASECC_BASE)   {
		rv = sm_iasecc_get_apdus(ctx, sm_info, init_data, init_len, out, 1);
		LOG_TEST_RET(ctx, rv, "SM get APDUs: failed for IAS/ECC");
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "SM get APDUs: unsupported card type");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


/**
 * Finalize
 *
 * Decode card answer(s)
 */
int
finalize(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata, unsigned char *out, size_t out_len)
{
	int rv = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_SM, "SM finalize: out buffer(%"SC_FORMAT_LEN_SIZE_T"u) %p",
			out_len, out);
	if (!sm_info || !rdata)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (sm_info->sm_type == SM_TYPE_GP_SCP01)
		rv = sm_gp_decode_card_answer(ctx, rdata, out, out_len);
	else if (sm_info->card_type/10*10 == SC_CARD_TYPE_IASECC_BASE)
		rv = sm_iasecc_decode_card_data(ctx, sm_info, rdata, out, out_len);
	else
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "SM finalize: cannot decode card response(s)");

	LOG_FUNC_RETURN(ctx, rv);
}

/**
 * Module Init
 *
 * Module specific initialization
 */
int
module_init(struct sc_context *ctx, char *data)
{

	return SC_SUCCESS;

}

/**
 * Module CleanUp
 *
 * Module specific cleanup
 */
int
module_cleanup(struct sc_context *ctx)
{
	return SC_SUCCESS;
}


int
test(struct sc_context *ctx, struct sm_info *info, char *out, size_t *out_len)
{
	return SC_SUCCESS;
}


