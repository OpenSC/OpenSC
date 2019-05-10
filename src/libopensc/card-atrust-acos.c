/*
 * atrust-acos.c: Support for A-Trust ACOS based cards
 *
 * Copyright (C) 2005  Franz Brandl <brandl@a-trust.at> based on work from
 *                     Jörn Zukowski <zukowski@trustcenter.de> and 
 *                     Nils Larsch   <larsch@trustcenter.de>, TrustCenter AG
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

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

/*****************************************************************************/

#define ACOS_EMV_A03		"A-TRUST ACOS"
#define ACOS_EMV_A05		"A-TRUST ACOS A05"

static const char *atrust_acos_atrs[] = {
  "3B:BF:11:00:81:31:fe:45:45:50:41",
  "3B:BF:11:00:81:31:fe:45:4d:43:41",
  "3B:BF:13:00:81:31:fe:45:45:50:41",
  "3B:BF:13:00:81:31:fe:45:4d:43:41",
  NULL
};

/* sequence and number has to match atr table ! */
static const char *atrust_acos_names[] = {
  ACOS_EMV_A03,
  ACOS_EMV_A03,
  ACOS_EMV_A05,
  ACOS_EMV_A05,
  NULL
};

static struct sc_card_operations atrust_acos_ops;
static struct sc_card_operations *iso_ops = NULL;

static struct sc_card_driver atrust_acos_drv = {
	"A-Trust ACOS cards",
	"atrust-acos",
	&atrust_acos_ops,
	NULL, 0, NULL
};

/* internal structure to save the current security environment */
typedef struct atrust_acos_ex_data_st {
	int    sec_ops;	/* the currently selected security operation,
			 * i.e. SC_SEC_OPERATION_AUTHENTICATE etc. */
	unsigned int    fix_digestInfo;
} atrust_acos_ex_data;

/*****************************************************************************/

static int atrust_acos_match_card(struct sc_card *card)
{
	int		i, match = 0;
  

	for (i = 0; atrust_acos_atrs[i] != NULL; i++) 
	{
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = atrust_acos_atrs[i];
      
		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		/* we may only verify part of ATR since */
		/* part of the hist chars is variable */
		if (len > card->atr.len)
			continue;
		if (memcmp(card->atr.value, defatr, len) != 0)
			continue;

		match = 1;
		card->name = atrust_acos_names[i];

		break;
    }
	return match;
}

/*****************************************************************************/

static int atrust_acos_init(struct sc_card *card)
{
	unsigned int flags;
	atrust_acos_ex_data *ex_data;

	ex_data = calloc(1, sizeof(atrust_acos_ex_data));
	if (ex_data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	card->cla  = 0x00;
	card->drv_data = (void *)ex_data;

	/* set the supported algorithm */

	flags = SC_ALGORITHM_RSA_PAD_PKCS1 
		| SC_ALGORITHM_RSA_HASH_NONE
		| SC_ALGORITHM_RSA_HASH_SHA1
		| SC_ALGORITHM_RSA_HASH_MD5
		| SC_ALGORITHM_RSA_HASH_RIPEMD160
		| SC_ALGORITHM_RSA_HASH_MD5_SHA1;

	if (!strcmp(card->name, ACOS_EMV_A05))
		flags |= SC_ALGORITHM_RSA_HASH_SHA256;

	_sc_card_add_rsa_alg(card, 1536, flags, 0x10001);

	/* we need read_binary&friends with max 128 bytes per read */
	card->max_send_size = 128;
	card->max_recv_size = 128;

	return 0;
}

/*****************************************************************************/

static int atrust_acos_finish(struct sc_card *card)
{
	if (card->drv_data)
		free((atrust_acos_ex_data *)card->drv_data);
	return 0;
}

/*****************************************************************************/

static int process_fci(struct sc_context *ctx, struct sc_file *file,
		       const u8 *buf, size_t buflen)
{

	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p;
  
	sc_log(ctx,  "processing FCI bytes\n");

	if (buflen < 2)
		return SC_ERROR_INTERNAL;
	if (buf[0] != 0x6f)					/* FCI template */
		return SC_ERROR_INVALID_DATA;
	len = (size_t)buf[1];
	if (buflen - 2 < len)
		return SC_ERROR_INVALID_DATA;
	p = buf + 2;

	/* defaults */
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_UNKNOWN;
	file->shareable = 0;
	file->record_length = 0;
	file->size = 0;
  
	/* get file size */
	tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		sc_log(ctx,  "  bytes in file: %d\n", bytes);
		file->size = bytes;
	}

	/* get file type */
  	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		const char *type = "unknown";
		const char *structure = "unknown";

		if (taglen == 1 && tag[0] == 0x01) {
			/* transparent EF */
			type = "working EF";
			structure = "transparent";
			file->type = SC_FILE_TYPE_WORKING_EF;
			file->ef_structure = SC_FILE_EF_TRANSPARENT;
		} else if (taglen == 1 && tag[0] == 0x11) {
			/* object EF */
			type = "working EF";
			structure = "object";
			file->type = SC_FILE_TYPE_WORKING_EF;
			file->ef_structure = SC_FILE_EF_TRANSPARENT; /* TODO */
		} else if (taglen == 3 && tag[1] == 0x21) {
			type = "working EF";
			file->record_length = tag[2];
			file->type = SC_FILE_TYPE_WORKING_EF;
			/* linear fixed, cyclic or compute */
			switch ( tag[0] )
			{
				case 0x02:
					structure = "linear fixed";
					file->ef_structure = SC_FILE_EF_LINEAR_FIXED;
					break;
				case 0x07:
					structure = "cyclic";
					file->ef_structure = SC_FILE_EF_CYCLIC;
					break;
				case 0x17:
					structure = "compute";
					file->ef_structure = SC_FILE_EF_UNKNOWN;
					break;
				default:
					structure = "unknown";
					file->ef_structure = SC_FILE_EF_UNKNOWN;
					file->record_length = 0;
					break;
			}
		}

	 	sc_log(ctx,  "  type: %s\n", type);
		sc_log(ctx,  "  EF structure: %s\n", structure);
	}
	file->magic = SC_FILE_MAGIC;

	return SC_SUCCESS;
}

/*****************************************************************************/

static int atrust_acos_select_aid(struct sc_card *card,
			      u8 aid[16], size_t len,
			      struct sc_file **file_out)
{
	sc_apdu_t apdu;
	int r;
	size_t i = 0;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x04, 0x0C);
	apdu.lc = len;
	apdu.data = (u8*)aid;
	apdu.datalen = len;
	apdu.resplen = 0;
	apdu.le = 0;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	/* check return value */
	if (!(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) && apdu.sw1 != 0x61 )
    		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
  
	/* update cache */
	card->cache.current_path.type = SC_PATH_TYPE_DF_NAME;
	card->cache.current_path.len = len;
	memcpy(card->cache.current_path.value, aid, len);

	if (file_out) {
		sc_file_t *file = sc_file_new();
		if (!file)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		file->type = SC_FILE_TYPE_DF;
		file->ef_structure = SC_FILE_EF_UNKNOWN;
		file->path.len = 0;
		file->size = 0;
		/* AID */
		for (i = 0; i < len; i++)  
			file->name[i] = aid[i];
		file->namelen = len;
		file->id = 0x0000;
		file->magic = SC_FILE_MAGIC;
		*file_out = file;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

/*****************************************************************************/

static int atrust_acos_select_fid(struct sc_card *card,
			      unsigned int id_hi, unsigned int id_lo,
			      struct sc_file **file_out)
{
	sc_apdu_t apdu;
	u8 data[] = {id_hi & 0xff, id_lo & 0xff};
	u8 resp[SC_MAX_APDU_BUFFER_SIZE];
	int bIsDF = 0, r;

	/* request FCI to distinguish between EFs and DFs */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);
	apdu.resp = (u8*)resp;
	apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
	apdu.le = 256;
	apdu.lc = 2;
	apdu.data = (u8*)data;
	apdu.datalen = 2;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.p2 == 0x00 && apdu.sw1 == 0x62 && apdu.sw2 == 0x84 ) {
		/* no FCI => we have a DF (see comment in process_fci()) */
		bIsDF = 1;
		apdu.p2 = 0x0C;
		apdu.cse = SC_APDU_CASE_3_SHORT;
		apdu.resplen = 0;
		apdu.le = 0;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU re-transmit failed");
    	} else if (apdu.sw1 == 0x61 || (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)) {
		/* SELECT returned some data (possible FCI) =>
		 * try a READ BINARY to see if a EF is selected */
		sc_apdu_t apdu2;
		u8 resp2[2];
		sc_format_apdu(card, &apdu2, SC_APDU_CASE_2_SHORT, 0xB0, 0, 0);
		apdu2.resp = (u8*)resp2;
		apdu2.resplen = 2;
		apdu2.le = 1;
		apdu2.lc = 0;
		r = sc_transmit_apdu(card, &apdu2);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu2.sw1 == 0x69 && apdu2.sw2 == 0x86)
			/* no current EF is selected => we have a DF */
			bIsDF = 1;
	}

	if (apdu.sw1 != 0x61 && (apdu.sw1 != 0x90 || apdu.sw2 != 0x00))
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));

	/* update cache */
	if (bIsDF) {
		card->cache.current_path.type = SC_PATH_TYPE_PATH;
		card->cache.current_path.value[0] = 0x3f;
		card->cache.current_path.value[1] = 0x00;
		if (id_hi == 0x3f && id_lo == 0x00)
			card->cache.current_path.len = 2;
		else {
			card->cache.current_path.len = 4;
			card->cache.current_path.value[2] = id_hi;
			card->cache.current_path.value[3] = id_lo;
		}
	}

	if (file_out) {
		sc_file_t *file = sc_file_new();
		if (!file)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		file->id   = (id_hi << 8) + id_lo;
		file->path = card->cache.current_path;

		if (bIsDF) {
			/* we have a DF */
			file->type = SC_FILE_TYPE_DF;
			file->ef_structure = SC_FILE_EF_UNKNOWN;
			file->size = 0;
			file->namelen = 0;
			file->magic = SC_FILE_MAGIC;
			*file_out = file;
		} else {
			/* ok, assume we have a EF */
			r = process_fci(card->ctx, file, apdu.resp, 
					apdu.resplen);
			if (r != SC_SUCCESS) {
				sc_file_free(file);
				return r;
			}

			*file_out = file;
		}
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

/*****************************************************************************/

static int atrust_acos_select_file(struct sc_card *card,
			       const struct sc_path *in_path,
			       struct sc_file **file_out)
{
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int    r;
	size_t i, pathlen;
	char pbuf[SC_MAX_PATH_STRING_SIZE];


	r = sc_path_print(pbuf, sizeof(pbuf), &card->cache.current_path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_log(card->ctx, 
		 "current path (%s, %s): %s (len: %"SC_FORMAT_LEN_SIZE_T"u)\n",
		 card->cache.current_path.type == SC_PATH_TYPE_DF_NAME ?
		 "aid" : "path",
		 card->cache.valid ? "valid" : "invalid", pbuf,
		 card->cache.current_path.len);

	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	if (in_path->type == SC_PATH_TYPE_FILE_ID)
	{	/* SELECT EF/DF with ID */
		/* Select with 2byte File-ID */
		if (pathlen != 2)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
		return atrust_acos_select_fid(card, path[0], path[1], file_out);
	}
	else if (in_path->type == SC_PATH_TYPE_DF_NAME)
      	{	/* SELECT DF with AID */
		/* Select with 1-16byte Application-ID */
		if (card->cache.valid 
		    && card->cache.current_path.type == SC_PATH_TYPE_DF_NAME
		    && card->cache.current_path.len == pathlen
		    && memcmp(card->cache.current_path.value, pathbuf, pathlen) == 0 )
		{
			sc_log(card->ctx,  "cache hit\n");
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
		}
		else
			return atrust_acos_select_aid(card, pathbuf, pathlen, file_out);
	}
	else if (in_path->type == SC_PATH_TYPE_PATH)
	{
		u8 n_pathbuf[SC_MAX_PATH_SIZE];
		int bMatch = -1;

		/* Select with path (sequence of File-IDs) */
		/* ACOS only supports one
		 * level of subdirectories, therefore a path is
		 * at most 3 FID long (the last one being the FID
		 * of a EF) => pathlen must be even and less than 6
		 */
		if (pathlen%2 != 0 || pathlen > 6 || pathlen <= 0)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
		/* if pathlen == 6 then the first FID must be MF (== 3F00) */
		if (pathlen == 6 && ( path[0] != 0x3f || path[1] != 0x00 ))
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

		/* unify path (the first FID should be MF) */
		if (path[0] != 0x3f || path[1] != 0x00)
		{
			n_pathbuf[0] = 0x3f;
			n_pathbuf[1] = 0x00;
			memcpy(n_pathbuf+2, path, pathlen);
			path = n_pathbuf;
			pathlen += 2; 
		}
	
		/* check current working directory */
		if (card->cache.valid 
		    && card->cache.current_path.type == SC_PATH_TYPE_PATH
		    && card->cache.current_path.len >= 2
		    && card->cache.current_path.len <= pathlen )
		{
			bMatch = 0;
			for (i=0; i < card->cache.current_path.len; i+=2)
				if (card->cache.current_path.value[i] == path[i] 
				    && card->cache.current_path.value[i+1] == path[i+1] )
					bMatch += 2;
		}

		if ( card->cache.valid && bMatch >= 0 )
		{
			if ( pathlen - bMatch == 2 )
				/* we are in the right directory */
				return atrust_acos_select_fid(card, path[bMatch], path[bMatch+1], file_out);
			else if ( pathlen - bMatch > 2 )
			{
				/* two more steps to go */
				sc_path_t new_path;
	
				/* first step: change directory */
				r = atrust_acos_select_fid(card, path[bMatch], path[bMatch+1], NULL);
				LOG_TEST_RET(card->ctx, r, "SELECT FILE (DF-ID) failed");
	
				memset(&new_path, 0, sizeof(sc_path_t));	
				new_path.type = SC_PATH_TYPE_PATH;
				new_path.len  = pathlen - bMatch-2;
				memcpy(new_path.value, &(path[bMatch+2]), new_path.len);
				/* final step: select file */
				return atrust_acos_select_file(card, &new_path, file_out);
      			}
			else /* if (bMatch - pathlen == 0) */
			{
				/* done: we are already in the
				 * requested directory */
				sc_log(card->ctx,  "cache hit\n");
				/* copy file info (if necessary) */
				if (file_out) {
					sc_file_t *file = sc_file_new();
					if (!file)
						LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
					file->id = (path[pathlen-2] << 8) +
						   path[pathlen-1];
					file->path = card->cache.current_path;
					file->type = SC_FILE_TYPE_DF;
					file->ef_structure = SC_FILE_EF_UNKNOWN;
					file->size = 0;
					file->namelen = 0;
					file->magic = SC_FILE_MAGIC;
					*file_out = file;
				}
				/* nothing left to do */
				return SC_SUCCESS;
			}
		}
		else
		{
			/* no usable cache */
			for ( i=0; i<pathlen-2; i+=2 )
			{
				r = atrust_acos_select_fid(card, path[i], path[i+1], NULL);
				LOG_TEST_RET(card->ctx, r, "SELECT FILE (DF-ID) failed");
			}
			return atrust_acos_select_fid(card, path[pathlen-2], path[pathlen-1], file_out);
		}
	}
	else
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
}

/** atrust_acos_set_security_env
 * sets the security environment
 * \param card pointer to the sc_card object
 * \param env pointer to a sc_security_env object
 * \param se_num not used here
 * \return SC_SUCCESS on success or an error code
 *
 * This function sets the security environment (using the
 * command MANAGE SECURITY ENVIRONMENT). In case a COMPUTE SIGNATURE
 * operation is requested , this function tries to detect whether
 * COMPUTE SIGNATURE or INTERNAL AUTHENTICATE must be used for signature
 * calculation.
 */
static int atrust_acos_set_security_env(struct sc_card *card,
				    const struct sc_security_env *env,
				    int se_num)
{
	u8              *p, *pp;
	int              r, operation = env->operation;
	struct sc_apdu   apdu;
	u8               sbuf[SC_MAX_APDU_BUFFER_SIZE];
	atrust_acos_ex_data *ex_data = (atrust_acos_ex_data *)card->drv_data;

	p     = sbuf;

	/* copy key reference, if present */
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		*p++ = env->key_ref_len;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	pp = p;
	if (operation == SC_SEC_OPERATION_DECIPHER){
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
			*p++ = 0x80;
			*p++ = 0x01;
			*p++ = 0x02;
		} else
			return SC_ERROR_INVALID_ARGUMENTS;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x81,
		               0xb8);
		apdu.data    = sbuf;
		apdu.datalen = p - sbuf;
		apdu.lc      = p - sbuf;
		apdu.le      = 0;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
		return SC_SUCCESS;
	}
	/* try COMPUTE SIGNATURE */
	if (operation == SC_SEC_OPERATION_SIGN && (
	    env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1 ||
	    env->algorithm_flags & SC_ALGORITHM_RSA_PAD_ISO9796)) {
		if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
			*p++ = 0x80;
			*p++ = 0x01;
			*p++ = env->algorithm_ref & 0xFF;
		} else if (env->flags & SC_SEC_ENV_ALG_PRESENT &&
		            env->algorithm == SC_ALGORITHM_RSA) {
			/* set the method to use based on the algorithm_flags */
			*p++ = 0x80;
			*p++ = 0x01;
			if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
				if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
					*p++ = 0x12;
				else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_RIPEMD160)
					*p++ = 0x22;
				else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5)
					*p++ = 0x32;
				else {
					/* can't use COMPUTE SIGNATURE =>
					 * try INTERNAL AUTHENTICATE */
					p = pp;
					operation = SC_SEC_OPERATION_AUTHENTICATE;
					goto try_authenticate;
				}
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_ISO9796) {
				if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
					*p++ = 0x11;
				else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_RIPEMD160)
					*p++ = 0x21;
				else
					return SC_ERROR_INVALID_ARGUMENTS;
			} else
				return SC_ERROR_INVALID_ARGUMENTS;
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xb6);
		apdu.data    = sbuf;
		apdu.datalen = p - sbuf;
		apdu.lc      = p - sbuf;
		apdu.le      = 0;
		/* we don't know whether to use 
		 * COMPUTE SIGNATURE or INTERNAL AUTHENTICATE */
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
			ex_data->fix_digestInfo = 0;
			ex_data->sec_ops        = SC_SEC_OPERATION_SIGN;
			return SC_SUCCESS;
		}
		/* reset pointer */
		p = pp;
		/* doesn't work => try next op */
		operation = SC_SEC_OPERATION_AUTHENTICATE;
	}
try_authenticate:
	/* try INTERNAL AUTHENTICATE */
	if (operation == SC_SEC_OPERATION_AUTHENTICATE && 
	    env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		*p++ = 0x80;
		*p++ = 0x01;
		*p++ = 0x01;
		
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xa4);
		apdu.data    = sbuf;
		apdu.datalen = p - sbuf;
		apdu.lc      = p - sbuf;
		apdu.le      = 0;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
		ex_data->fix_digestInfo = env->algorithm_flags;
		ex_data->sec_ops        = SC_SEC_OPERATION_AUTHENTICATE;
		return SC_SUCCESS;
	}

	return SC_ERROR_INVALID_ARGUMENTS;
}

/*****************************************************************************/

static int atrust_acos_compute_signature(struct sc_card *card,
				     const u8 * data, size_t datalen,
				     u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	atrust_acos_ex_data *ex_data = (atrust_acos_ex_data *)card->drv_data;

	if (datalen > SC_MAX_APDU_BUFFER_SIZE)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	if (ex_data->sec_ops == SC_SEC_OPERATION_SIGN) {
		/* compute signature with the COMPUTE SIGNATURE command */
		
		/* set the hash value     */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A,
			       0x90, 0x81);
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 0;
		memcpy(sbuf, data, datalen);
		apdu.data = sbuf;
		apdu.lc = datalen;
		apdu.datalen = datalen;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 
				       sc_check_sw(card, apdu.sw1, apdu.sw2));

		/* call COMPUTE SIGNATURE */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x2A,
			       0x9E, 0x9A);
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;

		apdu.lc = 0;
		apdu.datalen = 0;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
			size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;
			memcpy(out, apdu.resp, len);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
		}
	} else if (ex_data->sec_ops == SC_SEC_OPERATION_AUTHENTICATE) {
		size_t tmp_len;
		/* call INTERNAL AUTHENTICATE */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x10, 0x00);
		/* fix/create DigestInfo structure (if necessary) */
		if (ex_data->fix_digestInfo) {
			unsigned int flags = ex_data->fix_digestInfo & SC_ALGORITHM_RSA_HASHES;
			if (flags == 0x0)
				/* XXX: assume no hash is wanted */
				flags = SC_ALGORITHM_RSA_HASH_NONE;
			tmp_len = sizeof(sbuf);
			r = sc_pkcs1_encode(card->ctx, flags, data, datalen,
					sbuf, &tmp_len, sizeof(sbuf)*8);
			if (r < 0)
				return r;
		} else {
			memcpy(sbuf, data, datalen);
			tmp_len = datalen;
		}
		apdu.lc = tmp_len;
		apdu.data = sbuf;
		apdu.datalen = tmp_len;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
		{
			size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

			memcpy(out, apdu.resp, len);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
		}
	} else
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	/* clear old state */
	ex_data->sec_ops = 0;
	ex_data->fix_digestInfo = 0;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/*****************************************************************************/

static int atrust_acos_decipher(struct sc_card *card,
			    const u8 * crgram, size_t crgram_len,
			    u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	assert(card != NULL && crgram != NULL && out != NULL);
	LOG_FUNC_CALLED(card->ctx);
	if (crgram_len > 255)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	
	sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;
	apdu.le = 256;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/*****************************************************************************/

static int atrust_acos_check_sw(struct sc_card *card, unsigned int sw1,
	unsigned int sw2)
{

	sc_log(card->ctx,  "sw1 = 0x%02x, sw2 = 0x%02x\n", sw1, sw2);
  
	if (sw1 == 0x90)
		return SC_SUCCESS;
	if (sw1 == 0x63 && (sw2 & ~0x0fU) == 0xc0 )
	{
		sc_log(card->ctx,  "Verification failed (remaining tries: %d)\n",
		(sw2 & 0x0f));
		return SC_ERROR_PIN_CODE_INCORRECT;
	}
  
	/* iso error */
	return iso_ops->check_sw(card, sw1, sw2);
}

/*****************************************************************************/

static int acos_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;
	u8  rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	if (!serial)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* see if we have cached serial number */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		return SC_SUCCESS;
	}
	/* get serial number via GET CARD DATA */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xf6, 0x00, 0x00);
	apdu.cla |= 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le   = 256;
	apdu.lc   = 0;
	apdu.datalen = 0;
        r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	/* cache serial number */
	memcpy(card->serialnr.value, apdu.resp, MIN(apdu.resplen, SC_MAX_SERIALNR));
	card->serialnr.len = MIN(apdu.resplen, SC_MAX_SERIALNR);
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	return SC_SUCCESS;
}

/*****************************************************************************/

static int atrust_acos_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{

	switch (cmd)
	{
	case SC_CARDCTL_GET_SERIALNR:
		return acos_get_serialnr(card, (sc_serial_number_t *)ptr);
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}

/*****************************************************************************/

static int atrust_acos_logout(struct sc_card *card)
{
	int r;
	struct sc_apdu apdu;
	const u8 mf_buf[2] = {0x3f, 0x00};

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
	apdu.le = 0;
	apdu.lc = 2;
	apdu.data    = mf_buf;
	apdu.datalen = 2;
	apdu.resplen = 0;
	
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU re-transmit failed");

	if (apdu.sw1 == 0x69 && apdu.sw2 == 0x85)
		/* the only possible reason for this error here is, afaik,
		 * that no MF exists, but then there's no need to logout
		 * => return SC_SUCCESS
		 */
		return SC_SUCCESS;
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

/*****************************************************************************/

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
  
	atrust_acos_ops = *iso_drv->ops;
	atrust_acos_ops.match_card = atrust_acos_match_card;
	atrust_acos_ops.init   = atrust_acos_init;
	atrust_acos_ops.finish = atrust_acos_finish;
	atrust_acos_ops.select_file = atrust_acos_select_file;
	atrust_acos_ops.check_sw    = atrust_acos_check_sw;
	atrust_acos_ops.create_file = NULL;
	atrust_acos_ops.delete_file = NULL;
	atrust_acos_ops.set_security_env  = atrust_acos_set_security_env;
	atrust_acos_ops.compute_signature = atrust_acos_compute_signature;
	atrust_acos_ops.decipher    = atrust_acos_decipher;
	atrust_acos_ops.card_ctl    = atrust_acos_card_ctl;
	atrust_acos_ops.logout      = atrust_acos_logout;
  
	return &atrust_acos_drv;
}

/*****************************************************************************/

struct sc_card_driver * sc_get_atrust_acos_driver(void)
{
	return sc_get_driver();
}
