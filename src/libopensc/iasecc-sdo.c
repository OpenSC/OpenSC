/*
 * iasecc-sdo.c: library to manipulate the Security Data Objects (SDO)
 *		used by IAS/ECC card support.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

#include "iasecc.h"
#include "iasecc-sdo.h"

static int iasecc_parse_size(unsigned char *data, size_t *out);


static int
iasecc_parse_acls(struct sc_card *card, struct iasecc_sdo_docp *docp, int flags)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_extended_tlv *acls = &docp->acls_contact;
	int ii, offs;
	unsigned char mask = 0x40;

	if (flags)
		acls = &docp->acls_contactless;

	if (!acls->size)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	docp->amb = *(acls->value + 0);
	memset(docp->scbs, 0xFF, sizeof(docp->scbs));
	for (ii=0, offs = 1; ii<7; ii++, mask >>= 1)
		if (mask & docp->amb)
			docp->scbs[ii] = *(acls->value + offs++);

	sc_log(ctx, "iasecc_parse_docp() SCBs %02X:%02X:%02X:%02X:%02X:%02X:%02X",
			docp->scbs[0],docp->scbs[1],docp->scbs[2],docp->scbs[3],
			docp->scbs[4],docp->scbs[5],docp->scbs[6]);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
iasecc_sdo_convert_acl(struct sc_card *card, struct iasecc_sdo *sdo,
		unsigned char op, unsigned *out_method, unsigned *out_ref)
{
	struct sc_context *ctx = card->ctx;
	struct acl_op {
		unsigned char op;
		unsigned char mask;
	} ops[] = {
		{SC_AC_OP_PSO_COMPUTE_SIGNATURE,IASECC_ACL_PSO_SIGNATURE},
		{SC_AC_OP_INTERNAL_AUTHENTICATE,IASECC_ACL_INTERNAL_AUTHENTICATE},
		{SC_AC_OP_PSO_DECRYPT,	IASECC_ACL_PSO_DECIPHER},
		{SC_AC_OP_GENERATE,	IASECC_ACL_GENERATE_KEY},
		{SC_AC_OP_UPDATE,	IASECC_ACL_PUT_DATA},
		{SC_AC_OP_READ,		IASECC_ACL_GET_DATA},
		{0x00, 0x00}
	};
	unsigned char mask = 0x80, op_mask = 0;
	int ii;

	LOG_FUNC_CALLED(ctx);

	for (ii=0; ops[ii].mask; ii++)   {
		if (op == ops[ii].op)   {
			op_mask = ops[ii].mask;
			break;
		}
	}
	if (op_mask == 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	sc_log(ctx, "OP:%i, mask:0x%X", op, op_mask);
	sc_log(ctx, "AMB:%X, scbs:%s", sdo->docp.amb, sc_dump_hex(sdo->docp.scbs, IASECC_MAX_SCBS));
	sc_log(ctx, "docp.acls_contact:%s", sc_dump_hex(sdo->docp.acls_contact.value, sdo->docp.acls_contact.size));

	if (!sdo->docp.amb && sdo->docp.acls_contact.size)   {
		int rv = iasecc_parse_acls(card, &sdo->docp, 0);
		LOG_TEST_RET(ctx, rv, "Cannot parse ACLs in DOCP");
	}

	*out_method = SC_AC_NEVER;
	*out_ref = SC_AC_NEVER;

	for (ii=0; ii<7; ii++)   {
		mask >>= 1;
		if (sdo->docp.amb & mask)   {
			if (op_mask == mask)   {
				unsigned char scb = sdo->docp.scbs[ii];
				sc_log(ctx, "ii:%i, scb:0x%X", ii, scb);

				*out_ref = scb & 0x0F;
				if (scb == 0)
					*out_method = SC_AC_NONE;
				else if (scb == 0xFF)
					*out_method = SC_AC_NEVER;
				else if ((scb & IASECC_SCB_METHOD_MASK) == IASECC_SCB_METHOD_USER_AUTH)
					*out_method = SC_AC_SEN;
				else if ((scb & IASECC_SCB_METHOD_MASK) == IASECC_SCB_METHOD_EXT_AUTH)
					*out_method = SC_AC_AUT;
				else if ((scb & IASECC_SCB_METHOD_MASK) == IASECC_SCB_METHOD_SM)
					*out_method = SC_AC_PRO;
				else
					*out_method = SC_AC_SCB, *out_ref = scb;

				break;
			}
		}
	}

	sc_log(ctx, "returns method %X; ref %X", *out_method, *out_ref);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


void
iasecc_sdo_free_fields(struct sc_card *card, struct iasecc_sdo *sdo)
{
	if (sdo->docp.tries_remaining.value)
		free(sdo->docp.tries_remaining.value);
	if (sdo->docp.usage_remaining.value)
		free(sdo->docp.usage_remaining.value);
	if (sdo->docp.non_repudiation.value)
		free(sdo->docp.non_repudiation.value);
	if (sdo->docp.acls_contact.value)
		free(sdo->docp.acls_contact.value);
	if (sdo->docp.size.value)
		free(sdo->docp.size.value);
	if (sdo->docp.name.value)
		free(sdo->docp.name.value);
	if (sdo->docp.issuer_data.value)
		free(sdo->docp.issuer_data.value);

	if (sdo->sdo_class == IASECC_SDO_CLASS_RSA_PUBLIC)   {
		if (sdo->data.pub_key.n.value)
			free(sdo->data.pub_key.n.value);
		if (sdo->data.pub_key.e.value)
			free(sdo->data.pub_key.e.value);
		if (sdo->data.pub_key.compulsory.value)
			free(sdo->data.pub_key.compulsory.value);
		if (sdo->data.pub_key.chr.value)
			free(sdo->data.pub_key.chr.value);
		if (sdo->data.pub_key.cha.value)
			free(sdo->data.pub_key.cha.value);
	}
	else if (sdo->sdo_class == IASECC_SDO_CLASS_RSA_PRIVATE)   {
		if (sdo->data.prv_key.p.value)
			free(sdo->data.prv_key.p.value);
		if (sdo->data.prv_key.q.value)
			free(sdo->data.prv_key.q.value);
		if (sdo->data.prv_key.iqmp.value)
			free(sdo->data.prv_key.iqmp.value);
		if (sdo->data.prv_key.dmp1.value)
			free(sdo->data.prv_key.dmp1.value);
		if (sdo->data.prv_key.dmq1.value)
			free(sdo->data.prv_key.dmq1.value);
		if (sdo->data.prv_key.compulsory.value)
			free(sdo->data.prv_key.compulsory.value);
	}
	else if (sdo->sdo_class == IASECC_SDO_CLASS_CHV)   {
		if (sdo->data.chv.size_max.value)
			free(sdo->data.chv.size_max.value);
		if (sdo->data.chv.size_min.value)
			free(sdo->data.chv.size_min.value);
		if (sdo->data.chv.value.value)
			free(sdo->data.chv.value.value);
	}
}


void
iasecc_sdo_free(struct sc_card *card, struct iasecc_sdo *sdo)
{
	iasecc_sdo_free_fields(card, sdo);
	free(sdo);
}


static int
iasecc_crt_parse(struct sc_card *card, unsigned char *data, struct iasecc_se_info *se)
{
	struct sc_context *ctx = card->ctx;
	struct sc_crt crt;
	int ii, offs, len, parsed_len = -1;

	sc_log(ctx, "iasecc_crt_parse(0x%X) called", *data);

	memset(&crt, 0, sizeof(crt));
	crt.tag = *(data + 0);
	len = *(data + 1);

	for(offs = 2; offs < len + 2; offs += 3)   {
		sc_log(ctx, "iasecc_crt_parse(0x%X) CRT %X -> %X", *data, *(data + offs), *(data + offs + 2));
		if (*(data + offs) == IASECC_CRT_TAG_USAGE)   {
			crt.usage = *(data + offs + 2);
		}
		else if (*(data + offs) == IASECC_CRT_TAG_REFERENCE)   {
			int nn_refs = sizeof(crt.refs) / sizeof(crt.refs[0]);

			for (ii=0; ii<nn_refs && crt.refs[ii]; ii++)
				;
			if (ii == nn_refs)
				LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

			crt.refs[ii] = *(data + offs + 2);
		}
		else if (*(data + offs) == IASECC_CRT_TAG_ALGO)   {
			crt.algo = *(data + offs + 2);
		}
		else   {
			LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}
	}

	for (ii=0; ii<SC_MAX_CRTS_IN_SE; ii++)
		if (!se->crts[ii].tag)
			break;

	if (ii==SC_MAX_CRTS_IN_SE)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "iasecc_crt_parse() error: too much CRTs in SE");

	memcpy(&se->crts[ii], &crt, sizeof(crt));
	parsed_len = len + 2;
	LOG_FUNC_RETURN(ctx, parsed_len);
}


int
iasecc_se_get_crt(struct sc_card *card, struct iasecc_se_info *se, struct sc_crt *crt)
{
	struct sc_context *ctx = card->ctx;
	int ii;

	LOG_FUNC_CALLED(ctx);
	if (!se || !crt)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "CRT search template: %X:%X:%X, refs %X:%X:...",
			crt->tag, crt->algo, crt->usage, crt->refs[0], crt->refs[1]);

	for (ii=0; ii<SC_MAX_CRTS_IN_SE && se->crts[ii].tag; ii++)   {
		if (crt->tag != se->crts[ii].tag)
			continue;
		if (crt->algo && crt->algo != se->crts[ii].algo)
			continue;
		if (crt->usage && crt->usage != se->crts[ii].usage)
			continue;
		if (crt->refs[0] && crt->refs[0] != se->crts[ii].refs[0])
			continue;

		memcpy(crt, &se->crts[ii], sizeof(*crt));

		sc_log(ctx, "iasecc_se_get_crt() found CRT with refs %X:%X:...",
				se->crts[ii].refs[0], se->crts[ii].refs[1]);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	sc_log(ctx, "iasecc_se_get_crt() CRT is not found");
	return SC_ERROR_DATA_OBJECT_NOT_FOUND;
}


int
iasecc_se_get_crt_by_usage(struct sc_card *card, struct iasecc_se_info *se, unsigned char tag,
		unsigned char usage, struct sc_crt *crt)
{
	struct sc_context *ctx = card->ctx;
	int ii;

	LOG_FUNC_CALLED(ctx);
	if (!se || !crt || !tag || !usage)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "CRT search template with TAG:0x%X and UQB:0x%X", tag, usage);

	for (ii=0; ii<SC_MAX_CRTS_IN_SE && se->crts[ii].tag; ii++)   {
		if (tag != se->crts[ii].tag)
			continue;
		if (usage != se->crts[ii].usage)
			continue;

		memcpy(crt, &se->crts[ii], sizeof(*crt));

		sc_log(ctx, "iasecc_se_get_crt() found CRT with refs %X:%X:...", crt->refs[0], crt->refs[1]);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	sc_log(ctx, "iasecc_se_get_crt() CRT is not found");
	LOG_FUNC_RETURN(ctx, SC_ERROR_DATA_OBJECT_NOT_FOUND);
}


int
iasecc_se_parse(struct sc_card *card, unsigned char *data, size_t data_len, struct iasecc_se_info *se)
{
	struct sc_context *ctx = card->ctx;
	size_t size, offs, size_size;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (*data == IASECC_SDO_TEMPLATE_TAG)   {
		size_size = iasecc_parse_size(data + 1, &size);
		LOG_TEST_RET(ctx, size_size, "parse error: invalid size data of IASECC_SDO_TEMPLATE");

		data += size_size + 1;
		data_len = size;
		sc_log(ctx,
		       "IASECC_SDO_TEMPLATE: size %"SC_FORMAT_LEN_SIZE_T"u, size_size %"SC_FORMAT_LEN_SIZE_T"u",
		       size, size_size);

		if (*data != IASECC_SDO_TAG_HEADER)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

		if ((*(data + 1) & 0x7F) != IASECC_SDO_CLASS_SE)
			 LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

		size_size = iasecc_parse_size(data + 3, &size);
		LOG_TEST_RET(ctx, size_size, "parse error: invalid SDO SE data size");

		if (data_len != size + size_size + 3)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: invalid SDO SE data size");

		data += 3 + size_size;
		data_len = size;
		sc_log(ctx,
		       "IASECC_SDO_TEMPLATE SE: size %"SC_FORMAT_LEN_SIZE_T"u, size_size %"SC_FORMAT_LEN_SIZE_T"u",
		       size, size_size);
	}

	if (*data != IASECC_SDO_CLASS_SE)   {
		sc_log(ctx,
		       "Invalid SE tag 0x%X; data length %"SC_FORMAT_LEN_SIZE_T"u",
		       *data, data_len);
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	size_size = iasecc_parse_size(data + 1, &size);
	LOG_TEST_RET(ctx, size_size, "parse error: invalid size data");

	if (data_len != size + size_size + 1)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: invalid SE data size");

	offs = 1 + size_size;
	for (; offs < data_len;)   {
		rv = iasecc_crt_parse(card, data + offs, se);
		LOG_TEST_RET(ctx, rv, "parse error: invalid SE data");

		offs += rv;
	}

	if (offs != data_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: not totally parsed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_parse_size(unsigned char *data, size_t *out)
{
	if (*data < 0x80)   {
		*out = *data;
		return 1;
	}
	else if (*data == 0x81)   {
		*out = *(data + 1);
		return 2;
	}
	else if (*data == 0x82)   {
		*out = *(data + 1) * 0x100 + *(data + 2);
		return 3;
	}

	return SC_ERROR_INVALID_DATA;
}


static int
iasecc_parse_get_tlv(struct sc_card *card, unsigned char *data, struct iasecc_extended_tlv *tlv)
{
	struct sc_context *ctx = card->ctx;
	size_t size_len, tag_len;

	memset(tlv, 0, sizeof(*tlv));
	sc_log(ctx, "iasecc_parse_get_tlv() called for tag 0x%X", *data);
	if ((*data == 0x7F) || (*data == 0x5F))   {
		tlv->tag = *data * 0x100 + *(data + 1);
		tag_len = 2;
	}
	else   {
		tlv->tag = *data;
		tag_len = 1;
	}

	sc_log(ctx, "iasecc_parse_get_tlv() tlv->tag 0x%X", tlv->tag);
	size_len = iasecc_parse_size(data + tag_len, &tlv->size);
	LOG_TEST_RET(ctx, size_len, "parse error: invalid size data");

	tlv->value = calloc(1, tlv->size);
	if (!tlv->value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(tlv->value, data + size_len + tag_len, tlv->size);

	tlv->on_card = 1;

	sc_log(ctx,
	       "iasecc_parse_get_tlv() parsed %"SC_FORMAT_LEN_SIZE_T"u bytes",
	       tag_len + size_len + tlv->size);
	return tag_len + size_len + tlv->size;
}


static int
iasecc_parse_chv(struct sc_card *card, unsigned char *data, size_t data_len, struct iasecc_sdo_chv *chv)
{
	struct sc_context *ctx = card->ctx;
	size_t offs = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	while(offs < data_len)   {
		struct iasecc_extended_tlv tlv;

		rv = iasecc_parse_get_tlv(card, data + offs, &tlv);
		LOG_TEST_RET(ctx, rv, "iasecc_parse_chv() get and parse TLV error");

		sc_log(ctx,
		       "iasecc_parse_chv() get and parse TLV returned %i; tag %X; size %"SC_FORMAT_LEN_SIZE_T"u",
		       rv, tlv.tag, tlv.size);

		if (tlv.tag == IASECC_SDO_CHV_TAG_SIZE_MAX)
			chv->size_max = tlv;
		else if (tlv.tag == IASECC_SDO_CHV_TAG_SIZE_MIN)
			chv->size_min = tlv;
		else if (tlv.tag == IASECC_SDO_CHV_TAG_VALUE)
			chv->value = tlv;
		else
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "parse error: non CHV SDO tag");

		offs += rv;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_parse_prvkey(struct sc_card *card, unsigned char *data, size_t data_len, struct iasecc_sdo_prvkey *prvkey)
{
	struct sc_context *ctx = card->ctx;
	size_t offs = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	while(offs < data_len)   {
		struct iasecc_extended_tlv tlv;

		rv = iasecc_parse_get_tlv(card, data + offs, &tlv);
		LOG_TEST_RET(ctx, rv, "iasecc_parse_prvkey() get and parse TLV error");

		sc_log(ctx,
		       "iasecc_parse_prvkey() get and parse TLV returned %i; tag %X; size %"SC_FORMAT_LEN_SIZE_T"u",
		       rv, tlv.tag, tlv.size);

		if (tlv.tag == IASECC_SDO_PRVKEY_TAG_COMPULSORY)
			prvkey->compulsory = tlv;
		else
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "parse error: non PrvKey SDO tag");

		offs += rv;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_parse_pubkey(struct sc_card *card, unsigned char *data, size_t data_len, struct iasecc_sdo_pubkey *pubkey)
{
	struct sc_context *ctx = card->ctx;
	size_t offs = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	while(offs < data_len)   {
		struct iasecc_extended_tlv tlv;

		rv = iasecc_parse_get_tlv(card, data + offs, &tlv);
		LOG_TEST_RET(ctx, rv, "iasecc_parse_pubkey() get and parse TLV error");

		sc_log(ctx,
		       "iasecc_parse_pubkey() get and parse TLV returned %i; tag %X; size %"SC_FORMAT_LEN_SIZE_T"u",
		       rv, tlv.tag, tlv.size);

		if (tlv.tag == IASECC_SDO_PUBKEY_TAG_N)
			pubkey->n = tlv;
		else if (tlv.tag == IASECC_SDO_PUBKEY_TAG_E)
			pubkey->e = tlv;
		else if (tlv.tag == IASECC_SDO_PUBKEY_TAG_CHR)
			pubkey->chr = tlv;
		else if (tlv.tag == IASECC_SDO_PUBKEY_TAG_CHA)
			pubkey->cha = tlv;
		else if (tlv.tag == IASECC_SDO_PUBKEY_TAG_COMPULSORY)
			pubkey->compulsory = tlv;
		else
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "parse error: non PubKey SDO tag");

		offs += rv;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_parse_keyset(struct sc_card *card, unsigned char *data, size_t data_len, struct iasecc_sdo_keyset *keyset)
{
	struct sc_context *ctx = card->ctx;
	size_t offs = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	while(offs < data_len)   {
		struct iasecc_extended_tlv tlv;

		rv = iasecc_parse_get_tlv(card, data + offs, &tlv);
		LOG_TEST_RET(ctx, rv, "iasecc_parse_keyset() get and parse TLV error");

		sc_log(ctx,
		       "iasecc_parse_prvkey() get and parse TLV returned %i; tag %X; size %"SC_FORMAT_LEN_SIZE_T"u",
		       rv, tlv.tag, tlv.size);

		if (tlv.tag == IASECC_SDO_KEYSET_TAG_COMPULSORY)
			keyset->compulsory = tlv;
		else
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "parse error: non KeySet SDO tag");

		offs += rv;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_parse_docp(struct sc_card *card, unsigned char *data, size_t data_len, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	size_t offs = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	while(offs < data_len)   {
		struct iasecc_extended_tlv tlv;

		rv = iasecc_parse_get_tlv(card, data + offs, &tlv);
		LOG_TEST_RET(ctx, rv, "iasecc_parse_get_tlv() get and parse TLV error");

		sc_log(ctx,
		       "iasecc_parse_docp() parse_get_tlv returned %i; tag %X; size %"SC_FORMAT_LEN_SIZE_T"u",
		       rv, tlv.tag, tlv.size);

		if (tlv.tag == IASECC_DOCP_TAG_ACLS)   {
			int _rv = iasecc_parse_docp(card, tlv.value, tlv.size, sdo);
			free(tlv.value);
			LOG_TEST_RET(ctx, _rv, "parse error: cannot parse DOCP");
		}
		else if (tlv.tag == IASECC_DOCP_TAG_ACLS_CONTACT)   {
			sdo->docp.acls_contact = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_ACLS_CONTACTLESS)   {
			sdo->docp.acls_contactless = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_SIZE)   {
			sdo->docp.size = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_NAME)   {
			sdo->docp.name = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_ISSUER_DATA)   {
			sdo->docp.issuer_data = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_NON_REPUDIATION)   {
			sdo->docp.non_repudiation = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_USAGE_REMAINING)   {
			sdo->docp.usage_remaining = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_TRIES_MAXIMUM)   {
			sdo->docp.tries_maximum = tlv;
		}
		else if (tlv.tag == IASECC_DOCP_TAG_TRIES_REMAINING)   {
			sdo->docp.tries_remaining = tlv;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "iasecc_parse_get_tlv() parse error: non DOCP tag");
		}

		offs += rv;
	}

	rv = iasecc_parse_acls(card, &sdo->docp, 0);
	LOG_TEST_RET(ctx, rv, "Cannot parse ACLs in DOCP");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_parse_data(struct sc_card *card, unsigned char *data, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_extended_tlv tlv;
	int tlv_size, rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_sdo_parse_data() class %X; ref %X", sdo->sdo_class, sdo->sdo_ref);

	tlv_size = iasecc_parse_get_tlv(card, data, &tlv);
	LOG_TEST_RET(ctx, tlv_size, "parse error: get TLV");

	sc_log(ctx, "iasecc_sdo_parse_data() tlv.tag 0x%X", tlv.tag);
	if (tlv.tag == IASECC_DOCP_TAG)   {
		sc_log(ctx,
		       "iasecc_sdo_parse_data() parse IASECC_DOCP_TAG: 0x%X; size %"SC_FORMAT_LEN_SIZE_T"u",
		       tlv.tag, tlv.size);
		rv = iasecc_parse_docp(card, tlv.value, tlv.size, sdo);
		sc_log(ctx, "iasecc_sdo_parse_data() parsed IASECC_DOCP_TAG rv %i", rv);
		free(tlv.value);
		LOG_TEST_RET(ctx, rv, "parse error: cannot parse DOCP");
	}
	else if (tlv.tag == IASECC_DOCP_TAG_NON_REPUDIATION)   {
		sdo->docp.non_repudiation = tlv;
	}
	else if (tlv.tag == IASECC_DOCP_TAG_USAGE_REMAINING)   {
		sdo->docp.usage_remaining = tlv;
	}
	else if (tlv.tag == IASECC_DOCP_TAG_TRIES_MAXIMUM)   {
		sdo->docp.tries_maximum = tlv;
	}
	else if (tlv.tag == IASECC_DOCP_TAG_TRIES_REMAINING)   {
		sdo->docp.tries_remaining = tlv;
	}
	else if (tlv.tag == IASECC_SDO_CHV_TAG)   {
		if (sdo->sdo_class != IASECC_SDO_CLASS_CHV)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: IASECC_SDO_CHV_TAG tag in non User CHV SDO");

		rv = iasecc_parse_chv(card, tlv.value, tlv.size, &sdo->data.chv);
		LOG_TEST_RET(ctx, rv, "parse error: cannot parse SDO CHV data");

		free(tlv.value);
	}
	else if (tlv.tag == IASECC_SDO_PUBKEY_TAG)   {
		if (sdo->sdo_class != IASECC_SDO_CLASS_RSA_PUBLIC)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: SDO_PUBLIC_KEY tag in non PUBLIC_KEY SDO");

		rv = iasecc_parse_pubkey(card, tlv.value, tlv.size, &sdo->data.pub_key);
		LOG_TEST_RET(ctx, rv, "parse error: cannot parse SDO PUBLIC KEY data");

		free(tlv.value);
	}
	else if (tlv.tag == IASECC_SDO_PRVKEY_TAG)   {
		if (sdo->sdo_class != IASECC_SDO_CLASS_RSA_PRIVATE)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: SDO_PRIVATE_KEY tag in non PRIVATE_KEY SDO");

		rv = iasecc_parse_prvkey(card, tlv.value, tlv.size, &sdo->data.prv_key);
		LOG_TEST_RET(ctx, rv, "parse error: cannot parse SDO PRIVATE KEY data");

		free(tlv.value);
	}
	else if (tlv.tag == IASECC_SDO_KEYSET_TAG)   {
		if (sdo->sdo_class != IASECC_SDO_CLASS_KEYSET)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: SDO_KEYSET tag in non KEYSET SDO");

		rv = iasecc_parse_keyset(card, tlv.value, tlv.size, &sdo->data.keyset);
		LOG_TEST_RET(ctx, rv, "parse error: cannot parse SDO KEYSET data");

		free(tlv.value);
	}
	else   {
		sc_log(ctx, "iasecc_sdo_parse_data() non supported tag 0x%X", tlv.tag);
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	return tlv_size;
}


int
iasecc_sdo_parse(struct sc_card *card, unsigned char *data, size_t data_len, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	size_t size, offs, size_size;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (*data == IASECC_SDO_TEMPLATE_TAG)   {
		size_size = iasecc_parse_size(data + 1, &size);
		LOG_TEST_RET(ctx, size_size, "parse error: invalid size data of IASECC_SDO_TEMPLATE");

		data += size_size + 1;
		data_len = size;
		sc_log(ctx,
		       "IASECC_SDO_TEMPLATE: size %"SC_FORMAT_LEN_SIZE_T"u, size_size %"SC_FORMAT_LEN_SIZE_T"u",
		       size, size_size);
	}

	if (*data != IASECC_SDO_TAG_HEADER)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	if (sdo->sdo_class != (*(data + 1) & 0x7F))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	if (sdo->sdo_ref != (*(data + 2) & 0x3F))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	size_size = iasecc_parse_size(data + 3, &size);
	LOG_TEST_RET(ctx, size_size, "parse error: invalid size data");

	if (data_len != size + size_size + 3)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: invalid SDO data size");

	sc_log(ctx,
	       "sz %"SC_FORMAT_LEN_SIZE_T"u, sz_size %"SC_FORMAT_LEN_SIZE_T"u",
	       size, size_size);

	offs = 3 + size_size;
	for (; offs < data_len;)   {
		rv = iasecc_sdo_parse_data(card, data + offs, sdo);
		LOG_TEST_RET(ctx, rv, "parse error: invalid SDO data");

		offs += rv;
	}

	if (offs != data_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: not totally parsed");

	sc_log(ctx,
	       "docp.acls_contact.size %"SC_FORMAT_LEN_SIZE_T"u, docp.size.size %"SC_FORMAT_LEN_SIZE_T"u",
	       sdo->docp.acls_contact.size, sdo->docp.size.size);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
iasecc_sdo_allocate_and_parse(struct sc_card *card, unsigned char *data, size_t data_len,
		struct iasecc_sdo **out)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo *sdo = NULL;
	size_t size, offs, size_size;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (*data != IASECC_SDO_TAG_HEADER)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	if (data_len < 3)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	sdo = calloc(1, sizeof(struct iasecc_sdo));
	if (!sdo)
		return SC_ERROR_OUT_OF_MEMORY;
	*out = sdo;

	sdo->sdo_class = *(data + 1) & 0x7F;
	sdo->sdo_ref = *(data + 2) & 0x3F;

	sc_log(ctx, "sdo_class 0x%X, sdo_ref 0x%X", sdo->sdo_class, sdo->sdo_ref);
	if (data_len == 3)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	size_size = iasecc_parse_size(data + 3, &size);
	LOG_TEST_RET(ctx, size_size, "parse error: invalid size data");

	if (data_len != size + size_size + 3)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: invalid SDO data size");

	sc_log(ctx,
	       "sz %"SC_FORMAT_LEN_SIZE_T"u, sz_size %"SC_FORMAT_LEN_SIZE_T"u",
	       size, size_size);

	offs = 3 + size_size;
	for (; offs < data_len;)   {
		rv = iasecc_sdo_parse_data(card, data + offs, sdo);
		LOG_TEST_RET(ctx, rv, "parse error: invalid SDO data");

		offs += rv;
	}

	if (offs != data_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "parse error: not totally parsed");

	sc_log(ctx,
	       "docp.acls_contact.size %"SC_FORMAT_LEN_SIZE_T"u; docp.size.size %"SC_FORMAT_LEN_SIZE_T"u",
	       sdo->docp.acls_contact.size, sdo->docp.size.size);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_update_blob(struct sc_context *ctx, struct iasecc_extended_tlv *tlv,
		unsigned char **blob, size_t *blob_size)
{
	unsigned char *pp = NULL;
	int offs = 0, sz = tlv->size + 2;

	if (tlv->size == 0)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	sz = tlv->size + 2;

	if (tlv->tag > 0xFF)
		sz += 1;

	if (tlv->size > 0x7F && tlv->size < 0x100)
		sz += 1;
	else if (tlv->size >= 0x100)
		sz += 2;

	pp = realloc(*blob, *blob_size + sz);
	if (!pp)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	if (tlv->tag > 0xFF)
		*(pp + *blob_size + offs++) = (tlv->tag >> 8) & 0xFF;
	*(pp + *blob_size + offs++) = tlv->tag & 0xFF;

	if (tlv->size >= 0x100) {
		*(pp + *blob_size + offs++) = 0x82;
		*(pp + *blob_size + offs++) = (tlv->size >> 8) & 0xFF;
	}
	else if (tlv->size > 0x7F)   {
		*(pp + *blob_size + offs++) = 0x81;
	}
	*(pp + *blob_size + offs++) = tlv->size & 0xFF;

	memcpy(pp + *blob_size + offs, tlv->value, tlv->size);

	*blob_size += sz;
	*blob = pp;

	return 0;
}


static int
iasecc_encode_docp(struct sc_context *ctx, struct iasecc_sdo_docp *docp, unsigned char **out, size_t *out_len)
{
	struct iasecc_extended_tlv tlv, tlv_st;
	unsigned char *st_blob, *tmp_blob, *docp_blob;
	size_t blob_size;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!docp->acls_contact.size || (docp->size.size != 2))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	memset(&tlv, 0, sizeof(tlv));
	memset(&tlv_st, 0, sizeof(tlv_st));

	st_blob = NULL;
	blob_size = 0;
	rv = iasecc_update_blob(ctx, &docp->acls_contact, &st_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add contact ACLs to blob");

	rv = iasecc_update_blob(ctx, &docp->acls_contactless, &st_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add contactless ACLs to blob");

	tlv.tag = IASECC_DOCP_TAG_ACLS;
	tlv.size = blob_size;
	tlv.value = st_blob;

	tmp_blob = NULL;
	blob_size = 0;
	rv = iasecc_update_blob(ctx, &tlv, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add ACLs template to blob");

	rv = iasecc_update_blob(ctx, &docp->name, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add NAME to blob");

	rv = iasecc_update_blob(ctx, &docp->tries_maximum, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add TRIES MAXIMUM to blob");

	rv = iasecc_update_blob(ctx, &docp->tries_remaining, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add TRIES REMAINING to blob");

	rv = iasecc_update_blob(ctx, &docp->usage_maximum, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add USAGE MAXIMUM to blob");

	rv = iasecc_update_blob(ctx, &docp->usage_remaining, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add USAGE REMAINING to blob");

	rv = iasecc_update_blob(ctx, &docp->non_repudiation, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add NON REPUDIATION to blob");

	rv = iasecc_update_blob(ctx, &docp->size, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add SIZE to blob");

	rv = iasecc_update_blob(ctx, &docp->issuer_data, &tmp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add IDATA to blob");

	tlv.tag = IASECC_DOCP_TAG;
	tlv.size = blob_size;
	tlv.value = tmp_blob;

	docp_blob = NULL;
	blob_size = 0;
	rv = iasecc_update_blob(ctx, &tlv, &docp_blob, &blob_size);
	LOG_TEST_RET(ctx, rv, "ECC: cannot add ACLs to blob");

	free(tmp_blob);

	if (out && out_len)   {
		*out = docp_blob;
		*out_len = blob_size;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static unsigned
iasecc_sdo_encode_asn1_tag(unsigned in_tag)
{
	unsigned short_tag;
	unsigned out_tag;

	for (short_tag = in_tag; short_tag > 0xFF; short_tag >>= 8)
		;
	out_tag = in_tag;
	switch (short_tag & SC_ASN1_TAG_CLASS)   {
	case SC_ASN1_TAG_APPLICATION:
		out_tag |= SC_ASN1_APP;
		break;
	case SC_ASN1_TAG_CONTEXT:
		out_tag |= SC_ASN1_CTX;
		break;
	case SC_ASN1_TAG_PRIVATE:
		out_tag |= SC_ASN1_PRV;
		break;
	}
	return out_tag;
}


int
iasecc_sdo_encode_create(struct sc_context *ctx, struct iasecc_sdo *sdo, unsigned char **out)
{
	struct sc_asn1_entry c_asn1_docp_data[2] = {
		{ "docpData", SC_ASN1_OCTET_STRING, 0, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry c_asn1_create_data[2] = {
		{ "createData", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_APP | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_docp_data[2], asn1_create_data[2];
	unsigned char *blob = NULL;
	size_t len, out_len;
	unsigned sdo_full_ref;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "ecc_sdo_encode_create() sdo->sdo_class %X", sdo->sdo_class);
	sc_log(ctx, "id %02X%02X%02X", IASECC_SDO_TAG_HEADER, sdo->sdo_class | 0x80, sdo->sdo_ref);

	if (out)
		*out = NULL;

	rv = iasecc_encode_docp(ctx, &sdo->docp, &blob, &len);
	LOG_TEST_RET(ctx, rv, "ECC encode DOCP error");

	sdo_full_ref = (sdo->sdo_ref&0x3F)  + 0x100*(sdo->sdo_class | IASECC_OBJECT_REF_LOCAL) + 0x10000*IASECC_SDO_TAG_HEADER;
	c_asn1_docp_data[0].tag = iasecc_sdo_encode_asn1_tag(sdo_full_ref) | SC_ASN1_CONS;

	sc_copy_asn1_entry(c_asn1_docp_data, asn1_docp_data);
	sc_copy_asn1_entry(c_asn1_create_data, asn1_create_data);

	sc_format_asn1_entry(asn1_docp_data + 0, blob, &len, 1);
	sc_format_asn1_entry(asn1_create_data + 0, asn1_docp_data, NULL, 1);

	rv = sc_asn1_encode(ctx, asn1_create_data, out, &out_len);
	LOG_TEST_RET(ctx, rv, "Encode create data error");
	if (out)
		sc_debug(ctx, SC_LOG_DEBUG_ASN1,"Create data: %s", sc_dump_hex(*out, out_len));

	LOG_FUNC_RETURN(ctx, out_len);
}


int
iasecc_sdo_encode_update_field(struct sc_context *ctx, unsigned char sdo_class, unsigned char sdo_ref,
		struct iasecc_extended_tlv *tlv, unsigned char **out)
{
	unsigned sdo_full_ref;
	size_t out_len;
	int rv;

	struct sc_asn1_entry c_asn1_field_value[2] = {
	        { "fieldValue", SC_ASN1_OCTET_STRING, 0, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry c_asn1_sdo_field[2] = {
		{ "sdoField", SC_ASN1_STRUCT, 0, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry c_asn1_class_data[2] = {
		{ "classData", SC_ASN1_STRUCT, 0, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry c_asn1_update_data[2] = {
		{ "updateData", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_APP | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_field_value[4], asn1_sdo_field[2], asn1_class_data[2], asn1_update_data[2];

	LOG_FUNC_CALLED(ctx);

	c_asn1_field_value[0].tag = iasecc_sdo_encode_asn1_tag(tlv->tag);
	c_asn1_sdo_field[0].tag = iasecc_sdo_encode_asn1_tag(tlv->parent_tag) | SC_ASN1_CONS;

	sdo_full_ref = (sdo_ref&0x3F)  + 0x100*(sdo_class | IASECC_OBJECT_REF_LOCAL) + 0x10000*IASECC_SDO_TAG_HEADER;
	c_asn1_class_data[0].tag = iasecc_sdo_encode_asn1_tag(sdo_full_ref) | SC_ASN1_CONS;

	sc_copy_asn1_entry(c_asn1_field_value, asn1_field_value);
	sc_copy_asn1_entry(c_asn1_sdo_field, asn1_sdo_field);
	sc_copy_asn1_entry(c_asn1_class_data, asn1_class_data);
	sc_copy_asn1_entry(c_asn1_update_data, asn1_update_data);

	sc_format_asn1_entry(asn1_field_value + 0, tlv->value, &tlv->size, 1);
	sc_format_asn1_entry(asn1_sdo_field + 0, asn1_field_value, NULL, 1);
	sc_format_asn1_entry(asn1_class_data + 0, asn1_sdo_field, NULL, 1);
	sc_format_asn1_entry(asn1_update_data + 0, asn1_class_data, NULL, 1);

	rv = sc_asn1_encode(ctx, asn1_update_data, out, &out_len);
	LOG_TEST_RET(ctx, rv, "Encode update data error");

	sc_debug(ctx, SC_LOG_DEBUG_ASN1,"Data: %s", sc_dump_hex(tlv->value, tlv->size));
	sc_debug(ctx, SC_LOG_DEBUG_ASN1,"Encoded: %s", sc_dump_hex(*out, out_len));
	LOG_FUNC_RETURN(ctx, out_len);
}


int
iasecc_sdo_encode_rsa_update(struct sc_context *ctx, struct iasecc_sdo *sdo, struct sc_pkcs15_prkey_rsa *rsa,
		struct iasecc_sdo_update *sdo_update)
{
	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "iasecc_sdo_encode_rsa_update() SDO class %X", sdo->sdo_class);
	memset(sdo_update, 0, sizeof(*sdo_update));
	if (sdo->sdo_class == IASECC_SDO_CLASS_RSA_PRIVATE)   {
		int indx = 0;

		sc_log(ctx, "iasecc_sdo_encode_rsa_update(IASECC_SDO_CLASS_RSA_PRIVATE)");
		if (!rsa->p.len || !rsa->q.len || !rsa->iqmp.len || !rsa->dmp1.len || !rsa->dmq1.len)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "need all private RSA key components");

		sdo_update->magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
		sdo_update->sdo_ref = sdo->sdo_ref;

		sdo_update->sdo_class = IASECC_SDO_CLASS_RSA_PRIVATE;

		sdo_update->fields[indx].parent_tag = IASECC_SDO_PRVKEY_TAG;
		sdo_update->fields[indx].tag = IASECC_SDO_PRVKEY_TAG_P;
		sdo_update->fields[indx].value = rsa->p.data;
		sdo_update->fields[indx].size = rsa->p.len;
		indx++;

		sdo_update->fields[indx].parent_tag = IASECC_SDO_PRVKEY_TAG;
		sdo_update->fields[indx].tag = IASECC_SDO_PRVKEY_TAG_Q;
		sdo_update->fields[indx].value = rsa->q.data;
		sdo_update->fields[indx].size = rsa->q.len;
		indx++;

		sdo_update->fields[indx].parent_tag = IASECC_SDO_PRVKEY_TAG;
		sdo_update->fields[indx].tag = IASECC_SDO_PRVKEY_TAG_IQMP;
		sdo_update->fields[indx].value = rsa->iqmp.data;
		sdo_update->fields[indx].size = rsa->iqmp.len;
		indx++;

		sdo_update->fields[indx].parent_tag = IASECC_SDO_PRVKEY_TAG;
		sdo_update->fields[indx].tag = IASECC_SDO_PRVKEY_TAG_DMP1;
		sdo_update->fields[indx].value = rsa->dmp1.data;
		sdo_update->fields[indx].size = rsa->dmp1.len;
		indx++;

		sdo_update->fields[indx].parent_tag = IASECC_SDO_PRVKEY_TAG;
		sdo_update->fields[indx].tag = IASECC_SDO_PRVKEY_TAG_DMQ1;
		sdo_update->fields[indx].value = rsa->dmq1.data;
		sdo_update->fields[indx].size = rsa->dmq1.len;
		indx++;

		sc_log(ctx, "prv_key.compulsory.on_card %i", sdo->data.prv_key.compulsory.on_card);
		if (!sdo->data.prv_key.compulsory.on_card)   {
			if (sdo->data.prv_key.compulsory.value)   {
				sc_log(ctx,
				       "sdo_prvkey->data.prv_key.compulsory.size %"SC_FORMAT_LEN_SIZE_T"u",
				       sdo->data.prv_key.compulsory.size);
				sdo_update->fields[indx].parent_tag = IASECC_SDO_PRVKEY_TAG;
				sdo_update->fields[indx].tag = IASECC_SDO_PRVKEY_TAG_COMPULSORY;
				sdo_update->fields[indx].value = sdo->data.prv_key.compulsory.value;
				sdo_update->fields[indx].size = sdo->data.prv_key.compulsory.size;
				indx++;
			}
		}
	}
	else if (sdo->sdo_class == IASECC_SDO_CLASS_RSA_PUBLIC)   {
		int indx = 0;
		sc_log(ctx, "iasecc_sdo_encode_rsa_update(IASECC_SDO_CLASS_RSA_PUBLIC)");

		sdo_update->magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
		sdo_update->sdo_ref = sdo->sdo_ref;
		sdo_update->sdo_class = sdo->sdo_class;

		if (rsa->exponent.len)   {
			sdo_update->fields[indx].parent_tag = IASECC_SDO_PUBKEY_TAG;
			sdo_update->fields[indx].tag = IASECC_SDO_PUBKEY_TAG_E;
			sdo_update->fields[indx].value = rsa->exponent.data;
			sdo_update->fields[indx].size = rsa->exponent.len;
			indx++;
		}

		if (rsa->modulus.len)   {
			sdo_update->fields[indx].parent_tag = IASECC_SDO_PUBKEY_TAG;
			sdo_update->fields[indx].tag = IASECC_SDO_PUBKEY_TAG_N;
			sdo_update->fields[indx].value = rsa->modulus.data;
			sdo_update->fields[indx].size = rsa->modulus.len;
			indx++;
		}

		if (sdo->data.pub_key.cha.value)   {
			sdo_update->fields[indx].parent_tag = IASECC_SDO_PUBKEY_TAG;
			sdo_update->fields[indx].tag = IASECC_SDO_PUBKEY_TAG_CHA;
			sdo_update->fields[indx].value = sdo->data.pub_key.cha.value;
			sdo_update->fields[indx].size = sdo->data.pub_key.cha.size;
			indx++;
		}

		if (sdo->data.pub_key.chr.value)   {
			sdo_update->fields[indx].parent_tag = IASECC_SDO_PUBKEY_TAG;
			sdo_update->fields[indx].tag = IASECC_SDO_PUBKEY_TAG_CHR;
			sdo_update->fields[indx].value = sdo->data.pub_key.chr.value;
			sdo_update->fields[indx].size = sdo->data.pub_key.chr.size;
			indx++;
		}

		/* For ECC card 'compulsory' flag should be already here */
		if (!sdo->data.pub_key.compulsory.on_card)   {
			if (sdo->data.pub_key.compulsory.value)   {
				sdo_update->fields[indx].parent_tag = IASECC_SDO_PUBKEY_TAG;
				sdo_update->fields[indx].tag = IASECC_SDO_PUBKEY_TAG_COMPULSORY;
				sdo_update->fields[indx].value = sdo->data.pub_key.compulsory.value;
				sdo_update->fields[indx].size = sdo->data.pub_key.compulsory.size;
				indx++;
			}
		}
	}
	else   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
iasecc_sdo_parse_card_answer(struct sc_context *ctx, unsigned char *data, size_t data_len,
	struct iasecc_sm_card_answer *out)
{
	int have_mac = 0, have_status = 0;
	size_t size = 0, size_size, offs;

	LOG_FUNC_CALLED(ctx);
	if (!data || !data_len || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(out, 0, sizeof(*out));
	for (offs=0; offs<data_len; )   {
		size_size = iasecc_parse_size(data + 1, &size);

		if (*(data + offs) == IASECC_CARD_ANSWER_TAG_DATA )   {
			if (size > sizeof(out->data))
				LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "iasecc_sm_decode_answer() unbelievable !!!");

			memcpy(out->data, data + offs + size_size + 1, size);
			out->data_len = size;
			offs += 1 + size_size + size;
		}
		else if (*(data + offs) == IASECC_CARD_ANSWER_TAG_SW )   {
			if (*(data + offs + 1) != 2)
				LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "iasecc_sm_decode_answer() SW length not 2");
			out->sw = *(data + offs + 2) * 0x100 + *(data + offs + 3);

			memcpy(out->ticket, data + offs, 4);

			offs += 4;
			have_status = 1;
		}
		else if (*(data + offs) == IASECC_CARD_ANSWER_TAG_MAC )   {
			if (*(data + offs + 1) != 8)
				LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "iasecc_sm_decode_answer() MAC length not 8");
			memcpy(out->mac, data + offs + 2, 8);

			memcpy(out->ticket + 4, data + offs, 10);

			offs += 10;
			have_mac = 1;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "iasecc_sm_decode_answer() invalid card answer tag");
		}
	}

	if (!have_mac || !have_status)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "iasecc_sm_decode_answer() absent MAC or SW ");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_tlv_copy(struct sc_context *ctx, struct iasecc_extended_tlv *in, struct iasecc_extended_tlv *out)
{
	if (!in || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(out, 0, sizeof(struct iasecc_extended_tlv));
	out->tag = in->tag;
	out->parent_tag = in->parent_tag;
	out->on_card = in->on_card;
	if (in->value && in->size)   {
		out->value = calloc(1, in->size);
		if (!out->value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

		memcpy(out->value, in->value, in->size);
		out->size = in->size;
	}

	return SC_SUCCESS;
}


int
iasecc_docp_copy(struct sc_context *ctx, struct iasecc_sdo_docp *in, struct iasecc_sdo_docp *out)
{
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!in || !out) 
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(out, 0, sizeof(struct iasecc_sdo_docp));

	rv = iasecc_tlv_copy(ctx, &in->name, &out->name);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->tries_maximum, &out->tries_maximum);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->tries_remaining, &out->tries_remaining);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->usage_maximum, &out->usage_maximum);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->usage_remaining, &out->usage_remaining);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->non_repudiation, &out->non_repudiation);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->size, &out->size);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->acls_contact, &out->acls_contact);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	rv = iasecc_tlv_copy(ctx, &in->acls_contactless, &out->acls_contactless);
	LOG_TEST_RET(ctx, rv, "TLV copy error");

	out->amb = in->amb;
	memcpy(out->scbs, in->scbs, sizeof(out->scbs));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

#else

/* we need to define the functions below to export them */
#include "errors.h"

int
iasecc_sdo_encode_update_field()
{
	return SC_ERROR_NOT_SUPPORTED;
}

int
iasecc_se_get_crt()
{
	return SC_ERROR_NOT_SUPPORTED;
}

#endif /* ENABLE_OPENSSL */
