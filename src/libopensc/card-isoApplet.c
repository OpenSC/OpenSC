/*
 * Support for the IsoApplet JavaCard Applet.
 *
 * Copyright (C) 2014 Philip Wendland <wendlandphilip@gmail.com>
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

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "opensc.h"
#include "cardctl.h"
#include "log.h"
#include "asn1.h"
#include "pkcs15.h"

#define ISOAPPLET_ALG_REF_ECDSA 0x21
#define ISOAPPLET_ALG_REF_RSA_PAD_PKCS1 0x11

#define ISOAPPLET_API_VERSION_MAJOR 0x00
#define ISOAPPLET_API_VERSION_MINOR 0x03
#define ISOAPPLET_API_FEATURE_EXT_APDU 0x01

#define ISOAPPLET_AID_LEN 12
static const u8 isoAppletId[] = {0xf2,0x76,0xa2,0x88,0xbc,0xfb,0xa6,0x9d,0x34,0xf3,0x10,0x01};

struct isoApplet_drv_data
{
	unsigned int sec_env_alg_ref;
};
#define DRVDATA(card)	((struct isoApplet_drv_data *) ((card)->drv_data))

static struct sc_card_operations isoApplet_ops;
static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_driver isoApplet_drv =
{
	"Javacard with IsoApplet",
	"isoApplet",
	&isoApplet_ops,
	NULL, 0, NULL
};


/*
 * SELECT an applet on the smartcard. (Not in the emulated filesystem.)
 * The response will be written to resp.
 *
 * @param[in] 		card
 * @param[in] 		aid			The applet ID.
 * @param[in] 		aid_len		The legth of aid.
 * @param[out] 		resp		The response of the applet upon selection.
 * @param[in,out] 	resp_len	In: The buffer size of resp. Out: The length of the response.
 *
 * @return	SC_SUCCESS:	The applet is present and could be selected.
 *			any other: 	Transmit failure or the card returned an error.
 *						The card will return an error when the applet is
 *						not present.
 */
static int
isoApplet_select_applet(sc_card_t *card, const u8 aid[], const size_t aid_len, u8* resp, size_t *resp_len)
{
	int rv;
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 aid_wc[SC_MAX_APDU_BUFFER_SIZE];

	LOG_FUNC_CALLED(card->ctx);

	if(aid_len > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
	memcpy(aid_wc, aid, aid_len);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xa4, 0x04, 0x00);
	apdu.lc = aid_len;
	apdu.data = aid_wc;
	apdu.datalen = aid_len;
	apdu.resp = resp;
	apdu.resplen = *resp_len;
	apdu.le = 0;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit faiure.");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	*resp_len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoApplet_finish(sc_card_t * card)
{
	struct isoApplet_drv_data *drvdata=DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);
	if (drvdata)
	{
		free(drvdata);
		card->drv_data=NULL;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoApplet_match_card(sc_card_t * card)
{
	size_t rlen = SC_MAX_APDU_BUFFER_SIZE;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	rv = isoApplet_select_applet(card, isoAppletId, ISOAPPLET_AID_LEN, rbuf, &rlen);

	if(rv != SC_SUCCESS)
	{
		return 0;
	}

	/* If applet does not return API version, versions 0x00 will match */
	if(rlen == 0)
	{
		rbuf[0] = 0x00;
		rbuf[1] = 0x00;
		rbuf[2] = 0x00;
		rlen = 3;
	}

	/* We expect 3 bytes: MAJOR API version - MINOR API version - API feature bitmap */
	if(rlen != 3)
	{
		return 0;
	}

	if(rbuf[0] != ISOAPPLET_API_VERSION_MAJOR)
	{
		sc_log(card->ctx, "IsoApplet: Mismatching major API version. Not proceeding. "
		       "API versions: Driver (%02X-%02X), applet (%02X-%02X). Please update accordingly.",
		       ISOAPPLET_API_VERSION_MAJOR, ISOAPPLET_API_VERSION_MINOR, rbuf[0], rbuf[1]);
		return 0;
	}

	if(rbuf[1] != ISOAPPLET_API_VERSION_MINOR)
	{
		sc_log(card->ctx, "IsoApplet: Mismatching minor API version. Proceeding anyway. "
		       "API versions: Driver (%02X-%02X), applet (%02X-%02X)."
		       "Please update accordingly whenever possible.",
		       ISOAPPLET_API_VERSION_MAJOR, ISOAPPLET_API_VERSION_MINOR, rbuf[0], rbuf[1]);
	}

	if(rbuf[2] & ISOAPPLET_API_FEATURE_EXT_APDU)
	{
		card->caps |=  SC_CARD_CAP_APDU_EXT;
	}

	return 1;
}

static int
isoApplet_init(sc_card_t * card)
{
	unsigned long flags = 0;
	unsigned long ext_flags = 0;
	struct isoApplet_drv_data *drvdata;

	LOG_FUNC_CALLED(card->ctx);

	drvdata=malloc(sizeof(struct isoApplet_drv_data));
	if (!drvdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	memset(drvdata, 0, sizeof(struct isoApplet_drv_data));
	drvdata->sec_env_alg_ref = 0;

	card->drv_data = drvdata;
	card->cla = 0x00;

	/* ECDSA */
	flags = 0;
	flags |= SC_ALGORITHM_ECDSA_RAW;
	flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
	ext_flags =  SC_ALGORITHM_EXT_EC_NAMEDCURVE;
	ext_flags |= SC_ALGORITHM_EXT_EC_F_P;
	_sc_card_add_ec_alg(card, 192, flags, ext_flags);
	_sc_card_add_ec_alg(card, 256, flags, ext_flags);

	/* RSA */
	flags = 0;
	/* Padding schemes: */
	flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	/* Hashes: */
	flags |= SC_ALGORITHM_RSA_HASH_NONE;
	flags |= SC_ALGORITHM_RSA_HASH_SHA1;
	flags |= SC_ALGORITHM_RSA_HASH_MD5;
	flags |= SC_ALGORITHM_RSA_HASH_MD5_SHA1;
	flags |= SC_ALGORITHM_RSA_HASH_SHA224;
	flags |= SC_ALGORITHM_RSA_HASH_SHA256;
	flags |= SC_ALGORITHM_RSA_HASH_SHA384;
	flags |= SC_ALGORITHM_RSA_HASH_SHA512;
	flags |= SC_ALGORITHM_RSA_HASH_RIPEMD160;
	/* Key-generation: */
	flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
	/* Modulus lengths: */
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief convert an OpenSC ACL entry to the security condition
 * byte used by the IsoApplet.
 *
 * Used by IsoApplet_create_file to parse OpenSC ACL entries
 * into ISO 7816-4 Table 20 security condition bytes.
 *
 * @param entry The OpenSC ACL entry.
 *
 * @return 	The security condition byte. No restriction (0x00)
 *			if unknown operation.
 */
static u8
acl_to_security_condition_byte(const sc_acl_entry_t *entry)
{
	if(!entry)
		return 0x00;
	switch(entry->method)
	{
	case SC_AC_CHV:
		return 0x90;
	case SC_AC_NEVER:
		return 0xFF;
	case SC_AC_NONE:
	default:
		return 0x00;
	}
}

/*
 * The reason for this function is that OpenSC doesn't set any
 * Security Attribute Tag in the FCI upon file creation if there
 * is no file->sec_attr. I set the file->sec_attr to a format
 * understood by the applet (ISO 7816-4 tables 16, 17 and 20).
 * The iso7816_create_file will then set this as Tag 86 - Sec.
 * Attr. Prop. Format.
 * The applet will then be able to set and enforce access rights
 * for any file created by OpenSC. Without this function, the
 * applet would not know where to enforce security rules and
 * when.
 *
 * Note: IsoApplet currently only supports a "onepin" option.
 *
 * Format of the sec_attr: 8 Bytes:
 *		7 		- ISO 7816-4 table 16 or 17
 *	  	6 to 0 	- ISO 7816-4 table 20
 */
static int
isoApplet_create_file(sc_card_t *card, sc_file_t *file)
{
	int r = 0;

	LOG_FUNC_CALLED(card->ctx);

	if(file->sec_attr_len == 0)
	{
		u8 access_buf[8];
		int idx[8], i;

		if(file->type == SC_FILE_TYPE_DF)
		{
			const int df_idx[8] =   /* These are the SC operations. */
			{
				0, /* Reserved. */
				SC_AC_OP_DELETE_SELF, 	//b6
				SC_AC_OP_LOCK, 			//b5
				SC_AC_OP_ACTIVATE, 		//b4
				SC_AC_OP_DEACTIVATE, 	//b3
				SC_AC_OP_CREATE_DF, 	//b2
				SC_AC_OP_CREATE_EF, 	//b1
				SC_AC_OP_DELETE 		//b0
			};
			for(i=0; i<8; i++)
			{
				idx[i] = df_idx[i];
			}
		}
		else   //EF
		{
			const int ef_idx[8] =
			{
				0, /* Reserved. */
				SC_AC_OP_DELETE_SELF, 	//b6
				SC_AC_OP_LOCK, 			//b5
				SC_AC_OP_ACTIVATE, 		//b4
				SC_AC_OP_DEACTIVATE,	//b3
				SC_AC_OP_WRITE, 		//b2
				SC_AC_OP_UPDATE, 		//b1
				SC_AC_OP_READ 			//b0
			};
			for(i=0; i<8; i++)
			{
				idx[i] = ef_idx[i];
			}
		}
		/* Now idx contains the operation identifiers.
		 * We now search for the OPs. */
		access_buf[0] = 0xFF; /* A security condition byte is present for every OP. (Table 19) */
		for(i=1; i<8; i++)
		{
			const sc_acl_entry_t *entry;
			entry = sc_file_get_acl_entry(file, idx[i]);
			access_buf[i] = acl_to_security_condition_byte(entry);
		}

		r = sc_file_set_sec_attr(file, access_buf, 8);
		LOG_TEST_RET(card->ctx, r, "Error adding security attribute.");
	}

	r = iso_ops->create_file(card, file);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Adds an ACL entry to the OpenSC file struct, according to the operation
 * and the saByte (Encoded according to IsoApplet FCI proprietary security
 * information, see also ISO 7816-4 table 20).
 *
 * @param[in,out]	file
 * @param[in] 		operation	The OpenSC operation.
 * @param[in]		saByte		The security condition byte return by the applet.
 */
static int
sa_to_acl(sc_file_t *file, unsigned int operation, u8 saByte)
{
	int r;
	switch(saByte)
	{
	case 0x90:
		r = sc_file_add_acl_entry(file, operation, SC_AC_CHV, 1);
		if(r < 0)
			return r;
		break;
	case 0xFF:
		r = sc_file_add_acl_entry(file, operation, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		if(r < 0)
			return r;
		break;
	case 0x00:
		r = sc_file_add_acl_entry(file, operation, SC_AC_NONE, SC_AC_KEY_REF_NONE);
		if(r < 0)
			return r;
		break;
	default:
		r = sc_file_add_acl_entry(file, operation, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
		if(r < 0)
			return r;
	}
	return SC_SUCCESS;
}


/*
 * This function first calls the iso7816.c process_fci() for any other FCI
 * information and then updates the ACL of the OpenSC file struct according
 * to the FCI from the applet.
 */
static int
isoApplet_process_fci(sc_card_t *card, sc_file_t *file,
                      const u8 *buf, size_t buflen)
{
	int r;
	u8 *sa = NULL;

	LOG_FUNC_CALLED(card->ctx);

	r = iso_ops->process_fci(card, file, buf, buflen);
	LOG_TEST_RET(card->ctx, r, "Error while processing the FCI.");
	/* Construct the ACL from the sec_attr. */
	if(file->sec_attr && file->sec_attr_len == 8)
	{
		sa = file->sec_attr;
		if(sa[0] != 0xFF)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA,
			             "File security attribute does not contain a ACL byte for every operation.");
		}
		if(file->type == SC_FILE_TYPE_DF)
		{
			r = sa_to_acl(file, SC_AC_OP_DELETE_SELF, sa[1]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_LOCK, sa[2]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_ACTIVATE, sa[3]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_DEACTIVATE, sa[4]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_CREATE_DF, sa[5]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_CREATE_EF, sa[6]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_DELETE, sa[7]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
		}
		else if(file->type == SC_FILE_TYPE_INTERNAL_EF
		        || file->type == SC_FILE_TYPE_WORKING_EF)
		{
			r = sa_to_acl(file, SC_AC_OP_DELETE_SELF, sa[1]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_LOCK, sa[2]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_ACTIVATE, sa[3]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_DEACTIVATE, sa[4]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_WRITE, sa[5]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_UPDATE, sa[6]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
			r = sa_to_acl(file, SC_AC_OP_READ, sa[7]);
			LOG_TEST_RET(card->ctx, r, "Error adding ACL entry.");
		}

	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoApplet_ctl_generate_key(sc_card_t *card, struct sc_cardctl_isoApplet_genkey *args)
{
	int r, len;
	size_t tag_len;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	const u8 *curr_pos;

	LOG_FUNC_CALLED(card->ctx);

	/* MANAGE SECURITY ENVIRONMENT (SET). Set the algorithm and key references. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0x00);

	p = sbuf;
	*p++ = 0x80; /* algorithm reference */
	*p++ = 0x01;
	*p++ = args->algorithm_ref;

	*p++ = 0x84; /* Private key reference */
	*p++ = 0x01;
	*p++ = args->priv_key_ref;

	r = p - sbuf;
	p = NULL;

	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x6A && apdu.sw2 == 0x81)
	{
		sc_log(card->ctx, "Key generation not supported by the card with that particular key type."
		       "Your card may not support the specified algorithm used by the applet / specified by you."
		       "In most cases, this happens when trying to generate EC keys not supported by your java card."
		       "In this case, look for supported field lengths and whether FP and/or F2M are supported.");
	}
	LOG_TEST_RET(card->ctx, r, "Card returned error");


	/* GENERATE ASYMMETRIC KEY PAIR
	 * We use a larger buffer here, even if the card does not support extended apdus.
	 * There are two cases:
	 *		1) The card can do ext. apdus: The data fits in one apdu.
	 *		2) The card can't do ext. apdus: sc_transmit_apdu will handle that - the
	 *			card will send SW_BYTES_REMAINING, OpenSC will automaticall do a
	 *			GET RESPONSE to get the remaining data, and will append it to the data
	 *			buffer. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x46, 0x42, 0x00);

	apdu.resp = rbuf;
	apdu.resplen = SC_MAX_EXT_APDU_BUFFER_SIZE;
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* Parse the public key / response. */
	switch(args->algorithm_ref)
	{

	case SC_ISOAPPLET_ALG_REF_RSA_GEN_2048:
		/* We expect:
		 *	- Tag: 7F 49
		 *	- Length: 82 01 09 (265 Bytes) */
		p = rbuf;
		if(memcmp(p, "\x7F\x49\x82\x01\x09", 5) != 0)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA,
			             "The data returned by the card is unexpected.");
		}
		else
		{
			len = 265;
		}
		p += 5; /* p points to the value field of the outer (7F 49) tag.
				 * This value field is a TLV-structure again. */

		/* Search for the modulus tag (81). */
		curr_pos = sc_asn1_find_tag(card->ctx, p, len, (unsigned int) 0x81, &tag_len);
		if(curr_pos == NULL || tag_len != 256)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid modulus.");
		}
		if(args->pubkey_len < 256)
		{
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
		}
		args->pubkey_len = tag_len;
		memcpy(args->pubkey, curr_pos, args->pubkey_len);

		/* Exponent tag (82) */
		curr_pos = sc_asn1_find_tag(card->ctx, p, len, (unsigned int) 0x82, &tag_len);
		if(curr_pos == NULL || tag_len != 3)
		{
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_DATA);
		}
		if(args->exponent_len < 3)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Card returned no or a invalid exponent.");
		}
		if(memcmp(curr_pos, "\x01\x00\x01", 3) != 0)
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_INCOMPATIBLE_KEY,
			             "Key generation error: Unexpected public key exponent.");
		}
		args->exponent_len = 3;
		memcpy(args->exponent, curr_pos, args->exponent_len);
		p = NULL;
		break;

	case SC_ISOAPPLET_ALG_REF_EC_GEN_BRAINPOOLP192R1:
		p = rbuf;
		if(args->pubkey_len >= apdu.resplen)
		{
			memcpy(args->pubkey, p, apdu.resplen);
		}
		else
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_BUFFER_TOO_SMALL,
			             "Key generation error: Public key buffer too small.");
		}
		break;

	case SC_ISOAPPLET_ALG_REF_EC_GEN_PRIME256V1:
		p = rbuf;
		if(args->pubkey_len >= apdu.resplen)
		{
			memcpy(args->pubkey, p, apdu.resplen);
		}
		else
		{
			LOG_TEST_RET(card->ctx, SC_ERROR_BUFFER_TOO_SMALL,
			             "Key generation error: Public key buffer too small.");
		}
		break;

	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unable to parse public key: Unsupported algorithm.");
	}// switch

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * @brief Insert the length field of a TLV entry.
 *
 * The format is:
 *		0..127:			1 byte, 00-7F
 *		128..255:		2 bytes, 81; 00-FF
 *		256..65535:		3 bytes, 82; 0000-FFFF
 *
 * @param[out] 	p 		The buffer where the length tag should be placed.
 * @param[in]	p_len	The length of p.
 * @param[in]	len		The length to be inserted.
 *
 * @return 	positive values:	The length of the length field inserted.
 *			SC_ERROR_INVALID_ARGUMENTS:	Incorrect length value or p == null.
 *			SC_ERROR_BUFFER_TOO_SMALL:	The buffer p can not hold the length field.
 */
static int
tlv_insert_len(u8 *p, size_t p_len, size_t len)
{
	if(p == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Note: len < 0 can not happen as it is size_t */
	if(len <= 127)
	{
		if(p_len < 1)
			return SC_ERROR_BUFFER_TOO_SMALL;
		*p++ = len & 0x7F;
		return 1;
	}
	else if(len <= 255)
	{
		if(p_len < 2)
			return SC_ERROR_BUFFER_TOO_SMALL;
		*p++ = 0x81;
		*p++ = len & 0xFF;
		return 2;
	}
	else if(len <= 65535)
	{
		if(p_len < 3)
			return SC_ERROR_BUFFER_TOO_SMALL;
		*p++ = 0x82;
		*p++ = (len >> 8) & 0xFF;	/* MSB */
		*p++ = len & 0xFF;			/* LSB */
		return 3;
	}
	else
	{
		return SC_ERROR_INVALID_ARGUMENTS;
	}
}

/*
 * @brief Add a TLV-entry to a buffer.
 *
 * @param[out] 	buf				The buffer at where the TLV entry should be placed.
 * @param[in]	buf_len			The length of buf.
 * @param[in]	tag				The one byte tag of the TLV entry.
 * @param[in]	tag_data		The value field of the TLV entry.
 * @param[in]	tag_data_len	The length of the tag_data.
 *
 */
static int
tlv_add_tlv(u8 *buf, const size_t buf_len, const u8 tag,
            const u8 *tag_data, const size_t tag_data_len)
{
	size_t l_len; /* Length of the length field itself. */
	int r;

	if(buf == NULL || tag_data == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	if(tag_data_len <= 127)
		l_len = 1;
	else if(tag_data_len <= 255)
		l_len = 2;
	else if(tag_data_len <= 65535)
		l_len = 3;
	else
		return SC_ERROR_INVALID_ARGUMENTS;

	if(1 + l_len + tag_data_len > buf_len)
		return SC_ERROR_BUFFER_TOO_SMALL;

	*buf++ = tag;
	r = tlv_insert_len(buf, buf_len-1, tag_data_len);
	if(r < 0)
		return r;
	else if((unsigned int)r != l_len)
		return SC_ERROR_UNKNOWN;

	buf += l_len;

	memcpy(buf, tag_data, tag_data_len);
	return 1 + l_len + tag_data_len;
}

/*
 * @brief Use PUT DATA to import a private RSA key.
 *
 * For simplicity, command chaining has to be used. One chunk (apdu) must contain
 * one RSA field (P, Q, etc.). The first apdu must contain the outer tag (7F48).
 *
 * @param card
 * @param rsa	The RSA private key to import.
 *
 * @return	SC_ERROR_INVALID_ARGUMENTS:	The RSA key does not contain CRT fields.
 *			other errors:				Transmit errors / errors returned by card.
 */
static int
isoApplet_put_data_prkey_rsa(sc_card_t *card, struct sc_pkcs15_prkey_rsa *rsa)
{
	sc_apdu_t apdu;
	const size_t sbuf_len = SC_MAX_APDU_BUFFER_SIZE;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p = NULL;
	int r;
	size_t tags_len;

	LOG_FUNC_CALLED(card->ctx);

	if(!rsa
	        || !rsa->p.data
	        || !rsa->q.data
	        || !rsa->iqmp.data
	        || !rsa->dmp1.data
	        || !rsa->dmq1.data)
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Only CRT RSA keys may be imported.");
	}


	p = sbuf;
	/* Note: The format is according to ISO 2-byte tag 7F48 */
	*p++ = 0x7F;		/* T-L pair to indicate a private key data object */
	*p++ = 0x48;
	/* Calculate the length of all inner tag-length-value entries.
	 * One entry consists of: tag (1 byte) + length (1 byte if < 128, 2 if >= 128) + value (len)
	 * It may actually happen that a parameter is 127 byte (leading zero) */
	tags_len =	1 + (rsa->p.len 	< 128 ? 1 : 2) + rsa->p.len +
	            1 + (rsa->q.len		< 128 ? 1 : 2) + rsa->q.len +
	            1 + (rsa->iqmp.len	< 128 ? 1 : 2) + rsa->iqmp.len +
	            1 + (rsa->dmp1.len	< 128 ? 1 : 2) + rsa->dmp1.len +
	            1 + (rsa->dmq1.len	< 128 ? 1 : 2) + rsa->dmq1.len;
	r = tlv_insert_len(p, sbuf_len - (p - sbuf), tags_len);		/* Private key data object length */
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	p += r;

	/* p */
	r = tlv_add_tlv(p, sbuf_len - (p - sbuf), 0x92, rsa->p.data, rsa->p.len);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	p += r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
	apdu.cla |= 0x10; /* Chaining */
	apdu.data = sbuf;
	apdu.datalen = p - sbuf;
	apdu.lc = p - sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x6D && apdu.sw2 == 0x00)
	{
		sc_log(card->ctx, "The applet returned that the PUT DATA instruction byte is not supported."
		       "If you are using an older applet version and are trying to import keys, please update your applet first.");
	}
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* q */
	p = sbuf;
	r = tlv_add_tlv(p, sbuf_len - (p - sbuf), 0x93, rsa->q.data, rsa->q.len);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	p += r;

	apdu.data = sbuf;
	apdu.datalen = p - sbuf;
	apdu.lc = p - sbuf;
	r = sc_check_apdu(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* 1/q mod p */
	p = sbuf;
	r = tlv_add_tlv(p, sbuf_len - (p - sbuf), 0x94, rsa->iqmp.data, rsa->iqmp.len);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	p += r;

	apdu.data = sbuf;
	apdu.datalen = p - sbuf;
	apdu.lc = p - sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* d mod (p-1) */
	p = sbuf;
	r = tlv_add_tlv(p, sbuf_len - (p - sbuf), 0x95, rsa->dmp1.data, rsa->dmp1.len);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	p += r;

	apdu.data = sbuf;
	apdu.datalen = p - sbuf;
	apdu.lc = p - sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* d mod (q-1) */
	p = sbuf;
	r = tlv_add_tlv(p, sbuf_len - (p - sbuf), 0x96, rsa->dmq1.data, rsa->dmq1.len);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");
	p += r;

	apdu.cla = 0x00; /* Last part of the chain. */
	apdu.data = sbuf;
	apdu.datalen = p - sbuf;
	apdu.lc = p - sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * @brief Use PUT DATA to import a private EC key.
 *
 * I use a simpler format for EC keys (compared to RSA)
 * because the card has all the necessary information except the ecPointQ.
 * Only the ecPointQ is sent to the card. It is BER-TLV-encoded. The tag is:
 * 0xC1 - Private class, primitive encoding, number one.
 *
 * @param card
 * @param ec	The EC private key to import.
 *
 * @return	SC_ERROR_INVALID_ARGUMENTS:	The RSA key does not contain CRT fields.
 *			other errors:				Transmit errors / errors returned by card.
 */
static int
isoApplet_put_data_prkey_ec(sc_card_t *card, struct sc_pkcs15_prkey_ec *ec)
{
	sc_apdu_t apdu;
	size_t sbuf_len = SC_MAX_EXT_APDU_BUFFER_SIZE;
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if(!ec)
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "No EC private key.");
	}

	r = tlv_add_tlv(sbuf, sbuf_len, 0xC1, ec->privateD.data, ec->privateD.len);
	LOG_TEST_RET(card->ctx, r, "Error in handling TLV.");

	/* Send to card. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x6D && apdu.sw2 == 0x00)
	{
		sc_log(card->ctx, "The applet returned that the PUT DATA instruction byte is not supported."
		       "If you are using an older applet version and are trying to import keys, please update your applet first.");
	}
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, r);

}

/*
 * @brief Import a private key.
 */
static int
isoApplet_ctl_import_key(sc_card_t *card, sc_cardctl_isoApplet_import_key_t *args)
{
	int r;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;

	LOG_FUNC_CALLED(card->ctx);

	/*
	 * Private keys are not stored in the filesystem.
	 * ISO 7816-8 - section C.2	 describes:
	 * "Usage of the PUT DATA command for private key import"
	 * The applet uses this PUT DATA to import private keys, if private key import is allowed.
	 *
	 * The first step is to perform a MANAGE SECURITY ENVIRONMENT as it would be done
	 * with on-card key generation. The second step is PUT DATA (instead of
	 * GENERATE ASYMMETRIC KEYPAIR).
	 */

	/* MANAGE SECURITY ENVIRONMENT (SET). Set the algorithm and key references. */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0x00);

	p = sbuf;
	*p++ = 0x80; /* algorithm reference */
	*p++ = 0x01;
	*p++ = args->algorithm_ref;

	*p++ = 0x84; /* Private key reference */
	*p++ = 0x01;
	*p++ = args->priv_key_ref;

	r = p - sbuf;
	p = NULL;

	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "%s: APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(apdu.sw1 == 0x6A && apdu.sw2 == 0x81)
	{
		sc_log(card->ctx, "Key import not supported by the card with that particular key type."
		       "Your card may not support the specified algorithm used by the applet / specified by you."
		       "In most cases, this happens when trying to import EC keys not supported by your java card."
		       "In this case, look for supported field lengths and whether FP and/or F2M are supported."
		       "If you tried to import a private RSA key, check the key length.");
	}
	if(apdu.sw1 == 0x69 && apdu.sw2 == 0x00)
	{
		sc_log(card->ctx, "Key import not allowed by the applet's security policy."
		       "If you want to allow key import, set DEF_PRIVATE_KEY_IMPORT_ALLOWED in the IsoApplet,"
		       " rebuild and reinstall the applet.");
	}
	LOG_TEST_RET(card->ctx, r, "Card returned error");


	/* PUT DATA */
	switch(args->algorithm_ref)
	{

	case SC_ISOAPPLET_ALG_REF_RSA_GEN_2048:
		r = isoApplet_put_data_prkey_rsa(card, &args->prkey->u.rsa);
		LOG_TEST_RET(card->ctx, r, "Error in PUT DATA.");
		break;

	case SC_ISOAPPLET_ALG_REF_EC_GEN_BRAINPOOLP192R1:
	case SC_ISOAPPLET_ALG_REF_EC_GEN_PRIME256V1:
		r = isoApplet_put_data_prkey_ec(card, &args->prkey->u.ec);
		LOG_TEST_RET(card->ctx, r, "Error in PUT DATA.");
		break;

	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Uknown algorithm refernce.");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
isoApplet_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int r = 0;

	LOG_FUNC_CALLED(card->ctx);
	switch (cmd)
	{
	case SC_CARDCTL_ISOAPPLET_GENERATE_KEY:
		r = isoApplet_ctl_generate_key(card,
		                               (sc_cardctl_isoApplet_genkey_t *) ptr);
		break;
	case SC_CARDCTL_ISOAPPLET_IMPORT_KEY:
		r = isoApplet_ctl_import_key(card,
		                             (sc_cardctl_isoApplet_import_key_t *) ptr);
		break;
	default:
		r = SC_ERROR_NOT_SUPPORTED;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
isoApplet_set_security_env(sc_card_t *card,
                           const sc_security_env_t *env, int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;
	struct isoApplet_drv_data *drvdata = DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if(se_num != 0)
	{
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
		             "IsoApplet does not support storing of security environments.");
	}
	assert(card != NULL && env != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);
	switch (env->operation)
	{
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p = sbuf;

	if (env->flags & SC_SEC_ENV_ALG_PRESENT)
	{

		switch(env->algorithm)
		{

		case SC_ALGORITHM_RSA:
			if( env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1 )
			{
				drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_RSA_PAD_PKCS1;
			}
			else
			{
				LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "IsoApplet only supports RSA with PKCS1 padding.");
			}
			break;

		case SC_ALGORITHM_EC:
			if( env->algorithm_flags & SC_ALGORITHM_ECDSA_RAW )
			{
				drvdata->sec_env_alg_ref = ISOAPPLET_ALG_REF_ECDSA;
			}
			else
			{
				LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "IsoApplet only supports raw ECDSA.");
			}
			break;

		default:
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported algorithm.");
		}

		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = drvdata->sec_env_alg_ref;
	}

	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
	{
		*p++ = 0x81;
		*p++ = env->file_ref.len;
		assert(sizeof(sbuf) - (p - sbuf) >= env->file_ref.len);
		memcpy(p, env->file_ref.value, env->file_ref.len);
		p += env->file_ref.len;
	}

	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	{
		if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		*p++ = env->key_ref_len;
		assert(sizeof(sbuf) - (p - sbuf) >= env->key_ref_len);
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;

	if (se_num > 0)
	{
		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}

	if (apdu.datalen != 0)
	{
		r = sc_transmit_apdu(card, &apdu);
		if (r)
		{
			sc_log(card->ctx, "%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
		{
			sc_log(card->ctx, "%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}

	if (se_num <= 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num);
	r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, r);
err:
	if (locked)
		sc_unlock(card);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
isoApplet_compute_signature(struct sc_card *card,
                            const u8 * data, size_t datalen,
                            u8 * out, size_t outlen)
{
	struct isoApplet_drv_data *drvdata = DRVDATA(card);
	int r;
	size_t xlen, ylen;
	size_t i, offset;

	LOG_FUNC_CALLED(card->ctx);

	r = iso_ops->compute_signature(card, data, datalen, out, outlen);
	if(r < 0)
	{
		LOG_FUNC_RETURN(card->ctx, r);
	}

	/* If we used ECDSA for the signature op, OpenSC thinks it has to
	 * convert it to {sequence, sequence} which is already done by the
	 * card actually.
	 * To fix this, I strip the {sequence, sequence} structual information
	 * so that pkcs11-tool.c can add it again... */
	if(drvdata->sec_env_alg_ref == ISOAPPLET_ALG_REF_ECDSA)
	{
		/* Outer SEQUENCE tag and first INTEGER tag. */
		offset=0;
		if(r < 2
		        || out[offset++] != 0x30
		        || out[offset++] != r-2
		        || out[offset++] != 0x02)
		{
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}

		/* X */
		xlen = out[offset++];
		assert(xlen+4 < outlen);
		/* Remove the leading 0 of the coordinate, if present. */
		if(out[offset] == 0x00)
		{
			offset++;
			xlen--;
		}
		for(i=0; i < xlen; i++)
		{
			out[i] = out[i+offset];
		}

		/* Y */
		assert(i+offset+3 < outlen);
		if(out[i+offset++] != 0x02)
		{
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}
		ylen = out[i+offset++];
		/* Remove the leading 0 of the coordinate, if present. */
		if(out[i+offset] == 0x00)
		{
			offset++;
			ylen--;
		}
		assert(offset+xlen+ylen <= outlen);
		for(; i < xlen+ylen; i++)
		{
			out[i] = out[i+offset];
		}
		r = xlen+ylen;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static struct sc_card_driver *sc_get_driver(void)
{
	sc_card_driver_t *iso_drv = sc_get_iso7816_driver();

	if(iso_ops == NULL)
	{
		iso_ops = iso_drv->ops;
	}

	isoApplet_ops = *iso_drv->ops;

	isoApplet_ops.match_card = isoApplet_match_card;
	isoApplet_ops.init = isoApplet_init;
	isoApplet_ops.finish = isoApplet_finish;

	isoApplet_ops.card_ctl = isoApplet_card_ctl;

	isoApplet_ops.create_file = isoApplet_create_file;
	isoApplet_ops.process_fci = isoApplet_process_fci;
	isoApplet_ops.set_security_env = isoApplet_set_security_env;
	isoApplet_ops.compute_signature = isoApplet_compute_signature;

	/* unsupported functions */
	isoApplet_ops.write_binary = NULL;
	isoApplet_ops.read_record = NULL;
	isoApplet_ops.write_record = NULL;
	isoApplet_ops.append_record = NULL;
	isoApplet_ops.update_record = NULL;
	isoApplet_ops.get_challenge = NULL;
	isoApplet_ops.restore_security_env = NULL;

	return &isoApplet_drv;
}

struct sc_card_driver * sc_get_isoApplet_driver(void)
{
	return sc_get_driver();
}
