/*
 * card-etoken.c: Support for Siemens CardOS based cards and tokens
 * 	(for example Aladdin eToken PRO, Eutron CryptoIdentity IT-SEC)
 *
 * Copyright (C) 2002  Andreas Jellinghaus <aj@dungeon.inka.de>
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#include "cardctl.h"
#include <ctype.h>
#include <string.h>

/* andreas says: hm, my card only works for small payloads */
/* comment by okir: one of the examples in the developer guide
 * also talks about copying data in chunks of 128.
 * Either coincidence, or a known problem. */
#define ETOKEN_MAX_PAYLOAD	120

/* Different eToken types */
#define CARDOS_TYPE_ANY		1

static const struct sc_card_operations *iso_ops = NULL;

struct sc_card_operations etoken_ops;
struct sc_card_driver etoken_drv = {
	"Siemens CardOS",
	"etoken",
	&etoken_ops
};

const struct {
	const char *	atr;
	int		type;
} etoken_atrs[] = {
    { "3b:e2:00:ff:c1:10:31:fe:55:c8:02:9c",	CARDOS_TYPE_ANY }, /* 4.0 */
    { "3b:f2:98:00:ff:c1:10:31:fe:55:c8:03:15",	CARDOS_TYPE_ANY }, /* 4.01 */
    { "3b:f2:98:00:ff:c1:10:31:fe:55:c8:04:12",	CARDOS_TYPE_ANY }, /* 4.01a */
    /* Italian eID card: */
    { "3b:e9:00:ff:c1:10:31:fe:55:00:64:05:00:c8:02:31:80:00:47", CARDOS_TYPE_ANY },
    /* Italian eID card from Infocamere */
    { "3b:fb:98:00:ff:c1:10:31:fe:55:00:64:05:20:47:03:31:80:00:90:00:f3", CARDOS_TYPE_ANY },

    { NULL }
};

int etoken_finish(struct sc_card *card)
{
	return 0;
}

int etoken_identify_card(struct sc_card *card)
{
	int i;

	for (i = 0; etoken_atrs[i].atr; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);

		if (sc_hex_to_bin(etoken_atrs[i].atr, defatr, &len))
			continue;
		if (len != card->atr_len)
			continue;
		if (!memcmp(card->atr, defatr, len))
			return etoken_atrs[i].type;
	}

	return 0;
}

int etoken_match_card(struct sc_card *card)
{
	return etoken_identify_card(card) != 0;
}

int etoken_init(struct sc_card *card)
{
	unsigned long	flags;

	card->name = "CardOS M4";
	card->cla = 0x00;

	/* Set up algorithm info. */
	flags = SC_ALGORITHM_NEED_USAGE
		| SC_ALGORITHM_RSA_RAW
		| SC_ALGORITHM_RSA_HASH_NONE
		| SC_ALGORITHM_ONBOARD_KEY_GEN
		;
	_sc_card_add_rsa_alg(card,  512, flags, 0);
	_sc_card_add_rsa_alg(card,  768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);

	return 0;
}

const static struct sc_card_error etoken_errors[] = {
/* some error inside the card */
/* i.e. nothing you can do */
{ 0x6581, SC_ERROR_MEMORY_FAILURE,	"EEPROM error; command aborted"}, 
{ 0x6fff, SC_ERROR_CARD_CMD_FAILED,	"internal assertion error"},
{ 0x6700, SC_ERROR_WRONG_LENGTH,	"LC invalid"}, 
{ 0x6985, SC_ERROR_CARD_CMD_FAILED,	"no random number available"}, 
{ 0x6f81, SC_ERROR_CARD_CMD_FAILED,	"file invalid, maybe checksum error"}, 
{ 0x6f82, SC_ERROR_CARD_CMD_FAILED,	"not enough memory in xram"}, 
{ 0x6f84, SC_ERROR_CARD_CMD_FAILED,	"general protection fault"}, 

/* the card doesn't now thic combination of ins+cla+p1+p2 */
/* i.e. command will never work */
{ 0x6881, SC_ERROR_NO_CARD_SUPPORT,	"logical channel not supported"}, 
{ 0x6a86, SC_ERROR_INCORRECT_PARAMETERS,"p1/p2 invalid"}, 
{ 0x6d00, SC_ERROR_INS_NOT_SUPPORTED,	"ins invalid"}, 
{ 0x6e00, SC_ERROR_CLASS_NOT_SUPPORTED,	"class invalid (hi nibble)"}, 

/* known command, but incorrectly used */
/* i.e. command could work, but you need to change something */
{ 0x6981, SC_ERROR_CARD_CMD_FAILED,	"command cannot be used for file structure"}, 
{ 0x6a80, SC_ERROR_INCORRECT_PARAMETERS,"invalid parameters in data field"}, 
{ 0x6a81, SC_ERROR_NOT_SUPPORTED,	"function/mode not supported"}, 
{ 0x6a85, SC_ERROR_INCORRECT_PARAMETERS,"lc does not fit the tlv structure"}, 
{ 0x6986, SC_ERROR_INCORRECT_PARAMETERS,"no current ef selected"}, 
{ 0x6a87, SC_ERROR_INCORRECT_PARAMETERS,"lc does not fit p1/p2"}, 
{ 0x6c00, SC_ERROR_WRONG_LENGTH,	"le does not fit the data to be sent"}, 
{ 0x6f83, SC_ERROR_CARD_CMD_FAILED,	"command must not be used in transaction"}, 

/* (something) not found */
{ 0x6987, SC_ERROR_INCORRECT_PARAMETERS,"key object for sm not found"}, 
{ 0x6f86, SC_ERROR_CARD_CMD_FAILED,	"key object not found"}, 
{ 0x6a82, SC_ERROR_FILE_NOT_FOUND,	"file not found"}, 
{ 0x6a83, SC_ERROR_RECORD_NOT_FOUND,	"record not found"}, 
{ 0x6a88, SC_ERROR_CARD_CMD_FAILED,	"object not found"}, 

/* (something) invalid */
{ 0x6884, SC_ERROR_CARD_CMD_FAILED,	"chaining error"}, 
{ 0x6984, SC_ERROR_CARD_CMD_FAILED,	"bs object has invalid format"}, 
{ 0x6988, SC_ERROR_INCORRECT_PARAMETERS,"key object used for sm has invalid format"}, 

/* (something) deactivated */
{ 0x6283, SC_ERROR_CARD_CMD_FAILED,	"file is deactivated"	},
{ 0x6983, SC_ERROR_AUTH_METHOD_BLOCKED,	"bs object blocked"}, 

/* access denied */
{ 0x6300, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,"authentication failed"}, 
{ 0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,"required access right not granted"}, 

/* other errors */
{ 0x6a84, SC_ERROR_CARD_CMD_FAILED,	"not enough memory"}, 

/* command ok, execution failed */
{ 0x6f00, SC_ERROR_CARD_CMD_FAILED,	"technical error (see eToken developers guide)"}, 

/* no error, maybe a note */
{ 0x9000, SC_NO_ERROR,		NULL}, 
{ 0x9001, SC_NO_ERROR,		"success, but eeprom weakness detected"}, 
{ 0x9850, SC_NO_ERROR,		"over/underflow useing in/decrease"}
};

static int etoken_check_sw(struct sc_card *card, int sw1, int sw2)
{
	const int err_count = sizeof(etoken_errors)/sizeof(etoken_errors[0]);
	int i;
			        
	for (i = 0; i < err_count; i++) {
		if (etoken_errors[i].SWs == ((sw1 << 8) | sw2)) {
			if ( etoken_errors[i].errorstr ) 
				sc_error(card->ctx, "%s\n",
				 	etoken_errors[i].errorstr);
			return etoken_errors[i].errorno;
		}
	}

        sc_error(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
	return SC_ERROR_CARD_CMD_FAILED;
}

u8 etoken_extract_offset(u8 *buf, int buflen) {
	int i;
	int mode;
	u8 tag,len;

	tag=0; len=0;
	mode = 0;

	for (i=0; i < buflen;) {
		if (mode == 0) {
			tag = buf[i++];
			mode=1;
			continue;
		}
		if (mode == 1) {
			len=buf[i++];
			mode=2;
			continue;
		}
		if (len == 0) {
			mode=0;
			continue;
		}
		if (tag == 0x8a && len == 1) {
			return buf[i];
		}

		i+=len;
		mode=0;
	}
	
	return 0;
}

u8* etoken_extract_fid(u8 *buf, int buflen) {
	int i;
	int mode;
	u8 tag,len;

	mode = 0;
	tag = 0;
	len = 0;


	for (i=0; i < buflen;) {
		if (mode == 0) {
			tag = buf[i++];
			mode=1;
			continue;
		}
		if (mode == 1) {
			len=buf[i++];
			mode=2;
			continue;
		}
		if (len == 0) {
			mode=0;
			continue;
		}
		if ((tag == 0x86) && (len == 2) && (i+1 < buflen)) {
			return &buf[i];
		}

		i+=len;
		mode=0;
	}
	
	return NULL;
}

int etoken_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	u8 rbuf[256];
	int r;
	int len;
	size_t i, fids;
	u8 offset;
	u8 *fid;

	SC_FUNC_CALLED(card->ctx, 1);

	fids=0;
	offset=0;

	/* 0x16: DIRECTORY */
	/* 0x02: list both DF and EF */

get_next_part:
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x16, 0x02, offset);
	apdu.cla = 0x80;
	apdu.le = 256;
	apdu.resplen = 256;
	apdu.resp = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "DIRECTORY command returned error");

	if (apdu.resplen > 256) {
		sc_error(card->ctx, "directory listing > 256 bytes, cutting");
		r = 256;
	}
	for (i=0; i < apdu.resplen;) {
		/* is there a file informatin block (0x6f) ? */
		if (rbuf[i] != 0x6f) {
			sc_error(card->ctx, "directory listing not parseable");
			break;
		}
		if (i+1 > apdu.resplen) {
			sc_error(card->ctx, "directory listing short");
			break;
		}
		len = rbuf[i+1];
		if (i + 1 + len > apdu.resplen) {
			sc_error(card->ctx, "directory listing short");
			break;
		}
		fid = etoken_extract_fid(&rbuf[i+2], len);

		if (fid) {
			if (fids + 2 >= buflen)
				break;
			buf[fids++] = fid[0];
			buf[fids++] = fid[1];
		}

		offset = etoken_extract_offset(&rbuf[i+2], len);
		if (offset) 
			goto get_next_part;
		i += len+2;
	}

	r = fids;

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static void add_acl_entry(struct sc_file *file, int op, u8 byte)
{
	unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

	switch (byte) {
	case 0x00:
		method = SC_AC_NONE;
		break;
	case 0xFF:
		method = SC_AC_NEVER;
		break;
	default:
		if (byte > 0x7F) {
			method = SC_AC_UNKNOWN;
		} else {
			method = SC_AC_CHV;
			key_ref = byte;
		}
		break;
	}
	sc_file_add_acl_entry(file, op, method, key_ref);
}

static int acl_to_byte(const struct sc_acl_entry *e)
{
	if (e != NULL) {
		switch (e->method) {
		case SC_AC_NONE:
			return 0x00;
		case SC_AC_NEVER:
			return 0xFF;
		case SC_AC_CHV:
		case SC_AC_TERM:
		case SC_AC_AUT:
			if (e->key_ref == SC_AC_KEY_REF_NONE)
				return -1;
			if (e->key_ref < 0x00 || e->key_ref > 0x7F)
				return -1;
			return e->key_ref;
		}
	}
        return 0x00;
}

static const int df_acl[9] = {
	-1,			/* LCYCLE (life cycle change) */
	SC_AC_OP_UPDATE,	/* UPDATE Objects */
	-1,			/* APPEND Objects */

	SC_AC_OP_INVALIDATE,	/* DF */
	SC_AC_OP_REHABILITATE,	/* DF */
	SC_AC_OP_DELETE,	/* DF */

	-1,			/* ADMIN DF */
	SC_AC_OP_CREATE,	/* Files */
	-1			/* Reserved */
};
static const int ef_acl[9] = {
	SC_AC_OP_READ,		/* Data */
	SC_AC_OP_UPDATE,	/* Data (write file content) */
	SC_AC_OP_WRITE,		/* */

	SC_AC_OP_INVALIDATE,	/* EF */
	SC_AC_OP_REHABILITATE,	/* EF */
	SC_AC_OP_ERASE,		/* (delete) EF */

	/* XXX: ADMIN should be an ACL type of its own, or mapped
	 * to erase */
	-1,			/* ADMIN EF (modify meta information?) */
	-1,			/* INC (-> cylic fixed files) */
	-1			/* DEC */
};

static void parse_sec_attr(struct sc_file *file, const u8 *buf, size_t len)
{
	size_t i;
	const int *idx;

	idx = (file->type == SC_FILE_TYPE_DF) ?  df_acl : ef_acl;

	/* acl defaults to 0xFF if unspecified */
	for (i = 0; i < 9; i++)
		if (idx[i] != -1)
			add_acl_entry(file, idx[i], (u8)((i < len) ? buf[i] : 0xFF));
}

static int etoken_select_file(struct sc_card *card,
			      const struct sc_path *in_path,
			      struct sc_file **file)
{
	int r;
	
	SC_FUNC_CALLED(card->ctx, 1);
	r = iso_ops->select_file(card, in_path, file);
	if (r >= 0 && file)
		parse_sec_attr((*file), (*file)->sec_attr, (*file)->sec_attr_len);
	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int etoken_create_file(struct sc_card *card, struct sc_file *file)
{
	int r, i, byte;
	const int *idx;
	u8 acl[9], type[3], status[3];

	if (card->ctx->debug >= 1) {
		char	pbuf[128+1];
		size_t	n;

		for (n = 0; n < file->path.len; n++) {
			snprintf(pbuf + 2 * n, sizeof(pbuf) - 2 * n,
				"%02X", file->path.value[n]);
		}

		sc_debug(card->ctx, "etoken_create_file(%s)\n", pbuf);
	}

	if (file->type_attr_len == 0) {
		memset(type, 0, sizeof(type));
		type[0] = 0x00;
		switch (file->type) {
		case SC_FILE_TYPE_WORKING_EF:
			break;
		case SC_FILE_TYPE_INTERNAL_EF:
			type[0] = 0x08;
			break;
		case SC_FILE_TYPE_DF:
			type[0] = 0x38;
			break;
		default:
			r = SC_ERROR_NOT_SUPPORTED;
			goto out;
		}
		if (file->type != SC_FILE_TYPE_DF) {
			switch (file->ef_structure) {
			case SC_FILE_EF_LINEAR_FIXED_TLV:
			case SC_FILE_EF_LINEAR_VARIABLE:
			case SC_FILE_EF_CYCLIC_TLV:
				r = SC_ERROR_NOT_SUPPORTED;
				goto out;
				/* No idea what this means, but it
				 * seems to be required for key
				 * generation. */
			case SC_FILE_EF_LINEAR_VARIABLE_TLV:
				type[1] = 0xff;
			default:
				type[0] |= file->ef_structure & 7;
				break;
			}
		}
		r = sc_file_set_type_attr(file, type, sizeof(type));
		if (r)
			goto out;
	}
	if (file->prop_attr_len == 0) {
		status[0] = 0x01;
		if (file->type == SC_FILE_TYPE_DF) {
			status[1] = file->size >> 8;
			status[2] = file->size;
		} else {
			status[1] = status[2] = 0x00; /* not used */
		}
		r = sc_file_set_prop_attr(file, status, sizeof(status));
		if (r)
			goto out;
	}
	if (file->sec_attr_len == 0) {
		idx = (file->type == SC_FILE_TYPE_DF) ?  df_acl : ef_acl;
		for (i = 0; i < 9; i++) {
			if (idx[i] < 0)
				byte = 0x00;
			else
				byte = acl_to_byte(
				    sc_file_get_acl_entry(file, idx[i]));
                        if (byte < 0) {
                                sc_error(card->ctx, "Invalid ACL\n");
                                r = SC_ERROR_INVALID_ARGUMENTS;
				goto out;
                        }
			acl[i] = byte;
		}
		r = sc_file_set_sec_attr(file, acl, sizeof(acl));
		if (r)
			goto out;
	}
	r = iso_ops->create_file(card, file);

	/* FIXME: if this is a DF and there's an AID, set it here
	 * using PUT_DATA_FCI */

out:	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * Restore the indicated SE
 */
static int
etoken_restore_security_env(struct sc_card *card, int se_num)
{
	struct sc_apdu apdu;
	int	r;

	SC_FUNC_CALLED(card->ctx, 1);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 3, se_num);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * Set the security context
 * Things get a little messy here. It seems you cannot do any
 * crypto without a security environment - but there isn't really
 * a way to specify the security environment in PKCS15.
 * What I'm doing here (for now) is to assume that for a key
 * object with ID 0xNN there is always a corresponding SE object
 * with the same ID.
 * XXX Need to find out how the Aladdin drivers do it.
 */
static int
etoken_set_security_env(struct sc_card *card,
			    const struct sc_security_env *env,
			    int se_num)
{
	struct sc_apdu apdu;
	u8	data[3];
	int	key_id, r;

	assert(card != NULL && env != NULL);

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	 || env->key_ref_len != 1) {
		sc_error(card->ctx, "No or invalid key reference\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	key_id = env->key_ref[0];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 1, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	data[0] = 0x83;
	data[1] = 0x01;
	data[2] = key_id;
	apdu.lc = apdu.datalen = 3;
	apdu.data = data;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * Compute digital signature
 */

/* internal function to do the actual signature computation */
static int
do_compute_signature(struct sc_card *card, const u8 *data, size_t datalen,
		     u8 *out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	if (datalen > SC_MAX_APDU_BUFFER_SIZE ||
	    outlen > SC_MAX_APDU_BUFFER_SIZE)
		return SC_ERROR_INTERNAL;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.resp = rbuf;
	apdu.le = outlen;
	apdu.resplen = sizeof(rbuf);

	memcpy(sbuf, data, datalen);
	apdu.data = sbuf;
	apdu.lc = datalen;
	apdu.datalen = datalen;
	apdu.sensitive = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		memcpy(out, rbuf, outlen);
		SC_FUNC_RETURN(card->ctx, 4, apdu.resplen);
	}
	SC_FUNC_RETURN(card->ctx, 4, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int
etoken_compute_signature(struct sc_card *card, const u8 *data, size_t datalen,
			 u8 *out, size_t outlen)
{
	int    r;
	u8     buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t buf_len = sizeof(buf), tmp_len = buf_len;
	struct sc_context *ctx;

	assert(card != NULL && data != NULL && out != NULL);	
	ctx = card->ctx;
	SC_FUNC_CALLED(ctx, 1);

	if (datalen > 255)
		SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_INVALID_ARGUMENTS);
	if (outlen < datalen)
		SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_BUFFER_TOO_SMALL);
	outlen = datalen;

	/* XXX As we don't know what operations are allowed with a
	 * certain key, let's try RSA_PURE etc. and see which operation
	 * succeeds (this is not really beautiful, but currently the
	 * only way I see) -- Nils
	 */
	if (ctx->debug >= 3)
		sc_debug(ctx, "trying RSA_PURE_SIG (padded DigestInfo)\n");
	r = do_compute_signature(card, data, datalen, out, outlen);
	if (r >= SC_SUCCESS)
		SC_FUNC_RETURN(ctx, 4, r);
	if (ctx->debug >= 3)
		sc_debug(ctx, "trying RSA_SIG (just the DigestInfo)\n");
	/* remove padding: first try pkcs1 bt01 padding */
	r = sc_pkcs1_strip_01_padding(data, datalen, buf, &tmp_len);
	if (r != SC_SUCCESS) {
		/* no pkcs1 bt01 padding => let's try zero padding */
		tmp_len = buf_len;
		r = sc_strip_zero_padding(data, datalen, buf, &tmp_len);
		if (r != SC_SUCCESS)
			SC_FUNC_RETURN(ctx, 4, r);
	}
	r = do_compute_signature(card, buf, tmp_len, out, outlen);
	if (r >= SC_SUCCESS)	
		SC_FUNC_RETURN(ctx, 4, r);
	if (ctx->debug >= 3)
		sc_debug(ctx, "trying to sign raw hash value\n");
	r = sc_pkcs1_strip_digest_info_prefix(NULL,buf,tmp_len,buf,&buf_len);
	if (r != SC_SUCCESS)
		SC_FUNC_RETURN(ctx, 4, r);
	return do_compute_signature(card, buf, buf_len, out, outlen);
}

static int
etoken_lifecycle_get(struct sc_card *card, int *mode)
{
	struct sc_apdu	apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int		r;

	SC_FUNC_CALLED(card->ctx, 1);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 01, 0x83);
	apdu.cla = 0x00;
	apdu.le = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	if (apdu.resplen < 1) {
		SC_TEST_RET(card->ctx, r, "Lifecycle byte not in response");
	}

	r = SC_SUCCESS;
	switch (rbuf[0]) {
	case 0x10:
		*mode = SC_CARDCTRL_LIFECYCLE_USER;
		break;
	case 0x20:
		*mode = SC_CARDCTRL_LIFECYCLE_ADMIN;
		break;
	case 0x34: /* MANUFACTURING */
		*mode = SC_CARDCTRL_LIFECYCLE_OTHER;
		break;
	default:
		sc_error(card->ctx, "Unknown lifecycle byte %d", rbuf[0]);
		r = SC_ERROR_INTERNAL;
	}

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int
etoken_lifecycle_set(struct sc_card *card, int *mode)
{
	struct sc_apdu	apdu;
	int		r;

	int current;
	int target;

	SC_FUNC_CALLED(card->ctx, 1);

	target = *mode;

	r = etoken_lifecycle_get(card, &current);
	
	if (r != SC_SUCCESS)
		return r;

	if (current == target || current == SC_CARDCTRL_LIFECYCLE_OTHER)
		return SC_SUCCESS;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x10, 0, 0);
	apdu.cla = 0x80;
	apdu.le = 0;
	apdu.resplen = 0;
	apdu.resp = NULL;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int
etoken_put_data_oci(struct sc_card *card,
			struct sc_cardctl_etoken_obj_info *args)
{
	struct sc_apdu	apdu;
	int		r;

	SC_FUNC_CALLED(card->ctx, 1);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x00;
	apdu.ins = 0xda;
	apdu.p1  = 0x01;
	apdu.p2  = 0x6e;
	apdu.lc  = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int
etoken_put_data_seci(struct sc_card *card,
			struct sc_cardctl_etoken_obj_info *args)
{
	struct sc_apdu	apdu;
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x00;
	apdu.ins = 0xda;
	apdu.p1  = 0x01;
	apdu.p2  = 0x6d;
	apdu.lc  = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}

static int
etoken_generate_key(struct sc_card *card,
		struct sc_cardctl_etoken_genkey_info *args)
{
	struct sc_apdu	apdu;
	u8		data[8];
	int		r;

	if (args->random_len) {
		/* XXX FIXME: do a GIVE_RANDOM command with this data */
		sc_error(card->ctx,
			"initialization of card's random pool "
			"not yet implemented\n");
		return SC_ERROR_INTERNAL;
	}

	data[0] = 0x20;		/* store as PSO object */
	data[1] = args->key_id;
	data[2] = args->fid >> 8;
	data[3] = args->fid & 0xff;
	data[4] = 0;		/* additional Rabin Miller tests */
	data[5] = 0x10;		/* length difference between p, q (bits) */
	data[6] = 0;		/* default length of exponent, MSB */
	data[7] = 0x20;		/* default length of exponent, LSB */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x00;
	apdu.ins = 0x46;
	apdu.p1  = 0x00;
	apdu.p2  = args->key_id;/* doc is not clear, it just says "ID" */
	apdu.p2  = 0x00;
	apdu.data= data;
	apdu.datalen = apdu.lc = sizeof(data);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "GENERATE_KEY failed");

	return r;
}

static int
etoken_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_ETOKEN_PUT_DATA_FCI:
		break;
	case SC_CARDCTL_ETOKEN_PUT_DATA_OCI:
		return etoken_put_data_oci(card,
			(struct sc_cardctl_etoken_obj_info *) ptr);
		break;
	case SC_CARDCTL_ETOKEN_PUT_DATA_SECI:
		return etoken_put_data_seci(card,
			(struct sc_cardctl_etoken_obj_info *) ptr);
		break;
	case SC_CARDCTL_ETOKEN_GENERATE_KEY:
		return etoken_generate_key(card,
			(struct sc_cardctl_etoken_genkey_info *) ptr);
	case SC_CARDCTL_LIFECYCLE_GET:
		return etoken_lifecycle_get(card, (int *) ptr);
	case SC_CARDCTL_LIFECYCLE_SET:
		return etoken_lifecycle_set(card, (int *) ptr);
	}
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * The 0x80 thing tells the card it's okay to search parent
 * directories as well for the referenced object.
 * Unfortunately, it doesn't seem to work without this flag :-/
 */
static int
etoken_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data,
		 int *tries_left)
{
	data->flags |= SC_PIN_CMD_NEED_PADDING;
	data->pin_reference |= 0x80;
	/* FIXME: the following values depend on what pin length was
	 * used when creating the BS objects */
	if (data->pin1.max_length == 0)
		data->pin1.max_length = 8;
	if (data->pin2.max_length == 0)
		data->pin2.max_length = 8;
	return iso_ops->pin_cmd(card, data, tries_left);
}


/* eToken R2 supports WRITE_BINARY, PRO Tokens support UPDATE_BINARY */

static struct sc_card_driver * sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	etoken_ops = *iso_ops;
	etoken_ops.match_card = etoken_match_card;
	etoken_ops.init = etoken_init;
	etoken_ops.finish = etoken_finish;
	etoken_ops.select_file = etoken_select_file;
	etoken_ops.create_file = etoken_create_file;
	etoken_ops.set_security_env = etoken_set_security_env;
	etoken_ops.restore_security_env = etoken_restore_security_env;
	etoken_ops.compute_signature = etoken_compute_signature;

	etoken_ops.list_files = etoken_list_files;
	etoken_ops.check_sw = etoken_check_sw;
	etoken_ops.card_ctl = etoken_card_ctl;
	etoken_ops.pin_cmd = etoken_pin_cmd;

	return &etoken_drv;
}

#if 1
struct sc_card_driver * sc_get_etoken_driver(void)
{
	return sc_get_driver();
}
#endif
