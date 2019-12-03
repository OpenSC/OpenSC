/*
 * card-tcos.c: Support for TCOS cards
 *
 * Copyright (C) 2011  Peter Koch <pk@opensc-project.org>
 * Copyright (C) 2002  g10 Code GmbH
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

static const struct sc_atr_table tcos_atrs[] = {
	/* Infineon SLE44 */
	{ "3B:BA:13:00:81:31:86:5D:00:64:05:0A:02:01:31:80:90:00:8B", NULL, NULL, SC_CARD_TYPE_TCOS_V2, 0, NULL },
	/* Infineon SLE66S */
	{ "3B:BA:14:00:81:31:86:5D:00:64:05:14:02:02:31:80:90:00:91", NULL, NULL, SC_CARD_TYPE_TCOS_V2, 0, NULL },
	/* Infineon SLE66CX320P */
	{ "3B:BA:96:00:81:31:86:5D:00:64:05:60:02:03:31:80:90:00:66", NULL, NULL, SC_CARD_TYPE_TCOS_V2, 0, NULL },
	/* Infineon SLE66CX322P */
	{ "3B:BA:96:00:81:31:86:5D:00:64:05:7B:02:03:31:80:90:00:7D", NULL, NULL, SC_CARD_TYPE_TCOS_V2, 0, NULL },
	/* Philips P5CT072 */
	{ "3B:BF:96:00:81:31:FE:5D:00:64:04:11:03:01:31:C0:73:F7:01:D0:00:90:00:7D", NULL, NULL, SC_CARD_TYPE_TCOS_V3, 0, NULL },
	{ "3B:BF:96:00:81:31:FE:5D:00:64:04:11:04:0F:31:C0:73:F7:01:D0:00:90:00:74", NULL, NULL, SC_CARD_TYPE_TCOS_V3, 0, NULL },
	/* Philips P5CT080 */
	{ "3B:BF:B6:00:81:31:FE:5D:00:64:04:28:03:02:31:C0:73:F7:01:D0:00:90:00:67", NULL, NULL, SC_CARD_TYPE_TCOS_V3, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations tcos_ops;
static struct sc_card_driver tcos_drv = {
	"TCOS 3.0",
	"tcos",
	&tcos_ops,
	NULL, 0, NULL
};

static const struct sc_card_operations *iso_ops = NULL;

typedef struct tcos_data_st {
	unsigned int pad_flags;
	unsigned int next_sign;
} tcos_data;


static int tcos_finish(sc_card_t *card)
{
	free(card->drv_data);
	return 0;
}


static int tcos_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, tcos_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}


static int tcos_init(sc_card_t *card)
{
        unsigned long flags = 0;

	tcos_data *data = malloc(sizeof(tcos_data));
	if (!data) return SC_ERROR_OUT_OF_MEMORY;

	card->name = "TCOS";
	card->drv_data = (void *)data;
	card->cla = 0x00;

        if (card->type != SC_CARD_TYPE_TCOS_V3) {
                flags |= SC_ALGORITHM_RSA_RAW;
        }
        flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
        flags |= SC_ALGORITHM_RSA_HASH_NONE;

        _sc_card_add_rsa_alg(card, 512, flags, 0);
        _sc_card_add_rsa_alg(card, 768, flags, 0);
        _sc_card_add_rsa_alg(card, 1024, flags, 0);

	if (card->type == SC_CARD_TYPE_TCOS_V3) {
		card->caps |= SC_CARD_CAP_APDU_EXT;
		_sc_card_add_rsa_alg(card, 1280, flags, 0);
		_sc_card_add_rsa_alg(card, 1536, flags, 0);
		_sc_card_add_rsa_alg(card, 1792, flags, 0);
        	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	}

	return 0;
}


/* Hmmm, I don't know what to do.  It seems that the ACL design of
   OpenSC should be enhanced to allow for the command based security
   attributes of TCOS.  FIXME: This just allows to create a very basic
   file. */
static int tcos_construct_fci(const sc_file_t *file,
                              u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];
        size_t n;

        /* FIXME: possible buffer overflow */

        *p++ = 0x6F; /* FCI */
        p++;

	/* File size */
	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x81, buf, 2, p, 16, &p);

        /* File descriptor */
        n = 0;
	buf[n] = file->shareable ? 0x40 : 0;
	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		break;
	case SC_FILE_TYPE_DF:
		buf[0] |= 0x38;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
	buf[n++] |= file->ef_structure & 7;
        if ( (file->ef_structure & 7) > 1) {
                /* record structured file */
                buf[n++] = 0x41; /* indicate 3rd byte */
                buf[n++] = file->record_length;
        }
	sc_asn1_put_tag(0x82, buf, n, p, 8, &p);

        /* File identifier */
	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, 16, &p);

        /* Directory name */
        if (file->type == SC_FILE_TYPE_DF) {
                if (file->namelen) {
                        sc_asn1_put_tag(0x84, file->name, file->namelen,
                                        p, 16, &p);
                }
                else {
                        /* TCOS needs one, so we use a faked one */
                        snprintf ((char *) buf, sizeof(buf)-1, "foo-%lu",
                                  (unsigned long) time (NULL));
                        sc_asn1_put_tag(0x84, buf, strlen ((char *) buf), p, 16, &p);
                }
        }

        /* File descriptor extension */
        if (file->prop_attr_len && file->prop_attr) {
		n = file->prop_attr_len;
		memcpy(buf, file->prop_attr, n);
        }
        else {
                n = 0;
                buf[n++] = 0x01; /* not invalidated, permanent */
                if (file->type == SC_FILE_TYPE_WORKING_EF) 
                        buf[n++] = 0x00; /* generic data file */
        }
        sc_asn1_put_tag(0x85, buf, n, p, 16, &p);

        /* Security attributes */
	if (file->sec_attr_len && file->sec_attr) {
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		n = file->sec_attr_len;
	}
        else {
                /* no attributes given - fall back to default one */
                memcpy (buf+ 0, "\xa4\x00\x00\x00\xff\xff", 6); /* select */
                memcpy (buf+ 6, "\xb0\x00\x00\x00\xff\xff", 6); /* read bin */
                memcpy (buf+12, "\xd6\x00\x00\x00\xff\xff", 6); /* upd bin */
                memcpy (buf+18, "\x60\x00\x00\x00\xff\xff", 6); /* admin grp*/
                n = 24;
        }
        sc_asn1_put_tag(0x86, buf, n, p, sizeof (buf), &p);

        
        /* fixup length of FCI */
        out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}


static int tcos_create_file(sc_card_t *card, sc_file_t *file)
{
	int r;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	len = SC_MAX_APDU_BUFFER_SIZE;
	r = tcos_construct_fci(file, sbuf, &len);
	LOG_TEST_RET(card->ctx, r, "tcos_construct_fci() failed");
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
        apdu.cla |= 0x80;  /* this is an proprietary extension */
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}


static unsigned int map_operations (int commandbyte )
{
	unsigned int op = (unsigned int)-1;

	switch ( (commandbyte & 0xfe) ) {
		case 0xe2: /* append record */   op = SC_AC_OP_UPDATE; break;
		case 0x24: /* change password */ op = SC_AC_OP_UPDATE; break;
		case 0xe0: /* create */          op = SC_AC_OP_CREATE; break;
		case 0xe4: /* delete */          op = SC_AC_OP_DELETE; break;
		case 0xe8: /* exclude sfi */     op = SC_AC_OP_WRITE; break;
		case 0x82: /* external auth */   op = SC_AC_OP_READ; break;
		case 0xe6: /* include sfi */     op = SC_AC_OP_WRITE; break;
		case 0x88: /* internal auth */   op = SC_AC_OP_READ; break;
		case 0x04: /* invalidate */      op = SC_AC_OP_INVALIDATE; break;
		case 0x2a: /* perform sec. op */ op = SC_AC_OP_SELECT; break;
		case 0xb0: /* read binary */     op = SC_AC_OP_READ; break;
		case 0xb2: /* read record */     op = SC_AC_OP_READ; break;
		case 0x44: /* rehabilitate */    op = SC_AC_OP_REHABILITATE; break;
		case 0xa4: /* select */          op = SC_AC_OP_SELECT; break;
		case 0xee: /* set permanent */   op = SC_AC_OP_CREATE; break;
		case 0x2c: /* unblock password */op = SC_AC_OP_WRITE; break;
		case 0xd6: /* update binary */   op = SC_AC_OP_WRITE; break;
		case 0xdc: /* update record */   op = SC_AC_OP_WRITE; break;
		case 0x20: /* verify password */ op = SC_AC_OP_SELECT; break;
		case 0x60: /* admin group */     op = SC_AC_OP_CREATE; break;
	}
	return op;
}


/* Hmmm, I don't know what to do.  It seems that the ACL design of
   OpenSC should be enhanced to allow for the command based security
   attributes of TCOS.  FIXME: This just allows to create a very basic
   file. */
static void parse_sec_attr(sc_card_t *card,
                           sc_file_t *file, const u8 *buf, size_t len)
{
        unsigned int op;
        
        /* list directory is not covered by ACLs - so always add an entry */
        sc_file_add_acl_entry (file, SC_AC_OP_LIST_FILES,
                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
        /* FIXME: check for what LOCK is used */
        sc_file_add_acl_entry (file, SC_AC_OP_LOCK,
                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
        for (; len >= 6; len -= 6, buf += 6) {
                /* FIXME: temporary hacks */
                if (!memcmp(buf, "\xa4\x00\x00\x00\xff\xff", 6)) /* select */
                        sc_file_add_acl_entry (file, SC_AC_OP_SELECT,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                else if (!memcmp(buf, "\xb0\x00\x00\x00\xff\xff", 6)) /*read*/
                        sc_file_add_acl_entry (file, SC_AC_OP_READ,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                else if (!memcmp(buf, "\xd6\x00\x00\x00\xff\xff", 6)) /*upd*/
                        sc_file_add_acl_entry (file, SC_AC_OP_UPDATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                else if (!memcmp(buf, "\x60\x00\x00\x00\xff\xff", 6)) {/*adm */
                        sc_file_add_acl_entry (file, SC_AC_OP_WRITE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                        sc_file_add_acl_entry (file, SC_AC_OP_CREATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                        sc_file_add_acl_entry (file, SC_AC_OP_INVALIDATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                        sc_file_add_acl_entry (file, SC_AC_OP_REHABILITATE,
                                               SC_AC_NONE, SC_AC_KEY_REF_NONE);
                }
                else {
                        /* the first byte tells use the command or the
                           command group.  We have to mask bit 0
                           because this one distinguish between AND/OR
                           combination of PINs*/
                        op = map_operations (buf[0]);
                        if (op == (unsigned int)-1)
                        {
                                sc_log(card->ctx, 
                                       "Unknown security command byte %02x\n",
                                       buf[0]);
                                continue;
                        }
                        if (!buf[1])
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_NONE,
                                                       SC_AC_KEY_REF_NONE);
                        else
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_CHV, buf[1]);

                        if (!buf[2] && !buf[3])
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_NONE,
                                                       SC_AC_KEY_REF_NONE);
                        else
                                sc_file_add_acl_entry (file, op,
                                                       SC_AC_TERM,
                                                       (buf[2]<<8)|buf[3]);
                }
        }
}


static int tcos_select_file(sc_card_t *card,
			    const sc_path_t *in_path,
			    sc_file_t **file_out)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	sc_file_t *file=NULL;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE], pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;

	assert(card != NULL && in_path != NULL);
	ctx=card->ctx;
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0x04);
	
	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		if (pathlen != 2) return SC_ERROR_INVALID_ARGUMENTS;
		/* fall through */
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) path += 2, pathlen -= 2;
		if (pathlen == 0) apdu.p1 = 0;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		break;
	default:
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	}
	if( pathlen == 0 ) apdu.cse = SC_APDU_CASE_2_SHORT;

	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL) {
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 256;
	} else {
		apdu.resplen = 0;
		apdu.le = 0; 
		apdu.p2 = 0x0C; 
		apdu.cse = (pathlen == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r || file_out == NULL) SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);

	if (apdu.resplen < 1 || apdu.resp[0] != 0x62){
		sc_log(ctx,  "received invalid template %02X\n", apdu.resp[0]);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	file = sc_file_new();
	if (file == NULL) LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	*file_out = file;
	file->path = *in_path;

	iso_ops->process_fci(card, file, apdu.resp, apdu.resplen);

	parse_sec_attr(card, file, file->sec_attr, file->sec_attr_len);

	return 0;
}


static int tcos_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE], p1;
	int r, count = 0;

	assert(card != NULL);
	ctx = card->ctx;

	for (p1=1; p1<=2; p1++) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xAA, p1, 0);
		apdu.cla = 0x80;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, r, "APDU transmit failed");
		if (apdu.sw1==0x6A && (apdu.sw2==0x82 || apdu.sw2==0x88)) continue;
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, r, "List Dir failed");
		if (apdu.resplen > buflen) return SC_ERROR_BUFFER_TOO_SMALL;
		sc_log(ctx, 
			 "got %"SC_FORMAT_LEN_SIZE_T"u %s-FileIDs\n",
			 apdu.resplen / 2, p1 == 1 ? "DF" : "EF");

		memcpy(buf, apdu.resp, apdu.resplen);
		buf += apdu.resplen;
		buflen -= apdu.resplen;
		count += apdu.resplen;
	}
	return count;
}


static int tcos_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	u8 sbuf[2];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2) {
		sc_log(card->ctx,  "File type has to be SC_PATH_TYPE_FILE_ID\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	sbuf[0] = path->value[0];
	sbuf[1] = path->value[1];
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
        apdu.cla |= 0x80;
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}


static int tcos_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE], *p;
	int r, default_key, tcos3;
	tcos_data *data;

	assert(card != NULL && env != NULL);
	ctx = card->ctx;
	tcos3=(card->type==SC_CARD_TYPE_TCOS_V3);
	data=(tcos_data *)card->drv_data;

        if (se_num || (env->operation!=SC_SEC_OPERATION_DECIPHER && env->operation!=SC_SEC_OPERATION_SIGN)){
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	if(!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT))
		sc_log(ctx, 
			"No Key-Reference in SecEnvironment\n");
	else
		sc_log(ctx, 
			 "Key-Reference %02X (len=%"SC_FORMAT_LEN_SIZE_T"u)\n",
			 env->key_ref[0], env->key_ref_len);
	/* Key-Reference 0x80 ?? */
	default_key= !(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || (env->key_ref_len==1 && env->key_ref[0]==0x80);
	sc_log(ctx, 
		"TCOS3:%d PKCS1:%d\n", tcos3,
		!!(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1));

	data->pad_flags = env->algorithm_flags;
	data->next_sign = default_key;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, tcos3 ? 0x41 : 0xC1, 0xB8);
	p = sbuf;
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		*p++ = (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC) ? 0x83 : 0x84;
		*p++ = env->key_ref_len;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	apdu.data = sbuf;
	apdu.lc = apdu.datalen = (p - sbuf);

	r=sc_transmit_apdu(card, &apdu);
	if (r) {
		sc_log(ctx, 
			"%s: APDU transmit failed", sc_strerror(r));
		return r;
	}
	if (apdu.sw1==0x6A && (apdu.sw2==0x81 || apdu.sw2==0x88)) {
		sc_log(ctx, 
			"Detected Signature-Only key\n");
		if (env->operation==SC_SEC_OPERATION_SIGN && default_key) return SC_SUCCESS;
	}
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


static int tcos_restore_security_env(sc_card_t *card, int se_num)
{
	return 0;
}


static int tcos_compute_signature(sc_card_t *card, const u8 * data, size_t datalen, u8 * out, size_t outlen)
{
	size_t i, dlen=datalen;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int tcos3, r;

	assert(card != NULL && data != NULL && out != NULL);
	tcos3=(card->type==SC_CARD_TYPE_TCOS_V3);

	if (datalen > 255) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	if(((tcos_data *)card->drv_data)->next_sign){
		if(datalen>48){
			sc_log(card->ctx,  "Data to be signed is too long (TCOS supports max. 48 bytes)\n");
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
		memcpy(sbuf, data, datalen);
		dlen=datalen;
	} else {
		int keylen= tcos3 ? 256 : 128;
		sc_format_apdu(card, &apdu, keylen>255 ? SC_APDU_CASE_4_EXT : SC_APDU_CASE_4_SHORT, 0x2A,0x80,0x86);
		for(i=0; i<sizeof(sbuf);++i) sbuf[i]=0xff;
		sbuf[0]=0x02; sbuf[1]=0x00; sbuf[2]=0x01; sbuf[keylen-datalen]=0x00;
		memcpy(sbuf+keylen-datalen+1, data, datalen);
		dlen=keylen+1;
	}
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = tcos3 ? 256 : 128;
	apdu.data = sbuf;
	apdu.lc = apdu.datalen = dlen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (tcos3 && apdu.p1==0x80 && apdu.sw1==0x6A && apdu.sw2==0x87) {
		int keylen=128;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A,0x80,0x86);
		for(i=0; i<sizeof(sbuf);++i) sbuf[i]=0xff;
		sbuf[0]=0x02; sbuf[1]=0x00; sbuf[2]=0x01; sbuf[keylen-datalen]=0x00;
		memcpy(sbuf+keylen-datalen+1, data, datalen);
		dlen=keylen+1;

		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 128;
		apdu.data = sbuf;
		apdu.lc = apdu.datalen = dlen;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	}
	if (apdu.sw1==0x90 && apdu.sw2==0x00) {
		size_t len = apdu.resplen>outlen ? outlen : apdu.resplen;
		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


static int tcos_decipher(sc_card_t *card, const u8 * crgram, size_t crgram_len, u8 * out, size_t outlen)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	tcos_data *data;
	int tcos3, r;

	assert(card != NULL && crgram != NULL && out != NULL);
	ctx = card->ctx;
	tcos3=(card->type==SC_CARD_TYPE_TCOS_V3);
	data=(tcos_data *)card->drv_data;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, 
		"TCOS3:%d PKCS1:%d\n",tcos3,
		!!(data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1));

	sc_format_apdu(card, &apdu, crgram_len>255 ? SC_APDU_CASE_4_EXT : SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = crgram_len;

	apdu.data = sbuf;
	apdu.lc = apdu.datalen = crgram_len+1;
	sbuf[0] = tcos3 ? 0x00 : ((data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) ? 0x81 : 0x02);
	memcpy(sbuf+1, crgram, crgram_len);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1==0x90 && apdu.sw2==0x00) {
		size_t len= (apdu.resplen>outlen) ? outlen : apdu.resplen;
		unsigned int offset=0;
		if(tcos3 && (data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) && apdu.resp[0]==0 && apdu.resp[1]==2){
			offset=2; while(offset<len && apdu.resp[offset]!=0) ++offset;
			offset=(offset<len-1) ? offset+1 : 0;
		}
		memcpy(out, apdu.resp+offset, len-offset);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len-offset);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


/* Issue the SET PERMANENT command.  With ENABLE_NULLPIN set the
   NullPIN method will be activated, otherwise the permanent operation
   will be done on the active file. */
static int tcos_setperm(sc_card_t *card, int enable_nullpin)
{
	int r;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xEE, 0x00, 0x00);
        apdu.cla |= 0x80;
	apdu.lc = 0;
	apdu.datalen = 0;
	apdu.data = NULL;
	
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}


static int tcos_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;

	if (!serial)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* see if we have cached serial number */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		return SC_SUCCESS;
	}

	card->serialnr.len = sizeof card->serialnr.value;
	r = sc_parse_ef_gdo(card, card->serialnr.value, &card->serialnr.len, NULL, 0);
	if (r < 0) {
		card->serialnr.len = 0;
		return r;
	}

	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));

	return SC_SUCCESS;
}


static int tcos_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_TCOS_SETPERM:
		return tcos_setperm(card, !!ptr);
	case SC_CARDCTL_GET_SERIALNR:
		return tcos_get_serialnr(card, (sc_serial_number_t *)ptr);
	}
	return SC_ERROR_NOT_SUPPORTED;
}


struct sc_card_driver * sc_get_tcos_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL) iso_ops = iso_drv->ops;
	tcos_ops = *iso_drv->ops;

	tcos_ops.match_card           = tcos_match_card;
	tcos_ops.init                 = tcos_init;
	tcos_ops.finish               = tcos_finish;
	tcos_ops.create_file          = tcos_create_file;
	tcos_ops.set_security_env     = tcos_set_security_env;
	tcos_ops.select_file          = tcos_select_file;
	tcos_ops.list_files           = tcos_list_files;
	tcos_ops.delete_file          = tcos_delete_file;
	tcos_ops.compute_signature    = tcos_compute_signature;
	tcos_ops.decipher             = tcos_decipher;
	tcos_ops.restore_security_env = tcos_restore_security_env;
	tcos_ops.card_ctl             = tcos_card_ctl;
	
	return &tcos_drv;
}
