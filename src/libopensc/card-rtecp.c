/*
 * card-rtecp.c: Support for Rutoken ECP cards
 *
 * Copyright (C) 2009  Aleksey Samsonov <samsonov@guardant.ru>
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

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations rtecp_ops;

static struct sc_card_driver rtecp_drv = {
	"Rutoken ECP driver",
	"rutoken_ecp",
	&rtecp_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table rtecp_atrs[] = {
	/* Rutoken ECP */
	{ "3B:8B:01:52:75:74:6F:6B:65:6E:20:45:43:50:A0",
		NULL, "Rutoken ECP", SC_CARD_TYPE_RUTOKEN_ECP, 0, NULL },
	/* Rutoken ECP (DS) */
	{ "3B:8B:01:52:75:74:6F:6B:65:6E:20:44:53:20:C1",
		NULL, "Rutoken ECP (DS)", SC_CARD_TYPE_RUTOKEN_ECP, 0, NULL },
	/* Rutoken ECP SC T0 */
	{ "3B:9C:96:00:52:75:74:6F:6B:65:6E:45:43:50:73:63",
		"00:00:00:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
		"Rutoken ECP SC", SC_CARD_TYPE_RUTOKEN_ECP_SC, 0, NULL },
	/* Rutoken ECP SC T1 */
	{ "3B:9C:94:80:11:40:52:75:74:6F:6B:65:6E:45:43:50:73:63:C3",
		"00:00:00:00:00:00:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00",
		"Rutoken ECP SC", SC_CARD_TYPE_RUTOKEN_ECP_SC, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static int rtecp_match_card(sc_card_t *card)
{
	int i = -1;
	i = _sc_match_atr(card, rtecp_atrs, &card->type);
	if (i >= 0) {
		card->name = rtecp_atrs[i].name;
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}

static int rtecp_init(sc_card_t *card)
{
	sc_algorithm_info_t info;
	unsigned long flags;

	assert(card && card->ctx);
	card->caps |= SC_CARD_CAP_RNG;
	card->cla = 0;

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN
		| SC_ALGORITHM_RSA_PAD_NONE | SC_ALGORITHM_RSA_HASH_NONE;

	_sc_card_add_rsa_alg(card, 256, flags, 0);
	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1280, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 1792, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	memset(&info, 0, sizeof(info));
	info.algorithm = SC_ALGORITHM_GOSTR3410;
	info.key_length = 256;
	info.flags = SC_ALGORITHM_GOSTR3410_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN
		| SC_ALGORITHM_GOSTR3410_HASH_NONE;
	_sc_card_add_algorithm(card, &info);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);
}

static void reverse(unsigned char *buf, size_t len)
{
	unsigned char tmp;
	size_t i;

	assert(buf || len == 0);
	for (i = 0; i < len / 2; ++i)
	{
		tmp = buf[i];
		buf[i] = buf[len - 1 - i];
		buf[len - 1 - i] = tmp;
	}
}

static unsigned int sec_attr_to_method(unsigned int attr)
{
	if (attr == 0xFF)
		return SC_AC_NEVER;
	else if (attr == 0)
		return SC_AC_NONE;
	else if (attr & 0x03)
		return SC_AC_CHV;
	else
		return SC_AC_UNKNOWN;
}

static unsigned long sec_attr_to_key_ref(unsigned int attr)
{
	if (attr == 1 || attr == 2)
		return attr;
	return 0;
}

static unsigned int to_sec_attr(unsigned int method, unsigned int key_ref)
{
	if (method == SC_AC_NEVER || method == SC_AC_NONE)
		return method;
	if (method == SC_AC_CHV  &&  (key_ref == 1 || key_ref == 2))
		return key_ref;
	return 0;
}

static void set_acl_from_sec_attr(sc_card_t *card, sc_file_t *file)
{
	unsigned int method;
	unsigned long key_ref;

	assert(card && card->ctx && file);
	assert(file->sec_attr  &&  file->sec_attr_len == SC_RTECP_SEC_ATTR_SIZE);
	assert(1 + 6 < SC_RTECP_SEC_ATTR_SIZE);

	sc_file_add_acl_entry(file, SC_AC_OP_SELECT, SC_AC_NONE, SC_AC_KEY_REF_NONE);
	if (file->sec_attr[0] & 0x40) /* if AccessMode.6 */
	{
		method = sec_attr_to_method(file->sec_attr[1 + 6]);
		key_ref = sec_attr_to_key_ref(file->sec_attr[1 + 6]);
		sc_log(card->ctx, 
			"SC_AC_OP_DELETE %i %lu\n",
			(int)method, key_ref);
		sc_file_add_acl_entry(file, SC_AC_OP_DELETE, method, key_ref);
	}
	if (file->sec_attr[0] & 0x01) /* if AccessMode.0 */
	{
		method = sec_attr_to_method(file->sec_attr[1 + 0]);
		key_ref = sec_attr_to_key_ref(file->sec_attr[1 + 0]);
		sc_log(card->ctx, 
			(file->type == SC_FILE_TYPE_DF) ?
				"SC_AC_OP_CREATE %i %lu\n"
				: "SC_AC_OP_READ %i %lu\n",
			(int)method, key_ref);
		sc_file_add_acl_entry(file, (file->type == SC_FILE_TYPE_DF) ?
				SC_AC_OP_CREATE : SC_AC_OP_READ, method, key_ref);
	}
	if (file->type == SC_FILE_TYPE_DF)
	{
		sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES,
				SC_AC_NONE, SC_AC_KEY_REF_NONE);
	}
	else
		if (file->sec_attr[0] & 0x02) /* if AccessMode.1 */
		{
			method = sec_attr_to_method(file->sec_attr[1 + 1]);
			key_ref = sec_attr_to_key_ref(file->sec_attr[1 + 1]);
			sc_log(card->ctx, 
				"SC_AC_OP_UPDATE %i %lu\n",
				(int)method, key_ref);
			sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, method, key_ref);
			sc_log(card->ctx, 
				"SC_AC_OP_WRITE %i %lu\n",
				(int)method, key_ref);
			sc_file_add_acl_entry(file, SC_AC_OP_WRITE, method, key_ref);
		}
}

static int set_sec_attr_from_acl(sc_card_t *card, sc_file_t *file)
{
	const sc_acl_entry_t *entry;
	u8 sec_attr[SC_RTECP_SEC_ATTR_SIZE] = { 0 };
	int r;

	assert(card && card->ctx && file);
	assert(!file->sec_attr  &&  file->sec_attr_len == 0);
	assert(1 + 6 < sizeof(sec_attr));

	entry = sc_file_get_acl_entry(file, SC_AC_OP_DELETE);
	if (entry)
	{
		sec_attr[0] |= 0x40;
		sec_attr[1 + 6] = to_sec_attr(entry->method, entry->key_ref);
	}
	if (file->type == SC_FILE_TYPE_DF)
	{
		entry = sc_file_get_acl_entry(file, SC_AC_OP_CREATE);
		if (entry)
		{
			/* ATTR: Create DF/EF file */
			sec_attr[0] |= 0x01;
			sec_attr[1 + 0] = to_sec_attr(entry->method, entry->key_ref);
			/* ATTR: Create Internal EF (RSF) file */
			sec_attr[0] |= 0x02;
			sec_attr[1 + 1] = to_sec_attr(entry->method, entry->key_ref);
		}
	}
	else
	{
		entry = sc_file_get_acl_entry(file, SC_AC_OP_READ);
		if (entry)
		{
			sec_attr[0] |= 0x01;
			sec_attr[1 + 0] = to_sec_attr(entry->method, entry->key_ref);
		}
		entry = sc_file_get_acl_entry(file, SC_AC_OP_WRITE);
		if (entry)
		{
			sec_attr[0] |= 0x02;
			sec_attr[1 + 1] = to_sec_attr(entry->method, entry->key_ref);
		}
		entry = sc_file_get_acl_entry(file, SC_AC_OP_UPDATE);
		if (entry)
		{
			/* rewrite if sec_attr[1 + 1] already set */
			sec_attr[0] |= 0x02;
			sec_attr[1 + 1] = to_sec_attr(entry->method, entry->key_ref);
		}
	}
	/* FIXME: Find the best solution */
	if (file->path.len == 2 && !memcmp(file->path.value, "\x3F\x00", 2))
	{
		/* ATTR: Put data */
		sec_attr[0] |= 0x04;
		sec_attr[1 + 2] = 1; /* so-pin reference */
	}
	r = sc_file_set_sec_attr(file, sec_attr, sizeof(sec_attr));
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_select_file(sc_card_t *card,
		const sc_path_t *in_path, sc_file_t **file_out)
{
	sc_file_t *file = NULL;
	int r = SC_SUCCESS;

	if (!card || !card->ctx || !in_path)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	switch (in_path->type)
	{
	case SC_PATH_TYPE_DF_NAME:
	case SC_PATH_TYPE_FROM_CURRENT:
	case SC_PATH_TYPE_PARENT:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	}

	// Card Rutoken ECP SC T0 doesn't support SELECT FILE without return a file info.
	// So here we request a file and then assign/free it depending on file_out.
	r = iso_ops->select_file(card, in_path, &file);
	if (r != SC_SUCCESS)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

	if (file->sec_attr && file->sec_attr_len == SC_RTECP_SEC_ATTR_SIZE)
		set_acl_from_sec_attr(card, file);
	else
	{
		sc_file_free(file);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	if (file_out)
		*file_out = file;
	else
		sc_file_free(file);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_verify(sc_card_t *card, unsigned int type, int ref_qualifier,
		const u8 *data, size_t data_len, int *tries_left)
{
	sc_apdu_t apdu;
	int r, send_logout = 0;

	(void)type; /* no warning */
	assert(card && card->ctx && data);
	for (;;)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
				0x20, 0, ref_qualifier);
		apdu.lc = data_len;
		apdu.data = data;
		apdu.datalen = data_len;
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (send_logout++ == 0 && apdu.sw1 == 0x6F && apdu.sw2 == 0x86)
		{
			 r = sc_logout(card);
			 LOG_TEST_RET(card->ctx, r, "Logout failed");
		}
		else
			break;
	}
	if (apdu.sw1 == 0x63 && apdu.sw2 == 0)
	{
		/* Verification failed */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0, ref_qualifier);
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r == SC_ERROR_PIN_CODE_INCORRECT && tries_left)
		*tries_left = (int)(apdu.sw2 & 0x0F);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	int r;

	assert(card && card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x40, 0, 0);
	apdu.cla = 0x80;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_cipher(sc_card_t *card, const u8 *data, size_t data_len,
		u8 *out, size_t out_len, int sign)
{
	sc_apdu_t apdu;
	u8 *buf, *buf_out;
	size_t i;
	int r;

	assert(card && card->ctx && data && out);
	buf_out = malloc(out_len + 2);
	buf = malloc(data_len);
	if (!buf || !buf_out)
	{
		free(buf);
		free(buf_out);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	for (i = 0; i < data_len; ++i)
		buf[i] = data[data_len - 1 - i];

	if (sign)
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
	else
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.lc = data_len;
	apdu.data = buf;
	apdu.datalen = data_len;
	apdu.resp = buf_out;
	apdu.resplen = out_len + 2;
	apdu.le = out_len > 256 ? 256 : out_len;
	if (apdu.lc > 255)
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
	r = sc_transmit_apdu(card, &apdu);
	if (!sign)
	{
		assert(buf);
		sc_mem_clear(buf, data_len);
	}
	assert(buf);
	free(buf);
	if (r)
		sc_log(card->ctx,  "APDU transmit failed: %s\n", sc_strerror(r));
	else
	{
		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		{
			assert(buf_out);
			for (i = 0; i < apdu.resplen; ++i)
				out[i] = buf_out[apdu.resplen - 1 - i];
			r = (i > 0) ? (int)i : SC_ERROR_INTERNAL;
		}
		else
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	if (!sign)
	{
		assert(buf_out);
		sc_mem_clear(buf_out, out_len + 2);
	}
	assert(buf_out);
	free(buf_out);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

}

static int rtecp_decipher(sc_card_t *card,
		const u8 *data, size_t data_len, u8 *out, size_t out_len)
{
	int r;

	assert(card && card->ctx && data && out);
	/* decipher */
	r = rtecp_cipher(card, data, data_len, out, out_len, 0);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_compute_signature(sc_card_t *card,
		const u8 *data, size_t data_len, u8 *out, size_t out_len)
{
	int r;

	assert(card && card->ctx && data && out);
	/* compute digital signature */
	r = rtecp_cipher(card, data, data_len, out, out_len, 1);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_change_reference_data(sc_card_t *card, unsigned int type,
		int ref_qualifier, const u8 *old, size_t oldlen,
		const u8 *newref, size_t newlen, int *tries_left)
{
	sc_apdu_t apdu;
	u8 rsf_length[2], *buf, *buf_end, *p; 
	size_t val_length, buf_length, max_transmit_length;
	int transmits_num, r;

	assert(card && card->ctx && newref);
	sc_log(card->ctx, 
		 "newlen = %"SC_FORMAT_LEN_SIZE_T"u\n", newlen);
	if (newlen > 0xFFFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (type == SC_AC_CHV && old && oldlen != 0)
	{
		r = sc_verify(card, type, ref_qualifier, old, oldlen, tries_left);
		LOG_TEST_RET(card->ctx, r, "Verify old pin failed");
	}
	
	max_transmit_length = sc_get_max_send_size(card);
	assert(max_transmit_length > 2);
	/*
	 * (2 + sizeof(rsf_length) + newlen) - total length of data we need to transfer,
	 * (max_transmit_length - 2) - amount of useful data we can transfer in one transmit (2 bytes for 0xA5 tag)
	 */
	transmits_num = (2 + sizeof(rsf_length) + newlen) / (max_transmit_length - 2) + 1;
	/* buffer length = size of 0x80 TLV + size of RSF-file + (size of Tag and Length)*(number of APDUs) */
	buf_length = (2 + sizeof(rsf_length)) + newlen + 2*(transmits_num); 
	p = buf = (u8 *)malloc(buf_length);
	if (buf == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	buf_end = buf + buf_length; 

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, ref_qualifier);	
	/* put 0x80 TLV */
	rsf_length[0] = (newlen >> 8) & 0xFF;
	rsf_length[1] = newlen & 0xFF;
	assert(buf_end - p >= (int)(2 + sizeof(rsf_length)));
	sc_asn1_put_tag(0x80, rsf_length, sizeof(rsf_length), p, buf_end - p, &p);
	/* put 0xA5 TLVs (one or more); each transmit must begin with 0xA5 TLV */
	while (newlen)
	{
		assert(buf_end - p >= (int)(newlen + 2));
		if ((p - buf) % max_transmit_length + newlen + 2 > max_transmit_length)
			val_length = max_transmit_length - (p - buf) % max_transmit_length - 2;
		else
			val_length = newlen;
		/* not using sc_asn1_put_tag(...) because rtecp do not support asn1 properly (when val_length > 127) */
		*p++ = 0xA5;
		*p++ = (u8)val_length;
		assert(val_length <= newlen);
		memcpy(p, newref, val_length);
		p += val_length;
		newref += val_length;
		newlen -= val_length;
		if (newlen)
			apdu.flags |= SC_APDU_FLAGS_CHAINING;
	}
	apdu.lc = p - buf;
	apdu.data = buf;
	apdu.datalen = p - buf;

	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(buf, buf_length);
	free(buf);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_reset_retry_counter(sc_card_t *card, unsigned int type,
		int ref_qualifier, const u8 *puk, size_t puklen,
		const u8 *newref, size_t newlen)
{
	sc_apdu_t apdu;
	int r;

	(void)type, (void)puk, (void)puklen; /* no warning */
	assert(card && card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2C, 0x03, ref_qualifier);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Unblock card failed");
	
	if (newref && newlen)   {
        	u8 tmp[2], buf[SC_MAX_APDU_BUFFER_SIZE];
		u8 *p = buf;

		tmp[0] = (newlen >> 8) & 0xFF;
		tmp[1] = newlen & 0xFF;
		sc_asn1_put_tag(0x80, tmp, sizeof(tmp), p, sizeof(buf) - (p - buf), &p);
		r = sc_asn1_put_tag(0xA5, newref, newlen, p, sizeof(buf) - (p - buf), &p);
		LOG_TEST_RET(card->ctx, r, "Invalid new PIN length");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, ref_qualifier);
		apdu.lc = p - buf;
		apdu.data = buf;
		apdu.datalen = p - buf;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, r, "Set PIN failed");
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_create_file(sc_card_t *card, sc_file_t *file)
{
	int r;

	assert(card && card->ctx && file);
	if (file->sec_attr_len == 0)
	{
		r = set_sec_attr_from_acl(card, file);
		LOG_TEST_RET(card->ctx, r, "Set sec_attr from ACL failed");
	}
	assert(iso_ops && iso_ops->create_file);
	r = iso_ops->create_file(card, file);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_RESP_SIZE], previd[2];
	const u8 *tag;
	size_t taglen, len = 0;
	int r;

	assert(card && card->ctx && buf);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0, 0);
	for (;;)
	{
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = sizeof(rbuf);
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.sw1 == 0x6A  &&  apdu.sw2 == 0x82)
			break; /* Next file not found */

		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, r, "");

		if (apdu.resplen <= 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_LENGTH);

		/* save first file(dir) ID */
		tag = sc_asn1_find_tag(card->ctx, apdu.resp + 2, apdu.resplen - 2,
				0x83, &taglen);
		if (!tag || taglen != sizeof(previd))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		memcpy(previd, tag, sizeof(previd));

		if (len + sizeof(previd) <= buflen)
		{
			memcpy(&buf[len], previd, sizeof(previd));
			len += sizeof(previd);
		}

		tag = sc_asn1_find_tag(card->ctx, apdu.resp + 2, apdu.resplen - 2,
				0x82, &taglen);
		if (!tag || taglen != 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		if (tag[0] == 0x38)
		{
			/* Select parent DF of the current DF */
			sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0x03, 0);
			/* We should set le and resp buf to actually call Get Response for card on T0. */
			apdu.resp = rbuf;
			apdu.resplen = sizeof(rbuf);
			apdu.le = sizeof(rbuf);
			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			LOG_TEST_RET(card->ctx, r, "");
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0x02);
		apdu.lc = sizeof(previd);
		apdu.data = previd;
		apdu.datalen = sizeof(previd);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
}

static int rtecp_card_ctl(sc_card_t *card, unsigned long request, void *data)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	sc_rtecp_genkey_data_t *genkey_data = data;
	sc_serial_number_t *serial = data;
	int r;

	assert(card && card->ctx);
	switch (request)
	{
	case SC_CARDCTL_RTECP_INIT:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x8A, 0, 0);
		apdu.cla = 0x80;
		break;
	case SC_CARDCTL_RTECP_INIT_END:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x84, 0x4E, 0x19);
		apdu.cla = 0x80;
		break;
	case SC_CARDCTL_GET_SERIALNR:
		if (!serial)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x81);
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 256;
		serial->len = sizeof(serial->value);
		break;
	case SC_CARDCTL_RTECP_GENERATE_KEY:
		if (!genkey_data)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x46, 0x80,
				genkey_data->key_id);
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 256;
		break;
	case SC_CARDCTL_LIFECYCLE_SET:
		sc_log(card->ctx,  "%s\n",
				"SC_CARDCTL_LIFECYCLE_SET not supported");
		/* no call sc_debug (SC_FUNC_RETURN) */
		return SC_ERROR_NOT_SUPPORTED;
	default:
		sc_log(card->ctx, 
			"request = 0x%lx\n", request);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (!r && request == SC_CARDCTL_RTECP_GENERATE_KEY)
	{
		if (genkey_data->type == SC_ALGORITHM_RSA &&
				genkey_data->u.rsa.modulus_len >= apdu.resplen &&
				genkey_data->u.rsa.exponent_len >= 3)
		{
			memcpy(genkey_data->u.rsa.modulus, apdu.resp, apdu.resplen);
			genkey_data->u.rsa.modulus_len = apdu.resplen;
			reverse(genkey_data->u.rsa.modulus,
					genkey_data->u.rsa.modulus_len);
			memcpy(genkey_data->u.rsa.exponent, "\x01\x00\x01", 3);
			genkey_data->u.rsa.exponent_len = 3;
		}
		else if (genkey_data->type == SC_ALGORITHM_GOSTR3410 &&
				genkey_data->u.gostr3410.xy_len >= apdu.resplen)
		{
			memcpy(genkey_data->u.gostr3410.xy, apdu.resp, apdu.resplen);
			genkey_data->u.gostr3410.xy_len = apdu.resplen;
		}
		else
			r = SC_ERROR_BUFFER_TOO_SMALL;
	}
	else if (!r && request == SC_CARDCTL_GET_SERIALNR)
	{
		if (serial->len >= apdu.resplen)
		{
			memcpy(serial->value, apdu.resp, apdu.resplen);
			serial->len = apdu.resplen;
		}
		else
			r = SC_ERROR_BUFFER_TOO_SMALL;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int rtecp_construct_fci(sc_card_t *card, const sc_file_t *file,
		u8 *out, size_t *outlen)
{
	u8 buf[64], *p = out;

	assert(card && card->ctx && file && out && outlen);
	assert(*outlen  >=  (size_t)(p - out) + 2);
	*p++ = 0x6F; /* FCI template */
	p++; /* for length */

	/* 0x80 - Number of data bytes in the file, excluding structural information */
	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x80, buf, 2, p, *outlen - (p - out), &p);

	/* 0x82 - File descriptor byte */
	if (file->type_attr_len)
	{
		assert(sizeof(buf) >= file->type_attr_len);
		memcpy(buf, file->type_attr, file->type_attr_len);
		sc_asn1_put_tag(0x82, buf, file->type_attr_len,
				p, *outlen - (p - out), &p);
	}
	else
	{
		switch (file->type)
		{
		case SC_FILE_TYPE_WORKING_EF:
			buf[0] = 0x01;
			break;
		case SC_FILE_TYPE_DF:
			buf[0] = 0x38;
			break;
		case SC_FILE_TYPE_INTERNAL_EF:
		default:
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
		}
		buf[1] = 0;
		sc_asn1_put_tag(0x82, buf, 2, p, *outlen - (p - out), &p);
	}
	/* 0x83 - File identifier */
	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, *outlen - (p - out), &p);

	if (file->prop_attr_len)
	{
		assert(sizeof(buf) >= file->prop_attr_len);
		memcpy(buf, file->prop_attr, file->prop_attr_len);
		sc_asn1_put_tag(0x85, buf, file->prop_attr_len,
				p, *outlen - (p - out), &p);
	}
	if (file->sec_attr_len)
	{
		assert(sizeof(buf) >= file->sec_attr_len);
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		sc_asn1_put_tag(0x86, buf, file->sec_attr_len,
				p, *outlen - (p - out), &p);
	}
	out[1] = p - out - 2; /* length */
	*outlen = p - out;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);
}

struct sc_card_driver * sc_get_rtecp_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	rtecp_ops = *iso_ops;

	rtecp_ops.match_card = rtecp_match_card;
	rtecp_ops.init = rtecp_init;
	/* read_binary */
	rtecp_ops.write_binary = NULL;
	/* update_binary */
	rtecp_ops.read_record = NULL;
	rtecp_ops.write_record = NULL;
	rtecp_ops.append_record = NULL;
	rtecp_ops.update_record = NULL;
	rtecp_ops.select_file = rtecp_select_file;
	/* get_response */
	/* get_challenge */
	rtecp_ops.verify = rtecp_verify;
	rtecp_ops.logout = rtecp_logout;
	/* restore_security_env */
	/* set_security_env */
	rtecp_ops.decipher = rtecp_decipher;
	rtecp_ops.compute_signature = rtecp_compute_signature;
	rtecp_ops.change_reference_data = rtecp_change_reference_data;
	rtecp_ops.reset_retry_counter = rtecp_reset_retry_counter;
	rtecp_ops.create_file = rtecp_create_file;
	/* delete_file */
	rtecp_ops.list_files = rtecp_list_files;
	/* check_sw */
	rtecp_ops.card_ctl = rtecp_card_ctl;
	/* process_fci */
	rtecp_ops.construct_fci = rtecp_construct_fci;
	rtecp_ops.pin_cmd = NULL;

	return &rtecp_drv;
}

