/*
 * partial PKCS15 emulation for gemsafe GPK cards
 *
 * Copyright (C) 2005, Douglas E. Engert <deengert@anl.gov> 
 *               2004, Nils Larsch <larsch@trustcenter.de>
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
#include <stdio.h>

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "pkcs15.h"
#include "log.h"
#include "cardctl.h"

#define MANU_ID		"GemSAFE on GPK16000"

int sc_pkcs15emu_gemsafeGPK_init_ex(sc_pkcs15_card_t *, struct sc_aid *, sc_pkcs15emu_opt_t *);

static int (*pin_cmd_save)(struct sc_card *, struct sc_pin_cmd_data *, 
		int *tries_left);

typedef struct cdata_st {
	const char *label;
	int	    authority;
	const char *path;
	const char *id;
	int         obj_flags;
} cdata;

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	unsigned int storedlen;
	int         flags;	
	int         tries_left;
	const char  pad_char;
	int         obj_flags;
} pindata; 

typedef struct prdata_st {
	const char *id;
	const char *label;
	unsigned int modulus_len;
	int         usage;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
} prdata;

typedef struct keyinfo_st {
	int fileid;
	sc_pkcs15_id_t id;
	unsigned int modulus_len;
	u8 modulus[1024/8];
} keyinfo;

#define USAGE_NONREP	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
#define USAGE_KE	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_AUT	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP  | \
			SC_PKCS15_PRKEY_USAGE_SIGN

static const u8 gemsafe_aid[] = {0xA0, 0x00, 0x00, 0x00, 0x18,
		0x0F, 0x00, 0x00, 0x01, 0x63, 0x00, 0x01};

static int my_pin_cmd(sc_card_t * card, struct sc_pin_cmd_data * data,
			int *tries_left) 
{
	/* GemSAFE pin uses a null terminated string with 0xFF */
	/* so we need to add the 0x00 to the pin  then pad with 0xFF */
	
	int r;
	const u8 *saved_data = NULL;
	int saved_len = 0;
	u8  newpin[8];
	
	LOG_FUNC_CALLED(card->ctx);

	memset(newpin, 0xff, sizeof(newpin));

	if (data->pin1.data && data->pin1.len < 8 && data->pin1.len > 0) {
		memcpy(newpin,data->pin1.data, (size_t)data->pin1.len);
		newpin[data->pin1.len] = 0x00;
		
		sc_log(card->ctx,  "pin len=%d", data->pin1.len);

		saved_data = data->pin1.data;
		saved_len = data->pin1.len;
		data->pin1.data = newpin;
		data->pin1.len = sizeof(newpin);
	}

	r = pin_cmd_save(card, data, tries_left);

	if (saved_data) {
		data->pin1.data = saved_data;
		data->pin1.len = saved_len;
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}


static int is_seq(unsigned char * seq, unsigned int *seq_size, unsigned int *seq_len) 
{
	int i,j,k;

	if (seq[0] != 0x30)
		return 0;   /* not a sequence */
	if (seq[1] & 0x80) {
		i = seq[1] & 0x7f;
		if (i > 2 || i == 0) 
			return 0; /* cert would be bigger then 65k or zero */
		if (seq[2] == 0) 
			return 0; /* DER would not have extra zero */		
		k = 0;
		for (j = 0; j < i; j++) {
			k = (k << 8) + seq[j + 2];
		}
		if (k < 128)
			return 0; /* DER would have used single byte for len */
	} else {
		  i = 0;
		  k = seq[1];
	}
	
	*seq_size = i + 2;
	*seq_len = k;
	return 1;
}

static int gemsafe_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);


	if (strcmp(card->name, "Gemplus GPK"))
		return SC_ERROR_WRONG_CARD;
	
	return SC_SUCCESS;
}

static int sc_pkcs15emu_gemsafeGPK_init(sc_pkcs15_card_t *p15card)
{
	const cdata certs[] = {
		{"User certificate",0, "","1", 0},
		{NULL, 0, NULL, NULL, 0}
	};

	const pindata pins[] = {
		{ "01", "pin", "3F000200", 0x00,
		  SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		  8, 4, 8, SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
		  SC_PKCS15_PIN_FLAG_LOCAL, -1, 0x00,
		  SC_PKCS15_CO_FLAG_PRIVATE },
		{ NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	};

	const prdata prkeys[] = {
		{ "01", "AUTH key", 1024, USAGE_AUT, "I0009",
		  0x00, "01", 0},
		{ NULL, NULL, 0, 0, NULL, 0, NULL, 0}
	};

	int    r, i, j;
	int dfpath;
	sc_path_t path;
	sc_file_t *file = NULL;
	sc_card_t *card = p15card->card;
	unsigned char *gsdata = NULL;
	unsigned int idxlen, idx1, idx2, seq_len1, seq_len2, seq_size1, seq_size2;
	sc_serial_number_t serial;

	u8 sysrec[7];
	int num_keyinfo = 0;
	keyinfo kinfo[8]; /* will loook for 8 keys */
	u8 modulus_buf[ 1 + 1024 / 8]; /* tag+modulus */
	u8 *cp;
	char buf[256];

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* need to limit to 248 */
	card->max_send_size = 248;
	card->max_recv_size = 248;


	/* could read this off card if needed */

	p15card->tokeninfo->label = strdup("GemSAFE");
	p15card->tokeninfo->manufacturer_id = strdup(MANU_ID);
	/* get serial number */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	r = sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	p15card->tokeninfo->serial_number = strdup(buf);

	/* test if we have a gemsafe app df */
	memset(&path, 0, sizeof(path));
	memcpy(path.value, gemsafe_aid, sizeof(gemsafe_aid));
	path.len = sizeof(gemsafe_aid);
	path.type = SC_PATH_TYPE_DF_NAME;
	r = sc_select_file(card, &path, &file);
	if (r < 0) {
		/* OK, then lets try for 3f000200 */
		sc_format_path("3F000200",&path);
		path.type = SC_PATH_TYPE_PATH;
		r = sc_select_file(card, &path, &file);
	}

	if (r < 0)
		return SC_ERROR_WRONG_CARD;

	/* we will use dfpath in all other references */
	dfpath = file->id;
	sc_file_free(file);
	file = NULL;

	sc_log(card->ctx,  "GemSafe file found, id=%d",dfpath);

	/* There may be more then one key in the directory. */
	/* we need to find them so we can associate them with the */
	/* the certificate.  The files are 0007 to 000f */

	for (i = 7; i < 16; i++) {
		path.value[0] = 0x00;
		path.value[1] = i;
		path.len = 2;	
		path.type = SC_PATH_TYPE_FILE_ID;
		r = sc_select_file(card, &path, NULL);
		if (r < 0) 
			continue;
		r = sc_read_record(card, 1, sysrec, sizeof(sysrec), SC_RECORD_BY_REC_NR);
		if (r != 7 || sysrec[0] != 0) {
			continue;
		}
		if (sysrec[5] != 0x00) {
			continue;
		}

		switch (sysrec[1]) {
			case 0x00: kinfo[num_keyinfo].modulus_len =  512 / 8; break;
			case 0x10: kinfo[num_keyinfo].modulus_len =  768 / 8; break;
			case 0x11: kinfo[num_keyinfo].modulus_len = 1024 / 8; break;
			default:
				sc_log(card->ctx,  "Unsupported modulus length");
				continue;
		}

		kinfo[num_keyinfo].fileid = i;
		sc_pkcs15_format_id("", &kinfo[num_keyinfo].id); 

		sc_log(card->ctx, "reading modulus");
		r = sc_read_record(card, 2, modulus_buf, 
				kinfo[num_keyinfo].modulus_len+1, SC_RECORD_BY_REC_NR);
		if (r < 0) 
			continue;
			
		/* need to reverse the modulus skipping the tag */
		j = kinfo[num_keyinfo].modulus_len;
		cp = kinfo[num_keyinfo].modulus;
		while (j--) 
			*cp++ =  modulus_buf[j + 1];
		num_keyinfo++;
	} 

	/* Get the gemsafe data with the cert */
	 sc_format_path("3F000200004", &path);

	/* file.id has the real DF of the GemSAFE file from above*/
	 path.value[2] = dfpath >> 8;
	 path.value[3] = dfpath & 0xff; 
	
	if (sc_select_file(card, &path, &file) < 0) {
		return SC_ERROR_WRONG_CARD;
	}

	/* the GemSAFE file has our cert, but we do not know the format */
	/* of the file. But we do know a cert has SEQ SEQ SEQOF INT 2   */
	/* so we will look for that. We assume cert is larger then 127 bytes */
	/* and less then 65K, and must be fit in the file->size */
	/* There is a chance that we might find something that is not */
	/* a cert, but the chances are low. If GemPlus ever publishes */
	/* the format of the file, we can used that instead. */ 

	/* For performance reasons we will only */
	/* read part of the file , as it is about 6100 bytes */

	gsdata = malloc(file->size);

	if (!gsdata)
		return SC_ERROR_OUT_OF_MEMORY;

	/* set indices of data in gsdata  */
	idx1 = 0; /* start point */
	idx2 = 0; /* index of last data read so far */


	/* set certs  We only have one we are interested in */
	/* but the read loop is set up to allow for more in future */

	for (i = 0; certs[i].label; i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object    cert_obj;
		sc_pkcs15_cert_t 		*cert_out;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));

		sc_pkcs15_format_id(certs[i].id, &cert_info.id);
		cert_info.authority = certs[i].authority;

		strlcpy(cert_obj.label, certs[i].label, sizeof(cert_obj.label));
		cert_obj.flags = certs[i].obj_flags;

		while (idx1 < file->size - 16) { /* actually 13 for all these tests */
			if (idx1 + 16 > idx2 ) { 	/* need more data in buff */
				idxlen = 248; 		/* read in next 248 bytes */
				if (idxlen > file->size - idx2)
					idxlen = file->size - idx2;
				r = sc_read_binary(card, idx2, gsdata + idx2, idxlen, 0);
				if (r < 0)
					break;
				idx2 = idx2 + idxlen;
			}

			if ( gsdata[idx1] == 0x30 &&
				is_seq(gsdata + idx1, &seq_size1, &seq_len1) &&
			 	is_seq(gsdata + idx1 + seq_size1, &seq_size2, &seq_len2) &&
			    gsdata[idx1 + seq_size1 + seq_size2 + 0] == 0xa0 &&
				gsdata[idx1 + seq_size1 + seq_size2 + 1] == 0x03 &&
				gsdata[idx1 + seq_size1 + seq_size2 + 2] == 0x02 &&
				gsdata[idx1 + seq_size1 + seq_size2 + 3] == 0x01 &&
				gsdata[idx1 + seq_size1 + seq_size2 + 4] == 0x02 &&
				idx1 + 4 + seq_len1 < file->size) {
				/* we have a cert (I hope) */
				/* read in rest if needed */
				idxlen = idx1 + seq_len1 + 4 - idx2; 
				if (idxlen > 0) {
					idxlen = (idxlen + 3) & 0xfffffffc;  
					r = sc_read_binary(card, idx2, gsdata + idx2, idxlen, 0);
					if (r < 0)
						break; /* can not read cert */
					idx2 = idx2 + idxlen;
				}
				cert_info.value.len = seq_len1 + 4;
				sc_log(card->ctx,  "Found cert at offset %d", idx1);
				cert_info.value.value = (unsigned char *) 
						malloc(cert_info.value.len);
				if (!cert_info.value.value) 
					return SC_ERROR_OUT_OF_MEMORY;

				memcpy(cert_info.value.value, gsdata + idx1, cert_info.value.len);
			idx1 = idx1 + cert_info.value.len;
				break;
			}
			idx1++;
		}
		
		if (cert_info.value.value == NULL) 
			break; /* cert not found, no more certs */

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0) {
			free(gsdata);
			return SC_ERROR_INTERNAL;
		}

		/* now lets see if we have a matching key for this cert */
		
		r = sc_pkcs15_read_certificate(p15card, &cert_info, &cert_out);
		if (r < 0) {
			free(gsdata);
			return SC_ERROR_INTERNAL;
		}

		for (j = 0; j < num_keyinfo; j++) { 
			if (cert_out->key->u.rsa.modulus.len == kinfo[j].modulus_len &&	
					memcmp(cert_out->key->u.rsa.modulus.data, 
					&kinfo[j].modulus, cert_out->key->u.rsa.modulus.len) == 0) { 
			memcpy(&kinfo[j].id, &cert_info.id, sizeof(sc_pkcs15_id_t));
			sc_log(card->ctx,  "found match");
			}
		}
		sc_pkcs15_free_certificate(cert_out);
	}

	if (gsdata)
		free(gsdata);

	/* set pins */

	/* GemSAFE uses different padding, so need to trap */
	/* the pin_cmd and reset the padding */

	pin_cmd_save = card->ops->pin_cmd;
	card->ops->pin_cmd = my_pin_cmd;

	for (i = 0; pins[i].label; i++) {
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object   pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj,  0, sizeof(pin_obj));

		sc_pkcs15_format_id(pins[i].id, &pin_info.auth_id);
		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.attrs.pin.reference     = pins[i].ref;
		pin_info.attrs.pin.flags         = pins[i].flags;
		pin_info.attrs.pin.type          = pins[i].type;
		pin_info.attrs.pin.min_length    = pins[i].minlen;
		pin_info.attrs.pin.stored_length = pins[i].storedlen;
		pin_info.attrs.pin.max_length    = pins[i].maxlen;
		pin_info.attrs.pin.pad_char      = pins[i].pad_char;
		sc_format_path(pins[i].path, &pin_info.path);
		pin_info.path.value[2] = dfpath >> 8;
		pin_info.path.value[3] = dfpath & 0xff;
		pin_info.tries_left    = -1;
		pin_info.logged_in = SC_PIN_STATE_UNKNOWN;

		strlcpy(pin_obj.label, pins[i].label, sizeof(pin_obj.label));
		pin_obj.flags = pins[i].obj_flags;

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}

	/* needs work, as we may want to add more then one key */
	/* but not sure what the other keys do */

	/* set private keys */
	for (i = 0; prkeys[i].label; i++) {
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object     prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj,  0, sizeof(prkey_obj));

		sc_pkcs15_format_id(prkeys[i].id, &prkey_info.id);
		prkey_info.usage         = prkeys[i].usage;
		prkey_info.native        = 1;
		prkey_info.key_reference = prkeys[i].ref;
		prkey_info.modulus_length= prkeys[i].modulus_len;
		sc_format_path(prkeys[i].path, &prkey_info.path);

		/*DEE need to look for them by reading and checking modulus vs cert */

 		/* will use the default path, unless we found a key with */
		/* the same modulus as the cert(s) we already added */
		/* This allows us to have a card with a key but no cert */
	
		for (j = 0; j < num_keyinfo; j++) {
			if (sc_pkcs15_compare_id(&kinfo[j].id, &prkey_info.id))  {
				sc_log(card->ctx,  "found key in file %d for id %s",
					 kinfo[j].fileid, prkeys[i].id);
				prkey_info.path.value[0] = kinfo[j].fileid >> 8;
				prkey_info.path.value[1] = kinfo[j].fileid & 0xff;
				break;
			}
		}

		strlcpy(prkey_obj.label, prkeys[i].label, sizeof(prkey_obj.label));
		prkey_obj.flags = prkeys[i].obj_flags;
		if (prkeys[i].auth_id)
			sc_pkcs15_format_id(prkeys[i].auth_id, &prkey_obj.auth_id);

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}
	return SC_SUCCESS;
}

int sc_pkcs15emu_gemsafeGPK_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid,
				  sc_pkcs15emu_opt_t *opts)
{
	sc_card_t   *card = p15card->card;
	sc_context_t    *ctx = card->ctx;

	sc_log(ctx,  "Entering %s", __FUNCTION__);

	if (gemsafe_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_gemsafeGPK_init(p15card);
}
