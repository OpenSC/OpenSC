/*
 * partial PKCS15 emulation for PIV-II cards
 * only minimal use of the authentication cert and key
 *
 * Copyright (C) 2005,2006,2007,2008,2009,2010  
 *               Douglas E. Engert <deengert@anl.gov> 
 *               2004, Nils Larsch <larsch@trustcenter.de>
 * Copyright (C) 2006, Identity Alliance, 
 *               Thomas Harning <thomas.harning@identityalliance.com>
 * Copyright (C) 2007, EMC, Russell Larner <rlarner@rsa.com>
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
#include <ctype.h>

#include "internal.h"
#include "cardctl.h"
#include "asn1.h"
#include "pkcs15.h"

#define MANU_ID		"piv_II "

typedef struct objdata_st {
	const char *id;
	const char *label;
	const char *aoid;
	const char *auth_id;
	const char *path;
	int         obj_flags;
} objdata;

typedef struct cdata_st {
	const char *id;
	const char *label;
	const char *path;
	int	    authority;
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
	const unsigned char  pad_char;
	int         obj_flags;
} pindata; 

typedef struct pubdata_st {
	const char *id;
	const char *label;
	int         usage_rsa;
	int         usage_ec;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
	const char *getenvname;
} pubdata;

typedef struct prdata_st {
	const char *id;
	const char *label;
	int         usage_rsa;
	int			usage_ec;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
	int			user_consent; 
} prdata;

typedef struct common_key_info_st {
	int cert_found;
	int pubkey_found;
	int pubkey_from_file;
	int key_alg;
	unsigned int pubkey_len;
	unsigned int cert_keyUsage; /* x509 key usage as defined in certificate */
	int cert_keyUsage_present; /* 1 if keyUsage found in certificate */
	int pub_usage;
	int priv_usage;
	struct sc_pkcs15_pubkey *pubkey_from_cert;
	int not_present;
} common_key_info;


/*
 * The PIV applet has no serial number, and so the either the FASC-N
 * is used, or the GUID is used as a serial number.
 * We need to return a GUID like value for each object
 * But this needs to be some what unique.
 * So we will use two different methods, depending 
 * on the size of the serial number.
 * If it is 25 bytes, then it was from a FASCN. If 16 bytes
 * its from a GUID.
 * If neither, we will uase the default method. 
 */

static int piv_get_guid(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_object *obj,
		unsigned char *out, size_t *out_size)
{
	struct sc_serial_number serialnr;
	struct sc_pkcs15_id  id;
	unsigned char guid_bin[SC_PKCS15_MAX_ID_SIZE + SC_MAX_SERIALNR];
	size_t bin_size, offs, tlen, i;
	int r;
	unsigned char fbit, fbits, fbyte, fbyte2, fnibble;
	unsigned char *f5p, *f8p;

	if (!p15card || !obj || !out || *out_size < 3)
		return SC_ERROR_INCORRECT_PARAMETERS;

	r = sc_pkcs15_get_object_id(obj, &id);
	if (r)
		return r;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &serialnr);
	if (r)
		return r;

	memset(guid_bin, 0, sizeof(guid_bin));
	memset(out, 0, *out_size);

	if (id.len == 1 && serialnr.len == 25) {

		/* It is from a FASCN, and we need to shorten it but keep
		 * as much uniqueness as possible.
		 * FASC-N is stored like a ISO 7811 Magnetic Strip Card 
		 * Using the ANSI/ISO BCD Data Format
		 * 4 data bit + 1 parity bit (odd) least significant bit first. 
		 * It starts with the Start Sentinel 0x0b ";" 
		 * Fields are separated by 0x0d "="
		 * Ends with End Sentinel 0x0f "?"
		 * Its 39 characters + the LRC 
		 * http://www.dataip.co.uk/Reference/MagneticCardBCD.php
		 * 0x0a, 0x0c, 0x0e are some type of control
		 * the FASCN has a lot of extra bits, with only 32 digits.
		 */
		f5p = serialnr.value;
		f8p = guid_bin;
		fbyte = 0;
		fbyte2 = 0;
		fnibble = 0;
		fbits = 0;
		for (i = 0; i < 25*8; i++) {
			if (i%8 == 0) {
				fbyte=*f5p++;
			}
			fbit = (fbyte & 0x80) ? 1:0;
			fbyte <<= 1;
			fbits = (fbits >> 1) + (fbit << 4);
			/* reversed with parity */
			if ((i - 4)%5 == 0) {
				fbits = fbits & 0x0f; /* drop parity */
				if (fbits <= 9) {  /* only save digits, drop control codes */
					fbyte2 = (fbyte2 << 4) | fbits;
					if (fnibble) {
						*f8p = fbyte2;
						f8p++;
						fbyte2 = 0;
						fnibble = 0;
					} else
					fnibble = 1;
				}
				fbits = 0;
			}
		}

		/* overwrite two insignificant digits in middle with id */
		memcpy(guid_bin + 7, id.value, id.len); 
		tlen = 16;
	}
	else if (id.len == 1 && serialnr.len == 16) {
		/* its from a GUID, we will overwrite the 
		 * first byte with id.value, as this preserves most
	     * of the uniqueness. 
		 */ 
		memcpy(guid_bin, id.value, id.len);
		memcpy(guid_bin + id.len, serialnr.value + 1, serialnr.len - 1);
		
		tlen = id.len + serialnr.len - 1; /* i.e. 16 */
	} else {
		/* not what was expected...  use default */

		memcpy(guid_bin, serialnr.value, serialnr.len);
		memcpy(guid_bin + serialnr.len, id.value, id.len);

		tlen = id.len + serialnr.len;
	}

	/* reserve one byte for the 'C' line ending */
	bin_size = (*out_size - 1)/2;
	if (bin_size > tlen)
		bin_size = tlen;

	offs = tlen - bin_size;

	for (i=0; i<bin_size; i++)
		sprintf((char *) out + i*2, "%02x", guid_bin[offs + i]);

	return SC_SUCCESS;
}


static int piv_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (card->type < SC_CARD_TYPE_PIV_II_GENERIC
		|| card->type >= SC_CARD_TYPE_PIV_II_GENERIC+1000)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}


static int sc_pkcs15emu_piv_init(sc_pkcs15_card_t *p15card)
{

	/* The cert objects will return all the data */
	/* Note: pkcs11 objects do not have CK_ID values */

	static const objdata objects[] = {
	{"01", "Card Capability Container", 
			"2.16.840.1.101.3.7.1.219.0", NULL, "DB00", 0},
	{"02", "Card Holder Unique Identifier",
			"2.16.840.1.101.3.7.2.48.0", NULL, "3000", 0},
	{"03", "Unsigned Card Holder Unique Identifier",
			"2.16.840.1.101.3.7.2.48.2", NULL, "3010", 0},
	{"04", "X.509 Certificate for PIV Authentication",
			"2.16.840.1.101.3.7.2.1.1", NULL, "0101", 0},
	{"05", "Cardholder Fingerprints",
			"2.16.840.1.101.3.7.2.96.16", "01", "6010", SC_PKCS15_CO_FLAG_PRIVATE},
	{"06", "Printed Information",
			"2.16.840.1.101.3.7.2.48.1", "01", "3001", SC_PKCS15_CO_FLAG_PRIVATE},
	{"07", "Cardholder Facial Image", 
			"2.16.840.1.101.3.7.2.96.48", "01", "6030", SC_PKCS15_CO_FLAG_PRIVATE},
	{"08", "X.509 Certificate for Digital Signature",
			"2.16.840.1.101.3.7.2.1.0",  NULL, "0100", 0},
	{"09", "X.509 Certificate for Key Management", 
			"2.16.840.1.101.3.7.2.1.2", NULL, "0102", 0},
	{"10","X.509 Certificate for Card Authentication",
			"2.16.840.1.101.3.7.2.5.0", NULL, "0500", 0},
	{"11", "Security Object",
			"2.16.840.1.101.3.7.2.144.0", NULL, "9000", 0},
	{"12", "Discovery Object",
			"2.16.840.1.101.3.7.2.96.80", NULL, "6050", 0},
	{"13", "Key History Object",
			"2.16.840.1.101.3.7.2.96.96", NULL, "6060", 0},
	{"14", "Cardholder Iris Image",
			"2.16.840.1.101.3.7.2.16.21", NULL, "1015", SC_PKCS15_CO_FLAG_PRIVATE},

	{"15", "Retired X.509 Certificate for Key Management 1", 
			"2.16.840.1.101.3.7.2.16.1", NULL, "1001", 0},
	{"16", "Retired X.509 Certificate for Key Management 2", 
			"2.16.840.1.101.3.7.2.16.2", NULL, "1002", 0},
	{"17", "Retired X.509 Certificate for Key Management 3", 
			"2.16.840.1.101.3.7.2.16.3", NULL, "1003", 0},
	{"18", "Retired X.509 Certificate for Key Management 4", 
			"2.16.840.1.101.3.7.2.16.4", NULL, "1004", 0},
	{"19", "Retired X.509 Certificate for Key Management 5", 
			"2.16.840.1.101.3.7.2.16.5", NULL, "1005", 0},
	{"20", "Retired X.509 Certificate for Key Management 6", 
			"2.16.840.1.101.3.7.2.16.6", NULL, "1006", 0},
	{"21", "Retired X.509 Certificate for Key Management 7", 
			"2.16.840.1.101.3.7.2.16.7", NULL, "1007", 0},
	{"22", "Retired X.509 Certificate for Key Management 8", 
			"2.16.840.1.101.3.7.2.16.8", NULL, "1008", 0},
	{"23", "Retired X.509 Certificate for Key Management 9", 
			"2.16.840.1.101.3.7.2.16.9", NULL, "1009", 0},
	{"24", "Retired X.509 Certificate for Key Management 10", 
			"2.16.840.1.101.3.7.2.16.10", NULL, "100A", 0},
	{"25", "Retired X.509 Certificate for Key Management 11", 
			"2.16.840.1.101.3.7.2.16.11", NULL, "100B", 0},
	{"26", "Retired X.509 Certificate for Key Management 12", 
			"2.16.840.1.101.3.7.2.16.12", NULL, "100C", 0},
	{"27", "Retired X.509 Certificate for Key Management 13", 
			"2.16.840.1.101.3.7.2.16.13", NULL, "100D", 0},
	{"28", "Retired X.509 Certificate for Key Management 14", 
			"2.16.840.1.101.3.7.2.16.14", NULL, "100E", 0},
	{"29", "Retired X.509 Certificate for Key Management 15", 
			"2.16.840.1.101.3.7.2.16.15", NULL, "100F", 0},
	{"30", "Retired X.509 Certificate for Key Management 16", 
			"2.16.840.1.101.3.7.2.16.16", NULL, "1010", 0},
	{"31", "Retired X.509 Certificate for Key Management 17", 
			"2.16.840.1.101.3.7.2.16.17", NULL, "1011", 0},
	{"32", "Retired X.509 Certificate for Key Management 18", 
			"2.16.840.1.101.3.7.2.16.18", NULL, "1012", 0},
	{"33", "Retired X.509 Certificate for Key Management 19", 
			"2.16.840.1.101.3.7.2.16.19", NULL, "1013", 0},
	{"34", "Retired X.509 Certificate for Key Management 20", 
			"2.16.840.1.101.3.7.2.16.20", NULL, "1014", 0},
	{NULL, NULL, NULL, NULL, NULL, 0}
};
	/* 
	 * NIST 800-73-1 lifted the restriction on 
	 * requiring pin protected certs. Thus the default is to
	 * not require this.
	 */
	/* certs will be pulled out from the cert objects */
	/* the number of cert, pubkey and prkey triplets */

#define PIV_NUM_CERTS_AND_KEYS 24

	static const cdata certs[PIV_NUM_CERTS_AND_KEYS] = {
		{"01", "Certificate for PIV Authentication", "0101cece", 0, 0},
		{"02", "Certificate for Digital Signature", "0100cece", 0, 0},
		{"03", "Certificate for Key Management", "0102cece", 0, 0},
		{"04", "Certificate for Card Authentication", "0500cece", 0, 0},
		{"05", "Retired Certificate for Key Management 1", "1001cece", 0, 0},
		{"06", "Retired Certificate for Key Management 2", "1002cece", 0, 0},
		{"07", "Retired Certificate for Key Management 3", "1003cece", 0, 0},
		{"08", "Retired Certificate for Key Management 4", "1004cece", 0, 0},
		{"09", "Retired Certificate for Key Management 5", "1005cece", 0, 0},
		{"10", "Retired Certificate for Key Management 6", "1006cece", 0, 0},
		{"11", "Retired Certificate for Key Management 7", "1007cece", 0, 0},
		{"12", "Retired Certificate for Key Management 8", "1008cece", 0, 0},
		{"13", "Retired Certificate for Key Management 9", "1009cece", 0, 0},
		{"14", "Retired Certificate for Key Management 10", "100Acece", 0, 0},
		{"15", "Retired Certificate for Key Management 11", "100Bcece", 0, 0},
		{"16", "Retired Certificate for Key Management 12", "100Ccece", 0, 0},
		{"17", "Retired Certificate for Key Management 13", "100Dcece", 0, 0},
		{"18", "Retired Certificate for Key Management 14", "100Ecece", 0, 0},
		{"19", "Retired Certificate for Key Management 15", "100Fcece", 0, 0},
		{"20", "Retired Certificate for Key Management 16", "1010cece", 0, 0},
		{"21", "Retired Certificate for Key Management 17", "1011cece", 0, 0},
		{"22", "Retired Certificate for Key Management 18", "1012cece", 0, 0},
		{"23", "Retired Certificate for Key Management 19", "1013cece", 0, 0},
		{"24", "Retired Certificate for Key Management 20", "1014cece", 0, 0}
	};

	static const pindata pins[] = {
		{ "01", "PIN", "", 0x80,
		  /* label, flag  and ref will change if using global pin */
		  SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		  8, 4, 8, 
		  SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
		  SC_PKCS15_PIN_FLAG_INITIALIZED |
		  SC_PKCS15_PIN_FLAG_LOCAL, 
		  -1, 0xFF,
		  SC_PKCS15_CO_FLAG_PRIVATE },
		{ "02", "PIV PUK", "", 0x81, 
		  SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		  8, 4, 8, 
		  SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
		  SC_PKCS15_PIN_FLAG_INITIALIZED |
		  SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_SO_PIN |
		  SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN, 
		  -1, 0xFF, 
		  SC_PKCS15_CO_FLAG_PRIVATE },
		{ NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	};


	/*
	 * The size of the key or the algid is not really known
	 * but can be derived from the certificates. 
	 * the cert, pubkey and privkey are a set. 
	 * Key usages bits taken from pkcs15v1_1 Table 2
	 * RSA and EC have different sets of usage
	 */
	static const pubdata pubkeys[PIV_NUM_CERTS_AND_KEYS] = {

		{ "01", "PIV AUTH pubkey", 
			 	/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT |
			 		SC_PKCS15_PRKEY_USAGE_WRAP |
					SC_PKCS15_PRKEY_USAGE_VERIFY |
					SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,
				/*EC*/SC_PKCS15_PRKEY_USAGE_VERIFY,
			"9A06", 0x9A, NULL, 0, "PIV_9A_KEY"},
		{ "02", "SIGN pubkey", 
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT |
					SC_PKCS15_PRKEY_USAGE_VERIFY |
					SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER |
					SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
				/*EC*/SC_PKCS15_PRKEY_USAGE_VERIFY |
					SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
			"9C06", 0x9C, NULL, 0, "PIV_9C_KEY"},
		{ "03", "KEY MAN pubkey", 
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT| SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"9D06", 0x9D, NULL, 0, "PIV_9D_KEY"},
		{ "04", "CARD AUTH pubkey", 
				/*RSA*/SC_PKCS15_PRKEY_USAGE_VERIFY |
					SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER, 
				/*EC*/SC_PKCS15_PRKEY_USAGE_VERIFY,
			"9E06", 0x9E, NULL, 0, "PIV_9E_KEY"},  /* no pin, and avail in contactless */

		{ "05", "Retired KEY MAN 1",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8206", 0x82, NULL, 0, NULL},
		{ "06", "Retired KEY MAN 2",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8306", 0x83, NULL, 0, NULL},
		{ "07", "Retired KEY MAN 3",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8406", 0x84, NULL, 0, NULL},
		{ "08", "Retired KEY MAN 4",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8506", 0x85, NULL, 0, NULL},
		{ "09", "Retired KEY MAN 5",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8606", 0x86, NULL, 0, NULL},
		{ "10", "Retired KEY MAN 6",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8706", 0x87, NULL, 0, NULL},
		{ "11", "Retired KEY MAN 7",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8806", 0x88, NULL, 0, NULL},
		{ "12", "Retired KEY MAN 8",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8906", 0x89, NULL, 0, NULL},
		{ "13", "Retired KEY MAN 9",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8A06", 0x8A, NULL, 0, NULL},
		{ "14", "Retired KEY MAN 10",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8B06", 0x8B, NULL, 0, NULL},
		{ "15", "Retired KEY MAN 11",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8C06", 0x8C, NULL, 0, NULL},
		{ "16", "Retired KEY MAN 12",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8D06", 0x8D, NULL, 0, NULL},
		{ "17", "Retired KEY MAN 13",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8E06", 0x8E, NULL, 0, NULL},
		{ "18", "Retired KEY MAN 14",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "8F06", 0x8F, NULL, 0, NULL},
		{ "19", "Retired KEY MAN 15",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "9006", 0x90, NULL, 0, NULL},
		{ "20", "Retired KEY MAN 16",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "9106", 0x91, NULL, 0, NULL},
		{ "21", "Retired KEY MAN 17",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "9206", 0x92, NULL, 0, NULL},
		{ "22", "Retired KEY MAN 18",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "9306", 0x93, NULL, 0, NULL},
		{ "23", "Retired KEY MAN 19",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "9406", 0x94, NULL, 0, NULL},
		{ "24", "Retired KEY MAN 20",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			 "9506", 0x95, NULL, 0, NULL} };

/*
 * note some of the SC_PKCS15_PRKEY values are dependent
 * on the key algorithm, and will be reset. 
 */
	static const prdata prkeys[PIV_NUM_CERTS_AND_KEYS] = {
		{ "01", "PIV AUTH key", 
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT |
					SC_PKCS15_PRKEY_USAGE_UNWRAP |
					SC_PKCS15_PRKEY_USAGE_SIGN |
					SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,
				/*EC*/SC_PKCS15_PRKEY_USAGE_SIGN,
			"", 0x9A, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "02", "SIGN key", 
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT |
					SC_PKCS15_PRKEY_USAGE_SIGN |
					SC_PKCS15_PRKEY_USAGE_SIGNRECOVER |
					SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
				/*EC*/SC_PKCS15_PRKEY_USAGE_SIGN | 
					SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
			"", 0x9C, "01", SC_PKCS15_CO_FLAG_PRIVATE, 1},
		{ "03", "KEY MAN key", 
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x9D, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "04", "CARD AUTH key", 
				/*RSA*/SC_PKCS15_PRKEY_USAGE_SIGN |
				SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,
				/*EC*/SC_PKCS15_PRKEY_USAGE_SIGN,
			"", 0x9E, NULL, 0, 0}, /* no PIN needed, works with wireless */
		{ "05", "Retired KEY MAN 1",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x82, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "06", "Retired KEY MAN 2",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x83, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "07", "Retired KEY MAN 3",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x84, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "08", "Retired KEY MAN 4",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x85, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "09", "Retired KEY MAN 5",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x86, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "10", "Retired KEY MAN 6",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x87, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "11", "Retired KEY MAN 7",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x88, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "12", "Retired KEY MAN 8",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x89, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "13", "Retired KEY MAN 9",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x8A, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "14", "Retired KEY MAN 10",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x8B, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "15", "Retired KEY MAN 11",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x8C, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "16", "Retired KEY MAN 12",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x8D, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "17", "Retired KEY MAN 13",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x8E, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "18", "Retired KEY MAN 14",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x8F, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "19", "Retired KEY MAN 15",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x90, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "20", "Retired KEY MAN 16",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x91, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "21", "Retired KEY MAN 17",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x92, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "22", "Retired KEY MAN 18",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x93, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "23", "Retired KEY MAN 19",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x94, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0},
		{ "24", "Retired KEY MAN 20",
				/*RSA*/SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP,
				/*EC*/SC_PKCS15_PRKEY_USAGE_DERIVE,
			"", 0x95, "01", SC_PKCS15_CO_FLAG_PRIVATE, 0}
	};

	int    r, i;
	sc_card_t *card = p15card->card;
	sc_serial_number_t serial;
	char buf[SC_MAX_SERIALNR * 2 + 1];
	common_key_info ckis[PIV_NUM_CERTS_AND_KEYS];
	int follows_nist_fascn = 0;
	char *token_name = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&serial, 0, sizeof(serial));

	/* could read this off card if needed */

	/* CSP does not like a - in the name */
	p15card->tokeninfo->label = strdup("PIV_II");
	p15card->tokeninfo->manufacturer_id = strdup(MANU_ID);

	/*
	 * get serial number 
	 * We will use the FASC-N from the CHUID
	 * Note we are not verifying CHUID, belongs to this card
	 * but need serial number for Mac tokend 
	 */

	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r < 0) {
		sc_log(card->ctx, "sc_card_ctl rc=%d",r);
		p15card->tokeninfo->serial_number = strdup("00000000");
	} else {
		sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
		p15card->tokeninfo->serial_number = strdup(buf);
	}
	/* US gov issued PIVs have CHUID with a FASCN that does not start with 9999 */
	if (serial.len == 25 && !(serial.value[0] == 0xD4 && serial.value[1] == 0xE7 && serial.value[2] == 0x39 && (serial.value[3] | 0x7F) == 0xFF)) {
	    follows_nist_fascn = 1;
	}

	sc_log(card->ctx,  "PIV-II adding objects...");

	/* set other objects */
	for (i = 0; objects[i].label; i++) {
		struct sc_pkcs15_data_info obj_info;
		struct sc_pkcs15_object    obj_obj;

		memset(&obj_info, 0, sizeof(obj_info));
		memset(&obj_obj, 0, sizeof(obj_obj));
		sc_pkcs15_format_id(objects[i].id, &obj_info.id);
		sc_format_path(objects[i].path, &obj_info.path);

		/* See if the object can not be present on the card */
		r = sc_card_ctl(card, SC_CARDCTL_PIV_OBJECT_PRESENT, &obj_info.path);
		if (r == 1)
			continue; /* Not on card, do not define the object */
			
		strncpy(obj_info.app_label, objects[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		r = sc_format_oid(&obj_info.app_oid, objects[i].aoid);
		if (r != SC_SUCCESS)
			return r;

		if (objects[i].auth_id)
			sc_pkcs15_format_id(objects[i].auth_id, &obj_obj.auth_id);

		strncpy(obj_obj.label, objects[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		obj_obj.flags = objects[i].obj_flags;
		
		r = sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_DATA_OBJECT, 
			&obj_obj, &obj_info); 
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
/* TODO
 * PIV key 9C requires the pin verify be done just before any
 * crypto operation using the key. 
 * 
 * Nss 3.12.7 does not check the CKA_ALWAYS_AUTHENTICATE attribute of a key
 * and will do a C_FindObjects with only CKA_VALUE looking for a certificate
 * it had found earlier after c_Login. The template does not add CKA_TYPE=cert.
 * This will cause the card-piv to read all the objects and will reset
 * the security status for the 9C key.
 * Mozilla Bug 357025 
 * Mozilla Bug 613507
 * on 5/16/2012, both scheduled for NSS 3.14 
 * 
 * We can not read all the objects, as some need the PIN!
 */  
	}

	/*
	 * certs, pubkeys and priv keys are related and we assume
	 * they are in order 
	 * We need to read the cert, get modulus and keylen 
	 * We use those for the pubkey, and priv key objects. 
	 * If no cert, then see if pubkey (i.e. we are initializing,
	 * and the pubkey is in a file,) then add pubkey and privkey
	 * If no cert and no pubkey, skip adding them. 
 
	 */
	/* set certs */
	sc_log(card->ctx,  "PIV-II adding certs...");
	for (i = 0; i < PIV_NUM_CERTS_AND_KEYS; i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object    cert_obj;
		sc_pkcs15_der_t   cert_der;
		sc_pkcs15_cert_t *cert_out = NULL;
		
		ckis[i].cert_found = 0;
		ckis[i].key_alg = -1;
		ckis[i].pubkey_found = 0;
		ckis[i].pubkey_from_file = 0;
		ckis[i].pubkey_len = 0;
		ckis[i].pubkey_from_cert = NULL;
		ckis[i].cert_keyUsage = 0;
		ckis[i].cert_keyUsage_present = 0;
		ckis[i].pub_usage = 0;
		ckis[i].priv_usage = 0;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));
	
		sc_pkcs15_format_id(certs[i].id, &cert_info.id);
		cert_info.authority = certs[i].authority;
		sc_format_path(certs[i].path, &cert_info.path);

		strncpy(cert_obj.label, certs[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		cert_obj.flags = certs[i].obj_flags;

		/* See if the cert might be present or not. */
		r = sc_card_ctl(card, SC_CARDCTL_PIV_OBJECT_PRESENT, &cert_info.path);
		if (r == 1) {
			sc_log(card->ctx,  "Cert can not be present,i=%d", i);
			continue;
		}

		r = sc_pkcs15_read_file(p15card, &cert_info.path, &cert_der.value, &cert_der.len);

		if (r) {
			sc_log(card->ctx,  "No cert found,i=%d", i);
			continue;
		}

		ckis[i].cert_found = 1;
		/* cache it using the PKCS15 emulation objects */
		/* as it does not change */
		if (cert_der.value) {
			cert_info.value.value = cert_der.value;
			cert_info.value.len = cert_der.len;
			if (!p15card->opts.use_file_cache) {
				cert_info.path.len = 0; /* use in mem cert from now on */
			}
		}
		/* following will find the cached cert in cert_info */
		r =  sc_pkcs15_read_certificate(p15card, &cert_info, &cert_out);
		if (r < 0 || cert_out->key == NULL) {
			sc_log(card->ctx,  "Failed to read/parse the certificate r=%d",r);
			if (cert_out != NULL)
				sc_pkcs15_free_certificate(cert_out);
			free(cert_der.value);
			continue;
		}

		/* set the token name to the name of the CN of the first certificate */
		if (!token_name) {
			u8 * cn_name = NULL;
			size_t cn_len = 0;
			static const struct sc_object_id cn_oid = {{ 2, 5, 4, 3, -1 }};
			r = sc_pkcs15_get_name_from_dn(card->ctx, cert_out->subject,
				cert_out->subject_len, &cn_oid, &cn_name, &cn_len);
			if (r == SC_SUCCESS) {
				token_name = malloc (cn_len+1);
				if (!token_name) {
					sc_pkcs15_free_certificate(cert_out);
					free(cn_name);
					SC_FUNC_RETURN(card->ctx,
						SC_ERROR_OUT_OF_MEMORY, r);
				}
				memcpy(token_name, cn_name, cn_len);
				free(cn_name);
				token_name[cn_len] = 0;
				free(p15card->tokeninfo->label);
				p15card->tokeninfo->label = token_name;
			}
		}

		/* 
		 * get keyUsage if present save in ckis[i]
		 * Will only use it if this in a non FED issued card
		 * which has a CHUID with FASC-N not starting with 9999
		 */

		if (follows_nist_fascn == 0) {
			struct sc_object_id keyUsage_oid={{2,5,29,15,-1}};
			int r = 0;

			r = sc_pkcs15_get_bitstring_extension(card->ctx, cert_out,
				&keyUsage_oid,
				&ckis[i].cert_keyUsage, NULL);
			if ( r >= 0)
				ckis[i].cert_keyUsage_present = 1;
				/* TODO if no key usage, we could set all uses */
		}


		ckis[i].key_alg = cert_out->key->algorithm;
		switch (cert_out->key->algorithm) {
			case SC_ALGORITHM_RSA:
				/* save pubkey_len for pub and priv */
				ckis[i].pubkey_len = cert_out->key->u.rsa.modulus.len * 8;
				/* See RFC 5280 and PKCS#11 V2.40 */
				if (ckis[i].cert_keyUsage_present) {
					if (ckis[i].cert_keyUsage & SC_X509_DIGITAL_SIGNATURE) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT /* extra*/
									|SC_PKCS15_PRKEY_USAGE_WRAP
									|SC_PKCS15_PRKEY_USAGE_VERIFY
									|SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
					        ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT /*extra */
									|SC_PKCS15_PRKEY_USAGE_UNWRAP
									|SC_PKCS15_PRKEY_USAGE_SIGN
									|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
					}
					if (ckis[i].cert_keyUsage & SC_X509_NON_REPUDIATION) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT /* extra */
									|SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
									|SC_PKCS15_PRKEY_USAGE_VERIFY
									|SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT /*extra*/
									|SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
									|SC_PKCS15_PRKEY_USAGE_SIGN
									|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
					}
					if (ckis[i].cert_keyUsage & SC_X509_KEY_ENCIPHERMENT) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT| SC_PKCS15_PRKEY_USAGE_WRAP;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT| SC_PKCS15_PRKEY_USAGE_UNWRAP;
					}
					if (ckis[i].cert_keyUsage & SC_X509_DATA_ENCIPHERMENT) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
					}
					if (ckis[i].cert_keyUsage & SC_X509_KEY_AGREEMENT) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
					}
					if (ckis[i].cert_keyUsage & SC_X509_KEY_CERT_SIGN) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_VERIFY|SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
						ckis[i].priv_usage |=  SC_PKCS15_PRKEY_USAGE_SIGN;
					}
					if (ckis[i].cert_keyUsage & SC_X509_CRL_SIGN) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_VERIFY|SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
						ckis[i].priv_usage |=  SC_PKCS15_PRKEY_USAGE_SIGN;
					}
					if (ckis[i].cert_keyUsage & SC_X509_ENCIPHER_ONLY) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT|SC_PKCS15_PRKEY_USAGE_WRAP;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP;
					}
					if (ckis[i].cert_keyUsage & SC_X509_DECIPHER_ONLY) { /* TODO is this correct */
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT|SC_PKCS15_PRKEY_USAGE_WRAP;
					}
				}
				break;

			case SC_ALGORITHM_EC:
				ckis[i].pubkey_len = cert_out->key->u.ec.params.field_length;
				if (ckis[i].cert_keyUsage_present) {
					if (ckis[i].cert_keyUsage & SC_X509_DIGITAL_SIGNATURE) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_VERIFY;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_SIGN;
					}
					if (ckis[i].cert_keyUsage & SC_X509_NON_REPUDIATION) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
					}
					if (ckis[i].cert_keyUsage & SC_X509_KEY_ENCIPHERMENT) {
						ckis[i].pub_usage |= 0;
						ckis[i].priv_usage |= 0;
					}
					if (ckis[i].cert_keyUsage & SC_X509_DATA_ENCIPHERMENT) {
						ckis[i].pub_usage |= 0;
						ckis[i].priv_usage |= 0;
					}
					if (ckis[i].cert_keyUsage & SC_X509_KEY_AGREEMENT) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
					}
					if (ckis[i].cert_keyUsage & SC_X509_KEY_CERT_SIGN) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_VERIFY;
						ckis[i].priv_usage |= SC_PKCS15_PRKEY_USAGE_SIGN;
					}
					if (ckis[i].cert_keyUsage & SC_X509_CRL_SIGN) {
						ckis[i].pub_usage |= SC_PKCS15_PRKEY_USAGE_VERIFY;
						ckis[i].priv_usage |=  SC_PKCS15_PRKEY_USAGE_SIGN;
					}
					if (ckis[i].cert_keyUsage & SC_X509_ENCIPHER_ONLY) {
						ckis[i].pub_usage |= 0;
						ckis[i].priv_usage |= 0;
					}
					if (ckis[i].cert_keyUsage & SC_X509_DECIPHER_ONLY) {
						ckis[i].pub_usage |= 0;
						ckis[i].priv_usage |= 0;
					}
				}
				break;

			default:
				sc_log(card->ctx,  "Unsupported key.algorithm %d", cert_out->key->algorithm);
				ckis[i].pubkey_len = 0; /* set some value for now */
		}
		ckis[i].pubkey_from_cert = cert_out->key;
		cert_out->key = NULL;
		sc_pkcs15_free_certificate(cert_out);

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0) {
			sc_log(card->ctx,  " Failed to add cert obj r=%d",r);
			continue;
		}
	}

	/* set pins */
	sc_log(card->ctx,  "PIV-II adding pins...");
	for (i = 0; pins[i].label; i++) {
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object   pin_obj;
		const char * label;
		int pin_ref;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj,  0, sizeof(pin_obj));

		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		sc_pkcs15_format_id(pins[i].id, &pin_info.auth_id);
		pin_info.attrs.pin.reference     = pins[i].ref;
		pin_info.attrs.pin.flags         = pins[i].flags;
		pin_info.attrs.pin.type          = pins[i].type;
		pin_info.attrs.pin.min_length    = pins[i].minlen;
		pin_info.attrs.pin.stored_length = pins[i].storedlen;
		pin_info.attrs.pin.max_length    = pins[i].maxlen;
		pin_info.attrs.pin.pad_char      = pins[i].pad_char;
		sc_format_path(pins[i].path, &pin_info.path);
		pin_info.tries_left    = -1;

		label = pins[i].label;
		if (i == 0 &&
			sc_card_ctl(card, SC_CARDCTL_PIV_PIN_PREFERENCE,
					&pin_ref) == 0 &&
				pin_ref == 0x00) { /* must be 80 for PIV pin, or 00 for Global PIN */
			pin_info.attrs.pin.reference = pin_ref;
			pin_info.attrs.pin.flags &= ~SC_PKCS15_PIN_FLAG_LOCAL;
			label = "Global PIN";
		}
sc_log(card->ctx,  "DEE Adding pin %d label=%s",i, label);
		strncpy(pin_obj.label, label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj.flags = pins[i].obj_flags;
		if (i == 0 && pin_info.attrs.pin.reference == 0x80) {
			/*
			 * according to description of "RESET RETRY COUNTER"
			 * command in specs PUK can only unblock PIV PIN
			 */
			pin_obj.auth_id.len = 1;
			pin_obj.auth_id.value[0] = 2;
		}

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
	}



	/* set public keys */
	/* We may only need this during initialization when genkey
	 * gets the pubkey, but it can not be read from the card 
	 * at a later time. The piv-tool can stash  pubkey in file
	 */ 
	sc_log(card->ctx,  "PIV-II adding pub keys...");
	for (i = 0; i < PIV_NUM_CERTS_AND_KEYS; i++) {
		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_object     pubkey_obj;
		struct sc_pkcs15_pubkey *p15_key = NULL;

		memset(&pubkey_info, 0, sizeof(pubkey_info));
		memset(&pubkey_obj,  0, sizeof(pubkey_obj));


		sc_pkcs15_format_id(pubkeys[i].id, &pubkey_info.id);
		pubkey_info.native        = 1;
		pubkey_info.key_reference = pubkeys[i].ref;

//		sc_format_path(pubkeys[i].path, &pubkey_info.path);

		strncpy(pubkey_obj.label, pubkeys[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);

		pubkey_obj.flags = pubkeys[i].obj_flags;
		

		if (pubkeys[i].auth_id)
			sc_pkcs15_format_id(pubkeys[i].auth_id, &pubkey_obj.auth_id);

		/* If no cert found, piv-tool may have stashed the pubkey
		 * so we can use it when generating a certificate request
		 * The file is a OpenSSL DER EVP_KEY, which looks like 
		 * a certificate subjectPublicKeyInfo.
		 *
		 */
		if (ckis[i].cert_found == 0 ) { /*  no cert found */
			char * filename = NULL;
			
			sc_log(card->ctx, "No cert for this pub key i=%d",i);
			
			/* 
			 * If we used the piv-tool to generate a key,
			 * we would have saved the public key as a file.
			 * This code is only used while signing a request
			 * After the certificate is loaded on the card,
			 * the public key is extracted from the certificate.
			 */
	
			
			sc_log(card->ctx, "DEE look for env %s", 
					pubkeys[i].getenvname?pubkeys[i].getenvname:"NULL");

			if (pubkeys[i].getenvname == NULL) 
				continue;

			filename = getenv(pubkeys[i].getenvname); 
			sc_log(card->ctx, "DEE look for file %s", filename?filename:"NULL");
			if (filename == NULL)  
				continue;
			
			sc_log(card->ctx, "Adding pubkey from file %s",filename);

			r = sc_pkcs15_pubkey_from_spki_file(card->ctx,  filename, &p15_key);
			if (r < 0) {
				free(p15_key);
				continue;
			}

			/* Lets also try another method. */
			r = sc_pkcs15_encode_pubkey_as_spki(card->ctx, p15_key, &pubkey_info.direct.spki.value, &pubkey_info.direct.spki.len);
        		LOG_TEST_RET(card->ctx, r, "SPKI encode public key error");
			
			/* Only get here if no cert, and the the above found the
			 * pub key file (actually the SPKI version). This only 
			 * happens when trying initializing a card and have set 
			 * env PIV_9A_KEY or 9C, 9D, 9E to point at the file. 
			 *
			 * We will cache it using the PKCS15 emulation objects
			 */

			pubkey_info.path.len = 0;
			
			ckis[i].key_alg = p15_key->algorithm; 
			switch (p15_key->algorithm) {
				case SC_ALGORITHM_RSA:
					/* save pubkey_len in pub and priv */
					ckis[i].pubkey_len = p15_key->u.rsa.modulus.len * 8;
					ckis[i].pubkey_found = 1;
					ckis[i].pubkey_from_file = 1;
					break;
				case SC_ALGORITHM_EC:
					ckis[i].key_alg = SC_ALGORITHM_EC;
					ckis[i].pubkey_len = p15_key->u.ec.params.field_length;
					ckis[i].pubkey_found = 1;
					ckis[i].pubkey_from_file = 1;
					break;
				default:
					sc_log(card->ctx, "Unsupported key_alg %d",p15_key->algorithm);
					continue;
			}
			pubkey_obj.emulated = p15_key;
			p15_key = NULL;
		}
		else if (ckis[i].pubkey_from_cert)   {
			r = sc_pkcs15_encode_pubkey_as_spki(card->ctx, ckis[i].pubkey_from_cert, &pubkey_info.direct.spki.value, &pubkey_info.direct.spki.len);
        		LOG_TEST_RET(card->ctx, r, "SPKI encode public key error");

			pubkey_obj.emulated = ckis[i].pubkey_from_cert;
		}

		sc_log(card->ctx, "adding pubkey for %d keyalg=%d",i, ckis[i].key_alg);
		switch (ckis[i].key_alg) {
			case SC_ALGORITHM_RSA:
				if (ckis[i].cert_keyUsage_present) {
					pubkey_info.usage =  ckis[i].pub_usage;
				} else {
					pubkey_info.usage = pubkeys[i].usage_rsa;
				}
				pubkey_info.modulus_length = ckis[i].pubkey_len;
				strncpy(pubkey_obj.label, pubkeys[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);

				r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
				if (r < 0)
					LOG_FUNC_RETURN(card->ctx, r); /* should not fail */

				ckis[i].pubkey_found = 1;
				break;
			case SC_ALGORITHM_EC:
				if (ckis[i].cert_keyUsage_present) {
					pubkey_info.usage = ckis[i].pub_usage;
				} else {
				    pubkey_info.usage = pubkeys[i].usage_ec;
				}

				pubkey_info.field_length = ckis[i].pubkey_len; 
				strncpy(pubkey_obj.label, pubkeys[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);

				r = sc_pkcs15emu_add_ec_pubkey(p15card, &pubkey_obj, &pubkey_info);
				if (r < 0) 
					LOG_FUNC_RETURN(card->ctx, r); /* should not fail */
				ckis[i].pubkey_found = 1;
				break;
			default:
				sc_log(card->ctx, "key_alg %d not supported", ckis[i].key_alg);
				continue;
		}
		sc_log(card->ctx, "USAGE: cert_keyUsage_present:%d usage:0x%8.8x",
				ckis[i].cert_keyUsage_present ,pubkey_info.usage); 
	}


	/* set private keys */
	sc_log(card->ctx,  "PIV-II adding private keys...");
	for (i = 0; i < PIV_NUM_CERTS_AND_KEYS; i++) {
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object     prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj,  0, sizeof(prkey_obj));

		if (ckis[i].cert_found == 0 && ckis[i].pubkey_found == 0)
			continue; /* i.e. no cert or pubkey */
		
		sc_pkcs15_format_id(prkeys[i].id, &prkey_info.id);
		prkey_info.native        = 1;
		prkey_info.key_reference = prkeys[i].ref;
		sc_format_path(prkeys[i].path, &prkey_info.path);

		strncpy(prkey_obj.label, prkeys[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		prkey_obj.flags = prkeys[i].obj_flags;
		prkey_obj.user_consent = prkeys[i].user_consent; /* only Sign key */

		if (prkeys[i].auth_id)
			sc_pkcs15_format_id(prkeys[i].auth_id, &prkey_obj.auth_id);

		/*
		 * When no cert is present and a pubkey in a file was found, 
		 * means the caller is initializing a card. A sign operation
		 * will be required to sign a certificate request even if 
		 * normal usage would not allow it. Set SC_PKCS15_PRKEY_USAGE_SIGN 
		 * TODO if code is added to allow key generation and request
		 * sign in the same session, similar code will be needed.
		 */

		if (ckis[i].pubkey_from_file == 1) {
			prkey_info.usage = SC_PKCS15_PRKEY_USAGE_SIGN;
			sc_log(card->ctx,  "Adding SC_PKCS15_PRKEY_USAGE_SIGN");
		}

		switch (ckis[i].key_alg) {
			case SC_ALGORITHM_RSA:
				if(ckis[i].cert_keyUsage_present) {
					prkey_info.usage |= ckis[i].priv_usage;
					/* If retired key and non gov cert has NONREPUDIATION, treat as user_consent */
					if (i >= 4 && (ckis[i].priv_usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)) {
						prkey_obj.user_consent = 1;
					}
				} else {
					prkey_info.usage |= prkeys[i].usage_rsa;
				}
				prkey_info.modulus_length= ckis[i].pubkey_len;
				r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
				break;
			case SC_ALGORITHM_EC:
				if (ckis[i].cert_keyUsage_present) {
					prkey_info.usage  |= ckis[i].priv_usage;
					/* If retired key and non gov cert has NONREPUDIATION, treat as user_consent */
					if (i >= 4 && (ckis[i].priv_usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)) {
						prkey_obj.user_consent = 1;
					}
				} else {
					prkey_info.usage  |= prkeys[i].usage_ec;
				}
				prkey_info.field_length = ckis[i].pubkey_len;
				sc_log(card->ctx,  "DEE added key_alg %2.2x prkey_obj.flags %8.8x",
					 ckis[i].key_alg, prkey_obj.flags);
				r = sc_pkcs15emu_add_ec_prkey(p15card, &prkey_obj, &prkey_info);
				break;
			default:
				sc_log(card->ctx,  "Unsupported key_alg %d", ckis[i].key_alg);
				r = 0; /* we just skip this one */
		}
		sc_log(card->ctx, "USAGE: cert_keyUsage_present:%d usage:0x%8.8x", ckis[i].cert_keyUsage_present ,prkey_info.usage);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, r);
	}

	p15card->ops.get_guid = piv_get_guid;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_piv_init_ex(sc_pkcs15_card_t *p15card,
		struct sc_aid *aid)
{
	sc_card_t   *card = p15card->card;
	sc_context_t    *ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (piv_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_piv_init(p15card);
}
