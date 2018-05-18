/*
 * pkcs15-sc-hsm.c : Initialize PKCS#15 emulation
 *
 * Copyright (C) 2012 Andreas Schwier, CardContact, Minden, Germany
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

#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"
#include "common/compat_strlcpy.h"
#include "common/compat_strnlen.h"

#include "card-sc-hsm.h"


extern struct sc_aid sc_hsm_aid;


void sc_hsm_set_serialnr(sc_card_t *card, char *serial);



static struct ec_curve curves[] = {
		{
				{ (unsigned char *) "\x2A\x86\x48\xCE\x3D\x03\x01\x01", 8},	// secp192r1 aka prime192r1
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 24},
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 24},
				{ (unsigned char *) "\x64\x21\x05\x19\xE5\x9C\x80\xE7\x0F\xA7\xE9\xAB\x72\x24\x30\x49\xFE\xB8\xDE\xEC\xC1\x46\xB9\xB1", 24},
				{ (unsigned char *) "\x04\x18\x8D\xA8\x0E\xB0\x30\x90\xF6\x7C\xBF\x20\xEB\x43\xA1\x88\x00\xF4\xFF\x0A\xFD\x82\xFF\x10\x12\x07\x19\x2B\x95\xFF\xC8\xDA\x78\x63\x10\x11\xED\x6B\x24\xCD\xD5\x73\xF9\x77\xA1\x1E\x79\x48\x11", 49},
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x99\xDE\xF8\x36\x14\x6B\xC9\xB1\xB4\xD2\x28\x31", 24},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ (unsigned char *) "\x2A\x86\x48\xCE\x3D\x03\x01\x07", 8},	// secp256r1 aka prime256r1
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 32},
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32},
				{ (unsigned char *) "\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B", 32},
				{ (unsigned char *) "\x04\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5", 65},
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51", 32},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ (unsigned char *) "\x2B\x24\x03\x03\x02\x08\x01\x01\x03", 9},	// brainpoolP192r1
				{ (unsigned char *) "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x30\x93\xD1\x8D\xB7\x8F\xCE\x47\x6D\xE1\xA8\x62\x97", 24},
				{ (unsigned char *) "\x6A\x91\x17\x40\x76\xB1\xE0\xE1\x9C\x39\xC0\x31\xFE\x86\x85\xC1\xCA\xE0\x40\xE5\xC6\x9A\x28\xEF", 24},
				{ (unsigned char *) "\x46\x9A\x28\xEF\x7C\x28\xCC\xA3\xDC\x72\x1D\x04\x4F\x44\x96\xBC\xCA\x7E\xF4\x14\x6F\xBF\x25\xC9", 24},
				{ (unsigned char *) "\x04\xC0\xA0\x64\x7E\xAA\xB6\xA4\x87\x53\xB0\x33\xC5\x6C\xB0\xF0\x90\x0A\x2F\x5C\x48\x53\x37\x5F\xD6\x14\xB6\x90\x86\x6A\xBD\x5B\xB8\x8B\x5F\x48\x28\xC1\x49\x00\x02\xE6\x77\x3F\xA2\xFA\x29\x9B\x8F", 49},
				{ (unsigned char *) "\xC3\x02\xF4\x1D\x93\x2A\x36\xCD\xA7\xA3\x46\x2F\x9E\x9E\x91\x6B\x5B\xE8\xF1\x02\x9A\xC4\xAC\xC1", 24},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ (unsigned char *) "\x2B\x24\x03\x03\x02\x08\x01\x01\x05", 9},	// brainpoolP224r1
				{ (unsigned char *) "\xD7\xC1\x34\xAA\x26\x43\x66\x86\x2A\x18\x30\x25\x75\xD1\xD7\x87\xB0\x9F\x07\x57\x97\xDA\x89\xF5\x7E\xC8\xC0\xFF", 28},
				{ (unsigned char *) "\x68\xA5\xE6\x2C\xA9\xCE\x6C\x1C\x29\x98\x03\xA6\xC1\x53\x0B\x51\x4E\x18\x2A\xD8\xB0\x04\x2A\x59\xCA\xD2\x9F\x43", 28},
				{ (unsigned char *) "\x25\x80\xF6\x3C\xCF\xE4\x41\x38\x87\x07\x13\xB1\xA9\x23\x69\xE3\x3E\x21\x35\xD2\x66\xDB\xB3\x72\x38\x6C\x40\x0B", 28},
				{ (unsigned char *) "\x04\x0D\x90\x29\xAD\x2C\x7E\x5C\xF4\x34\x08\x23\xB2\xA8\x7D\xC6\x8C\x9E\x4C\xE3\x17\x4C\x1E\x6E\xFD\xEE\x12\xC0\x7D\x58\xAA\x56\xF7\x72\xC0\x72\x6F\x24\xC6\xB8\x9E\x4E\xCD\xAC\x24\x35\x4B\x9E\x99\xCA\xA3\xF6\xD3\x76\x14\x02\xCD", 57},
				{ (unsigned char *) "\xD7\xC1\x34\xAA\x26\x43\x66\x86\x2A\x18\x30\x25\x75\xD0\xFB\x98\xD1\x16\xBC\x4B\x6D\xDE\xBC\xA3\xA5\xA7\x93\x9F", 28},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ (unsigned char *) "\x2B\x24\x03\x03\x02\x08\x01\x01\x07", 9},	// brainpoolP256r1
				{ (unsigned char *) "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x77", 32},
				{ (unsigned char *) "\x7D\x5A\x09\x75\xFC\x2C\x30\x57\xEE\xF6\x75\x30\x41\x7A\xFF\xE7\xFB\x80\x55\xC1\x26\xDC\x5C\x6C\xE9\x4A\x4B\x44\xF3\x30\xB5\xD9", 32},
				{ (unsigned char *) "\x26\xDC\x5C\x6C\xE9\x4A\x4B\x44\xF3\x30\xB5\xD9\xBB\xD7\x7C\xBF\x95\x84\x16\x29\x5C\xF7\xE1\xCE\x6B\xCC\xDC\x18\xFF\x8C\x07\xB6", 32},
				{ (unsigned char *) "\x04\x8B\xD2\xAE\xB9\xCB\x7E\x57\xCB\x2C\x4B\x48\x2F\xFC\x81\xB7\xAF\xB9\xDE\x27\xE1\xE3\xBD\x23\xC2\x3A\x44\x53\xBD\x9A\xCE\x32\x62\x54\x7E\xF8\x35\xC3\xDA\xC4\xFD\x97\xF8\x46\x1A\x14\x61\x1D\xC9\xC2\x77\x45\x13\x2D\xED\x8E\x54\x5C\x1D\x54\xC7\x2F\x04\x69\x97", 65},
				{ (unsigned char *) "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x71\x8C\x39\x7A\xA3\xB5\x61\xA6\xF7\x90\x1E\x0E\x82\x97\x48\x56\xA7", 32},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ (unsigned char *) "\x2B\x24\x03\x03\x02\x08\x01\x01\x09", 9},	// brainpoolP320r1
				{ (unsigned char *) "\xD3\x5E\x47\x20\x36\xBC\x4F\xB7\xE1\x3C\x78\x5E\xD2\x01\xE0\x65\xF9\x8F\xCF\xA6\xF6\xF4\x0D\xEF\x4F\x92\xB9\xEC\x78\x93\xEC\x28\xFC\xD4\x12\xB1\xF1\xB3\x2E\x27", 40},
				{ (unsigned char *) "\x3E\xE3\x0B\x56\x8F\xBA\xB0\xF8\x83\xCC\xEB\xD4\x6D\x3F\x3B\xB8\xA2\xA7\x35\x13\xF5\xEB\x79\xDA\x66\x19\x0E\xB0\x85\xFF\xA9\xF4\x92\xF3\x75\xA9\x7D\x86\x0E\xB4", 40},
				{ (unsigned char *) "\x52\x08\x83\x94\x9D\xFD\xBC\x42\xD3\xAD\x19\x86\x40\x68\x8A\x6F\xE1\x3F\x41\x34\x95\x54\xB4\x9A\xCC\x31\xDC\xCD\x88\x45\x39\x81\x6F\x5E\xB4\xAC\x8F\xB1\xF1\xA6", 40},
				{ (unsigned char *) "\x04\x43\xBD\x7E\x9A\xFB\x53\xD8\xB8\x52\x89\xBC\xC4\x8E\xE5\xBF\xE6\xF2\x01\x37\xD1\x0A\x08\x7E\xB6\xE7\x87\x1E\x2A\x10\xA5\x99\xC7\x10\xAF\x8D\x0D\x39\xE2\x06\x11\x14\xFD\xD0\x55\x45\xEC\x1C\xC8\xAB\x40\x93\x24\x7F\x77\x27\x5E\x07\x43\xFF\xED\x11\x71\x82\xEA\xA9\xC7\x78\x77\xAA\xAC\x6A\xC7\xD3\x52\x45\xD1\x69\x2E\x8E\xE1", 81},
				{ (unsigned char *) "\xD3\x5E\x47\x20\x36\xBC\x4F\xB7\xE1\x3C\x78\x5E\xD2\x01\xE0\x65\xF9\x8F\xCF\xA5\xB6\x8F\x12\xA3\x2D\x48\x2E\xC7\xEE\x86\x58\xE9\x86\x91\x55\x5B\x44\xC5\x93\x11", 40},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ (unsigned char *) "\x2B\x81\x04\x00\x1F", 5},	// secp192k1
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xEE\x37", 24},
				{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 24},
				{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03", 24},
				{ (unsigned char *) "\x04\xDB\x4F\xF1\x0E\xC0\x57\xE9\xAE\x26\xB0\x7D\x02\x80\xB7\xF4\x34\x1D\xA5\xD1\xB1\xEA\xE0\x6C\x7D\x9B\x2F\x2F\x6D\x9C\x56\x28\xA7\x84\x41\x63\xD0\x15\xBE\x86\x34\x40\x82\xAA\x88\xD9\x5E\x2F\x9D", 49},
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\x26\xF2\xFC\x17\x0F\x69\x46\x6A\x74\xDE\xFD\x8D", 24},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ (unsigned char *) "\x2B\x81\x04\x00\x0A", 5},	// secp256k1
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F", 32},
				{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32},
				{ (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07", 32},
				{ (unsigned char *) "\x04\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98\x48\x3A\xDA\x77\x26\xA3\xC4\x65\x5D\xA4\xFB\xFC\x0E\x11\x08\xA8\xFD\x17\xB4\x48\xA6\x85\x54\x19\x9C\x47\xD0\x8F\xFB\x10\xD4\xB8", 65},
				{ (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41", 32},
				{ (unsigned char *) "\x01", 1}
		},
		{
				{ NULL, 0},
				{ NULL, 0},
				{ NULL, 0},
				{ NULL, 0},
				{ NULL, 0},
				{ NULL, 0},
				{ NULL, 0}
		}
};



#define C_ASN1_CVC_PUBKEY_SIZE 10
static const struct sc_asn1_entry c_asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE] = {
	{ "publicKeyOID", SC_ASN1_OBJECT, SC_ASN1_UNI | SC_ASN1_OBJECT, 0, NULL, NULL },
	{ "primeOrModulus", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "coefficientAorExponent", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 2,  SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "coefficientB", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "basePointG", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "order", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "publicPoint", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 6, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "cofactor", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 7, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "modulusSize", SC_ASN1_INTEGER, SC_ASN1_UNI | SC_ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_CVC_BODY_SIZE 5
static const struct sc_asn1_entry c_asn1_cvc_body[C_ASN1_CVC_BODY_SIZE] = {
	{ "certificateProfileIdentifier", SC_ASN1_INTEGER, SC_ASN1_APP | 0x1F29, 0, NULL, NULL },
	{ "certificationAuthorityReference", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "publicKey", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F49, 0, NULL, NULL },
	{ "certificateHolderReference", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 0x1F20, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_CVCERT_SIZE 3
static const struct sc_asn1_entry c_asn1_cvcert[C_ASN1_CVCERT_SIZE] = {
	{ "certificateBody", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F4E, 0, NULL, NULL },
	{ "signature", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F37, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_CVC_SIZE 2
static const struct sc_asn1_entry c_asn1_cvc[C_ASN1_CVC_SIZE] = {
	{ "certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_AUTHREQ_SIZE 4
static const struct sc_asn1_entry c_asn1_authreq[C_ASN1_AUTHREQ_SIZE] = {
	{ "certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ "outerCAR", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "signature", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F37, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_REQ_SIZE 2
static const struct sc_asn1_entry c_asn1_req[C_ASN1_REQ_SIZE] = {
	{ "authenticatedrequest", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 7, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};



static int read_file(sc_pkcs15_card_t * p15card, u8 fid[2],
		u8 *efbin, size_t *len, int optional)
{
	sc_path_t path;
	int r;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, 0);
	/* look this up with our AID */
	path.aid = sc_hsm_aid;
	/* we don't have a pre-known size of the file */
	path.count = -1;
	if (!p15card->opts.use_file_cache || !efbin
			|| SC_SUCCESS != sc_pkcs15_read_cached_file(p15card, &path, &efbin, len)) {
		/* avoid re-selection of SC-HSM */
		path.aid.len = 0;
		r = sc_select_file(p15card->card, &path, NULL);
		if (r < 0) {
			sc_log(p15card->card->ctx, "Could not select EF");
		} else {
			r = sc_read_binary(p15card->card, 0, efbin, *len, 0);
		}

		if (r < 0) {
			sc_log(p15card->card->ctx, "Could not read EF");
			if (!optional) {
				return r;
			}
			/* optional files are saved as empty files to avoid card
			 * transactions. Parsing the file's data will reveal that they were
			 * missing. */
			*len = 0;
		} else {
			*len = r;
		}

		if (p15card->opts.use_file_cache) {
			/* save this with our AID */
			path.aid = sc_hsm_aid;
			sc_pkcs15_cache_file(p15card, &path, efbin, *len);
		}
	}

	return SC_SUCCESS;
}



/*
 * Decode a card verifiable certificate as defined in TR-03110.
 */
int sc_pkcs15emu_sc_hsm_decode_cvc(sc_pkcs15_card_t * p15card,
											const u8 ** buf, size_t *buflen,
											sc_cvc_t *cvc)
{
	sc_card_t *card = p15card->card;
	struct sc_asn1_entry asn1_req[C_ASN1_REQ_SIZE];
	struct sc_asn1_entry asn1_authreq[C_ASN1_AUTHREQ_SIZE];
	struct sc_asn1_entry asn1_cvc[C_ASN1_CVC_SIZE];
	struct sc_asn1_entry asn1_cvcert[C_ASN1_CVCERT_SIZE];
	struct sc_asn1_entry asn1_cvc_body[C_ASN1_CVC_BODY_SIZE];
	struct sc_asn1_entry asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE];
	unsigned int cla,tag;
	size_t taglen;
	size_t lenchr = sizeof(cvc->chr);
	size_t lencar = sizeof(cvc->car);
	size_t lenoutercar = sizeof(cvc->outer_car);
	const u8 *tbuf;
	int r;

	memset(cvc, 0, sizeof(*cvc));
	sc_copy_asn1_entry(c_asn1_req, asn1_req);
	sc_copy_asn1_entry(c_asn1_authreq, asn1_authreq);
	sc_copy_asn1_entry(c_asn1_cvc, asn1_cvc);
	sc_copy_asn1_entry(c_asn1_cvcert, asn1_cvcert);
	sc_copy_asn1_entry(c_asn1_cvc_body, asn1_cvc_body);
	sc_copy_asn1_entry(c_asn1_cvc_pubkey, asn1_cvc_pubkey);

	sc_format_asn1_entry(asn1_cvc_pubkey    , &cvc->pukoid, NULL, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 1, &cvc->primeOrModulus, &cvc->primeOrModuluslen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 2, &cvc->coefficientAorExponent, &cvc->coefficientAorExponentlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 3, &cvc->coefficientB, &cvc->coefficientBlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 4, &cvc->basePointG, &cvc->basePointGlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 5, &cvc->order, &cvc->orderlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 6, &cvc->publicPoint, &cvc->publicPointlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 7, &cvc->cofactor, &cvc->cofactorlen, 0);
	sc_format_asn1_entry(asn1_cvc_pubkey + 8, &cvc->modulusSize, NULL, 0);

	sc_format_asn1_entry(asn1_cvc_body    , &cvc->cpi, NULL, 0);
	sc_format_asn1_entry(asn1_cvc_body + 1, &cvc->car, &lencar, 0);
	sc_format_asn1_entry(asn1_cvc_body + 2, &asn1_cvc_pubkey, NULL, 0);
	sc_format_asn1_entry(asn1_cvc_body + 3, &cvc->chr, &lenchr, 0);

	sc_format_asn1_entry(asn1_cvcert    , &asn1_cvc_body, NULL, 0);
	sc_format_asn1_entry(asn1_cvcert + 1, &cvc->signature, &cvc->signatureLen, 0);

	sc_format_asn1_entry(asn1_cvc , &asn1_cvcert, NULL, 0);

	sc_format_asn1_entry(asn1_authreq    , &asn1_cvcert, NULL, 0);
	sc_format_asn1_entry(asn1_authreq + 1, &cvc->outer_car, &lenoutercar, 0);
	sc_format_asn1_entry(asn1_authreq + 2, &cvc->outerSignature, &cvc->outerSignatureLen, 0);

	sc_format_asn1_entry(asn1_req , &asn1_authreq, NULL, 0);

/*	sc_asn1_print_tags(*buf, *buflen); */

	tbuf = *buf;
	r = sc_asn1_read_tag(&tbuf, *buflen, &cla, &tag, &taglen);
	LOG_TEST_RET(card->ctx, r, "Could not decode card verifiable certificate");

	/*  Determine if we deal with an authenticated request, plain request or certificate */
	if ((cla == (SC_ASN1_TAG_APPLICATION|SC_ASN1_TAG_CONSTRUCTED)) && (tag == 7)) {
		r = sc_asn1_decode(card->ctx, asn1_req, *buf, *buflen, buf, buflen);
	} else {
		r = sc_asn1_decode(card->ctx, asn1_cvc, *buf, *buflen, buf, buflen);
	}

	LOG_TEST_RET(card->ctx, r, "Could not decode card verifiable certificate");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



/*
 * Encode a card verifiable certificate as defined in TR-03110.
 */
int sc_pkcs15emu_sc_hsm_encode_cvc(sc_pkcs15_card_t * p15card,
		sc_cvc_t *cvc,
		u8 ** buf, size_t *buflen)
{
	sc_card_t *card = p15card->card;
	struct sc_asn1_entry asn1_cvc[C_ASN1_CVC_SIZE];
	struct sc_asn1_entry asn1_cvcert[C_ASN1_CVCERT_SIZE];
	struct sc_asn1_entry asn1_cvc_body[C_ASN1_CVC_BODY_SIZE];
	struct sc_asn1_entry asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE];
	size_t lenchr;
	size_t lencar;
	int r;

	sc_copy_asn1_entry(c_asn1_cvc, asn1_cvc);
	sc_copy_asn1_entry(c_asn1_cvcert, asn1_cvcert);
	sc_copy_asn1_entry(c_asn1_cvc_body, asn1_cvc_body);
	sc_copy_asn1_entry(c_asn1_cvc_pubkey, asn1_cvc_pubkey);

	asn1_cvc_pubkey[1].flags = SC_ASN1_OPTIONAL;
	asn1_cvcert[1].flags = SC_ASN1_OPTIONAL;

	sc_format_asn1_entry(asn1_cvc_pubkey    , &cvc->pukoid, NULL, 1);
	if (cvc->primeOrModulus && (cvc->primeOrModuluslen > 0)) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 1, cvc->primeOrModulus, &cvc->primeOrModuluslen, 1);
	}
	sc_format_asn1_entry(asn1_cvc_pubkey + 2, cvc->coefficientAorExponent, &cvc->coefficientAorExponentlen, 1);
	if (cvc->coefficientB && (cvc->coefficientBlen > 0)) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 3, cvc->coefficientB, &cvc->coefficientBlen, 1);
		sc_format_asn1_entry(asn1_cvc_pubkey + 4, cvc->basePointG, &cvc->basePointGlen, 1);
		sc_format_asn1_entry(asn1_cvc_pubkey + 5, cvc->order, &cvc->orderlen, 1);
		if (cvc->publicPoint && (cvc->publicPointlen > 0)) {
			sc_format_asn1_entry(asn1_cvc_pubkey + 6, cvc->publicPoint, &cvc->publicPointlen, 1);
		}
		sc_format_asn1_entry(asn1_cvc_pubkey + 7, cvc->cofactor, &cvc->cofactorlen, 1);
	}
	if (cvc->modulusSize > 0) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 8, &cvc->modulusSize, NULL, 1);
	}

	sc_format_asn1_entry(asn1_cvc_body    , &cvc->cpi, NULL, 1);
	lencar = strnlen(cvc->car, sizeof cvc->car);
	sc_format_asn1_entry(asn1_cvc_body + 1, &cvc->car, &lencar, 1);
	sc_format_asn1_entry(asn1_cvc_body + 2, &asn1_cvc_pubkey, NULL, 1);
	lenchr = strnlen(cvc->chr, sizeof cvc->chr);
	sc_format_asn1_entry(asn1_cvc_body + 3, &cvc->chr, &lenchr, 1);

	sc_format_asn1_entry(asn1_cvcert    , &asn1_cvc_body, NULL, 1);
	if (cvc->signature && (cvc->signatureLen > 0)) {
		sc_format_asn1_entry(asn1_cvcert + 1, cvc->signature, &cvc->signatureLen, 1);
	}

	sc_format_asn1_entry(asn1_cvc , &asn1_cvcert, NULL, 1);

	r = sc_asn1_encode(card->ctx, asn1_cvc, buf, buflen);
	LOG_TEST_RET(card->ctx, r, "Could not encode card verifiable certificate");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



int sc_pkcs15emu_sc_hsm_get_curve(struct ec_curve **curve, u8 *oid, size_t oidlen)
{
	int i;

	for (i = 0; curves[i].oid.value; i++) {
		if ((curves[i].oid.len == oidlen) && !memcmp(curves[i].oid.value, oid, oidlen)) {
			*curve = &curves[i];
			return SC_SUCCESS;
		}
	}
	return SC_ERROR_INVALID_DATA;
}



int sc_pkcs15emu_sc_hsm_get_curve_oid(sc_cvc_t *cvc, const struct sc_lv_data **oid)
{
	int i;

	for (i = 0; curves[i].oid.value; i++) {
		if ((curves[i].prime.len == cvc->primeOrModuluslen) && !memcmp(curves[i].prime.value, cvc->primeOrModulus, cvc->primeOrModuluslen)) {
			*oid = &curves[i].oid;
			return SC_SUCCESS;
		}
	}
	return SC_ERROR_INVALID_DATA;
}



static int sc_pkcs15emu_sc_hsm_get_rsa_public_key(struct sc_context *ctx, sc_cvc_t *cvc, struct sc_pkcs15_pubkey *pubkey)
{
	pubkey->algorithm = SC_ALGORITHM_RSA;

	pubkey->alg_id = (struct sc_algorithm_id *)calloc(1, sizeof(struct sc_algorithm_id));
	if (!pubkey->alg_id)
		return SC_ERROR_OUT_OF_MEMORY;

	pubkey->alg_id->algorithm = SC_ALGORITHM_RSA;

	pubkey->u.rsa.modulus.len	= cvc->primeOrModuluslen;
	pubkey->u.rsa.modulus.data	= malloc(pubkey->u.rsa.modulus.len);
	pubkey->u.rsa.exponent.len	= cvc->coefficientAorExponentlen;
	pubkey->u.rsa.exponent.data	= malloc(pubkey->u.rsa.exponent.len);
	if (!pubkey->u.rsa.modulus.data || !pubkey->u.rsa.exponent.data)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(pubkey->u.rsa.exponent.data, cvc->coefficientAorExponent, pubkey->u.rsa.exponent.len);
	memcpy(pubkey->u.rsa.modulus.data, cvc->primeOrModulus, pubkey->u.rsa.modulus.len);

	return SC_SUCCESS;
}



static int sc_pkcs15emu_sc_hsm_get_ec_public_key(struct sc_context *ctx, sc_cvc_t *cvc, struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_ec_parameters *ecp;
	const struct sc_lv_data *oid;
	int r;

	pubkey->algorithm = SC_ALGORITHM_EC;

	r = sc_pkcs15emu_sc_hsm_get_curve_oid(cvc, &oid);
	if (r != SC_SUCCESS)
		return r;

	ecp = calloc(1, sizeof(struct sc_ec_parameters));
	if (!ecp)
		return SC_ERROR_OUT_OF_MEMORY;

	ecp->der.len = oid->len + 2;
	ecp->der.value = calloc(ecp->der.len, 1);
	if (!ecp->der.value) {
		free(ecp);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	*(ecp->der.value + 0) = 0x06;
	*(ecp->der.value + 1) = (u8)oid->len;
	memcpy(ecp->der.value + 2, oid->value, oid->len);
	ecp->type = 1;		// Named curve

	pubkey->alg_id = (struct sc_algorithm_id *)calloc(1, sizeof(struct sc_algorithm_id));
	if (!pubkey->alg_id) {
		free(ecp->der.value);
		free(ecp);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	pubkey->alg_id->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->params = ecp;

	pubkey->u.ec.ecpointQ.value = malloc(cvc->publicPointlen);
	if (!pubkey->u.ec.ecpointQ.value)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(pubkey->u.ec.ecpointQ.value, cvc->publicPoint, cvc->publicPointlen);
	pubkey->u.ec.ecpointQ.len = cvc->publicPointlen;

	pubkey->u.ec.params.der.value = malloc(ecp->der.len);
	if (!pubkey->u.ec.params.der.value)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(pubkey->u.ec.params.der.value, ecp->der.value, ecp->der.len);
	pubkey->u.ec.params.der.len = ecp->der.len;

	/* FIXME: check return value? */
	sc_pkcs15_fix_ec_parameters(ctx, &pubkey->u.ec.params);

	return SC_SUCCESS;
}



int sc_pkcs15emu_sc_hsm_get_public_key(struct sc_context *ctx, sc_cvc_t *cvc, struct sc_pkcs15_pubkey *pubkey)
{
	if (cvc->publicPoint && cvc->publicPointlen) {
		return sc_pkcs15emu_sc_hsm_get_ec_public_key(ctx, cvc, pubkey);
	} else {
		return sc_pkcs15emu_sc_hsm_get_rsa_public_key(ctx, cvc, pubkey);
	}
}



void sc_pkcs15emu_sc_hsm_free_cvc(sc_cvc_t *cvc)
{
	if (cvc->signature) {
		free(cvc->signature);
		cvc->signature = NULL;
	}
	if (cvc->primeOrModulus) {
		free(cvc->primeOrModulus);
		cvc->primeOrModulus = NULL;
	}
	if (cvc->coefficientAorExponent) {
		free(cvc->coefficientAorExponent);
		cvc->coefficientAorExponent = NULL;
	}
	if (cvc->coefficientB) {
		free(cvc->coefficientB);
		cvc->coefficientB = NULL;
	}
	if (cvc->basePointG) {
		free(cvc->basePointG);
		cvc->basePointG = NULL;
	}
	if (cvc->order) {
		free(cvc->order);
		cvc->order = NULL;
	}
	if (cvc->publicPoint) {
		free(cvc->publicPoint);
		cvc->publicPoint = NULL;
	}
	if (cvc->cofactor) {
		free(cvc->cofactor);
		cvc->cofactor = NULL;
	}
}



static int sc_pkcs15emu_sc_hsm_add_pubkey(sc_pkcs15_card_t *p15card, u8 *efbin, size_t len, sc_pkcs15_prkey_info_t *key_info, char *label)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_card_t *card = p15card->card;
	sc_pkcs15_pubkey_info_t pubkey_info;
	sc_pkcs15_object_t pubkey_obj;
	struct sc_pkcs15_pubkey pubkey;
	sc_cvc_t cvc;
	u8 *cvcpo;
	int r;

	cvcpo = efbin;

	memset(&cvc, 0, sizeof(cvc));
	r = sc_pkcs15emu_sc_hsm_decode_cvc(p15card, (const u8 **)&cvcpo, &len, &cvc);
	LOG_TEST_RET(ctx, r, "Could decode certificate signing request");

	memset(&pubkey, 0, sizeof(pubkey));
	r = sc_pkcs15emu_sc_hsm_get_public_key(ctx, &cvc, &pubkey);
	LOG_TEST_RET(card->ctx, r, "Could not extract public key");

	memset(&pubkey_info, 0, sizeof(pubkey_info));
	memset(&pubkey_obj, 0, sizeof(pubkey_obj));

	r = sc_pkcs15_encode_pubkey(ctx, &pubkey, &pubkey_obj.content.value, &pubkey_obj.content.len);
	LOG_TEST_RET(ctx, r, "Could not encode public key");
	r = sc_pkcs15_encode_pubkey(ctx, &pubkey, &pubkey_info.direct.raw.value, &pubkey_info.direct.raw.len);
	LOG_TEST_RET(ctx, r, "Could not encode public key");
	r = sc_pkcs15_encode_pubkey_as_spki(ctx, &pubkey, &pubkey_info.direct.spki.value, &pubkey_info.direct.spki.len);
	LOG_TEST_RET(ctx, r, "Could not encode public key");

	pubkey_info.id = key_info->id;
	strlcpy(pubkey_obj.label, label, sizeof(pubkey_obj.label));

	if (pubkey.algorithm == SC_ALGORITHM_RSA) {
		pubkey_info.modulus_length = pubkey.u.rsa.modulus.len << 3;
		pubkey_info.usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT|SC_PKCS15_PRKEY_USAGE_VERIFY|SC_PKCS15_PRKEY_USAGE_WRAP;
		r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
	} else {
		/* TODO fix if support of non multiple of 8 curves are added */
		pubkey_info.field_length = cvc.primeOrModuluslen << 3;
		pubkey_info.usage = SC_PKCS15_PRKEY_USAGE_VERIFY;
		r = sc_pkcs15emu_add_ec_pubkey(p15card, &pubkey_obj, &pubkey_info);
	}
	LOG_TEST_RET(ctx, r, "Could not add public key");

	sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
	sc_pkcs15_erase_pubkey(&pubkey);

	return SC_SUCCESS;
}



/*
 * Add a key and the key description in PKCS#15 format to the framework
 */
static int sc_pkcs15emu_sc_hsm_add_prkd(sc_pkcs15_card_t * p15card, u8 keyid) {

	sc_card_t *card = p15card->card;
	sc_pkcs15_cert_info_t cert_info;
	sc_pkcs15_object_t cert_obj;
	struct sc_pkcs15_object prkd;
	sc_pkcs15_prkey_info_t *key_info;
	u8 fid[2];
	/* enough to hold a complete certificate */
	u8 efbin[4096];
	u8 *ptr;
	size_t len;
	int r;

	fid[0] = PRKD_PREFIX;
	fid[1] = keyid;

	/* Try to select a related EF containing the PKCS#15 description of the key */
	len = sizeof efbin;
	r = read_file(p15card, fid, efbin, &len, 1);
	LOG_TEST_RET(card->ctx, r, "Skipping optional EF.PRKD");

	ptr = efbin;

	memset(&prkd, 0, sizeof(prkd));
	r = sc_pkcs15_decode_prkdf_entry(p15card, &prkd, (const u8 **)&ptr, &len);
	LOG_TEST_RET(card->ctx, r, "Skipping optional EF.PRKD");

	/* All keys require user PIN authentication */
	prkd.auth_id.len = 1;
	prkd.auth_id.value[0] = 1;

	/*
	 * Set private key flag as all keys are private anyway
	 */
	prkd.flags |= SC_PKCS15_CO_FLAG_PRIVATE;

	key_info = (sc_pkcs15_prkey_info_t *)prkd.data;
	key_info->key_reference = keyid;
	key_info->path.aid.len = 0;

	if (prkd.type == SC_PKCS15_TYPE_PRKEY_RSA) {
		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkd, key_info);
	} else {
		r = sc_pkcs15emu_add_ec_prkey(p15card, &prkd, key_info);
	}

	LOG_TEST_RET(card->ctx, r, "Could not add private key to framework");

	/* Check if we also have a certificate for the private key */
	fid[0] = EE_CERTIFICATE_PREFIX;

	len = sizeof efbin;
	r = read_file(p15card, fid, efbin, &len, 0);
	LOG_TEST_RET(card->ctx, r, "Could not read EF");

	if (efbin[0] == 0x67) {		/* Decode CSR and create public key object */
		sc_pkcs15emu_sc_hsm_add_pubkey(p15card, efbin, len, key_info, prkd.label);
		free(key_info);
		return SC_SUCCESS;		/* Ignore any errors */
	}

	if (efbin[0] != 0x30) {
		free(key_info);
		return SC_SUCCESS;
	}

	memset(&cert_info, 0, sizeof(cert_info));
	memset(&cert_obj, 0, sizeof(cert_obj));

	cert_info.id = key_info->id;
	sc_path_set(&cert_info.path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, 0);
	cert_info.path.count = -1;
	if (p15card->opts.use_file_cache) {
		/* look this up with our AID, which should already be cached from the
		 * call to `read_file`. This may have the side effect that OpenSC's
		 * caching layer re-selects our applet *if the cached file cannot be
		 * found/used* and we may loose the authentication status. We assume
		 * that caching works perfectly without this side effect. */
		cert_info.path.aid = sc_hsm_aid;
	}

	strlcpy(cert_obj.label, prkd.label, sizeof(cert_obj.label));
	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);

	free(key_info);

	LOG_TEST_RET(card->ctx, r, "Could not add certificate");

	return SC_SUCCESS;
}



/*
 * Add a data object and description in PKCS#15 format to the framework
 */
static int sc_pkcs15emu_sc_hsm_add_dcod(sc_pkcs15_card_t * p15card, u8 id) {

	sc_card_t *card = p15card->card;
	sc_pkcs15_data_info_t *data_info;
	sc_pkcs15_object_t data_obj;
	u8 fid[2];
	u8 efbin[512];
	const u8 *ptr;
	size_t len;
	int r;

	fid[0] = DCOD_PREFIX;
	fid[1] = id;

	/* Try to select a related EF containing the PKCS#15 description of the data */
	len = sizeof efbin;
	r = read_file(p15card, fid, efbin, &len, 1);
	LOG_TEST_RET(card->ctx, r, "Skipping optional EF.DCOD");

	ptr = efbin;

	memset(&data_obj, 0, sizeof(data_obj));
	r = sc_pkcs15_decode_dodf_entry(p15card, &data_obj, &ptr, &len);
	LOG_TEST_RET(card->ctx, r, "Could not decode optional EF.DCOD");

	data_info = (sc_pkcs15_data_info_t *)data_obj.data;

	r = sc_pkcs15emu_add_data_object(p15card, &data_obj, data_info);

	LOG_TEST_RET(card->ctx, r, "Could not add data object to framework");

	return SC_SUCCESS;
}



/*
 * Add a unrelated certificate object and description in PKCS#15 format to the framework
 */
static int sc_pkcs15emu_sc_hsm_add_cd(sc_pkcs15_card_t * p15card, u8 id) {

	sc_card_t *card = p15card->card;
	sc_pkcs15_cert_info_t *cert_info;
	sc_pkcs15_object_t obj;
	u8 fid[2];
	u8 efbin[512];
	const u8 *ptr;
	size_t len;
	int r;

	fid[0] = CD_PREFIX;
	fid[1] = id;

	/* Try to select a related EF containing the PKCS#15 description of the data */
	len = sizeof efbin;
	r = read_file(p15card, fid, efbin, &len, 1);
	LOG_TEST_RET(card->ctx, r, "Skipping optional EF.DCOD");

	ptr = efbin;

	memset(&obj, 0, sizeof(obj));
	r = sc_pkcs15_decode_cdf_entry(p15card, &obj, &ptr, &len);
	LOG_TEST_RET(card->ctx, r, "Skipping optional EF.CDOD");

	cert_info = (sc_pkcs15_cert_info_t *)obj.data;

	r = sc_pkcs15emu_add_x509_cert(p15card, &obj, cert_info);

	LOG_TEST_RET(card->ctx, r, "Could not add data object to framework");

	return SC_SUCCESS;
}



static int sc_pkcs15emu_sc_hsm_read_tokeninfo (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	int r;
	u8 efbin[512];
	size_t len;

	LOG_FUNC_CALLED(card->ctx);

	/* Read token info */
	len = sizeof efbin;
	r = read_file(p15card, (u8 *) "\x2F\x03", efbin, &len, 1);
	LOG_TEST_RET(card->ctx, r, "Skipping optional EF.TokenInfo");

	r = sc_pkcs15_parse_tokeninfo(card->ctx, p15card->tokeninfo, efbin, len);
	LOG_TEST_RET(card->ctx, r, "Skipping optional EF.TokenInfo");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



/*
 * Initialize PKCS#15 emulation with user PIN, private keys, certificate and data objects
 *
 */
static int sc_pkcs15emu_sc_hsm_init (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 filelist[MAX_EXT_APDU_LENGTH];
	int filelistlength;
	int r, i;
	sc_cvc_t devcert;
	struct sc_app_info *appinfo;
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;
	struct sc_pin_cmd_data pindata;
	u8 efbin[1024];
	u8 *ptr;
	size_t len;

	LOG_FUNC_CALLED(card->ctx);

	appinfo = calloc(1, sizeof(struct sc_app_info));

	if (appinfo == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	appinfo->aid = sc_hsm_aid;

	appinfo->ddo.aid = sc_hsm_aid;
	p15card->app = appinfo;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, sc_hsm_aid.value, sc_hsm_aid.len, 0, 0);
	r = sc_select_file(card, &path, &file);
	LOG_TEST_RET(card->ctx, r, "Could not select SmartCard-HSM application");

	p15card->card->version.hw_major = 24;	/* JCOP 2.4.1r3 */
	p15card->card->version.hw_minor = 13;
	if (file && file->prop_attr && file->prop_attr_len >= 2) {
		p15card->card->version.fw_major = file->prop_attr[file->prop_attr_len - 2];
		p15card->card->version.fw_minor = file->prop_attr[file->prop_attr_len - 1];
	}

	sc_file_free(file);

	/* Read device certificate to determine serial number */
	if (priv->EF_C_DevAut && priv->EF_C_DevAut_len) {
		ptr = priv->EF_C_DevAut;
		len = priv->EF_C_DevAut_len;
	} else {
		len = sizeof efbin;
		r = read_file(p15card, (u8 *) "\x2F\x02", efbin, &len, 1);
		LOG_TEST_RET(card->ctx, r, "Skipping optional EF.C_DevAut");

		/* save EF_C_DevAut for further use */
		ptr = realloc(priv->EF_C_DevAut, len);
		if (ptr) {
			memcpy(ptr, efbin, len);
			priv->EF_C_DevAut = ptr;
			priv->EF_C_DevAut_len = len;
		}

		ptr = efbin;
	}

	memset(&devcert, 0 ,sizeof(devcert));
	r = sc_pkcs15emu_sc_hsm_decode_cvc(p15card, (const u8 **)&ptr, &len, &devcert);
	LOG_TEST_RET(card->ctx, r, "Could not decode EF.C_DevAut");

	sc_pkcs15emu_sc_hsm_read_tokeninfo(p15card);

	if (p15card->tokeninfo->label == NULL) {
		if (p15card->card->type == SC_CARD_TYPE_SC_HSM_GOID
				|| p15card->card->type == SC_CARD_TYPE_SC_HSM_SOC) {
			p15card->tokeninfo->label = strdup("GoID");
		} else {
			p15card->tokeninfo->label = strdup("SmartCard-HSM");
		}
		if (p15card->tokeninfo->label == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	if ((p15card->tokeninfo->manufacturer_id != NULL) && !strcmp("(unknown)", p15card->tokeninfo->manufacturer_id)) {
		free(p15card->tokeninfo->manufacturer_id);
		p15card->tokeninfo->manufacturer_id = NULL;
	}

	if (p15card->tokeninfo->manufacturer_id == NULL) {
		if (p15card->card->type == SC_CARD_TYPE_SC_HSM_GOID
				|| p15card->card->type == SC_CARD_TYPE_SC_HSM_SOC) {
			p15card->tokeninfo->manufacturer_id = strdup("Bundesdruckerei GmbH");
		} else {
			p15card->tokeninfo->manufacturer_id = strdup("www.CardContact.de");
		}
		if (p15card->tokeninfo->manufacturer_id == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	appinfo->label = strdup(p15card->tokeninfo->label);
	if (appinfo->label == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	len = strnlen(devcert.chr, sizeof devcert.chr);		/* Strip last 5 digit sequence number from CHR */
	assert(len >= 8);
	len -= 5;

	p15card->tokeninfo->serial_number = calloc(len + 1, 1);
	if (p15card->tokeninfo->serial_number == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(p15card->tokeninfo->serial_number, devcert.chr, len);
	*(p15card->tokeninfo->serial_number + len) = 0;

	sc_hsm_set_serialnr(card, p15card->tokeninfo->serial_number);

	sc_pkcs15emu_sc_hsm_free_cvc(&devcert);

	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	pin_info.auth_id.len = 1;
	pin_info.auth_id.value[0] = 1;
	pin_info.path.aid = sc_hsm_aid;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = 0x81;
	pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_LOCAL|SC_PKCS15_PIN_FLAG_INITIALIZED|SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length = 6;
	pin_info.attrs.pin.stored_length = 0;
	pin_info.attrs.pin.max_length = 15;
	pin_info.attrs.pin.pad_char = '\0';
	pin_info.tries_left = 3;
	pin_info.max_tries = 3;

	pin_obj.auth_id.len = 1;
	pin_obj.auth_id.value[0] = 2;
	strlcpy(pin_obj.label, "UserPIN", sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE|SC_PKCS15_CO_FLAG_MODIFIABLE;

	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	if (r < 0)
		LOG_FUNC_RETURN(card->ctx, r);

	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	pin_info.auth_id.len = 1;
	pin_info.auth_id.value[0] = 2;
	pin_info.path.aid = sc_hsm_aid;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = 0x88;
	pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_LOCAL|SC_PKCS15_PIN_FLAG_INITIALIZED|SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED|SC_PKCS15_PIN_FLAG_SO_PIN;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_BCD;
	pin_info.attrs.pin.min_length = 16;
	pin_info.attrs.pin.stored_length = 0;
	pin_info.attrs.pin.max_length = 16;
	pin_info.attrs.pin.pad_char = '\0';
	pin_info.tries_left = 15;
	pin_info.max_tries = 15;

	strlcpy(pin_obj.label, "SOPIN", sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	if (r < 0)
		LOG_FUNC_RETURN(card->ctx, r);


	if (card->type == SC_CARD_TYPE_SC_HSM_SOC
			|| card->type == SC_CARD_TYPE_SC_HSM_GOID) {
		/* SC-HSM of this type always has a PIN-Pad */
		r = SC_SUCCESS;
	} else {
		memset(&pindata, 0, sizeof(pindata));
		pindata.cmd = SC_PIN_CMD_GET_INFO;
		pindata.pin_type = SC_AC_CHV;
		pindata.pin_reference = 0x85;

		r = sc_pin_cmd(card, &pindata, NULL);
	}
	if (r == SC_ERROR_DATA_OBJECT_NOT_FOUND) {
		memset(&pindata, 0, sizeof(pindata));
		pindata.cmd = SC_PIN_CMD_GET_INFO;
		pindata.pin_type = SC_AC_CHV;
		pindata.pin_reference = 0x86;

		r = sc_pin_cmd(card, &pindata, NULL);
	}

	if ((r != SC_ERROR_DATA_OBJECT_NOT_FOUND) && (r != SC_ERROR_INCORRECT_PARAMETERS))
		card->caps |= SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH;


	filelistlength = sc_list_files(card, filelist, sizeof(filelist));
	LOG_TEST_RET(card->ctx, filelistlength, "Could not enumerate file and key identifier");

	for (i = 0; i < filelistlength; i += 2) {
		switch(filelist[i]) {
		case KEY_PREFIX:
			r = sc_pkcs15emu_sc_hsm_add_prkd(p15card, filelist[i + 1]);
			break;
		case DCOD_PREFIX:
			r = sc_pkcs15emu_sc_hsm_add_dcod(p15card, filelist[i + 1]);
			break;
		case CD_PREFIX:
			r = sc_pkcs15emu_sc_hsm_add_cd(p15card, filelist[i + 1]);
			break;
		}
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, "Error %d adding elements to framework", r);
		}
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



int sc_pkcs15emu_sc_hsm_init_ex(sc_pkcs15_card_t *p15card,
				struct sc_aid *aid,
				sc_pkcs15emu_opt_t *opts)
{
	if (opts && (opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)) {
		return sc_pkcs15emu_sc_hsm_init(p15card);
	} else {
		if (p15card->card->type != SC_CARD_TYPE_SC_HSM
				&& p15card->card->type != SC_CARD_TYPE_SC_HSM_SOC
				&& p15card->card->type != SC_CARD_TYPE_SC_HSM_GOID) {
			return SC_ERROR_WRONG_CARD;
		}
		return sc_pkcs15emu_sc_hsm_init(p15card);
	}
}
