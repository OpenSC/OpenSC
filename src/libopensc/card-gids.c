/*
 * card-gids.c: Support for GIDS smart cards.
 *
 * Copyright (C) 2015 Vincent Le Toux (My Smart Logon) <vincent.letoux@mysmartlogon.com>
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

/*
The GIDS specification can be viewed here:
https://msdn.microsoft.com/en-us/library/windows/hardware/dn642100%28v=vs.85%29.aspx

and its formatting into the MS minidriver specification.
Some features are undocumented like the format used to store certificates. They have been reverse engineered.
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_OPENSSL
/* openssl only needed for card administration */
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif /* ENABLE_OPENSSL */

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "iso7816.h"

#ifdef ENABLE_ZLIB

#include "compression.h"
// used for changing the default label if used twice
#include "../pkcs15init/pkcs15-init.h"
#include "card-gids.h"

#define GIDS_STATE_NONE 0
#define GIDS_STATE_READ_DATA_PRESENT 1

#define INS_ACTIVATE_FILE 0x44
#define INS_CREATE_FILE 0xE0
#define INS_DELETE_FILE 0xE4
#define INS_GENERAL_AUTHENTICATE 0x87
#define INS_GENERATE_ASYMECTRIC_KEY_PAIR 0x47
#define INS_GET_DATA 0xCB
#define INS_MANAGE_SECURITY_ENVIRONMENT 0x22
#define INS_PUT_DATA 0xDB
#define INS_SELECT 0xA4
#define INS_VERIFY 0x20

#define P1_SELECT_DF_OR_EF_WITH_EFID 0x00
#define P1_SELECT_DF_BY_NAME 0x04
#define P1_DECIPHERMENT_INTERNAL_AUTHENTICATE_KEY_AGREEMENT 0x41

#define P2_SELECT_FIRST_OR_ONLY_OCCURENCE 0x00
#define P2_PIN_DEAUTHENTICATE 0x82
#define P2_DIGITAL_SIGNATURE 0xB6
#define P2_DECIPHERMENT 0xB8

#define GIDS_PIN_STATUS_OBJECT_IDENTIFIER 0x7F71
#define GIDS_PUK_STATUS_OBJECT_IDENTIFIER 0x7F73
#define GIDS_APPLET_EFID 0x3FFF
#define GIDS_PUT_KEY_DO 0x70
#define GIDS_RSA_1024_IDENTIFIER 0x06
#define GIDS_RSA_2048_IDENTIFIER 0x07
#define GIDS_RSA_3072_IDENTIFIER 0x08
#define GIDS_RSA_4096_IDENTIFIER 0x09
#define GIDS_ECC_192_IDENTIFIER 0x0A
#define GIDS_ECC_224_IDENTIFIER 0x0B
#define GIDS_ECC_256_IDENTIFIER 0x0C
#define GIDS_ECC_384_IDENTIFIER 0x0D
#define GIDS_ECC_521_IDENTIFIER 0x0E

#define GIDS_PUBKEY_TAG 0x7F49
#define GIDS_PUBKEY_TAG_MODULUS 0x81
#define GIDS_PUBKEY_TAG_EXPONENT 0x82

#define GIDS_FIRST_KEY_IDENTIFIER 0x81

#define GIDS_PIN_IDENTIFIER 0x80
#define GIDS_PUK_IDENTIFIER 0x81
#define GIDS_TRY_COUNTER_OLD_TAG 0x9F17
#define GIDS_TRY_COUNTER_TAG 0x97
#define GIDS_TRY_LIMIT_TAG 0x93
#define GIDS_APPLICATION_TEMPLATE_TAG 0x61
#define GIDS_APPLICATION_AID_TAG 0x4F

#define GIDS_KEY_TYPE_AT_KEYEXCHANGE 0x9A
#define GIDS_KEY_TYPE_AT_SIGNATURE 0x9C

static struct sc_card_operations *iso_ops;
static struct sc_card_operations gids_ops;
static struct sc_card_driver gids_drv = {
	"GIDS Smart Card",
	"gids",
	&gids_ops,
	NULL, 0, NULL
};

struct gids_aid {
	int enumtag;
	size_t len_short;	/* min length without version */
	size_t len_long;	/* With version and other stuff */
	u8 *value;
};

/* GIDS AID */
struct sc_aid gids_aid = { { 0xA0,0x00,0x00,0x03,0x97,0x42,0x54,0x46,0x59 }, 9 };

static struct gids_aid gids_aids[] = {
	{SC_CARD_TYPE_GIDS_V1,
		 9, 10, (u8 *) "\xA0\x00\x00\x03\x97\x42\x54\x46\x59\x01" },
	{SC_CARD_TYPE_GIDS_V2,
		 9, 10, (u8 *) "\xA0\x00\x00\x03\x97\x42\x54\x46\x59\x02" },
	{0,  9, 0, NULL }
};

// stolen from cardmod.h for the cardcf file
typedef struct _CARD_CACHE_FILE_FORMAT
{
    unsigned char bVersion;			// Cache version
    unsigned char bPinsFreshness;		// Card PIN
    unsigned short wContainersFreshness;
    unsigned short wFilesFreshness;

} CARD_CACHE_FILE_FORMAT, *PCARD_CACHE_FILE_FORMAT;

struct gids_private_data {
	u8 masterfile[MAX_GIDS_FILE_SIZE];
	size_t masterfilesize;
	u8 cmapfile[MAX_GIDS_FILE_SIZE];
	size_t cmapfilesize;
	unsigned short currentEFID;
	unsigned short currentDO;
	int state;
	u8 buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t buffersize;
};

// LOW LEVEL API
///////////////////////////////////////////

// find file identifier & DO identifier from the masterfile for a directory/file
static int gids_get_identifiers(sc_card_t* card, u8* masterfile, size_t masterfilesize, char *directory, char *filename, int *fileIdentifier, int *dataObjectIdentifier) {
	gids_mf_record_t *records = (gids_mf_record_t *) (masterfile+1);
	size_t recordcount = ((masterfilesize-1) / sizeof(gids_mf_record_t));
	size_t i;
	assert(masterfilesize >= 1);

	for (i = 0; i < recordcount; i++) {
		if (strcmp(directory, records[i].directory) == 0 && strcmp(filename, records[i].filename) == 0) {
			*fileIdentifier = records[i].fileIdentifier;
			*dataObjectIdentifier = records[i].dataObjectIdentifier;
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"Identifiers of %s %s is fileIdentifier=%x, dataObjectIdentifier=%x\n", directory, filename, *fileIdentifier, *dataObjectIdentifier);
			return 0;
		}
	}
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "file %s %s not found\n", directory, filename);
	return SC_ERROR_FILE_NOT_FOUND;
}

// used when storing a new certificates
static int gids_find_available_DO(sc_card_t *card, u8* masterfile, size_t masterfilesize, int* fileIdentifier, int *dataObjectIdentifier) {
	// find the first available DO from the masterfile since A010 DF21
	// A010 = read everyone, card user write
	gids_mf_record_t *records = (gids_mf_record_t *) (masterfile+1);
	size_t recordcount = (masterfilesize / sizeof(gids_mf_record_t));
	size_t i;

	assert(masterfilesize >= 1);

	*fileIdentifier = CERT_FI;

	for (*dataObjectIdentifier = CARDAPPS_DO; *dataObjectIdentifier < GIDS_MAX_DO; (*dataObjectIdentifier)++) {
		for (i = 0; i < recordcount; i++) {
			if (records[i].fileIdentifier == *fileIdentifier && records[i].dataObjectIdentifier == *dataObjectIdentifier) {
				break;
			}
		}
		if (i == recordcount) {
			return SC_SUCCESS;
		}
	}
	return SC_ERROR_NOT_ENOUGH_MEMORY;
}

// read a DO from the card
static int gids_get_DO(sc_card_t* card, int fileIdentifier, int dataObjectIdentifier, u8* response, size_t *responselen) {
	sc_apdu_t apdu;
	int r;
	u8 data[4] = {0x5C, 0x02, (dataObjectIdentifier&0xFF00)>>8, (dataObjectIdentifier&0xFF)};
	size_t datasize = 0;
	const u8* p;
	u8 buffer[MAX_GIDS_FILE_SIZE];

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "Got args: fileIdentifier=%x, dataObjectIdentifier=%x, response=%p, responselen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 fileIdentifier, dataObjectIdentifier, response,
		 responselen ? *responselen : 0);

	sc_format_apdu(card, &apdu,
		response == NULL ? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT, INS_GET_DATA, (fileIdentifier&0xFF00)>>8, (fileIdentifier&0xFF));
	apdu.lc = 04;
	apdu.data = data;
	apdu.datalen = 04;
	apdu.resp = buffer;
	apdu.resplen = sizeof(buffer);
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids get data failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");

	p = sc_asn1_find_tag(card->ctx, buffer, sizeof(buffer), dataObjectIdentifier, &datasize);
	if (!p) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);
	}
	if (datasize > *responselen) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_BUFFER_TOO_SMALL);
	}
	memcpy(response, p, datasize);
	*responselen = datasize;
	return SC_SUCCESS;
}

// write a DO to the card
static int gids_put_DO(sc_card_t* card, int fileIdentifier, int dataObjectIdentifier, u8 *data, size_t datalen) {
	sc_apdu_t apdu;
	int r;
	u8 buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
	u8* p = buffer;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "Got args: fileIdentifier=%x, dataObjectIdentifier=%x, data=%p, datalen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 fileIdentifier, dataObjectIdentifier, data, datalen);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, INS_PUT_DATA, (fileIdentifier&0xFF00)>>8, (fileIdentifier&0xFF));

	r = sc_asn1_put_tag(dataObjectIdentifier, data, datalen, buffer, sizeof(buffer), &p);
	LOG_TEST_RET(card->ctx, r, "Error handling TLV.");

	apdu.data = buffer;
	apdu.datalen = (size_t) (p - buffer);
	apdu.lc = apdu.datalen;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids put data failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");

	return SC_SUCCESS;
}

// select the GIDS applet
static int gids_select_aid(sc_card_t* card, u8* aid, size_t aidlen, u8* response, size_t *responselen)
{
	sc_apdu_t apdu;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "Got args: aid=%p, aidlen=%"SC_FORMAT_LEN_SIZE_T"u, response=%p, responselen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 aid, aidlen, response, responselen ? *responselen : 0);

	sc_format_apdu(card, &apdu,
		response == NULL ? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT, INS_SELECT, P1_SELECT_DF_BY_NAME, P2_SELECT_FIRST_OR_ONLY_OCCURENCE);
	apdu.lc = aidlen;
	apdu.data = aid;
	apdu.datalen = aidlen;
	apdu.resp = response;
	apdu.resplen = responselen ? *responselen : 0;
	apdu.le = response == NULL ? 0 : 256; /* could be 21  for fci */

	r = sc_transmit_apdu(card, &apdu);
	if (responselen)
		*responselen = apdu.resplen;
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids select failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  sc_check_sw(card, apdu.sw1, apdu.sw2));
}

// DIRECT FILE MANIPULATION
///////////////////////////////////////////

// read a file given the masterfile
static int gids_read_gidsfile_without_cache(sc_card_t* card, u8* masterfile, size_t masterfilesize, char *directory, char *filename, u8* response, size_t *responselen) {
	int r;
	int fileIdentifier;
	int dataObjectIdentifier;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	r = gids_get_identifiers(card, masterfile, masterfilesize, directory, filename, &fileIdentifier, &dataObjectIdentifier);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to get the identifier for the gids file");
	r = gids_get_DO(card, fileIdentifier, dataObjectIdentifier, response, responselen);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to get the data from the file");
	return r;
}

// write a file given the masterfile
static int gids_write_gidsfile_without_cache(sc_card_t* card, u8* masterfile, size_t masterfilesize, char *directory, char *filename, u8* data, size_t datalen) {
	int r;
	int fileIdentifier;
	int dataObjectIdentifier;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (datalen > MAX_GIDS_FILE_SIZE) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_DATA);
	}

	r = gids_get_identifiers(card, masterfile, masterfilesize, directory, filename, &fileIdentifier, &dataObjectIdentifier);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to get the identifier for the gids file");
	r = gids_put_DO(card, fileIdentifier, dataObjectIdentifier, data, datalen);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to get the data from the file");
	return r;
}

// read the masterfile from the card
static int gids_read_masterfile(sc_card_t* card) {
	struct gids_private_data* data = (struct gids_private_data*) card->drv_data;
	int r = SC_SUCCESS;

	data->masterfilesize = sizeof(data->masterfile);
	r = gids_get_DO(card, MF_FI, MF_DO, data->masterfile, &data->masterfilesize);
	if (r<0) {
		data->masterfilesize = sizeof(data->masterfile);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_CARD);
	}
	if (data->masterfilesize < 1 || data->masterfile[0] != 1) {
		data->masterfilesize = sizeof(data->masterfile);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_CARD);
	}
	return r;
}

// signal to the windows minidriver that something changed on the card and that it should refresh its cache
// the format of this file is specified in the minidriver specification
static int gids_update_cardcf(sc_card_t* card, int file, int container) {
	struct gids_private_data* data = (struct gids_private_data*) card->drv_data;
	u8 cardcf[6];
	int r;
	size_t cardcfsize = sizeof(cardcf);
	r = gids_read_gidsfile_without_cache(card, data->masterfile, data->masterfilesize, "", "cardcf", cardcf, &cardcfsize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to get the cardcf");

	if (file) {
		short filefreshness = cardcf[4] + cardcf[5] * 0x100;
		filefreshness++;
		cardcf[4] = filefreshness & 0xFF;
		cardcf[5] = (filefreshness>>8) & 0xFF;
	}
	if (container) {
		short containerfreshness = cardcf[2] + cardcf[3] * 0x100;
		containerfreshness++;
		cardcf[2] = containerfreshness & 0xFF;
		cardcf[3] = (containerfreshness>>8) & 0xFF;
	}
	r = gids_write_gidsfile_without_cache(card, data->masterfile, data->masterfilesize, "", "cardcf", cardcf, 6);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the cardcf file");
	return r;
}

// read a file
static int gids_read_gidsfile(sc_card_t* card, char *directory, char *filename, u8* response, size_t *responselen) {
	struct gids_private_data* privatedata = (struct gids_private_data*) card->drv_data;
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (privatedata->masterfilesize == sizeof(privatedata->masterfile)) {
		r = gids_read_masterfile(card);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to get the masterfile");
	}
	r = gids_read_gidsfile_without_cache(card, privatedata->masterfile, privatedata->masterfilesize,
		directory, filename, response, responselen);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to read the file");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,r);
}

// check for the existence of a file
static int gids_does_file_exists(sc_card_t *card, char* directory, char* filename) {
	struct gids_private_data* privatedata = (struct gids_private_data*) card->drv_data;
	int fileIdentifier, dataObjectIdentifier;
	return gids_get_identifiers(card, privatedata->masterfile, privatedata->masterfilesize, directory, filename,
		&fileIdentifier, &dataObjectIdentifier);
}

// write a file already existing
static int gids_write_gidsfile(sc_card_t* card, char *directory, char *filename, u8* data, size_t datalen) {
	struct gids_private_data* privatedata = (struct gids_private_data*) card->drv_data;
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	r = gids_update_cardcf(card, 1, 0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the cache file");

	r = gids_write_gidsfile_without_cache(card, privatedata->masterfile, privatedata->masterfilesize,
		directory, filename, data, datalen);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to write the file");
	if (strcmp(directory, "mscp") == 0 && strcmp(filename, "cmapfile") == 0) {
		// update the cmapfile cache
		privatedata->cmapfilesize = datalen;
		memcpy(privatedata->cmapfile, data, datalen);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,r);
}

// read the cmapfile (container description)
static int gids_read_cmapfile(sc_card_t* card) {
	struct gids_private_data* data = (struct gids_private_data*) card->drv_data;
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	data->cmapfilesize = sizeof(data->cmapfile);
	r = gids_read_gidsfile(card, "mscp", "cmapfile", data->cmapfile, &data->cmapfilesize);
	if (r<0) {
		data->cmapfilesize = sizeof(data->cmapfile);
	}
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to get the cmapfile");
	return r;
}

// create a file record in the masterfile
static int gids_create_file(sc_card_t *card, char* directory, char* filename) {
	int r;
	u8 masterfilebuffer[MAX_GIDS_FILE_SIZE];
	size_t masterfilebuffersize;
	struct gids_private_data* privatedata = (struct gids_private_data*) card->drv_data;
	int fileIdentifier, dataObjectIdentifier;
	size_t records;
	int offset;
	gids_mf_record_t* record;

	r = gids_find_available_DO(card, privatedata->masterfile, privatedata->masterfilesize, &fileIdentifier, &dataObjectIdentifier);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to find an empty DO");

	memcpy(masterfilebuffer, privatedata->masterfile, privatedata->masterfilesize);
	masterfilebuffersize = privatedata->masterfilesize + sizeof(gids_mf_record_t);
	if (masterfilebuffersize > MAX_GIDS_FILE_SIZE) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_ENOUGH_MEMORY);
	}

	records = ((privatedata->masterfilesize -1)  / sizeof(gids_mf_record_t));
	offset = 1 + sizeof(gids_mf_record_t) * records;
	memcpy(masterfilebuffer + offset + sizeof(gids_mf_record_t), masterfilebuffer + offset,
		privatedata->masterfilesize - offset);
	memset(masterfilebuffer + offset, 0, sizeof(gids_mf_record_t));
	record = (gids_mf_record_t*) (masterfilebuffer + offset);
	strncpy(record->directory, directory, 8);
	strncpy(record->filename, filename, 8);
	record->fileIdentifier = fileIdentifier;
	record->dataObjectIdentifier = dataObjectIdentifier;

	r = gids_update_cardcf(card, 1, 0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the cardcf");

	r = gids_put_DO(card, MF_FI, MF_DO, masterfilebuffer, masterfilebuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the masterfile");

	memcpy(privatedata->masterfile, masterfilebuffer, masterfilebuffersize);
	privatedata->masterfilesize = masterfilebuffersize;
	return r;
}

// CERTIFICATE HANDLING FUNCTIONS
////////////////////////////////////////////////////

// prepare a sc_path structure given a file identifier & DO
// this will be an input of the gids_read_public_key function
static int gids_build_certificate_path(sc_card_t* card, unsigned char containerindex, unsigned char issignatureonly,sc_path_t* cpath) {
	struct gids_private_data* data = (struct gids_private_data*) card->drv_data;
	int r, fileIdentifier, dataObjectIdentifier;
	char file[9];
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (issignatureonly) {
		snprintf(file, 9, "ksc%02X", containerindex);
	} else {
		snprintf(file, 9, "kxc%02X", containerindex);
	}
	r = gids_get_identifiers(card, data->masterfile, data->masterfilesize, "mscp", file, &fileIdentifier, &dataObjectIdentifier);
	if (r < 0) return SC_ERROR_OBJECT_NOT_FOUND;

	memset(cpath, 0, sizeof(sc_path_t));
	cpath->type = SC_PATH_TYPE_PATH;
	cpath->len = 4;
	cpath->value[0] = (u8) ((fileIdentifier >> 8) & 0xFF);
	cpath->value[1] = (u8) fileIdentifier & 0xFF;
	cpath->value[2] = (u8) ((dataObjectIdentifier >> 8) & 0xFF);
	cpath->value[3] = (u8) dataObjectIdentifier & 0xFF;
	cpath->count = -1;
	return SC_SUCCESS;
}

// PIN HANDLING FUNCTIONS
////////////////////////////////////////////////////

// get the pin status
static int gids_get_pin_status(sc_card_t *card, int pinreference, int *tries_left, int *max_tries) {
	int dataObjectIdentifier, r;
	u8 buffer[100];
	const u8* p;
	size_t buffersize = sizeof(buffer);
	size_t datasize;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (tries_left) *tries_left = -1;
	if (max_tries) *max_tries = -1;
	switch(pinreference) {
	case GIDS_PIN_IDENTIFIER:
		dataObjectIdentifier = GIDS_PIN_STATUS_OBJECT_IDENTIFIER;
		break;
	case GIDS_PUK_IDENTIFIER:
		dataObjectIdentifier = GIDS_PUK_STATUS_OBJECT_IDENTIFIER;
		break;
	default:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OBJECT_NOT_FOUND);
	}
	r = gids_get_DO(card, GIDS_APPLET_EFID, dataObjectIdentifier, buffer, &buffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the masterfile");

	buffersize = buffersize > sizeof(buffer) ? sizeof(buffer) : buffersize;

	p = sc_asn1_find_tag(card->ctx, buffer, buffersize, GIDS_TRY_COUNTER_OLD_TAG, &datasize);
	if (p && datasize == 1) {
		if (tries_left)
			*tries_left = p[0];
	}
	p = sc_asn1_find_tag(card->ctx, buffer, buffersize, GIDS_TRY_COUNTER_TAG, &datasize);
	if (p && datasize == 1) {
		if (tries_left)
			*tries_left = p[0];
	}
	p = sc_asn1_find_tag(card->ctx, buffer, buffersize , GIDS_TRY_LIMIT_TAG, &datasize);
	if (p && datasize == 1) {
		if (tries_left)
			*max_tries = p[0];
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"Pin information for PIN 0x%x: triesleft=%d trieslimit=%d\n", pinreference, (tries_left?*tries_left:-1), (max_tries?*max_tries:-1));
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static int gids_match_card(sc_card_t * card)
{
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r,i;
	size_t resplen = sizeof(rbuf);
	const u8 *tag;
	size_t taglen;
	const u8 *aid;
	size_t aidlen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* Detect by selecting applet */
	r = gids_select_aid(card, gids_aid.value, gids_aid.len, rbuf, &resplen);
	if (r<0) return 0;

	card->type = SC_CARD_TYPE_GIDS_GENERIC;
	if (resplen > 2) {
		tag = sc_asn1_find_tag(card->ctx, rbuf, resplen, GIDS_APPLICATION_TEMPLATE_TAG, &taglen);
		if (tag != NULL) {
			aid = sc_asn1_find_tag(card->ctx, tag, taglen, GIDS_APPLICATION_AID_TAG, &aidlen);
			if (aid != NULL ) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"found AID");
				for (i = 0; gids_aids[i].len_long != 0; i++) {
					if ( aidlen > gids_aids[i].len_long && memcmp(aid, gids_aids[i].value,
									gids_aids[i].len_long) == 0) {
						card->type = gids_aids[i].enumtag;
						break;
					}
				}
			}
		}
	}

	return 1;
}


// extract the serial number from the cardid file
static int gids_get_serialnr(sc_card_t * card, sc_serial_number_t * serial)
{
	int r;
	u8 buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t buffersize;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	buffersize = sizeof(buffer);
	r = gids_read_gidsfile(card, "", "cardid", buffer, &buffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to read cardid");

	if (SC_MAX_SERIALNR < buffersize)
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}

	/* cache serial number */
	card->serialnr.len = buffersize;
	memcpy(card->serialnr.value, buffer, card->serialnr.len);

	/* return cached serial number */
	if (serial)
		memcpy(serial, &card->serialnr, sizeof(*serial));

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

// initialize the driver
static int gids_init(sc_card_t * card)
{
	unsigned long flags;
	struct gids_private_data *data;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	// cache some data in memory
	data = (struct gids_private_data*) calloc(1, sizeof(struct gids_private_data));
	if (!data) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_MEMORY_FAILURE);
	}
	memset(data, 0, sizeof(struct gids_private_data));
	card->drv_data = data;
	// invalidate the master file and cmap file cache
	data->cmapfilesize = sizeof(data->cmapfile);
	data->masterfilesize = sizeof(data->masterfile);

	/* supported RSA keys and how padding is done */
	flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_ONBOARD_KEY_GEN | SC_ALGORITHM_RSA_RAW;
	/* fix me: add other algorithms when the gids specification will tell how to extract the algo id from the FCP */
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	return SC_SUCCESS;
}

// cleanup
static int gids_finish(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* free the private data */
	if (card->drv_data) {
		free(card->drv_data);
		card->drv_data = NULL;
	}
	return 0;
}

//see 12.5.3.1 Cryptographic Mechanism Identifier for Key with CRT
// the cmap file is used to detect the key algorithm / size
static int gids_get_crypto_identifier_from_key_ref(sc_card_t *card, const unsigned char keyref, unsigned char *cryptoidentifier) {
	struct gids_private_data *data = (struct gids_private_data *) card->drv_data;
	PCONTAINER_MAP_RECORD records = (PCONTAINER_MAP_RECORD) data->cmapfile;
	int recordsnum = (int) (data->cmapfilesize / sizeof(CONTAINER_MAP_RECORD));
	int index = keyref - GIDS_FIRST_KEY_IDENTIFIER;
	if (index >= recordsnum) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
	}
	*cryptoidentifier = 0x00; /* initialize to zero */
	if (records[index].wKeyExchangeKeySizeBits == 1024 || records[index].wSigKeySizeBits == 1024) {
		*cryptoidentifier = GIDS_RSA_1024_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 2048 || records[index].wSigKeySizeBits == 2048) {
		*cryptoidentifier = GIDS_RSA_2048_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 3072 || records[index].wSigKeySizeBits == 3072) {
		*cryptoidentifier = GIDS_RSA_3072_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 4096 || records[index].wSigKeySizeBits == 4096) {
		*cryptoidentifier = GIDS_RSA_4096_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 192 || records[index].wSigKeySizeBits == 192) {
		*cryptoidentifier = GIDS_ECC_192_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 224 || records[index].wSigKeySizeBits == 224) {
		*cryptoidentifier = GIDS_ECC_224_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 256 || records[index].wSigKeySizeBits == 256) {
		*cryptoidentifier = GIDS_ECC_256_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 384 || records[index].wSigKeySizeBits == 384) {
		*cryptoidentifier = GIDS_ECC_384_IDENTIFIER;
		return SC_SUCCESS;
	}
	if (records[index].wKeyExchangeKeySizeBits == 521 || records[index].wSigKeySizeBits == 521) {
		*cryptoidentifier = GIDS_ECC_521_IDENTIFIER;
		return SC_SUCCESS;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
}

// same here
static u8 gids_get_crypto_identifier_from_prkey_info(struct sc_pkcs15_prkey_info *key_info) {
	if (key_info->modulus_length > 0) {
		if (key_info->modulus_length == 1024) {
			return GIDS_RSA_1024_IDENTIFIER;
		}
		if (key_info->modulus_length == 2048) {
			return GIDS_RSA_2048_IDENTIFIER;
		}
		if (key_info->modulus_length == 3072) {
			return GIDS_RSA_3072_IDENTIFIER;
		}
		if (key_info->modulus_length == 4096) {
			return GIDS_RSA_4096_IDENTIFIER;
		}
		return 0;
	} else {
		return 0;
	}
}

// GIDS implementation of set security environment
static int gids_set_security_env(sc_card_t *card,
                                     const sc_security_env_t *env,
                                     int se_num)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;

	assert(card != NULL && env != NULL);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	memset(sbuf, 0, sizeof(sbuf));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, INS_MANAGE_SECURITY_ENVIRONMENT, P1_DECIPHERMENT_INTERNAL_AUTHENTICATE_KEY_AGREEMENT, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = P2_DECIPHERMENT;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = P2_DIGITAL_SIGNATURE;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		return SC_ERROR_NOT_SUPPORTED;
	} else {
		// ALG REF is mandatory
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		gids_get_crypto_identifier_from_key_ref(card,env->key_ref[0],p);
		if (env->operation == SC_SEC_OPERATION_DECIPHER) {
			*p++ |= 0x40;
		} else {
			*p++ |= 0x50;
		}
	}
	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT)) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC)
		*p++ = 0x83;
	else
		*p++ = 0x84;
	*p++ = (u8) env->key_ref_len;
	assert(sizeof(sbuf) - (p - sbuf) >= env->key_ref_len);
	memcpy(p, env->key_ref, env->key_ref_len);
	p += env->key_ref_len;

	r = (int) (p - sbuf);
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	if (se_num > 0) {
		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_log(card->ctx, "%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_log(card->ctx, "%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
	if (se_num <= 0)
		return 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, INS_MANAGE_SECURITY_ENVIRONMENT, 0xF2, se_num);
	r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}

// deauthenticate all pins
static int gids_logout(sc_card_t *card)
{
	struct sc_apdu apdu;
	int r;
	assert(card && card->ctx);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	// use the special PIN to deauthenticate
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, INS_VERIFY, 0x00, P2_PIN_DEAUTHENTICATE);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  sc_check_sw(card, apdu.sw1, apdu.sw2));
}

// read a public key
static int gids_read_public_key (struct sc_card *card , unsigned int algorithm,
			struct sc_path * path, unsigned key_reference, unsigned modulus_length,
			unsigned char **response, size_t *responselen) {

	struct sc_pkcs15_pubkey_rsa rsa_key;
	sc_apdu_t apdu;
	size_t tlen, len;
	const u8* keytemplate;
	const u8* keydata;
	int r;
	u8 data[] = {0x70, 0x08, // retrieve key
						0x84, 0x01, key_reference, // key reference
						0xA5, 0x03, 0x7F, 0x49, 0x80 // key value template: only public key
				};
	u8 buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t buffersize = sizeof(buffer);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "Got args: key_reference=%x, response=%p, responselen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 key_reference, response, responselen ? *responselen : 0);

	sc_format_apdu(card, &apdu,
		response == NULL ? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT, INS_GET_DATA, 0x3F, 0xFF);
	apdu.lc = sizeof(data);
	apdu.data = data;
	apdu.datalen = sizeof(data);
	apdu.resp = buffer;
	apdu.resplen = buffersize;
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read public key failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");
	buffersize = apdu.resplen;

	keytemplate = sc_asn1_find_tag(card->ctx, buffer, buffersize, GIDS_PUBKEY_TAG, &tlen);
	if (keytemplate == NULL) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid public key data: missing tag");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	keydata = sc_asn1_find_tag(card->ctx, keytemplate, tlen, GIDS_PUBKEY_TAG_MODULUS, &len);
	if (keydata != NULL) {
		rsa_key.modulus.data = (u8*) keydata;
		rsa_key.modulus.len = len;
	} else {
		rsa_key.modulus.len = 0;
	}

	keydata = sc_asn1_find_tag(card->ctx, keytemplate, tlen, GIDS_PUBKEY_TAG_EXPONENT, &len);
	if (keydata != NULL) {
		rsa_key.exponent.data = (u8*) keydata;
		rsa_key.exponent.len = len;
	} else {
		rsa_key.exponent.len = 0;
	}

	if (rsa_key.exponent.len && rsa_key.modulus.len) {
		r = sc_pkcs15_encode_pubkey_rsa(card->ctx, &rsa_key, response, responselen);
		LOG_TEST_RET(card->ctx, r, "failed to read public key: cannot encode RSA public key");
	} else {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "it is not a known public key");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	if (response && responselen)
		sc_log_hex(card->ctx, "encoded public key", *response, *responselen);

	return SC_SUCCESS;
}

// emulate a filesystem given EF and DO
static int gids_select_file(sc_card_t *card, const struct sc_path *in_path,
			   struct sc_file **file_out) {
	struct sc_file *file = NULL;
	struct sc_context *ctx = card->ctx;
	struct gids_private_data *data = (struct gids_private_data *) card->drv_data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	data->state = GIDS_STATE_NONE;
	data->currentDO = 0;
	data->currentEFID = 0;
	if (in_path->len == 4 && in_path->value[0] == 0xA0) {
		// is it a DO pseudo file ?
		// yes, succeed
		data->currentEFID = in_path->value[1] + (in_path->value[0]<<8);
		data->currentDO = in_path->value[3] + (in_path->value[2]<<8);

		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = SC_MAX_EXT_APDU_BUFFER_SIZE;
		*file_out = file;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	} else if (in_path->len == 4 && in_path->value[0] == 0x3F && in_path->value[1] == 0xFF &&  in_path->type == SC_PATH_TYPE_PATH) {
		// GIDS does not allow a select with a path containing a DF
		// replace the file selection from SC_PATH_TYPE_PATH to SC_PATH_TYPE_FILE_ID
		struct sc_path key_path;
		memset(&key_path, 0, sizeof(key_path));
		key_path.len = 2;
		key_path.value[0] = in_path->value[2];
		key_path.value[1] = in_path->value[3];
		key_path.type = SC_PATH_TYPE_FILE_ID;
		return iso_ops->select_file(card, &key_path, file_out);
	} else {
		return iso_ops->select_file(card, in_path, file_out);
	}
}

static int gids_get_pin_policy(struct sc_card *card, struct sc_pin_cmd_data *data) {
	int r;
	if (data->pin_type != SC_AC_CHV)   {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	r = gids_get_pin_status(card, data->pin_reference, &(data->pin1.tries_left), &(data->pin1.max_tries));
	LOG_TEST_RET(card->ctx, r, "gids_get_pin_status failed");
	data->pin1.max_length = 16;
	data->pin1.min_length = 4;
	data->pin1.stored_length = 0;
	data->pin1.encoding = SC_PIN_ENCODING_ASCII;
	data->pin1.offset = 5;
	data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;
	return SC_SUCCESS;
}

static int
gids_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left) {
	if (data->cmd == SC_PIN_CMD_GET_INFO) {
		return gids_get_pin_policy(card, data);
	} else {
		return iso_ops->pin_cmd(card, data, tries_left);
	}
}

// used to read existing certificates
static int gids_read_binary(sc_card_t *card, unsigned int offset,
		unsigned char *buf, size_t count, unsigned long flags) {
	struct gids_private_data *data = (struct gids_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	int r;
	int size;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	if (! data->currentDO || ! data->currentEFID) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	if (data->state != GIDS_STATE_READ_DATA_PRESENT) {
		// this function is called to read the certificate only
		u8 buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
		size_t buffersize = sizeof(buffer);
		r = gids_get_DO(card, data->currentEFID, data->currentDO, buffer, &(buffersize));
		if (r <0) return r;
		if (buffersize < 4) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_DATA);
		}
		if (buffer[0] == 1 && buffer[1] == 0) {
			size_t expectedsize = buffer[2] + buffer[3] * 0x100;
			data->buffersize = sizeof(data->buffer);
			r = sc_decompress(data->buffer, &(data->buffersize), buffer+4, buffersize-4, COMPRESSION_ZLIB);
			if (r != SC_SUCCESS) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Zlib error: %d", r);
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
			}
			if (data->buffersize != expectedsize) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
					 "expected size: %"SC_FORMAT_LEN_SIZE_T"u real size: %"SC_FORMAT_LEN_SIZE_T"u",
					 expectedsize, data->buffersize);
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_DATA);
			}
		} else {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unknown compression method %d", buffer[0] + (buffer[1] <<8));
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_DATA);
		}
		data->state = GIDS_STATE_READ_DATA_PRESENT;
	}
	if (offset >= data->buffersize) {
		return 0;
	}
	size = (int) MIN((data->buffersize - offset), count);
	memcpy(buf, data->buffer + offset, size);
	return size;
}

// refresh the internal caches and return the number of containers
static int
gids_get_all_containers(sc_card_t* card, size_t *recordsnum) {
	int r;
	struct gids_private_data *privatedata = (struct gids_private_data *) card->drv_data;
	r = gids_read_masterfile(card);
	LOG_TEST_RET(card->ctx, r, "unable to read the masterfile");
	r = gids_read_cmapfile(card);
	LOG_TEST_RET(card->ctx, r, "unable to read the cmapfile");
	*recordsnum = (privatedata ->cmapfilesize / sizeof(CONTAINER_MAP_RECORD));
	return SC_SUCCESS;
}

// return the detail about a container to emulate a pkcs15 card
static int
gids_get_container_detail(sc_card_t* card, sc_cardctl_gids_get_container_t* container) {
	PCONTAINER_MAP_RECORD records = NULL;
	struct gids_private_data *privatedata = (struct gids_private_data *) card->drv_data;
	size_t recordsnum, num, i;
	records = (PCONTAINER_MAP_RECORD) privatedata ->cmapfile;
	recordsnum = (privatedata ->cmapfilesize / sizeof(CONTAINER_MAP_RECORD));

	num = container->containernum ;
	if (num >= recordsnum) {
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	memset(container, 0, sizeof(sc_cardctl_gids_get_container_t));
	container->containernum = num;

	if (!(records[num].bFlags & CONTAINER_MAP_VALID_CONTAINER)) {
		return SC_SUCCESS;
	}
	// ignore problematic containers
	if (records[num].wKeyExchangeKeySizeBits > 0 && records[num].wSigKeySizeBits > 0) {
		return SC_SUCCESS;
	}
	if (records[num].wKeyExchangeKeySizeBits == 0 && records[num].wSigKeySizeBits == 0) {
		return SC_SUCCESS;
	}
	for (i = 0; i < MAX_CONTAINER_NAME_LEN; i++) {
		container->label[i] = (char) records[num].wszGuid[i];
	}
	container->label[MAX_CONTAINER_NAME_LEN] = 0;

	container->module_length = MAX(records[num].wKeyExchangeKeySizeBits, records[num].wSigKeySizeBits);
	container->prvusage = SC_PKCS15_PRKEY_USAGE_SIGN;
	container->pubusage = SC_PKCS15_PRKEY_USAGE_VERIFY;
	if (records[num].wKeyExchangeKeySizeBits > 0) {
		 container->prvusage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
		 container->pubusage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
	}

	// do not check for return code, typically if there is no certificate associated to the key
	gids_build_certificate_path(card, (unsigned char) num, (records[num].wSigKeySizeBits > 0), &(container->certificatepath));

	return SC_SUCCESS;
}

// find a new key reference
static int
gids_select_key_reference(sc_card_t *card, sc_pkcs15_prkey_info_t* key_info) {
	struct gids_private_data *data = (struct gids_private_data *) card->drv_data;
	PCONTAINER_MAP_RECORD records = (PCONTAINER_MAP_RECORD) data->cmapfile;
	size_t recordsnum;
	int r;
	char ch_tmp[10];

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	// refresh the cached data in case some thing has been modified
	r = gids_read_masterfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read masterfile failed");
	r = gids_read_cmapfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read cmapfile failed");

	recordsnum = (data->cmapfilesize / sizeof(CONTAINER_MAP_RECORD));

	if (!key_info->key_reference) {
		// new key
		size_t i;
		// search for a key number not used anymore
		for (i = 0; i < recordsnum; i++) {
			if (!(records[i].bFlags & CONTAINER_MAP_VALID_CONTAINER)) {
				key_info->key_reference = (int) (GIDS_FIRST_KEY_IDENTIFIER + i);
				return SC_SUCCESS;
			}
		}
		// use a new key number
		if (recordsnum > GIDS_MAX_CONTAINER) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_ENOUGH_MEMORY);
		}
		key_info->key_reference = (int) (GIDS_FIRST_KEY_IDENTIFIER + recordsnum);
	} else {
		// key was specified. Search if the key can be used
		size_t i = key_info->key_reference - GIDS_FIRST_KEY_IDENTIFIER;
		if (i > GIDS_MAX_CONTAINER) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "invalid key ref %d", key_info->key_reference);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
		}
		if (i > recordsnum) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "container num is not allowed %"SC_FORMAT_LEN_SIZE_T"u %"SC_FORMAT_LEN_SIZE_T"u",
				 i, recordsnum);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
		}
	}
	snprintf(ch_tmp, sizeof(ch_tmp), "3FFFB0%02X", key_info->key_reference);
	sc_format_path(ch_tmp, &(key_info->path));
	return SC_SUCCESS;
}

// perform the creation of the key file
// try to mimic the GIDS minidriver key permission
static int gids_perform_create_keyfile(sc_card_t *card, u8 keytype, u8 kid, u8 algid) {
	struct sc_apdu apdu;
	int r;
	u8 keyexchange[] = {0x62,0x47,
							0x82,0x01,0x18,  // file type
							0x83,0x02,0xB0,kid, // key id = 81
							0x8C,0x05,0x8F,0x10,0x10,0x10,0x00, // security
							0xA5,0x37,
								0xB8,0x09, // confidentiality
									0x80,0x01,algid, //algo: rsa without padding
									0x83,0x01,kid, // key id
									0x95,0x01,0x40, // usage
								0xB8,0x09, // confidentiality
									0x80,0x01,0x80 + algid, // RSAES-OAEP padding
									0x83,0x01,kid,
									0x95,0x01,0x40,
								0xB8,0x09, // confidentiality
									0x80,0x01,0x40 + algid, // RSAES-PKCS1-v1_5 padding
									0x83,0x01,kid,
									0x95,0x01,0x40,
								0xB6,0x09, // signature
									0x80,0x01,0x10 + algid, // Full SHA off-card authorized
									0x83,0x01,kid,
									0x95,0x01,0x40,
								0xB6,0x09, // signature
									0x80,0x01,0x50 + algid, // RSASSA PKCS1-v 1_5 padding scheme (for RSA only; otherwise, RFU)
									0x83,0x01,kid,
									0x95,0x01,0x40
	};
	u8 sign[] = {0x62,0x26,
					0x82,0x01,0x18,  // file type
					0x83,0x02,0xB0,kid, // key id = 81
					0x8C,0x05,0x8F,0x10,0x10,0x10,0x00, // security
					0xA5,0x16,
						0xB6,0x09, // signature
							0x80,0x01,0x10+ algid, // Full SHA off-card authorized
							0x83,0x01,0x83, // key id
							0x95,0x01,0x40, // usage
						0xB6,0x09, // signature
							0x80,0x01,0x50 + algid, // RSASSA PKCS1-v 1_5 padding scheme (for RSA only; otherwise, RFU)
							0x83,0x01,0x83,
							0x95,0x01,0x40};

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	// create the key file

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, INS_CREATE_FILE, 0x00, 0x00);
	if (keytype == 1) {
		apdu.lc = sizeof(keyexchange);
		apdu.datalen = sizeof(keyexchange);
		apdu.data = keyexchange;
	} else if (keytype == 2) {
		apdu.lc = sizeof(sign);
		apdu.datalen = sizeof(sign);
		apdu.data = sign;
	} else {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	// activate file
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, INS_ACTIVATE_FILE, 0x00, 0x00);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "ACTIVATE_FILE returned error");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

// perform the creation of the keyfile and its registration in the cmapfile and keymap file
static int gids_create_keyfile(sc_card_t *card, sc_pkcs15_object_t *object) {

	int r;
	u8 keytype;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	u8 kid = key_info->key_reference;
	u8 algid = gids_get_crypto_identifier_from_prkey_info(key_info);
	u8 cmapbuffer[MAX_GIDS_FILE_SIZE];
	size_t cmapbuffersize = 0;
	u8 keymapbuffer[MAX_GIDS_FILE_SIZE];
	size_t keymapbuffersize = 0;
	size_t keymaprecordnum = 0;
	struct gids_private_data *data = (struct gids_private_data *) card->drv_data;
	size_t recordnum;
	size_t containernum = key_info->key_reference - GIDS_FIRST_KEY_IDENTIFIER;
	PCONTAINER_MAP_RECORD records = ((PCONTAINER_MAP_RECORD) cmapbuffer) + containernum;
	struct gids_keymap_record* keymaprecord = NULL;
	int i;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	// sanity check
	assert((object->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY);

	if (!algid) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
	}

	// masterfile & cmapfile have been refreshed in gids_perform_create_keyfile

	recordnum = (data->cmapfilesize / sizeof(CONTAINER_MAP_RECORD));

	// sanity check
	if (containernum > recordnum || containernum > GIDS_MAX_CONTAINER)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);

	// refresh the key map file
	keymapbuffersize = sizeof(keymapbuffer);
	r = gids_get_DO(card, KEYMAP_FI, KEYMAP_DO, keymapbuffer, &keymapbuffersize);
	if (r<0) {
		// the keymap DO should be present if the cmapfile is not empty
		if (recordnum > 0) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
		}
		// else can be empty if not record
		keymapbuffersize = 0;
	} else {
		keymaprecordnum = (keymapbuffersize - 1) / sizeof(struct gids_keymap_record);
		if (keymaprecordnum != recordnum) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL , "Error: Unable to create the key file because the keymap and cmapfile are inconsistent");
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL ,
				 "keymaprecordnum = %"SC_FORMAT_LEN_SIZE_T"u recordnum = %"SC_FORMAT_LEN_SIZE_T"u",
				 keymaprecordnum, recordnum);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
		}
	}


	// prepare the cmap & keymap buffer
	if (containernum == recordnum) {
		// reserve space on the cmap file
		memset(cmapbuffer, 0, sizeof(cmapbuffer));
		memcpy(cmapbuffer, data->cmapfile, data->cmapfilesize);
		cmapbuffersize = data->cmapfilesize + sizeof(CONTAINER_MAP_RECORD);
		r = gids_write_gidsfile(card, "mscp", "cmapfile", cmapbuffer, cmapbuffersize);
		LOG_TEST_RET(card->ctx, r, "unable to reserve space on the cmapfile");

		if (keymapbuffersize == 0) {
			keymapbuffersize = 1;
			keymapbuffer[0] = 1;
		}
		keymapbuffersize += sizeof(struct gids_keymap_record);
	} else {
		memcpy(cmapbuffer, data->cmapfile, data->cmapfilesize);
		cmapbuffersize = data->cmapfilesize;
	}
	keymaprecord = ((struct gids_keymap_record*)(keymapbuffer +1)) + containernum;

	memset(records, 0, sizeof(CONTAINER_MAP_RECORD));
	memset(keymaprecord, 0, sizeof(struct gids_keymap_record));

	if (key_info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT) {
		keytype = 1; // AT_KEYEXCHANGE
		records->wKeyExchangeKeySizeBits = (unsigned short) key_info->modulus_length;
		keymaprecord->keytype = GIDS_KEY_TYPE_AT_KEYEXCHANGE;
	} else if (key_info->usage & SC_PKCS15_PRKEY_USAGE_SIGN) {
		keytype = 2; // AT_SIGNATURE
		records->wSigKeySizeBits = (unsigned short) key_info->modulus_length;
		keymaprecord->keytype = GIDS_KEY_TYPE_AT_SIGNATURE;
	} else {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
	}

	//the GIDS card must have unique container names
	// avoid the problem with the default label by making it unique
	if (strcmp(DEFAULT_PRIVATE_KEY_LABEL, object->label) == 0 && strlen(DEFAULT_PRIVATE_KEY_LABEL) + 3 < MAX_CONTAINER_NAME_LEN) {
		char addition[4] = " 00";
		addition[1] += containernum % 10;
		addition[2] += (containernum < 0xFF) / 10;
		strcat(object->label, addition);
	}

	// convert char to wchar
	for(i = 0; i < MAX_CONTAINER_NAME_LEN && object->label[i]; i++) {
		records->wszGuid[i] = object->label[i];
	}

	// TODO: check if a container with the same name already exists and prevent is creation or change its name

	records->bFlags = CONTAINER_MAP_VALID_CONTAINER;
	if (recordnum == 0) {
		records->bFlags |= CONTAINER_MAP_DEFAULT_CONTAINER;
	}
	keymaprecord->algid = algid;
	keymaprecord->state = 1;
	keymaprecord->unknownWithFFFF = (unsigned short) (-1);
	keymaprecord->keyref = 0xB000 + kid;
	r = gids_perform_create_keyfile(card, keytype, kid, algid);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to create the key file");

	r = gids_update_cardcf(card, 0, 1);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the cardcf file regarding container");
	r = gids_put_DO(card, KEYMAP_FI, KEYMAP_DO, keymapbuffer, keymapbuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to write the keymap file");

	r = gids_write_gidsfile(card, "mscp", "cmapfile", cmapbuffer, cmapbuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to write the cmap file after the container creation");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

// generate a key on an existing container
static int gids_generate_key(sc_card_t *card, sc_pkcs15_object_t *object, struct sc_pkcs15_pubkey* pubkey) {

	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	u8 kid = key_info->key_reference;
	u8 algid = gids_get_crypto_identifier_from_prkey_info(key_info);
	struct sc_apdu apdu;
	u8 generatekey[] = {0xAC, 0x06, // CRT template
							0x80, 0x01, algid, // algorithm
							0x83, 0x01, kid // key reference
						};
	int r;
	u8 *buffer = NULL;
	size_t buffersize = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	assert((object->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY);

	if ((key_info->key_reference > GIDS_FIRST_KEY_IDENTIFIER + GIDS_MAX_CONTAINER) || (kid < GIDS_FIRST_KEY_IDENTIFIER)) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_DATA);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, INS_GENERATE_ASYMECTRIC_KEY_PAIR, 0x00, 0x00);
	apdu.lc = sizeof(generatekey);
	apdu.datalen = sizeof(generatekey);
	apdu.data = generatekey;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generate key returned error");

	r = gids_read_public_key(card, 0, NULL, kid, 0, &buffer, &buffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "read public key returned error");
	r = sc_pkcs15_decode_pubkey(card->ctx, pubkey, buffer, buffersize);
	if (buffer)
		free(buffer);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

// import the key in an existing container
static int gids_import_key(sc_card_t *card, sc_pkcs15_object_t *object, sc_pkcs15_prkey_t *key) {
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	int version = 0;
	int keytype = 2; // RSA
	u8 kid = key_info->key_reference;
	size_t len = 1;
	int encryptkeyref = 0; //NONE
	int r;
	u8* buffer = NULL;
	size_t buflen = 0;

	struct sc_asn1_entry asn1_key_usage_template[] = {
		{ "keyReference", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING | SC_ASN1_CTX, 0, NULL, NULL },
		{ "KeyValueTemplate", SC_ASN1_STRUCT, SC_ASN1_TAG_NULL | SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};

	struct sc_asn1_entry asn1_key_value_template[] = {
		{ "keyType", SC_ASN1_INTEGER, SC_ASN1_TAG_BIT_STRING | SC_ASN1_CTX, 0, NULL, NULL },
		{ "encryptKeyRef", SC_ASN1_INTEGER, SC_ASN1_TAG_OCTET_STRING | SC_ASN1_CTX, 0, NULL, NULL },
		{ "keyValue", SC_ASN1_STRUCT, SC_ASN1_TAG_OBJECT_DESCRIPTOR | SC_ASN1_CTX, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};

	struct sc_asn1_entry asn1_key_data[] = {
		{ "keyData", SC_ASN1_STRUCT, SC_ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};

	struct sc_asn1_entry asn1_rsa_priv_coefficients_gids[] = {
		{ "version", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
		{ "modulus", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ "publicExponent", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ "privateExponent", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ "p", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ "q", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ "dmp1", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ "dmq1", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ "iqmp", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	assert((object->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY);

	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA || key->algorithm != SC_ALGORITHM_RSA) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "GIDS supports RSA keys only (but may support ECC one day).");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (!key->u.rsa.dmp1.len || !key->u.rsa.dmq1.len || !key->u.rsa.iqmp.len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "GIDS needs dmp1 & dmq1 & iqmp");
		return SC_ERROR_NOT_SUPPORTED;
	}
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 0, &version, NULL, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 1, key->u.rsa.modulus.data, &key->u.rsa.modulus.len, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 2, key->u.rsa.exponent.data, &key->u.rsa.exponent.len, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 3, key->u.rsa.d.data, &key->u.rsa.d.len, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 4, key->u.rsa.p.data, &key->u.rsa.p.len, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 5, key->u.rsa.q.data, &key->u.rsa.q.len, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 6, key->u.rsa.dmp1.data, &key->u.rsa.dmp1.len, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 7, key->u.rsa.dmq1.data, &key->u.rsa.dmq1.len, 1);
	sc_format_asn1_entry(asn1_rsa_priv_coefficients_gids + 8, key->u.rsa.iqmp.data, &key->u.rsa.iqmp.len, 1);

	sc_format_asn1_entry(asn1_key_data + 0, asn1_rsa_priv_coefficients_gids, NULL, 1);

	sc_format_asn1_entry(asn1_key_value_template + 0, &keytype, NULL, 1);
	sc_format_asn1_entry(asn1_key_value_template + 1, &encryptkeyref, NULL, 1);
	sc_format_asn1_entry(asn1_key_value_template + 2, asn1_key_data, NULL, 1);

	sc_format_asn1_entry(asn1_key_usage_template + 0, &kid, &len, 1);
	sc_format_asn1_entry(asn1_key_usage_template + 1, asn1_key_value_template, NULL, 1);

	r = sc_asn1_encode(card->ctx, asn1_key_usage_template, &buffer, &buflen);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to encode the private key");

	r = gids_put_DO(card, GIDS_APPLET_EFID, GIDS_PUT_KEY_DO, buffer, buflen);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to put the private key - key greater than 2048 bits ?");
	r = SC_SUCCESS;
err:
	sc_mem_clear(buffer, buflen);
	LOG_FUNC_RETURN(card->ctx, r);
}

// remove a crt file
static int gids_delete_key_file(sc_card_t *card, int containernum) {
	int r;
	char ch_tmp[10];
	sc_path_t cpath;
	snprintf(ch_tmp, sizeof(ch_tmp), "B0%02X",containernum + GIDS_FIRST_KEY_IDENTIFIER);
	sc_format_path(ch_tmp, &cpath);
	r = iso_ops->select_file(card, &cpath, NULL);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to select the key file");
	// delete current selected file
	memset(&cpath, 0, sizeof(cpath));
	r = iso_ops->delete_file(card, &cpath);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to delete the key file");
	return r;
}

// encode a certificate using the minidriver compression
static int gids_encode_certificate(sc_card_t *card, u8* source, size_t sourcesize, u8* destination, size_t* destinationsize) {
	int r;
	size_t outlen;
	if (*destinationsize < 4) {
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	if (sourcesize > 0xFFFF) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	}
	// format is:
	// 2 bytes for compression version
	// 2 bytes for uncompressed file size
	// ZLIB compression of the certificate
	destination[0] = 1;
	destination[1] = 0;
	destination[2] = sourcesize & 0xFF;
	destination[3] = (sourcesize & 0xFF00) >> 8;
	outlen = *destinationsize - 4;
	r = sc_compress(destination + 4, &outlen, source, sourcesize, COMPRESSION_ZLIB);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to compress the certificate");
	*destinationsize = outlen + 4;
	return SC_SUCCESS;
}

// save a certificate associated to a container to the card
static int gids_save_certificate(sc_card_t *card, sc_pkcs15_object_t *certobject,
								sc_pkcs15_object_t *privkeyobject, struct sc_path *path) {
	int r;
	u8 certbuffer[MAX_GIDS_FILE_SIZE];
	size_t certbuffersize = sizeof(certbuffer);
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) certobject->data;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *) privkeyobject->data;
	unsigned char containernum;
	char filename[9];
	assert((certobject->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT);
	assert((privkeyobject->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY);

	// refresh the cached data in case some thing has been modified
	r = gids_read_masterfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read masterfile failed");
	r= gids_read_cmapfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read cmapfile failed");

	// compress the certificate according to the minidriver specification
	r = gids_encode_certificate(card, cert_info->value.value, cert_info->value.len, certbuffer, &certbuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to encode the certificate");

	// save it to a minidriver file
	containernum = prkey_info->key_reference - GIDS_FIRST_KEY_IDENTIFIER;
	if (!(prkey_info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT)) {
		snprintf(filename, sizeof(filename), "ksc%02X", containernum);
	} else {
		snprintf(filename, sizeof(filename), "kxc%02X", containernum);
	}

	r = gids_does_file_exists(card, "mscp", filename);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		r = gids_create_file(card, "mscp", filename);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to create the certificate file");
	}
	r = gids_write_gidsfile(card, "mscp", filename, certbuffer, certbuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to write the certificate data");

	// return the path to the DO
	r = gids_build_certificate_path(card, containernum, !(prkey_info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT), path);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to build the certificate path");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

// remove a container and its registration in the cmapfile
static int gids_delete_container_num(sc_card_t *card, size_t containernum) {
	int r;
	u8 cmapbuffer[MAX_GIDS_FILE_SIZE];
	size_t cmapbuffersize = 0;
	u8 keymapbuffer[MAX_GIDS_FILE_SIZE];
	size_t keymapbuffersize = 0;
	size_t keymaprecordnum = 0;
	struct gids_private_data *data = (struct gids_private_data *) card->drv_data;
	size_t recordnum;
	PCONTAINER_MAP_RECORD records = ((PCONTAINER_MAP_RECORD) cmapbuffer) + containernum;
	struct gids_keymap_record* keymaprecord = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	// masterfile & cmapfile have been refreshed before

	recordnum = (data->cmapfilesize / sizeof(CONTAINER_MAP_RECORD));

	// sanity check
	if (containernum >= recordnum || recordnum > GIDS_MAX_CONTAINER)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);

	// refresh the key map file
	keymapbuffersize = sizeof(keymapbuffer);
	r = gids_get_DO(card, KEYMAP_FI, KEYMAP_DO, keymapbuffer, &keymapbuffersize);
	if (r<0) {
		// the keymap DO should be present if the cmapfile is not empty
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	keymaprecordnum = (keymapbuffersize - 1) / sizeof(struct gids_keymap_record);
	if (keymaprecordnum != recordnum) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}

	// update the key map file
	memcpy(cmapbuffer, data->cmapfile, data->cmapfilesize);
	cmapbuffersize = data->cmapfilesize;
	keymaprecord = ((struct gids_keymap_record*)(keymapbuffer +1)) + containernum;

	memset(records, 0, sizeof(CONTAINER_MAP_RECORD));
	memset(keymaprecord, 0, sizeof(struct gids_keymap_record));

	keymaprecord->unknownWithFFFF = (unsigned short) (-1);
	keymaprecord->keyref =(unsigned short) (-1);

	// remove the key, update the key map & cmap file and signal the change
	r = gids_delete_key_file(card, (int) containernum);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to delete the key file");
	r = gids_update_cardcf(card, 0, 1);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the cardcf file regarding container");
	r = gids_put_DO(card, KEYMAP_FI, KEYMAP_DO, keymapbuffer, keymapbuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to write the keymap file");

	r = gids_write_gidsfile(card, "mscp", "cmapfile", cmapbuffer, cmapbuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to write the cmap file after the container creation");

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

// delete a certificate associated to a container
static int gids_delete_cert(sc_card_t *card, sc_pkcs15_object_t* object) {
	int r;
	struct gids_private_data *privatedata = (struct gids_private_data *) card->drv_data;
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	unsigned short fileIdentifier, DO;
	u8 masterfilebuffer[MAX_GIDS_FILE_SIZE];
	size_t masterfilebuffersize = 0;
	gids_mf_record_t *records = (gids_mf_record_t *) masterfilebuffer;
	size_t recordcount, recordnum = (size_t) -1;
	size_t i;


	assert((object->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT);
	// refresh the cached data in case some thing has been modified
	r = gids_read_masterfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read masterfile failed");
	r= gids_read_cmapfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read cmapfile failed");

	// remove the file reference from the masterfile
	if (cert_info->path.len != 4) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	fileIdentifier = cert_info->path.value[0] * 0x100 + cert_info->path.value[1];
	DO = cert_info->path.value[2] * 0x100 + cert_info->path.value[3];

	memcpy(masterfilebuffer, privatedata->masterfile, privatedata->masterfilesize);
	masterfilebuffersize = privatedata->masterfilesize;

	recordcount = (masterfilebuffersize / sizeof(gids_mf_record_t));
	for (i = 0; i < recordcount; i++) {
		if (records[i].fileIdentifier == fileIdentifier && records[i].dataObjectIdentifier == DO) {
			recordnum = i;
			break;
		}
	}
	if (recordnum == (size_t) -1) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);
	}

	for (i = (recordnum+1) * sizeof(gids_mf_record_t); i < masterfilebuffersize; i++) {
		masterfilebuffer[i - sizeof(gids_mf_record_t)] = masterfilebuffer[i];
	}
	masterfilebuffersize -= sizeof(gids_mf_record_t);

	// remove the DO, update the masterfile, and signal the change
	r = gids_update_cardcf(card, 1, 0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to update the cache file");

	r = gids_put_DO(card, fileIdentifier, DO, NULL, 0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to delete the certificate DO");

	r = gids_put_DO(card, MF_FI, MF_DO, masterfilebuffer, masterfilebuffersize);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to update the masterfile");

	memcpy(privatedata->masterfile, masterfilebuffer, masterfilebuffersize);
	privatedata->masterfilesize = masterfilebuffersize;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int gids_delete_key(sc_card_t *card, sc_pkcs15_object_t* object) {
	int r;
	size_t containernum;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;

	assert((object->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY);
	// refresh the cached data in case some thing has been modified
	r = gids_read_masterfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read masterfile failed");
	r = gids_read_cmapfile(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids read cmapfile failed");
	containernum = key_info->key_reference - GIDS_FIRST_KEY_IDENTIFIER;

	r = gids_delete_container_num(card, containernum);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to delete the container");
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

// used by gids_initialize to create the filesystem
static int gids_initialize_create_file(sc_card_t *card, u8* command, size_t commandsize) {
	int r;
	sc_apdu_t apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, INS_CREATE_FILE, 0x00, 0x00);
	apdu.lc = commandsize;
	apdu.data = command;
	apdu.datalen = commandsize;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU1 transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");

	// activate file
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, INS_ACTIVATE_FILE, 0x00, 0x00);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU2 transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

// used by gids_initialize to set the admin key
static int gids_set_administrator_key(sc_card_t *card, u8* key) {
	int r;
	u8 adminKeyData[] = {0x84,0x01,0x80, // key reference
						 0xA5,0x1F, // key template
						 // key value
							0x87,0x18,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,
									0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,
									0x03,0x04,0x05,0x06,0x07,0x08,
						// key file
							0x88, 0x03,0xB0,0x73,0xDC};

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	memcpy(adminKeyData+7, key, 24);
	r = gids_put_DO(card, GIDS_APPLET_EFID, GIDS_PUT_KEY_DO, adminKeyData, sizeof(adminKeyData));
	sc_mem_clear(adminKeyData, sizeof(adminKeyData));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to set the admin key");
	return SC_SUCCESS;
}

static int gids_check_that_card_is_new(sc_card_t *card) {
	int r;
	// retrieve the masterfile
	// if it succeed, the card has already been initialized
	r = gids_read_masterfile(card);
	if (r == SC_SUCCESS) {
		r = SC_ERROR_INVALID_CARD;
		LOG_TEST_RET(card->ctx, r, "unable to read the masterfile");
	}
	return SC_SUCCESS;
}

// initialize a card
// see the minidriver specification annex for the details about this
static int gids_initialize(sc_card_t *card, sc_cardctl_gids_init_param_t* param) {
	sc_apdu_t apdu;
	int r;
#ifdef ENABLE_OPENSSL
	int i;
#endif
	// hardcoded file setting
	// File type=39=TLV structure for BER-TLV DOs then ACL varies depending on the file)
	// this DO EF are used like DF file so the permission has to be set only once
	u8 UserCreateDeleteDirAc[] = {0x62,0x0C,0x82,0x01,0x39,0x83,0x02,0xA0,0x00,0x8C,0x03,0x03,0x30,0x00};
	u8 EveryoneReadUserWriteAc[] = {0x62,0x0C,0x82,0x01,0x39,0x83,0x02,0xA0,0x10,0x8C,0x03,0x03,0x30,0x00};
	u8 UserWriteExecuteAc[] = {0x62,0x0C,0x82,0x01,0x39,0x83,0x02,0xA0,0x11,0x8C,0x03,0x03,0x30,0xFF};
	u8 EveryoneReadAdminWriteAc[] = {0x62,0x0C,0x82,0x01,0x39,0x83,0x02,0xA0,0x12,0x8C,0x03,0x03,0x20,0x00};
	u8 UserReadWriteAc[] = {0x62,0x0C,0x82,0x01,0x39,0x83,0x02,0xA0,0x13,0x8C,0x03,0x03,0x30,0x30};
	u8 AdminReadWriteAc[] = {0x62,0x0C,0x82,0x01,0x39,0x83,0x02,0xA0,0x14,0x8C,0x03,0x03,0x20,0x20};
	// File type=18=key file ; type = symmetric key
	u8 AdminKey[] = {0x62,0x1A,0x82,0x01,0x18,0x83,0x02,0xB0,0x80,0x8C,0x04,0x87,0x00,0x20,0xFF,0xA5,
											0x0B,0xA4,0x09,0x80,0x01,0x02,0x83,0x01,0x80,0x95,0x01,0xC0};
	// file used to store other file references. Format undocumented.
	u8 masterfile[] = {0x01,0x6d,0x73,0x63,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					   0x00,0x00,0x00,0x00,0x63,0x61,0x72,0x64,0x69,0x64,0x00,0x00,0x00,0x00,0x00,0x20,0xdf,
					   0x00,0x00,0x12,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x63,0x61,
					   0x72,0x64,0x61,0x70,0x70,0x73,0x00,0x00,0x00,0x21,0xdf,0x00,0x00,0x10,0xa0,0x00,0x00,
					   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x63,0x61,0x72,0x64,0x63,0x66,0x00,0x00,
					   0x00,0x00,0x00,0x22,0xdf,0x00,0x00,0x10,0xa0,0x00,0x00,0x6d,0x73,0x63,0x70,0x00,0x00,
					   0x00,0x00,0x00,0x63,0x6d,0x61,0x70,0x66,0x69,0x6c,0x65,0x00,0x00,0x00,0x23,0xdf,0x00,
					   0x00,0x10,0xa0,0x00,0x00};
	// list the application on the card - defined in the minidriver specification
	u8 cardapps[] = {0x6d,0x73,0x63,0x70,0x00,0x00,0x00,0x00};
	// used to detect if modifications have been done outside of the minidriver - defined in the minidriver specification
	u8 cardcf[] = {0x00,0x00,0x00,0x00,0x00,0x00};
	struct sc_pin_cmd_data pindata;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	// avoid multiple initialization
	r = gids_check_that_card_is_new(card);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "card seems to have been already initialized");

	memset(&pindata, 0, sizeof(pindata));
	// create PIN & PUK
	pindata.cmd = SC_PIN_CMD_CHANGE;
	pindata.pin_type = SC_AC_CHV;
	pindata.pin2.len = param->user_pin_len;
	pindata.pin2.data = param->user_pin;
	pindata.pin_reference = 0x80;

	r = sc_pin_cmd(card, &pindata, NULL);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids set pin");

	// create file
	r = gids_initialize_create_file(card, UserCreateDeleteDirAc, sizeof(UserCreateDeleteDirAc));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids to create the file UserCreateDeleteDirAc");
	r = gids_initialize_create_file(card, EveryoneReadUserWriteAc, sizeof(EveryoneReadUserWriteAc));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids to create the file EveryoneReadUserWriteAc");
	r = gids_initialize_create_file(card, UserWriteExecuteAc, sizeof(UserWriteExecuteAc));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids to create the file UserWriteExecuteAc");
	r = gids_initialize_create_file(card, EveryoneReadAdminWriteAc, sizeof(EveryoneReadAdminWriteAc));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids to create the file EveryoneReadAdminWriteAc");
	r = gids_initialize_create_file(card, UserReadWriteAc, sizeof(UserReadWriteAc));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids to create the file UserReadWriteAc");
	r = gids_initialize_create_file(card, AdminReadWriteAc, sizeof(AdminReadWriteAc));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids to create the file AdminReadWriteAc");

	//admin key
	r = gids_initialize_create_file(card, AdminKey, sizeof(AdminKey));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids to create the file AdminKey");

	r = gids_set_administrator_key(card, param->init_code);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to set the admin key");

	// create the filesystem
	r = gids_put_DO(card, MF_FI, MF_DO, masterfile, sizeof(masterfile));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to save the masterfile");
	r = gids_put_DO(card, CARDAPPS_FI, CARDAPPS_DO, cardapps, sizeof(cardapps));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to save the cardapps");
	r = gids_put_DO(card, CARDCF_FI, CARDCF_DO, cardcf, sizeof(cardcf));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to save the cardcf");
	r = gids_put_DO(card, CMAP_FI, CMAP_DO, NULL, 0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to save the cmapfile");
#ifdef ENABLE_OPENSSL
	for (i = sizeof(param->cardid) -1; i >= 0; i--) {
		if (param->cardid[i]) break;
	}
	if (i < 0) {
		// set a random cardid if not set
		r = RAND_bytes(param->cardid, sizeof(param->cardid));
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to set a random serial number");

	}
#endif
	r = gids_put_DO(card, CARDID_FI, CARDID_DO, param->cardid, sizeof(param->cardid));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "gids unable to save the cardid");

	//select applet
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, INS_SELECT, 0x00, 0x0C);
	apdu.lc = 2;
	apdu.data = (const unsigned char *) "\x3F\xFF";
	apdu.datalen = 2;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");
	// activate file
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, INS_ACTIVATE_FILE, 0x00, 0x00);
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

// execute an admin authentication based on a secret key
// this is a 3DES authentication with a secret key
// the card mechanism is described in the GIDS specification and the computer side on the minidriver specification
// the minidriver specification is incorrect because it is not ECB but CBC
// then the GIDS specification is incorrect because the z1 key should be 8 bytes instead of 7
// this data comes from the reverse of the GIDS minidriver.
static int gids_authenticate_admin(sc_card_t *card, u8* key) {
#ifndef ENABLE_OPENSSL
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
#else
	EVP_CIPHER_CTX *ctx = NULL;
	int r;
	u8 apduSetRandom[20] = {0x7C,0x12,0x81,0x10,0};
	u8* randomR1 = apduSetRandom + 4;
	u8 apduSetRandomResponse[256];
	u8* randomR2 = apduSetRandomResponse+4;
	u8 apduSendReponse[40 + 4] = {0x7C,0x2A,0x82,0x28};
	u8 z1[8];
	u8 buffer[16+16+8];
	u8* buffer2 = apduSendReponse + 4;
	int buffer2size = 40;
	u8 apduSendResponseResponse[256];
	u8 buffer3[16+16+8];
	int buffer3size = 40;
	sc_apdu_t apdu;
	const EVP_CIPHER *cipher;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	// this is CBC instead of ECB
	cipher = EVP_des_ede3_cbc();
	if (!cipher) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}

	// select the admin key
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, INS_MANAGE_SECURITY_ENVIRONMENT, 0xC1, 0xA4);
	apdu.lc = 3;
	apdu.data = (const unsigned char *) "\x83\x01\x80";
	apdu.datalen = 3;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");

	// generate a challenge
	r = RAND_bytes(randomR1, 16);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to set computer random");

	// send it to the card
	memcpy(apduSetRandom+4, randomR1, 16);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, INS_GENERAL_AUTHENTICATE, 0x00, 0x00);
	apdu.lc = sizeof(apduSetRandom);
	apdu.data = apduSetRandom;
	apdu.datalen = sizeof(apduSetRandom);
	apdu.resp = apduSetRandomResponse;
	apdu.resplen = sizeof(apduSetRandomResponse);
	apdu.le = 256;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");

	// compute the half size of the mutual authentication secret
	r = RAND_bytes(z1, 7);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to set computer random");
	// set the padding
	z1[7] = 0x80;

	// Encrypt R2||R1||Z1
	memcpy(buffer, randomR2, 16);
	memcpy(buffer+16, randomR1, 16);
	memcpy(buffer+32, z1, sizeof(z1));
	// init crypto
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
	    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}

	if (!EVP_EncryptInit(ctx, cipher, key, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	EVP_CIPHER_CTX_set_padding(ctx,0);
	if (!EVP_EncryptUpdate(ctx, buffer2, &buffer2size, buffer, sizeof(buffer))) {
		EVP_CIPHER_CTX_free(ctx);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}

	if(!EVP_EncryptFinal(ctx, buffer2+buffer2size, &buffer2size)) {
		EVP_CIPHER_CTX_free(ctx);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;
	// send it to the card
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, INS_GENERAL_AUTHENTICATE, 0x00, 0x00);
	apdu.lc = sizeof(apduSendReponse);
	apdu.data = apduSendReponse;
	apdu.datalen = sizeof(apduSendReponse);
	apdu.resp = apduSendResponseResponse;
	apdu.resplen = sizeof(apduSendResponseResponse);
	apdu.le = 256;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,  sc_check_sw(card, apdu.sw1, apdu.sw2), "invalid return");
	
	if (apdu.resplen != 44)
	{
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Expecting a response len of 44 - found %d",(int) apdu.resplen);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	// init crypto
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
	    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	if (!EVP_DecryptInit(ctx, cipher, key, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	EVP_CIPHER_CTX_set_padding(ctx,0);
	if (!EVP_DecryptUpdate(ctx, buffer3, &buffer3size, apdu.resp + 4, apdu.resplen - 4)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to decrypt data");
		EVP_CIPHER_CTX_free(ctx);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_PIN_CODE_INCORRECT);
	}
	if(!EVP_DecryptFinal(ctx, buffer3+buffer3size, &buffer3size)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to decrypt final data");
		EVP_CIPHER_CTX_free(ctx);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_PIN_CODE_INCORRECT);
	}
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "data has been decrypted using the key");
	if (memcmp(buffer3, randomR1, 16) != 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "R1 doesn't match");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_PIN_CODE_INCORRECT);
	}
	if (memcmp(buffer3 + 16, randomR2, 16) != 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "R2 doesn't match");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_PIN_CODE_INCORRECT);
	}
	if (buffer[39] != 0x80) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Padding not found");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_PIN_CODE_INCORRECT);
	}
	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
#endif
}

static int gids_card_ctl(sc_card_t * card, unsigned long cmd, void *ptr)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	switch (cmd) {
		case SC_CARDCTL_GET_SERIALNR:
			return gids_get_serialnr(card, (sc_serial_number_t *) ptr);
		case SC_CARDCTL_GIDS_GET_ALL_CONTAINERS:
			return gids_get_all_containers(card, (size_t*) ptr);
		case SC_CARDCTL_GIDS_GET_CONTAINER_DETAIL:
			return gids_get_container_detail(card, (sc_cardctl_gids_get_container_t*) ptr);
		case SC_CARDCTL_GIDS_SELECT_KEY_REFERENCE:
			return gids_select_key_reference(card, (sc_pkcs15_prkey_info_t*) ptr);
		case SC_CARDCTL_GIDS_CREATE_KEY:
			return gids_create_keyfile(card, (sc_pkcs15_object_t*) ptr);
		case SC_CARDCTL_GIDS_GENERATE_KEY:
			return gids_generate_key(card, ((struct sc_cardctl_gids_genkey*) ptr)->object, ((struct sc_cardctl_gids_genkey*) ptr)->pubkey);
		case SC_CARDCTL_GIDS_IMPORT_KEY:
			return gids_import_key(card, ((struct sc_cardctl_gids_importkey*) ptr)->object, ((struct sc_cardctl_gids_importkey*) ptr)->key);
		case SC_CARDCTL_GIDS_SAVE_CERT:
			return gids_save_certificate(card, ((struct sc_cardctl_gids_save_cert*) ptr)->certobject,
										((struct sc_cardctl_gids_save_cert*) ptr)->privkeyobject, ((struct sc_cardctl_gids_save_cert*) ptr)->path);
		case SC_CARDCTL_GIDS_DELETE_CERT:
			return gids_delete_cert(card, (sc_pkcs15_object_t*) ptr);
		case SC_CARDCTL_GIDS_DELETE_KEY:
			return gids_delete_key(card, (sc_pkcs15_object_t*) ptr);
		case SC_CARDCTL_GIDS_INITIALIZE:
			return gids_initialize(card, (sc_cardctl_gids_init_param_t*) ptr);
		case SC_CARDCTL_GIDS_SET_ADMIN_KEY:
			return gids_set_administrator_key(card, (u8*) ptr);
		case SC_CARDCTL_GIDS_AUTHENTICATE_ADMIN:
			return gids_authenticate_admin(card, (u8*) ptr);
		default:
			return SC_ERROR_NOT_SUPPORTED;
	}
}

static int gids_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (was_reset > 0) {
		u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
		size_t resplen = sizeof(rbuf);
		r = gids_select_aid(card, gids_aid.value, gids_aid.len, rbuf, &resplen);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static struct sc_card_driver *sc_get_driver(void)
{

	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	gids_ops.match_card = gids_match_card;
	gids_ops.init = gids_init;
	gids_ops.finish = gids_finish;
	gids_ops.read_binary = gids_read_binary;
	gids_ops.write_binary = NULL;
	gids_ops.update_binary = NULL;
	gids_ops.erase_binary = NULL;
	gids_ops.read_record = NULL;
	gids_ops.write_record = NULL;
	gids_ops.append_record = NULL;
	gids_ops.update_record = NULL;
	gids_ops.select_file = gids_select_file;
	gids_ops.get_response = iso_ops->get_response;
	gids_ops.get_challenge = NULL;
	gids_ops.verify = NULL; // see pin_cmd
	gids_ops.logout = gids_logout;
	gids_ops.restore_security_env = NULL;
	gids_ops.set_security_env = gids_set_security_env;
	gids_ops.decipher = iso_ops->decipher;
	gids_ops.compute_signature = iso_ops->compute_signature;
	gids_ops.change_reference_data = NULL; // see pin_cmd
	gids_ops.reset_retry_counter = NULL; // see pin_cmd
	gids_ops.create_file = iso_ops->create_file;
	gids_ops.delete_file = NULL;
	gids_ops.list_files = NULL;
	gids_ops.check_sw = iso_ops->check_sw;
	gids_ops.card_ctl = gids_card_ctl;
	gids_ops.process_fci = iso_ops->process_fci;
	gids_ops.construct_fci = iso_ops->construct_fci;
	gids_ops.pin_cmd = gids_pin_cmd;
	gids_ops.get_data = NULL;
	gids_ops.put_data = NULL;
	gids_ops.delete_record = NULL;
	gids_ops.read_public_key = gids_read_public_key;
	gids_ops.card_reader_lock_obtained = gids_card_reader_lock_obtained;

	return &gids_drv;
}

struct sc_card_driver *sc_get_gids_driver(void)
{
	return sc_get_driver();
}

#else

struct sc_card_driver *sc_get_gids_driver(void)
{
	return NULL;
}

#endif
