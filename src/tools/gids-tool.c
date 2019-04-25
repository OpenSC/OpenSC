/*
 * gids-tool.c: Support for GIDS smart cards.
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include <openssl/opensslv.h>
#include "libopensc/sc-ossl-compat.h"
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#endif
#include <openssl/conf.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/card-gids.h"
#include "libopensc/asn1.h"
#include "util.h"

static const char *app_name = "gids-tool";

static struct sc_aid gids_aid = { { 0xA0,0x00,0x00,0x03,0x97,0x42,0x54,0x46,0x59 }, 9 };

static int	opt_wait = 0;
static char *opt_reader = NULL;
static int	verbose = 0;

enum {
	OPT_SO_PIN = 0x100,
	OPT_PIN,
	OPT_SERIAL_NUMBER,
	OPT_NEW_KEY,
};

static const struct option options[] = {
	{ "initialize",				0, NULL,		'X' },
	{ "admin-key",			    1, NULL,		OPT_SO_PIN },
	{ "pin",					1, NULL,		OPT_PIN },
	{ "serial-number",          1, NULL,        OPT_SERIAL_NUMBER },
	{ "unblock",                0, NULL,        'U' },
	{ "change-admin-key",       0, NULL,        'C' },
	{ "new-admin-key",          1, NULL,        OPT_NEW_KEY },
	{ "reader",					1, NULL,		'r' },
	{ "wait",					0, NULL,		'w' },
	{ "verbose",				0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Initialize token",
	"Define the administrator key",
	"Define user PIN",
	"Define serial number",
	"Unblock the user PIN after an administrator authentication",
	"Change the administrator key",
	"Define the new administrator key",
	"Uses reader number <arg> [0]",
	"Wait for a card to be inserted",
	"Verbose operation. Use several times to enable debug output.",
};

static int initialize(sc_card_t *card, const char *so_pin, const char *user_pin, const char* serial)
{
	sc_cardctl_gids_init_param_t param;
	size_t len;
	char *_so_pin = NULL, *_user_pin = NULL, *_serial = NULL;
	int r;

	memset(&param, 0, sizeof(sc_cardctl_gids_init_param_t));

	if (so_pin == NULL) {
		printf("Enter admin key (48 hexadecimal characters) : \n");
		printf("Press Enter to set the admin key to 00...00\n");
		util_getpass(&_so_pin, NULL, stdin);
		printf("\n");
	} else {
		_so_pin = (char *)so_pin;
	}

	len = sizeof(param.init_code);
	r = sc_hex_to_bin(_so_pin, param.init_code, &len);
	if (r < 0) {
		fprintf(stderr, "Error decoding initialization code (%s)\n", sc_strerror(r));
		return -1;
	}

	if (len == 0) {
	} else if (len != 24) {
		fprintf(stderr, "The admin key must be a hexadecimal string of 48 characters\n");
		return -1;
	}

	if (user_pin == NULL) {
		printf("Enter initial User-PIN (4 - 16 characters) : ");
		util_getpass(&_user_pin, NULL, stdin);
		printf("\n");
	} else {
		_user_pin = (char *)user_pin;
	}

	if (serial == NULL) {
		printf("Enter serial number (32 hexadecimal characters): \n");
		printf("Press Enter to set a random serial number\n");
		util_getpass(&_serial, NULL, stdin);
		printf("\n");
	} else {
		_serial = (char *)serial;
	}

	if (_serial[0] == '\0') {
		memset(param.cardid, 0, sizeof(param.cardid));
	} else if (strlen(_serial) != 32) {
		fprintf(stderr, "the serial number must be a hexadecimal string of 32 characters\n");
		return -1;
	} else {
		len = sizeof(param.cardid);
		r = sc_hex_to_bin(_serial, param.cardid, &len);
		if (r < 0) {
			fprintf(stderr, "Error decoding serial number (%s)\n", sc_strerror(r));
			return -1;
		}
	}

	param.user_pin_len = strlen(_user_pin);

	if (param.user_pin_len < 4) {
		fprintf(stderr, "PIN must be at least 4 characters long\n");
		return -1;
	}

	if (param.user_pin_len > 16) {
		fprintf(stderr, "PIN must not be longer than 16 characters\n");
		return -1;
	}

	param.user_pin = (u8 *)_user_pin;

	r = sc_card_ctl(card, SC_CARDCTL_GIDS_INITIALIZE, (void *)&param);
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GIDS_INITIALIZE, *) failed with %s\n", sc_strerror(r));
	}

	return 0;
}

static int unblock(sc_card_t* card, const char *so_pin, const char *user_pin) {
	int r;
	char *_so_pin = NULL, *_user_pin = NULL;
	size_t len;
	u8 key[24];
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(struct sc_pin_cmd_data));

	if (so_pin == NULL) {
		printf("============================================================\n");
		printf("WARNING\n");
		printf("Entering an incorrect admin key can break your card\n");
		printf("WARNING\n");
		printf("============================================================\n");
		printf("Enter admin key (48 hexadecimal characters) : ");
		util_getpass(&_so_pin, NULL, stdin);
		printf("\n");
	} else {
		_so_pin = (char *)so_pin;
	}

	len = sizeof(key);
	r = sc_hex_to_bin(_so_pin, key, &len);
	if (r < 0) {
		fprintf(stderr, "Error decoding initialization code (%s)\n", sc_strerror(r));
		return -1;
	}

	if (len != 24) {
		fprintf(stderr, "admin key must be a hexadecimal string of 48 characters\n");
		return -1;
	}

	r = sc_card_ctl(card, SC_CARDCTL_GIDS_AUTHENTICATE_ADMIN, (void *)key);
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GIDS_AUTHENTICATE_ADMIN, *) failed with %s\n", sc_strerror(r));
		return -1;
	}
	printf("Administrator authentication successful\n");
	printf("Setting the new PIN\n");

	if (user_pin == NULL) {
		printf("Enter User-PIN (4 - 16 characters) : ");
		util_getpass(&_user_pin, NULL, stdin);
		printf("\n");
	} else {
		_user_pin = (char *)user_pin;
	}

	data.pin_type = SC_AC_CHV;
	data.cmd = SC_PIN_CMD_UNBLOCK;
	data.pin2.len = strlen(_user_pin);
	data.pin2.data = (unsigned char*) _user_pin;
	data.pin_reference = 0x80;
	r = sc_pin_cmd(card, &data, NULL);
	if (r < 0) {
		fprintf(stderr, "reset pin failed with %s\n", sc_strerror(r));
		return -1;
	}
	printf("Unblock PIN done successfully\n");
	// the card should have deauthenticated the admin, but to be sure:
	sc_logout(card);
	return 0;
}

static int changeAdminKey(sc_card_t* card, const char *so_pin, const char* new_key) {
	char *_so_pin = NULL, *_new_key = NULL;
	size_t len;
	u8 key[24];
	int r;

	if (so_pin == NULL) {
		printf("============================================================\n");
		printf("WARNING\n");
		printf("Entering an incorrect admin key can break your card\n");
		printf("WARNING\n");
		printf("============================================================\n");
		printf("Enter admin key (48 hexadecimal characters) : ");
		util_getpass(&_so_pin, NULL, stdin);
		printf("\n");
	} else {
		_so_pin = (char *)so_pin;
	}

	len = sizeof(key);
	r = sc_hex_to_bin(_so_pin, key, &len);
	if (r < 0) {
		fprintf(stderr, "Error decoding initialization code (%s)\n", sc_strerror(r));
		return -1;
	}

	if (len != 24) {
		fprintf(stderr, "admin key must be a hexadecimal string of 48 characters\n");
		return -1;
	}

	r = sc_card_ctl(card, SC_CARDCTL_GIDS_AUTHENTICATE_ADMIN, (void *)key);
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GIDS_AUTHENTICATE_ADMIN, *) failed with %s\n", sc_strerror(r));
		return -1;
	}

	if (new_key == NULL) {
		printf("Enter new admin key (48 hexadecimal characters) : ");
		util_getpass(&_new_key, NULL, stdin);
		printf("\n");
	} else {
		_new_key = (char *)new_key;
	}

	len = sizeof(key);
	r = sc_hex_to_bin(_new_key, key, &len);
	if (r < 0) {
		fprintf(stderr, "Error decoding initialization code (%s)\n", sc_strerror(r));
		return -1;
	}

	if (len != 24) {
		fprintf(stderr, "admin key must be a hexadecimal string of 48 characters\n");
		return -1;
	}

	r = sc_card_ctl(card, SC_CARDCTL_GIDS_SET_ADMIN_KEY, (void *)key);
	sc_logout(card);
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GIDS_SET_ADMIN_KEY, *) failed with %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

// read a DO from the card
static int gids_get_DO(sc_card_t* card, int fileIdentifier, int dataObjectIdentifier, u8* response, size_t *responselen) {
	sc_apdu_t apdu;
	int r;
	u8 data[4] = {0x5C, 0x02, (dataObjectIdentifier&0xFF00)>>8, (dataObjectIdentifier&0xFF)};
	size_t datasize = 0;
	const u8* p;
	u8 buffer[MAX_GIDS_FILE_SIZE];

	sc_format_apdu(card, &apdu,
		response == NULL ? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT, 0xCB, (fileIdentifier&0xFF00)>>8, (fileIdentifier&0xFF));
	apdu.lc = 04;
	apdu.data = data;
	apdu.datalen = 04;
	apdu.resp = buffer;
	apdu.resplen = sizeof(buffer);
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0)
		return r;

	p = sc_asn1_find_tag(card->ctx, buffer, sizeof(buffer), dataObjectIdentifier, &datasize);
	if (!p) {
		return SC_ERROR_FILE_NOT_FOUND;
	}
	if (datasize > *responselen) {
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	if (response) {
		memcpy(response, p, datasize);
	}
	*responselen = datasize;
	return SC_SUCCESS;
}

static int print_info(sc_card_t *card) {
	int r;
	u8 buffer[MAX_GIDS_FILE_SIZE];
	size_t size = sizeof(buffer);
	u8 masterfile[MAX_GIDS_FILE_SIZE];
	size_t masterfilesize = sizeof(masterfile);
	u8 cmapfile[MAX_GIDS_FILE_SIZE];
	size_t cmapfilesize = sizeof(cmapfile);
	u8 keymap[MAX_GIDS_FILE_SIZE];
	size_t keymapsize = sizeof(keymap);
	gids_mf_record_t *records = (gids_mf_record_t *) (masterfile+1);
	int recordcount;
	int i;
	
	printf("===============================\n");
	printf("Dumping the content of the card\n");
	printf("===============================\n");
	r = gids_get_DO(card, MF_FI, MF_DO, masterfile, &masterfilesize);
	if (r < 0) {
		fprintf(stderr, "unable to retrieve the master file: %s\n", sc_strerror(r));
		fprintf(stderr, "Is that a new card ?\n");
		return r;
	}
	printf("Dumping Files:\n");
	if (masterfilesize >= 1) {
		recordcount = (int) ((masterfilesize-1) / sizeof(gids_mf_record_t));
		printf("Found %d entries in the masterfile\n", recordcount);
		for (i = 0; i < recordcount; i++) {
			if (records[i].filename[0] == 0) {
				printf("   Directory: %s\n", records[i].directory);
				printf("      FileIdentifier: 0x%x\n", records[i].fileIdentifier);
				printf("\n");
			}
		}
		for (i = 0; i < recordcount; i++) {
			if (records[i].filename[0] != 0) {
				printf("   File: %s\\%s\n", records[i].directory, records[i].filename);
				printf("      FileIdentifier: 0x%x\n", records[i].fileIdentifier);
				printf("      DataObjectIdentifier: 0x%x\n", records[i].dataObjectIdentifier);
				size = sizeof(buffer);
				r = gids_get_DO(card, records[i].fileIdentifier, records[i].dataObjectIdentifier, buffer, &size);
				if (r < 0) {
					printf("      unable to read the file: %s\n", sc_strerror(r));
				} else {
					printf("      Size: %"SC_FORMAT_LEN_SIZE_T"u\n", size);
				}
				printf("\n");
				if (strcmp(records[i].directory, "mscp") == 0 && strcmp(records[i].filename, "cmapfile") == 0 ) {
					cmapfilesize = size;
					memcpy(cmapfile, buffer, size);
				}
			}
		}
		printf("Dumping containers:\n");
		if (cmapfilesize == sizeof(cmapfile)) {
			printf("Unable to find the container file (mscp\\cmapfile)\n");
		} else {
			PCONTAINER_MAP_RECORD cmaprecords = (PCONTAINER_MAP_RECORD) cmapfile;
			int cmaprecordnum = (cmapfilesize / sizeof(CONTAINER_MAP_RECORD));
			int keymaprecordnum = -1;
			struct gids_keymap_record* keymaprecord = ((struct gids_keymap_record*)(keymap +1));
			if (cmaprecordnum == 0) {
				printf("   no container found\n");
			} else {
				r = gids_get_DO(card, KEYMAP_FI, KEYMAP_DO, keymap, &keymapsize);
				if (r < 0) {
					printf("   the keymap couldn't be found\n");
				} else {
					keymaprecordnum = (keymapsize - 1) / sizeof(struct gids_keymap_record);
				}
				for (i = 0; i < cmaprecordnum; i++) {
					printf("   container:                  %d\n", i);
					wprintf(L"      guid:                    %ls\n", cmaprecords[i].wszGuid);
					printf("      bFlags:                  ");
					if (cmaprecords[i].bFlags & CONTAINER_MAP_VALID_CONTAINER) {
						printf("Valid container");
						if (cmaprecords[i].bFlags & CONTAINER_MAP_DEFAULT_CONTAINER) {
							printf(",Default container");
						}
					} else {
						printf("Empty container");
					}
					printf("\n");
					printf("      wSigKeySizeBits:         %d\n", cmaprecords[i].wSigKeySizeBits);
					printf("      wKeyExchangeKeySizeBits: %d\n", cmaprecords[i].wKeyExchangeKeySizeBits);
					if (i < keymaprecordnum) {
						printf("      key info:\n");
						printf("         state:                %d\n", keymaprecord[i].state);
						printf("         algid:                %d\n", keymaprecord[i].algid);
						printf("         keyref:               0x%x\n", keymaprecord[i].keyref);
						printf("         key type:             ");
						switch(keymaprecord[i].keytype) {
						case 0:
							printf("none\n");
							break;
						case 0x9C:
							printf("signature\n");
							break;
						case 0x9A:
							printf("signature + decryption\n");
							break;
						default:
							printf("unknown\n");
							break;
						}
					}
					printf("\n");
				}
			}
		}
	} else {
		printf("No file system found\n");
	}
	return SC_SUCCESS;
}

int main(int argc, char * argv[])
{
	int err = 0, r, c, long_optind = 0;
	int action_count = 0;
	int do_initialize = 0;
	int do_unblock = 0;
	int do_change_admin = 0;
	sc_path_t path;
	const char *opt_so_pin = NULL;
	const char *opt_pin = NULL;
	const char *opt_serial_number = NULL;
	const char *opt_new_key = NULL;
	sc_context_param_t ctx_param;
	sc_context_t *ctx = NULL;
	sc_card_t *card = NULL;

	while (1) {
		c = getopt_long(argc, argv, "XUCr:wv", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case 'X':
			do_initialize = 1;
			action_count++;
			break;
		case OPT_SO_PIN:
			util_get_pin(optarg, &opt_so_pin);
			break;
		case OPT_PIN:
			util_get_pin(optarg, &opt_pin);
			break;
		case OPT_SERIAL_NUMBER:
			util_get_pin(optarg, &opt_serial_number);
			break;
		case OPT_NEW_KEY:
			util_get_pin(optarg, &opt_new_key);
			break;
		case 'U':
			do_unblock = 1;
			action_count++;
			break;
		case 'C':
			do_change_admin = 1;
			action_count++;
			break;
		case 'r':
			opt_reader = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			opt_wait = 1;
			break;
		}
	}


	/* OpenSSL magic */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	OPENSSL_config(NULL);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
		| OPENSSL_INIT_ADD_ALL_CIPHERS
		| OPENSSL_INIT_ADD_ALL_DIGESTS,
               NULL);
#else
	/* OpenSSL magic */
	OPENSSL_malloc_init();

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
#endif

	memset(&ctx_param, 0, sizeof(sc_context_param_t));
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		exit(1);
	}

	r = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	if (r != SC_SUCCESS) {
		if (r < 0) {
			fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(err));
		}
		goto end;
	}

	sc_path_set(&path, SC_FILE_TYPE_WORKING_EF, gids_aid.value, gids_aid.len, 0, 0);
	r = sc_select_file(card, &path, NULL);

	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to select application: %s\n", sc_strerror(r));
		goto fail;
	}

	if (do_initialize && initialize(card, opt_so_pin, opt_pin, opt_serial_number))
		goto fail;

	if (do_unblock && unblock(card, opt_so_pin, opt_pin))
		goto fail;

	if (do_change_admin && changeAdminKey(card, opt_so_pin, opt_new_key))
		goto fail;

	if (action_count == 0) {
		print_info(card);
	}

	err = 0;
	goto end;
fail:
	err = 1;
end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	sc_release_context(ctx);

	ERR_print_errors_fp(stderr);
	return err;
}
