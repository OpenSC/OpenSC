/*
 * sc-hsm-tool.c: SmartCard-HSM Management Tool
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2012 www.CardContact.de, Andreas Schwier, Minden, Germany
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

/* Requires openssl for dkek import */
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>


#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/asn1.h"
#include "libopensc/card-sc-hsm.h"
#include "util.h"

static const char *app_name = "sc-hsm-tool";

static const char magic[] = "Salted__";

static struct sc_aid sc_hsm_aid = { { 0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01 }, 11 };

static int	opt_wait = 0;
static char *opt_reader;
static int	verbose = 0;

// Some reasonable maximums
#define MAX_CERT		4096
#define MAX_PRKD		256
#define MAX_KEY			512
#define MAX_WRAPPED_KEY	(MAX_CERT + MAX_PRKD + MAX_KEY)

enum {
	OPT_SO_PIN = 0x100,
	OPT_PIN,
	OPT_RETRY,
	OPT_PASSWORD
};

static const struct option options[] = {
	{ "initialize",			0, NULL,		'X' },
	{ "create-dkek-share",	1, NULL,		'C' },
	{ "import-dkek-share",	1, NULL,		'I' },
	{ "wrap-key",			1, NULL,		'W' },
	{ "unwrap-key",			1, NULL,		'U' },
	{ "dkek-shares",		1, NULL,		's' },
	{ "so-pin",				1, NULL,		OPT_SO_PIN },
	{ "pin",				1, NULL,		OPT_PIN },
	{ "pin-retry",			1, NULL,		OPT_RETRY },
	{ "password",			1, NULL,		OPT_PASSWORD },
	{ "key-reference",		1, NULL,		'i' },
	{ "force",				0, NULL,		'f' },
	{ "reader",				1, NULL,		'r' },
	{ "wait",				0, NULL,		'w' },
	{ "verbose",			0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Initialize token",
	"Create DKEK key share and save to <filename>",
	"Import DKEK key share <filename>",
	"Wrap key and save to <filename>",
	"Unwrap key read from <filename>",
	"Number of DKEK shares [No DKEK]",
	"Define security officer PIN (SO-PIN)",
	"Define user PIN",
	"Define user PIN retry counter",
	"Define password for DKEK share",
	"Key reference for key wrap/unwrap",
	"Force replacement of key and certificate",
	"Uses reader number <arg> [0]",
	"Wait for a card to be inserted",
	"Verbose operation. Use several times to enable debug output.",
};


static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;




static void print_dkek_info(sc_cardctl_sc_hsm_dkek_t *dkekinfo) {
	printf("DKEK shares          : %d\n", dkekinfo->dkek_shares);
	if (dkekinfo->outstanding_shares > 0) {
		printf("DKEK import pending, %d share(s) still missing\n",dkekinfo->outstanding_shares);
	} else {
		printf("DKEK key check value : ");
		util_hex_dump(stdout, dkekinfo->key_check_value, 8, NULL);
		printf("\n");
	}
}



static void print_info(sc_card_t *card, sc_file_t *file)
{
	int r, tries_left;
	struct sc_pin_cmd_data data;
	sc_cardctl_sc_hsm_dkek_t dkekinfo;

	u8 major, minor;

	major = file->prop_attr[file->prop_attr_len - 2];
	minor = file->prop_attr[file->prop_attr_len - 1];
	printf("Version              : %d.%d\n", (int)major, (int)minor);

	/* Try to update PIN info from card */
	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_GET_INFO;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ID_USER_PIN;

	r = sc_pin_cmd(card, &data, &tries_left);

	if (r == SC_ERROR_REF_DATA_NOT_USABLE) {
		printf("SmartCard-HSM has never been initialized\n");
	} else {
		if (tries_left == 0) {
			printf("User PIN locked\n");
		} else {
			printf("User PIN tries left  : %d\n", tries_left);
		}
	}

	memset(&dkekinfo, 0, sizeof(dkekinfo));

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, (void *)&dkekinfo);

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		return;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, *) failed with %s\n", sc_strerror(r));
	}
	print_dkek_info(&dkekinfo);
}



static void initialize(sc_card_t *card, const char *so_pin, const char *user_pin, int retry_counter, int dkek_shares)
{
	sc_cardctl_sc_hsm_init_param_t param;
	size_t len;
	char *_so_pin = NULL, *_user_pin = NULL;
	int r;

	if (so_pin == NULL) {
		printf("Enter SO-PIN : ");
		util_getpass(&_so_pin, NULL, stdin);
		printf("\n");
	} else {
		_so_pin = (char *)so_pin;
	}

	if (user_pin == NULL) {
		printf("Enter initial User-PIN : ");
		util_getpass(&_user_pin, NULL, stdin);
		printf("\n");
	} else {
		_user_pin = (char *)user_pin;
	}

	len = sizeof(param.init_code);
	r = sc_hex_to_bin(_so_pin, param.init_code, &len);
	if (r < 0) {
		fprintf(stderr, "Error decoding initialization code (%s)\n", sc_strerror(r));
		return;
	}

	if (len != 8) {
		fprintf(stderr, "Initialization code must contain 8 bytes\n");
		return;
	}

	param.user_pin_len = strlen(_user_pin);
	param.user_pin = (u8 *)_user_pin;

	param.user_pin_retry_counter = (u8)retry_counter;

	param.options[0] = 0x00;
	param.options[1] = 0x01;

	param.dkek_shares = (char)dkek_shares;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_INITIALIZE, (void *)&param);
	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_INITIALIZE, *) failed with %s\n", sc_strerror(r));
	}
}



static void import_dkek_share(sc_card_t *card, const char *inf, int iter, char *password)
{
	sc_cardctl_sc_hsm_dkek_t dkekinfo;
	EVP_CIPHER_CTX ctx;
	FILE *in = NULL;
	u8 filebuff[64],key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH],outbuff[64];
	char *pwd = NULL;
	int r, outlen;

	in = fopen(inf, "rb");

	if (in == NULL) {
		perror(inf);
		return;
	}

	if (fread(filebuff, 1, sizeof(filebuff), in) != sizeof(filebuff)) {
		perror(inf);
		return;
	}

	fclose(in);

	if (memcmp(filebuff, magic, sizeof(magic) - 1)) {
		printf("File %s is not a DKEK share\n", inf);
		return;
	}

	if (password == NULL) {
		printf("Enter password to decrypt DKEK share : ");
		util_getpass(&pwd, NULL, stdin);
		printf("\n");
	} else {
		pwd = password;
	}

	printf("Deciphering DKEK share, please wait...\n");
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), filebuff + 8, (u8 *)pwd, strlen(pwd), iter, key, iv);
	OPENSSL_cleanse(pwd, strlen(pwd));

	if (password == NULL) {
		free(pwd);
	}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
	if (!EVP_DecryptUpdate(&ctx, outbuff, &outlen, filebuff + 16, sizeof(filebuff) - 16)) {
		printf("Error decrypting DKEK share. Password correct ?\n");
		return;
	}

	if (!EVP_DecryptFinal_ex(&ctx, outbuff + outlen, &r)) {
		printf("Error decrypting DKEK share. Password correct ?\n");
		return;
	}

	memset(&dkekinfo, 0, sizeof(dkekinfo));
	memcpy(dkekinfo.dkek_share, outbuff, sizeof(dkekinfo.dkek_share));
	dkekinfo.importShare = 1;

	OPENSSL_cleanse(outbuff, sizeof(outbuff));

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, (void *)&dkekinfo);

	OPENSSL_cleanse(&dkekinfo.dkek_share, sizeof(dkekinfo.dkek_share));
	EVP_CIPHER_CTX_cleanup(&ctx);

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		return;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE, *) failed with %s\n", sc_strerror(r));
		return;
	}
	printf("DKEK share imported\n");
	print_dkek_info(&dkekinfo);
}



static void create_dkek_share(sc_card_t *card, const char *outf, int iter, char *password)
{
	EVP_CIPHER_CTX ctx;
	FILE *out = NULL;
	u8 filebuff[64],key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH],outbuff[64];
	u8 dkek_share[32];
	char *pwd = NULL;
	int r, outlen;

	if (password == NULL) {
		char *refpwd = NULL;

		printf("\nThe DKEK share will be enciphered using a key derived from a user supplied password.\n");
		printf("The security of the DKEK share relies on a well chosen and sufficiently long password.\n");
		printf("The recommended length is more than 10 characters, which are mixed letters, numbers and\n");
		printf("symbols.\n\n");
		printf("Please keep the generated DKEK share file in a save location. We also recommend to keep a\n");
		printf("paper printout, in case the electronic version becomes unavailable. A printable version\n");
		printf("of the file can be generated using \"openssl base64 -in <filename>\".\n");
		while(1) {
			printf("Enter password to encrypt DKEK share : ");
			util_getpass(&pwd, NULL, stdin);
			printf("\n");
			if (strlen(pwd) < 6) {
				printf("Password way to short. Please retry.\n");
				continue;
			}
			printf("Please retype password to confirm : ");
			util_getpass(&refpwd, NULL, stdin);
			printf("\n");
			if (strcmp(pwd, refpwd)) {
				printf("Passwords do not match. Please retry.\n");
				continue;
			}
			break;
		}
		OPENSSL_cleanse(refpwd, strlen(refpwd));
		free(refpwd);
	} else {
		pwd = password;
	}

	memcpy(filebuff, magic, sizeof(magic) - 1);

	r = sc_get_challenge(card, filebuff + 8, 8);
	if (r < 0) {
		printf("Error generating random number failed with ", sc_strerror(r));
		return;
	}

	printf("Enciphering DKEK share, please wait...\n");
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), filebuff + 8, (u8 *)pwd, strlen(pwd), iter, key, iv);

	if (password == NULL) {
		OPENSSL_cleanse(pwd, strlen(pwd));
		free(pwd);
	}

	r = sc_get_challenge(card, dkek_share, sizeof(dkek_share));
	if (r < 0) {
		printf("Error generating random number failed with ", sc_strerror(r));
		return;
	}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
	if (!EVP_EncryptUpdate(&ctx, filebuff + 16, &outlen, dkek_share, sizeof(dkek_share))) {
		printf("Error encrypting DKEK share\n");
		return;
	}

	if (!EVP_EncryptFinal_ex(&ctx, filebuff + 16 + outlen, &r)) {
		printf("Error encrypting DKEK share\n");
		return;
	}

	out = fopen(outf, "wb");

	if (out == NULL) {
		perror(outf);
		return;
	}

	if (fwrite(filebuff, 1, sizeof(filebuff), out) != sizeof(filebuff)) {
		perror(outf);
		return;
	}

	fclose(out);

	OPENSSL_cleanse(filebuff, sizeof(filebuff));
	EVP_CIPHER_CTX_cleanup(&ctx);

	printf("DKEK share created and saved to %s\n", outf);
}



static size_t determineLength(const u8 *tlv, size_t buflen)
{
	const u8 *ptr = tlv;
	unsigned int cla,tag;
	size_t len;

	if (sc_asn1_read_tag(&ptr, buflen, &cla, &tag, &len) != SC_SUCCESS) {
		return 0;
	}

	return len + (ptr - tlv);
}



static void wrap_key(sc_card_t *card, u8 keyid, const char *outf, const char *pin)
{
	sc_cardctl_sc_hsm_wrapped_key_t wrapped_key;
	struct sc_pin_cmd_data data;
	sc_file_t *file = NULL;
	sc_path_t path;
	FILE *out = NULL;
	u8 fid[2];
	u8 ef_prkd[MAX_PRKD];
	u8 ef_cert[MAX_CERT];
	u8 keyblob[MAX_WRAPPED_KEY];
	u8 *key;
	u8 *ptr;
	char *lpin = NULL;
	size_t key_len;
	int r, ef_prkd_len, ef_cert_len;

	if (pin == NULL) {
		printf("Enter User PIN : ");
		util_getpass(&lpin, NULL, stdin);
		printf("\n");
	} else {
		lpin = (u8 *)pin;
	}

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ID_USER_PIN;
	data.pin1.data = lpin;
	data.pin1.len = strlen(lpin);

	r = sc_pin_cmd(card, &data, NULL);

	if (r < 0) {
		fprintf(stderr, "PIN verification failed with %s\n", sc_strerror(r));
		return;
	}

	if (pin == NULL) {
		free(lpin);
	}

	wrapped_key.key_id = keyid;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_WRAP_KEY, (void *)&wrapped_key);

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		return;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_WRAP_KEY, *) failed with %s\n", sc_strerror(r));
		return;
	}


	fid[0] = PRKD_PREFIX;
	fid[1] = keyid;
	ef_prkd_len = 0;

	/* Try to select a related EF containing the PKCS#15 description of the key */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, NULL);

	if (r == SC_SUCCESS) {
		ef_prkd_len = sc_read_binary(card, 0, ef_prkd, sizeof(ef_prkd), 0);

		if (ef_prkd_len < 0) {
			fprintf(stderr, "Error reading PRKD file %s. Skipping.\n", sc_strerror(ef_prkd_len));
			ef_prkd_len = 0;
		} else {
			ef_prkd_len = determineLength(ef_prkd, ef_prkd_len);
		}
	}

	fid[0] = EE_CERTIFICATE_PREFIX;
	fid[1] = keyid;
	ef_cert_len = 0;

	/* Try to select a related EF containing the certificate for the key */
	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
	r = sc_select_file(card, &path, NULL);

	if (r == SC_SUCCESS) {
		ef_cert_len = sc_read_binary(card, 0, ef_cert, sizeof(ef_cert), 0);

		if (ef_cert_len < 0) {
			fprintf(stderr, "Error reading certificate %s. Skipping\n", sc_strerror(ef_cert_len));
			ef_cert_len = 0;
		} else {
			ef_cert_len = determineLength(ef_cert, ef_cert_len);
		}
	}


	ptr = keyblob;

	// Encode key in octet string object
	sc_asn1_write_element(card->ctx, SC_ASN1_OCTET_STRING,
			wrapped_key.wrapped_key, wrapped_key.wrapped_key_length,
			&key, &key_len);

	memcpy(ptr, key, key_len);
	ptr += key_len;
	free(key);

	// Add private key description
	if (ef_prkd_len > 0) {
		memcpy(ptr, ef_prkd, ef_prkd_len);
		ptr += ef_prkd_len;
	}

	// Add certificate
	if (ef_cert_len > 0) {
		memcpy(ptr, ef_cert, ef_cert_len);
		ptr += ef_cert_len;
	}

	// Encode key in octet string object
	sc_asn1_write_element(card->ctx, SC_ASN1_SEQUENCE|SC_ASN1_CONS,
			keyblob, ptr - keyblob,
			&key, &key_len);

	out = fopen(outf, "wb");

	if (out == NULL) {
		perror(outf);
		free(key);
		return;
	}

	if (fwrite(key, 1, key_len, out) != key_len) {
		perror(outf);
		free(key);
		return;
	}

	free(key);
	fclose(out);
}



static int update_ef(sc_card_t *card, u8 prefix, u8 id, int erase, const u8 *buf, size_t buflen)
{
	sc_file_t *file = NULL;
	sc_file_t newfile;
	sc_path_t path;
	u8 fid[2];
	int r;

	fid[0] = prefix;
	fid[1] = id;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, -1);

	r = sc_select_file(card, &path, NULL);

	if ((r == SC_SUCCESS) && erase) {
		r = sc_delete_file(card, &path);
		r = SC_ERROR_FILE_NOT_FOUND;
	}

	if (r == SC_ERROR_FILE_NOT_FOUND) {
		file = sc_file_new();
		file->id = (path.value[0] << 8) | path.value[1];
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = (size_t) 0;
		file->status = SC_FILE_STATUS_ACTIVATED;
		r = sc_create_file(card, file);
		sc_file_free(file);
		if (r < 0) {
			return r;
		}
	}

	r = sc_update_binary(card, 0, buf, buflen, 0);
	return r;
}



static void unwrap_key(sc_card_t *card, u8 keyid, const char *inf, const char *pin, int force)
{
	sc_cardctl_sc_hsm_wrapped_key_t wrapped_key;
	struct sc_pin_cmd_data data;
	u8 keyblob[MAX_WRAPPED_KEY];
	const u8 *ptr,*prkd,*cert;
	FILE *in = NULL;
	sc_path_t path;
	u8 fid[2];
	char *lpin = NULL;
	unsigned int cla, tag;
	int r, keybloblen;
	size_t len, olen, prkd_len, cert_len;

	in = fopen(inf, "rb");

	if (in == NULL) {
		perror(inf);
		return;
	}

	if ((keybloblen = fread(keyblob, 1, sizeof(keyblob), in)) < 0) {
		perror(inf);
		return;
	}

	fclose(in);

	ptr = keyblob;
	if ((sc_asn1_read_tag(&ptr, keybloblen, &cla, &tag, &len) != SC_SUCCESS) ||
			((cla & SC_ASN1_TAG_CONSTRUCTED) != SC_ASN1_TAG_CONSTRUCTED) ||
			((tag != SC_ASN1_TAG_SEQUENCE)) ){
		fprintf(stderr, "Invalid wrapped key format (Outer sequence).\n");
		return;
	}

	if ((sc_asn1_read_tag(&ptr, len, &cla, &tag, &olen) != SC_SUCCESS) ||
			(cla & SC_ASN1_TAG_CONSTRUCTED) ||
			((tag != SC_ASN1_TAG_OCTET_STRING)) ){
		fprintf(stderr, "Invalid wrapped key format (Key binary).\n");
		return;
	}

	wrapped_key.wrapped_key = (u8 *)ptr;
	wrapped_key.wrapped_key_length = olen;

	ptr += olen;
	prkd = ptr;
	prkd_len = determineLength(ptr, keybloblen - (ptr - keyblob));

	ptr += prkd_len;
	cert = ptr;
	cert_len = determineLength(ptr, keybloblen - (ptr - keyblob));

	printf("Wrapped key contains:\n");
	printf("  Key blob\n");
	if (prkd_len > 0) {
		printf("  Private Key Description (PRKD)\n");
	}
	if (cert_len > 0) {
		printf("  Certificate\n");
	}

	if ((prkd_len > 0) && !force) {
		fid[0] = PRKD_PREFIX;
		fid[1] = keyid;

		/* Try to select a related EF containing the PKCS#15 description of the key */
		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
		r = sc_select_file(card, &path, NULL);

		if (r == SC_SUCCESS) {
			fprintf(stderr, "Found existing private key description in EF with fid %02x%02x. Please remove key first, select unused key reference or use --force.\n", fid[0], fid[1]);
			return;
		}
	}

	if ((cert_len > 0) && !force) {
		fid[0] = EE_CERTIFICATE_PREFIX;
		fid[1] = keyid;

		/* Try to select a related EF containing the certificate */
		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
		r = sc_select_file(card, &path, NULL);

		if (r == SC_SUCCESS) {
			fprintf(stderr, "Found existing certificate in EF with fid %02x%02x. Please remove certificate first, select unused key reference or use --force.\n", fid[0], fid[1]);
			return;
		}
	}

	if (pin == NULL) {
		printf("Enter User PIN : ");
		util_getpass(&lpin, NULL, stdin);
		printf("\n");
	} else {
		lpin = (u8 *)pin;
	}

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ID_USER_PIN;
	data.pin1.data = lpin;
	data.pin1.len = strlen(lpin);

	r = sc_pin_cmd(card, &data, NULL);

	if (r < 0) {
		fprintf(stderr, "PIN verification failed with %s\n", sc_strerror(r));
		return;
	}

	if (pin == NULL) {
		free(lpin);
	}

	if (force) {
		fid[0] = KEY_PREFIX;
		fid[1] = keyid;

		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, -1);
		sc_delete_file(card, &path);
	}

	wrapped_key.key_id = keyid;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_UNWRAP_KEY, (void *)&wrapped_key);

	if (r == SC_ERROR_INS_NOT_SUPPORTED) {			// Not supported or not initialized for key shares
		return;
	}

	if (r < 0) {
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_SC_HSM_UNWRAP_KEY, *) failed with %s\n", sc_strerror(r));
		return;
	}

	if (prkd_len > 0) {
		r = update_ef(card, PRKD_PREFIX, keyid, force, prkd, prkd_len);

		if (r < 0) {
			fprintf(stderr, "Updating private key description failed with %s\n", sc_strerror(r));
			return;
		}
	}

	if (cert_len > 0) {
		r = update_ef(card, EE_CERTIFICATE_PREFIX, keyid, force, cert, cert_len);

		if (r < 0) {
			fprintf(stderr, "Updating certificate failed with %s\n", sc_strerror(r));
			return;
		}
	}

	printf("Key successfully imported\n");
}



int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int action_count = 0;
	int do_initialize = 0;
	int do_import_dkek_share = 0;
	int do_create_dkek_share = 0;
	int do_wrap_key = 0;
	int do_unwrap_key = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	const char *opt_so_pin = NULL;
	const char *opt_pin = NULL;
	const char *opt_filename = NULL;
	char *opt_password = NULL;
	int opt_retry_counter = 3;
	int opt_dkek_shares = -1;
	int opt_key_reference = -1;
	int opt_force = 0;
	int opt_iter = 10000000;
	sc_context_param_t ctx_param;

	setbuf(stderr, NULL);
	setbuf(stdout, NULL);

	while (1) {
		c = getopt_long(argc, argv, "XC:I:W:U:s:i:fr:wv", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case 'X':
			do_initialize = 1;
			action_count++;
			break;
		case 'C':
			do_create_dkek_share = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'I':
			do_import_dkek_share = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'W':
			do_wrap_key = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case 'U':
			do_unwrap_key = 1;
			opt_filename = optarg;
			action_count++;
			break;
		case OPT_PASSWORD:
			opt_password = optarg;
			break;
		case OPT_SO_PIN:
			opt_so_pin = optarg;
			break;
		case OPT_PIN:
			opt_pin = optarg;
			break;
		case OPT_RETRY:
			opt_retry_counter = atol(optarg);
			break;
		case 's':
			opt_dkek_shares = atol(optarg);
			break;
		case 'f':
			opt_force = 1;
			break;
		case 'i':
			opt_key_reference = atol(optarg);
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

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	memset(&ctx_param, 0, sizeof(sc_context_param_t));
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	/* Only change if not in opensc.conf */
	if (verbose > 1 && ctx->debug == 0) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	err = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	if (err)
		goto end;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, sc_hsm_aid.value, sc_hsm_aid.len, 0, 0);
	r = sc_select_file(card, &path, &file);

	if (do_initialize) {
		initialize(card, opt_so_pin, opt_pin, opt_retry_counter, opt_dkek_shares);
	}

	if (do_create_dkek_share) {
		create_dkek_share(card, opt_filename, opt_iter, opt_password);
	}

	if (do_import_dkek_share) {
		import_dkek_share(card, opt_filename, opt_iter, opt_password);
	}

	if (do_wrap_key) {
		wrap_key(card, opt_key_reference, opt_filename, opt_pin);
	}

	if (do_unwrap_key) {
		unwrap_key(card, opt_key_reference, opt_filename, opt_pin, opt_force);
	}

	if (action_count == 0) {
		print_info(card, file);
	}

end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);

	ERR_print_errors_fp(stderr);
	return err;
}
