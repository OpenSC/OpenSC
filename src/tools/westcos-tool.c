/*
 * westcos-tool.c: tool for westcos card
 *
 * Copyright (C) 2009 francois.leblanc@cev-sa.com
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
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include "libopensc/sc-ossl-compat.h"
#include "libopensc/opensc.h"
#include "libopensc/errors.h"
#include "libopensc/pkcs15.h"
#include "libopensc/cardctl.h"

#include "util.h"

static const char *app_name = "westcos-tool";

static const struct option options[] = {
	{ "reader", 1, NULL, 'r' },
	{ "wait", 0, NULL, 'w' },
	{ "generate-key", 0, NULL, 'g' },
	{ "overwrite-key", 0, NULL, 'o' },
	{ "key-length", 1, NULL, 'l' },
	{ "install-pin", 0, NULL, 'i' },
	{ "pin-value", 1, NULL, 'x' },
	{ "puk-value", 1, NULL, 'y' },
	{ "change-pin", 0, NULL, 'n' },
	{ "unblock-pin", 0, NULL, 'u' },
	{ "certificate", 1, NULL, 't' },
	{ "finalize", 0, NULL, 'f' },
	{ "read-file", 1, NULL, 'j' },
	{ "write-file", 1, NULL, 'k' },
	{ "help", 0, NULL, 'h' },
	{ "verbose", 0, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Wait for card insertion",
	"Generate key 1536 default",
	"Overwrite key if already exist",
	"Key length <arg> [512,1024,1536]",
	"Install pin",
	"Pin value <arg>",
	"Puk value <arg>",
	"Change pin (new pin in puk value)",
	"Unblock pin",
	"Write certificate <arg> (in pem format)",
	"Finalize card(!!! MANDATORY FOR SECURITY !!!)",
	"Read file <arg>",
	"Write file <arg> (ex 0002 write file 0002 to 0002)",
	"This message",
	"Verbose operation. Use several times to enable debug output."
};


static int opt_wait = 0, verbose = 0;
static const char *opt_driver = NULL;
static const char *opt_reader = NULL;

static int finalize = 0;
static int install_pin = 0;
static int overwrite = 0;

static const char *pin = NULL;
static const char *puk = NULL;
static char *cert = NULL;

static int keylen = 0;

static int new_pin = 0;
static int unlock = 0;

static char *get_filename = NULL;
static char *put_filename = NULL;

static int do_convert_bignum(sc_pkcs15_bignum_t *dst, const BIGNUM *src)
{
	if (src == 0) return 0;
	dst->len = BN_num_bytes(src);
	dst->data = malloc(dst->len);
	BN_bn2bin(src, dst->data);
	return 1;
}

static int	charge = 0;
static void print_openssl_error(void)
{
	long r;

	if (!charge)
	{
		ERR_load_crypto_strings();
		charge = 1;
	}

	while ((r = ERR_get_error()) != 0)
		printf("%s\n", ERR_error_string(r, NULL));
}

static int verify_pin(sc_card_t *card, int pin_reference, const char *pin_value)
{
	int r, tries_left = -1;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;

	data.pin_type = SC_AC_CHV;

	data.pin_reference = pin_reference;

	data.flags = SC_PIN_CMD_NEED_PADDING;

	if (card->reader->capabilities & SC_READER_CAP_PIN_PAD)
	{
		printf("Please enter PIN on the reader's pin pad.\n");
		data.pin1.prompt = "Please enter PIN";
		data.flags |= SC_PIN_CMD_USE_PINPAD;
	}
	else
	{
		if(pin_value == NULL)
		{
			return SC_ERROR_INVALID_ARGUMENTS;
		}

		data.pin1.data = (u8*)pin_value;
		data.pin1.len = strlen(pin_value);
	}

	r = sc_pin_cmd(card, &data, &tries_left);

	if (r)
	{
		if (r == SC_ERROR_PIN_CODE_INCORRECT)
		{
			if (tries_left >= 0)
				printf("Error %d attempts left.\n", tries_left);
			else
				printf("Wrong pin.\n");
		}
		else
			printf("The pin can be verify: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Pin correct.\n");
	return 0;
}

static int change_pin(sc_card_t *card,
		int pin_reference,
		const char *pin_value1,
		const char *pin_value2)
{
	int r, tries_left = -1;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_CHANGE;

	data.pin_type = SC_AC_CHV;

	data.pin_reference = pin_reference;

	data.flags = SC_PIN_CMD_NEED_PADDING;

	if (card->reader->capabilities & SC_READER_CAP_PIN_PAD)
	{
		printf("Please enter PIN on the reader's pin pad.\n");
		data.pin1.prompt = "Please enter PIN";
		data.flags |= SC_PIN_CMD_USE_PINPAD;
	}
	else
	{
		if(pin_value1 == NULL || pin_value2 == NULL)
		{
			return SC_ERROR_INVALID_ARGUMENTS;
		}

		data.pin1.data = (u8*)pin_value1;
		data.pin1.len = strlen(pin_value1);

		data.pin2.data = (u8*)pin_value2;
		data.pin2.len = strlen(pin_value2);

	}

	r = sc_pin_cmd(card, &data, &tries_left);

	if (r)
	{
		if (r == SC_ERROR_PIN_CODE_INCORRECT)
		{
			if (tries_left >= 0)
				printf("Error %d attempts left.\n", tries_left);
			else
				printf("Wrong pin.\n");
		}
		else
			printf("Can't change pin: %s\n",
				sc_strerror(r));
		return -1;
	}
	printf("Pin changed.\n");
	return 0;
}

static int unlock_pin(sc_card_t *card,
			int pin_reference,
			const char *puk_value,
			const char *pin_value)
{
	int r, tries_left = -1;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_UNBLOCK;

	data.pin_type = SC_AC_CHV;

	data.pin_reference = pin_reference;

	data.flags = SC_PIN_CMD_NEED_PADDING;

	if (card->reader->capabilities & SC_READER_CAP_PIN_PAD)
	{
		printf("Please enter PIN on the reader's pin pad.\n");
		data.pin1.prompt = "Please enter PIN";
		data.flags |= SC_PIN_CMD_USE_PINPAD;
	}
	else
	{
		if(pin == NULL || puk == NULL)
		{
			return SC_ERROR_INVALID_ARGUMENTS;
		}

		data.pin1.data = (u8*)puk_value;
		data.pin1.len = strlen(puk_value);

		data.pin2.data = (u8*)pin_value;
		data.pin2.len = strlen(pin_value);

	}

	r = sc_pin_cmd(card, &data, &tries_left);

	if (r)
	{
		if (r == SC_ERROR_PIN_CODE_INCORRECT)
		{
			if (tries_left >= 0)
				printf("Error %d attempts left.\n", tries_left);
			else
				printf("Wrong pin.\n");
		}
		else
			printf("Can't unblock pin: %s\n",
				sc_strerror(r));
		return -1;
	}
	printf("Unlock pin.\n");
	return 0;
}

static int cert2der(X509 *cert, u8 **value)
{
	int len;
	u8 *p;
	len = i2d_X509(cert, NULL);
	p = *value = malloc(len);
	i2d_X509(cert, &p);
	return len;
}

static int create_file_cert(sc_card_t *card)
{
	int r;
	int size = 0;
	sc_path_t path;
	sc_file_t *file = NULL;

	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, &file);
	if(r) goto out;

	if(file)
	{
		size = (file->size) - 32;
		sc_file_free(file);
		file = NULL;
	} else {
		size = 2048;
	}

	sc_format_path("0002", &path);
	r = sc_select_file(card, &path, NULL);
	if(r)
	{
		if(r != SC_ERROR_FILE_NOT_FOUND) goto out;

		file = sc_file_new();
		if(file == NULL)
		{
			printf("Memory error.\n");
			goto out;
		}

		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->shareable = 0;

		file->size = size;

		r = sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_NONE, 0);
		if(r) goto out;
		r = sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, SC_AC_CHV, 0);
		if(r) goto out;
		r = sc_file_add_acl_entry(file, SC_AC_OP_ERASE, SC_AC_CHV, 0);
		if(r) goto out;

		file->path = path;
		r = sc_create_file(card, file);
		if(r) goto out;
	}

out:
	if(file)
		sc_file_free(file);

	return r;
}

int main(int argc, char *argv[])
{
	int r, c, long_optind = 0;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	sc_context_t *ctx = NULL;
	sc_file_t *file = NULL;
	sc_path_t path;
	RSA	*rsa = NULL;
	BIGNUM	*bn = NULL;
	BIO	*mem = NULL;

	while (1)
	{
		c = getopt_long(argc, argv, "r:wgol:ix:y:nut:fj:k:hv", \
			options, &long_optind);
		if (c == -1)
			break;
		if (c == '?' || c == 'h')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c)
		{
			case 'r':
				opt_reader = optarg;
				break;
			case 'w':
				opt_wait = 1;
				break;
			case 'g':
				if(keylen == 0) keylen = 1536;
				break;
			case 'o':
				overwrite = 1;
				break;
			case 'l':
				keylen = atoi(optarg);
				break;
			case 'i':
				install_pin = 1;
				break;
			case 'x':
				util_get_pin(optarg, &pin);
				break;
			case 'y':
				util_get_pin(optarg, &puk);
				break;
			case 'n':
				new_pin = 1;
				break;
			case 'u':
				unlock = 1;
				break;
			case 't':
				cert = optarg;
				break;
			case 'f':
				finalize = 1;
				break;
			case 'j':
				get_filename = optarg;
				break;
			case 'k':
				put_filename = optarg;
				break;
			case 'v':
				verbose++;
				break;
		}
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = argv[0];

	r = sc_context_create(&ctx, &ctx_param);
	if (r)
	{
		printf("Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	if (verbose > 1) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	if (opt_driver != NULL)
	{
		r = sc_set_card_driver(ctx, opt_driver);
		if (r)
		{
			printf("Driver '%s' not found!\n", opt_driver);
			goto out;
		}
	}

	r = util_connect_card(ctx, &card, opt_reader, opt_wait, 0);
	if (r)
		goto out;

	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	if(r) goto out;

	if(install_pin)
	{
		sc_format_path("AAAA", &path);
		r = sc_select_file(card, &path, NULL);
		if(r)
		{
			if(r != SC_ERROR_FILE_NOT_FOUND) goto out;

			file = sc_file_new();
			if(file == NULL)
			{
				printf("Not enougth memory.\n");
				goto out;
			}

			file->type = SC_FILE_TYPE_INTERNAL_EF;
			file->ef_structure = SC_FILE_EF_TRANSPARENT;
			file->shareable = 0;

			file->id = 0xAAAA;
			file->size = 37;

			r = sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_NONE, 0);
			if(r) goto out;
			r = sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, SC_AC_NONE, 0);
			if(r) goto out;
			r = sc_file_add_acl_entry(file, SC_AC_OP_ERASE, SC_AC_NONE, 0);
			if(r) goto out;

			/* sc_format_path("3F00AAAA", &(file->path)); */
			file->path = path;
			r = sc_create_file(card, file);
			if(r) goto out;
		}

		if(pin != NULL)
		{
			sc_changekey_t ck;
			struct sc_pin_cmd_pin pin_cmd;
			int ret;

			memset(&pin_cmd, 0, sizeof(pin_cmd));
			memset(&ck, 0, sizeof(ck));

			memcpy(ck.key_template, "\x1e\x00\x00\x10", 4);

			pin_cmd.encoding = SC_PIN_ENCODING_GLP;
			pin_cmd.len = strlen(pin);
			pin_cmd.data = (u8*)pin;
			pin_cmd.max_length = 8;

			ret = sc_build_pin(ck.new_key.key_value,
				sizeof(ck.new_key.key_value), &pin_cmd, 1);
			if(ret < 0)
				goto out;

			ck.new_key.key_len = ret;
			r = sc_card_ctl(card, SC_CARDCTL_WESTCOS_CHANGE_KEY, &ck);
			if(r) goto out;
		}

		if(puk != NULL)
		{
			sc_changekey_t ck;
			struct sc_pin_cmd_pin puk_cmd;
			int ret;

			memset(&puk_cmd, 0, sizeof(puk_cmd));
			memset(&ck, 0, sizeof(ck));

			memcpy(ck.key_template, "\x1e\x00\x00\x20", 4);

			puk_cmd.encoding = SC_PIN_ENCODING_GLP;
			puk_cmd.len = strlen(puk);
			puk_cmd.data = (u8*)puk;
			puk_cmd.max_length = 8;

			ret = sc_build_pin(ck.new_key.key_value,
				sizeof(ck.new_key.key_value), &puk_cmd, 1);
			if(ret < 0)
				goto out;

			ck.new_key.key_len = ret;
			r = sc_card_ctl(card, SC_CARDCTL_WESTCOS_CHANGE_KEY, &ck);
			if(r) goto out;
		}
	}

	if(new_pin)
	{
		if(change_pin(card, 0, pin, puk))
			printf("Wrong pin.\n");
		goto out;
	}

	if(unlock)
	{
		if(unlock_pin(card, 0, puk, pin))
			printf("Error unblocking pin.\n");
		goto out;
	}

	printf("verify pin.\n");
	{
		if(verify_pin(card, 0, pin))
		{
			printf("Wrong pin.\n");
			goto out;
		}
	}

	if(keylen)
	{
		size_t lg;
		struct sc_pkcs15_pubkey key;
		struct sc_pkcs15_pubkey_rsa *dst = &(key.u.rsa);
		u8 *pdata;

		memset(&key, 0, sizeof(key));
		key.algorithm = SC_ALGORITHM_RSA;

		printf("Generate key of length %d.\n", keylen);

#if OPENSSL_VERSION_NUMBER>=0x00908000L
		rsa = RSA_new();
		bn = BN_new();
		mem = BIO_new(BIO_s_mem());

		if(rsa == NULL || bn == NULL || mem == NULL)
		{
			printf("Not enougth memory.\n");
			goto out;
		}

		if(!BN_set_word(bn, RSA_F4) ||
			!RSA_generate_key_ex(rsa, keylen, bn, NULL))
#else
		rsa = RSA_generate_key(keylen, RSA_F4, NULL, NULL);
		mem = BIO_new(BIO_s_mem());

		if(mem == NULL)
		{
			printf("Not enougth memory.\n");
			goto out;
		}

		if (!rsa)
#endif
		{
			printf("RSA_generate_key_ex return %ld\n", ERR_get_error());
			goto out;
		}

		RSA_set_method(rsa, RSA_PKCS1_OpenSSL());

		if(!i2d_RSAPrivateKey_bio(mem, rsa))
		{
			printf("i2d_RSAPrivateKey_bio return %ld\n", ERR_get_error());
			goto out;
		}

		lg = BIO_get_mem_data(mem, &pdata);

		sc_format_path("0001", &path);
		r = sc_select_file(card, &path, NULL);
		if(r)
		{
			if(r != SC_ERROR_FILE_NOT_FOUND) goto out;

			file = sc_file_new();
			if(file == NULL)
			{
				printf("Not enougth memory.\n");
				goto out;
			}

			file->type = SC_FILE_TYPE_WORKING_EF;
			file->ef_structure = SC_FILE_EF_TRANSPARENT;
			file->shareable = 0;

			file->size = ((lg/4)+1)*4;

			r = sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_CHV, 0);
			if(r) goto out;
			r = sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, SC_AC_CHV, 0);
			if(r) goto out;
			r = sc_file_add_acl_entry(file, SC_AC_OP_ERASE, SC_AC_CHV, 0);
			if(r) goto out;

			file->path = path;

			printf("File key creation %s, size %zd.\n", file->path.value,
				file->size);

			r = sc_create_file(card, file);
			if(r) goto out;
		}
		else
		{
			if(!overwrite)
			{
				printf("Key file already exist,"\
						" use -o to replace it.\n");
				goto out;
			}
		}

		printf("Private key length is %zd\n", lg);

		printf("Write private key.\n");
		r = sc_update_binary(card,0,pdata,lg,0);
		if(r<0) goto out;
		printf("Private key correctly written.\n");

		r = create_file_cert(card);
		if(r) goto out;

		{
			const BIGNUM *rsa_n, *rsa_e;

			RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);

			if (!do_convert_bignum(&dst->modulus, rsa_n)
			 || !do_convert_bignum(&dst->exponent, rsa_e))
				goto out;

		}

		r = sc_pkcs15_encode_pubkey(ctx, &key, &pdata, &lg);
		if(r) goto out;

		printf("Public key length %zd\n", lg);

		sc_format_path("3F000002", &path);
		r = sc_select_file(card, &path, NULL);
		if(r) goto out;

		printf("Write public key.\n");
		r = sc_update_binary(card,0,pdata,lg,0);
		if(r<0) goto out;
		printf("Public key correctly written.\n");

	}

	if(cert)
	{
		BIO *bio;
		X509 *xp;
		u8 *pdata;

		bio = BIO_new(BIO_s_file());
		if (BIO_read_filename(bio, cert) <= 0)
		{
			BIO_free(bio);
			printf("Can't open file %s.\n", cert);
			goto out;
		}
		xp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
		if (xp == NULL)
		{
			print_openssl_error();
			goto out;
		}
		else
		{
			int lg = cert2der(xp, &pdata);

			sc_format_path("0002", &path);
			r = sc_select_file(card, &path, NULL);
			if(r) goto out;

			/* FIXME: verify if the file has a compatible size... */
			printf("Write certificate %s.\n", cert);

			r = sc_update_binary(card,0,pdata,lg,0);
			if(r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
			{
				if(verify_pin(card, 0, pin))
				{
					printf("Wrong pin.\n");
				}
				else
				{
					r = sc_update_binary(card,0,pdata,lg,0);
				}
			}
			if(r<0)
			{
				if(pdata) free(pdata);
				goto out;
			}
			if(xp) X509_free(xp);
			if(pdata) free(pdata);

			printf("Certificate correctly written.\n");
		}
	}

	if(finalize)
	{
		int mode = SC_CARDCTRL_LIFECYCLE_USER;

		if(card->atr.value[10] != 0x82)
		{
			sc_format_path("0001", &path);
			r = sc_select_file(card, &path, NULL);
			if(r)
			{
				printf("This card don't have private key"\
					" and can't be finalize.\n");
				goto out;
			}
			printf("Finalize card...\n");
			if(sc_card_ctl(card, SC_CARDCTL_WESTCOS_AUT_KEY, NULL) ||
				sc_card_ctl(card, SC_CARDCTL_LIFECYCLE_SET, &mode))
			{
				printf("Error finalizing card,"\
					" card isn't secure.\n");
				goto out;
			}
		}
		printf("Card correctly finalized.\n");
	}

	if(get_filename)
	{
		FILE *fp;
		u8 *b;

		if(file)
		{
			sc_file_free(file);
			file = NULL;
		}

		sc_format_path(get_filename, &path);
		r = sc_select_file(card, &path, &file);
		if(r)
		{
				printf("Error file not found.\n");
				goto out;
		}

		b = malloc(file->size);
		if(b == NULL)
		{
				printf("Not enougth memory.\n");
				goto out;
		}

		r = sc_read_binary(card, 0, b, file->size, 0);
		if(r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		{
			if(verify_pin(card, 0, pin))
			{
				printf("Wrong pin.\n");
				goto out;
			}
			r = sc_read_binary(card, 0, b, file->size, 0);
		}

		if(r<0)
		{
				printf("Error reading file.\n");
				goto out;
		}

		fp = fopen(get_filename, "wb");
		fwrite(b, 1, file->size, fp);
		fclose(fp);

		free(b);
	}

	if(put_filename)
	{
		FILE *fp;
		u8 *b;

		if(file)
		{
			sc_file_free(file);
			file = NULL;
		}

		sc_format_path(put_filename, &path);
		r = sc_select_file(card, &path, &file);
		if(r)
		{
				printf("File not found.\n");
				goto out;
		}

		b = malloc(file->size);
		if(b == NULL)
		{
				printf("Not enougth memory.\n");
				goto out;
		}

		memset(b, 0, file->size);

		fp = fopen(put_filename, "rb");
		fread(b, 1, file->size, fp);
		fclose(fp);

		r = sc_update_binary(card, 0, b, file->size, 0);
		if(r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		{
			if(verify_pin(card, 0, pin))
			{
				printf("Wrong pin.\n");
			}
			else
			{
				r = sc_update_binary(card, 0, b, file->size, 0);
			}
		}
		if(r<0)
		{
				free(b);
				printf("Error writing file.\n");
				goto out;
		}

		free(b);
	}

out:

	if(mem)
		BIO_free(mem);
	if(bn)
		BN_free(bn);
	if(rsa)
		RSA_free(rsa);

	if(file)
		sc_file_free(file);

	if (card)
	{
		sc_unlock(card);
		sc_disconnect_card(card);
	}

	sc_release_context(ctx);

	return EXIT_SUCCESS;
}

