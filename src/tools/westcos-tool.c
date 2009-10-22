/*
 * westcos-tool.exe: tool for westcos card
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

 
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <opensc/opensc.h>
#include <opensc/errors.h>
#include <opensc/pkcs15.h>
#include <opensc/cardctl.h>

#include <openssl/opensslv.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

static char *version ="0.0.6";

static char *nom_card = "WESTCOS";

static int finalise = 0;
static int verbose = 0;
static int install_pin = 0;
static int remplace = 0;

static char *pin = NULL;
static char *puk = NULL;
static char *cert = NULL;

static int keylen = 0;

static int no_lecteur = -1;

static int new_pin = 0;
static int debloque = 0;

static char *get_filename = NULL;
static char *put_filename = NULL;

static int do_convert_bignum(sc_pkcs15_bignum_t *dst, BIGNUM *src)
{
	if (src == 0) return 0;
	dst->len = BN_num_bytes(src);
	dst->data = (u8 *) malloc(dst->len);
	BN_bn2bin(src, dst->data);
	return 1;
}

static int	charge = 0;
static void print_openssl_erreur(void)
{
	long r;

	if (!charge) 
	{
		ERR_load_crypto_strings();
		charge = 1;
	}

	while ((r = ERR_get_error()) != 0)
		fprintf(stderr, "%s\n", ERR_error_string(r, NULL));
}

static int verify_pin(sc_card_t *card, int pin_reference, char *pin_value)
{
	int r, tries_left = -1;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;

	data.pin_type = SC_AC_CHV;

	data.pin_reference = pin_reference;

	data.flags = SC_PIN_CMD_NEED_PADDING;

	if (card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) 
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
				printf("Error %d attemps left.\n", tries_left);
			else
				printf("Wrong pin.\n");
		}
		else
			fprintf(stderr, "The pin can be verify: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Pin correct.\n");
	return 0;
}

static int change_pin(sc_card_t *card, 
		int pin_reference, 
		char *pin_value1, 
		char *pin_value2)
{
	int r, tries_left = -1;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_CHANGE;

	data.pin_type = SC_AC_CHV;

	data.pin_reference = pin_reference;

	data.flags = SC_PIN_CMD_NEED_PADDING;

	if (card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) 
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
				printf("Error %d attemps left.\n", tries_left);
			else
				printf("Wrong pin.\n");
		}
		else
			fprintf(stderr, "Can't change pin: %s\n", 
				sc_strerror(r));
		return -1;
	}
	printf("Pin changed.\n");
	return 0;
}

static int debloque_pin(sc_card_t *card, 
			int pin_reference, 
			char *puk_value, 
			char *pin_value)
{
	int r, tries_left = -1;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_UNBLOCK;

	data.pin_type = SC_AC_CHV;

	data.pin_reference = pin_reference;

	data.flags = SC_PIN_CMD_NEED_PADDING;

	if (card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) 
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
				printf("Error %d attemps left.\n", tries_left);
			else
				printf("Wrong pin.\n");
		}
		else
			fprintf(stderr, "Can't unblock pin: %s\n", 
				sc_strerror(r));
		return -1;
	}
	printf("Code debloque.\n");
	return 0;
}

static int cert2der(X509 *cert, u8 **value)
{
	int len;
	u8 *p;
	len = i2d_X509(cert, NULL);
	p = *value = (u8*)malloc(len);
	i2d_X509(cert, &p);
	return len;
}

static int creation_fichier_cert(sc_card_t *card)
{
	int r;
	int size;
	sc_path_t path;
	sc_file_t *file = NULL;
	sc_context_t *ctx = card->ctx;

	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, &file);
	if(r) goto out;
	
	size = (file->size) - 32;

	if(file)
	{
		sc_file_free(file);
		file = NULL;
	}

	sc_format_path("0002", &path);
	sc_ctx_suppress_errors_on(ctx);
	r = sc_select_file(card, &path, NULL);
	sc_ctx_suppress_errors_off(ctx);
	if(r) 
	{
		if(r != SC_ERROR_FILE_NOT_FOUND) goto out;

		file = sc_file_new();
		if(file == NULL)
		{
			fprintf(stderr, "memory error.\n");
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

void usage(void)
{
printf("Tools for westcos card.\n");
printf("version %s.\n\n", version);
printf("\t -G                 Generate key 1536 default.\n");
printf("\t -L [length]        Key length 512,1024,1536.\n");
printf("\t -i                 Install pin.\n");
printf("\t -pin [value]       Pin.\n");
printf("\t -puk [value]       Puk.\n");
printf("\t -n                 Change pin (new pin in puk option).\n");
printf("\t -u                 Unblock pin.\n");
printf("\t -cert [file]       Write certificate (in pem format).\n");
printf("\t -F                 Finalize card "\
	"(!!! MANDATORY FOR SECURITY !!!).\n");
printf("\t -r [n]             Use reader number [n]"\
	" (default: autodetect).\n");
printf("\t -gf [path]         Read file [path].\n");
printf("\t -pf [path]         Write file [path].\n");
printf("\t -v                 verbose.\n");
printf("\t -h                 This message.\n");
exit(0);
}

int main(int argc, char *argv[])
{
	int r;
	int i = 1;
	char *p;
	int card_presente = 0;
	sc_context_param_t ctx_param;
	sc_reader_t *lecteur = NULL;
	sc_card_t *card = NULL;
	sc_context_t *ctx = NULL;
	sc_file_t *file = NULL;
	sc_path_t path;
	RSA	*rsa = NULL;
	BIGNUM	*bn = NULL;
	BIO	*mem = NULL;

	while(i<argc)
	{
		p = argv[i++];
		if(strcmp(p, "-gf") == 0)
		{
			if(i<argc)
			{
				get_filename = argv[i++];
				continue;
			}
		}

		if(strcmp(p, "-pf") == 0)
		{
			if(i<argc)
			{
				put_filename = argv[i++];
				continue;
			}
		}

		if(strcmp(p, "-F") == 0)
		{
			finalise = 1;
			continue;
		}

		if(strcmp(p, "-i") == 0)
		{
			install_pin = 1;
			continue;
		}

		if(strcmp(p, "-R") == 0)
		{
			remplace = 1;
			continue;
		}

		if(strcmp(p, "-G") == 0)
		{
			if(keylen == 0) keylen = 1536;
			continue;
		}

		if(strcmp(p, "-L") == 0)
		{
			if(i<argc)
			{
				keylen = atoi(argv[i++]);
				continue;
			}
		}

		if(strcmp(p, "-pin") == 0)
		{
			if(i<argc)
			{
				pin = argv[i++];
				continue;
			}
		}

		if(strcmp(p, "-puk") == 0)
		{
			if(i<argc)
			{
				puk = argv[i++];
				continue;
			}
		}

		if(strcmp(p, "-cert") == 0)
		{
			if(i<argc)
			{
				cert = argv[i++];
				continue;
			}
		}

		if(strcmp(p, "-n") == 0)
		{
			new_pin = 1;
			continue;
		}

		if(strcmp(p, "-u") == 0)
		{
			debloque = 1;
			continue;
		}

		if(strcmp(p, "-r") == 0)
		{
			if(i<argc)
			{
				no_lecteur = atoi(argv[i++]);
				continue;
			}
		}

		if(!strcmp(p, "-h") || !strcmp(p,"--help"))
		{
			usage();
		}

		if(!strncmp(p, "-v", 2))
		{
			char *n = p+1;
			while(*n++ == 'v') verbose++;
			continue;
		}

		printf("Unknown %s \n", p);
		usage();
		exit(-1);
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = argv[0];

	r = sc_context_create(&ctx, &ctx_param);
	if (r) 
	{
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose > 1)
		ctx->debug = verbose-1;

	if(no_lecteur == -1)
	{
		for(i = 0; i<sc_ctx_get_reader_count(ctx); i++)
		{
			lecteur = sc_ctx_get_reader(ctx, i);
			if(sc_detect_card_presence(lecteur, 0))
			{
				r = sc_connect_card(lecteur, 0, &card);
				if(r>=0)
				{
					printf("card->name = %s\n", card->name);
					if(strncmp(card->name, nom_card, strlen(nom_card)) == 0)
					{
						card_presente = 1;
						break;
					}
					sc_disconnect_card(card,0);
					card = NULL;
				}
			}
		}
	}
	else
	{
		if(no_lecteur < sc_ctx_get_reader_count(ctx))
		{
			lecteur = sc_ctx_get_reader(ctx, no_lecteur);
			r = sc_connect_card(lecteur, 0, &card);
			if(r>=0)
			{
				card_presente = 1;
			}
			else
			{
				sc_disconnect_card(card,0);
			}
		}
	}

	if(!card_presente) goto out;

	sc_lock(card);

	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	if(r) goto out;

	if(install_pin)
	{
		sc_format_path("AAAA", &path);
		sc_ctx_suppress_errors_on(ctx);
		r = sc_select_file(card, &path, NULL);
		sc_ctx_suppress_errors_off(ctx);
		if(r) 
		{
			if(r != SC_ERROR_FILE_NOT_FOUND) goto out;

			file = sc_file_new();
			if(file == NULL)
			{
				fprintf(stderr, "Not enougth memory.\n");
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

			//sc_format_path("3F00AAAA", &(file->path));
			file->path = path;
			r = sc_create_file(card, file);
			if(r) goto out;
		}		

		if(pin != NULL)
		{
			sc_changekey_t ck;
			struct sc_pin_cmd_pin pin_cmd;

			memset(&pin_cmd, 0, sizeof(pin_cmd));
			memset(&ck, 0, sizeof(ck));

			memcpy(ck.key_template, "\x1e\x00\x00\x10", 4);

			pin_cmd.encoding = SC_PIN_ENCODING_GLP;
			pin_cmd.len = strlen(pin);
			pin_cmd.data = (u8*)pin;
			pin_cmd.max_length = 8;

			ck.new_key.key_len = sc_build_pin(ck.new_key.key_value, 
				sizeof(ck.new_key.key_value), &pin_cmd, 1); 
			if(ck.new_key.key_len<0)
				goto out;

			r = sc_card_ctl(card, SC_CARDCTL_WESTCOS_CHANGE_KEY, &ck);
			if(r) goto out;
		}

		if(puk != NULL)
		{
			sc_changekey_t ck;
			struct sc_pin_cmd_pin puk_cmd;

			memset(&puk_cmd, 0, sizeof(puk_cmd));
			memset(&ck, 0, sizeof(ck));

			memcpy(ck.key_template, "\x1e\x00\x00\x20", 4);

			puk_cmd.encoding = SC_PIN_ENCODING_GLP;
			puk_cmd.len = strlen(puk);
			puk_cmd.data = (u8*)puk;
			puk_cmd.max_length = 8;

			ck.new_key.key_len = sc_build_pin(ck.new_key.key_value, 
				sizeof(ck.new_key.key_value), &puk_cmd, 1); 
			if(ck.new_key.key_len<0)
				goto out;

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

	if(debloque)
	{
		if(debloque_pin(card, 0, puk, pin)) 
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
			fprintf(stderr,"Not enougth memory.\n");
			goto out;
		}

		if(!BN_set_word(bn, RSA_F4) || 
			!RSA_generate_key_ex(rsa, keylen, bn, NULL))
#else
		rsa = RSA_generate_key(keylen, RSA_F4, NULL, NULL);
		mem = BIO_new(BIO_s_mem());

		if(mem == NULL) 
		{
			fprintf(stderr,"Not enougth memory.\n");
			goto out;
		}

		if (!rsa)
#endif
		{
			fprintf(stderr, 
				"RSA_generate_key_ex return %ld\n", ERR_get_error());
			goto out;
		}

		rsa->meth = RSA_PKCS1_SSLeay();

		if(!i2d_RSAPrivateKey_bio(mem, rsa))
		{
			fprintf(stderr, 
				"i2d_RSAPrivateKey_bio return %ld\n", ERR_get_error());
			goto out;
		}

		lg = BIO_get_mem_data(mem, &pdata);

		sc_format_path("0001", &path);
		sc_ctx_suppress_errors_on(ctx);
		r = sc_select_file(card, &path, NULL);
		sc_ctx_suppress_errors_off(ctx);
		if(r) 
		{
			if(r != SC_ERROR_FILE_NOT_FOUND) goto out;

			file = sc_file_new();
			if(file == NULL)
			{
				fprintf(stderr, "Not enougth memory.\n");
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

			printf("File key creation %s, size %d.\n", file->path.value, 
				file->size);

			r = sc_create_file(card, file);
			if(r) goto out;
		}	
		else
		{
			if(!remplace)
			{
				fprintf(stderr, 
					"Key file already exist,"\
					" use -R to replace it.\n");
				goto out;
			}
		}

		printf("Private key length is %d\n", lg);

		printf("Write private key.\n");
		r = sc_update_binary(card,0,pdata,lg,0);
		if(r<0) goto out;
		printf("Private key correctly written.\n");

		r = creation_fichier_cert(card);
		if(r) goto out;

		if (!do_convert_bignum(&dst->modulus, rsa->n)
		 || !do_convert_bignum(&dst->exponent, rsa->e))
			goto out;
		
		r = sc_pkcs15_encode_pubkey(ctx, &key, &pdata, &lg);
		if(r) goto out;

		printf("Public key length %d\n", lg);

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
			fprintf(stderr, "Can't open file %s.\n", cert);
			goto out;
		}
		xp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
		if (xp == NULL) 
		{
			print_openssl_erreur();
			goto out;
		}
		else
		{
			int lg = cert2der(xp, &pdata);

			sc_format_path("0002", &path);
			r = sc_select_file(card, &path, NULL);
			if(r) goto out;

			/* FIXME: verifier taille fichier compatible... */
			printf("Write certificate %s.\n", cert);

			r = sc_update_binary(card,0,pdata,lg,0);
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

	if(finalise)
	{
		int mode = SC_CARDCTRL_LIFECYCLE_USER;

		if(card->atr[10] != 0x82)
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

		b = (u8*)malloc(file->size);
		if(b == NULL)
		{
				fprintf(stderr, "Not enougth memory.\n");
				goto out;
		}

		r = sc_read_binary(card, 0, b, file->size, 0);
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

		b = (u8*)malloc(file->size);
		if(b == NULL)
		{
				fprintf(stderr, "Not enougth memory.\n");
				goto out;
		}

		memset(b, 0, file->size);

		fp = fopen(put_filename, "rb");
		fread(b, 1, file->size, fp);
		fclose(fp);

		r = sc_update_binary(card, 0, b, file->size, 0);
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
		sc_disconnect_card(card, 0);
	}

	if (ctx)
		sc_release_context(ctx);

	return EXIT_SUCCESS;
}

