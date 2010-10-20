/*
 * rutoken-tool.c: RuToken Tool
 *
 * Copyright (C) 2007  Pavel Mironchik <rutoken@rutoken.ru>
 * Copyright (C) 2007  Eugene Hermann <rutoken@rutoken.ru>
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
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/pkcs15.h"
#include "util.h"

/* win32 needs this in open(2) */
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define IV_SIZE         8
#define HASH_SIZE       4

static const char *app_name = "rutoken-tool";

enum {
	OP_NONE,
	OP_GET_INFO,
	OP_GEN_KEY,
	OP_ENCRYPT,
	OP_DECRYPT,
	OP_MAC
};

static const struct option options[] = {
	{"reader",      1, NULL, 'r'},
	{"wait",        0, NULL, 'w'},
	{"pin",         1, NULL, 'p'},
	{"key",         1, NULL, 'k'},
	{"IV",          1, NULL, 'I'},
	{"type",        1, NULL, 't'},
	{"input",       1, NULL, 'i'},
	{"output",      1, NULL, 'o'},
	{"info",        0, NULL, 's'},
	{"genkey",      0, NULL, 'g'},
	{"encrypt",     0, NULL, 'e'},
	{"decrypt",     0, NULL, 'd'},
	{"mac",         0, NULL, 'm'},
	{"verbose",     0, NULL, 'v'},
	{NULL,          0, NULL,  0 }
};

static const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Wait for a card to be inserted",
	"Specify PIN",
	"Selects the GOST key ID to use",
	"Initialization vector of the encryption to use",
	"Specify a new GOST key type: ECB (default), SM or CFB",
	"Selects the input file to cipher",
	"Selects the output file to cipher",
	"Show ruToken information",
	"Generate new GOST key",
	"Performs GOST encryption operation",
	"Performs GOST decryption operation",
	"Performs MAC computation with GOST key",
	"Verbose operation. Use several times to enable debug output."
};

/*  Get ruToken device information  */

static int rutoken_info(sc_card_t *card)
{	
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_serial_number_t serial;
	int r;
	
	r = sc_card_ctl(card, SC_CARDCTL_RUTOKEN_GET_INFO, rbuf);
	if (r) {
		fprintf(stderr, "Error: Get info failed: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Type: %d\n", rbuf[0]);
	printf("Version: %d.%d\n", rbuf[1]>>4, rbuf[1] & 0x0F);
	printf("Memory: %d Kb\n", rbuf[2]*8);
	printf("Protocol version: %d\n", rbuf[3]);
	printf("Software version: %d\n", rbuf[4]);
	printf("Order: %d\n", rbuf[5]);
	
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r) {
		fprintf(stderr, "Error: Get serial failed: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Serial number: ");
	util_hex_dump(stdout, serial.value, serial.len, NULL);
	putchar('\n');
	return 0;
}
	
/*  Cipher/Decipher a buffer on token (used GOST key chosen by ID)  */
	
static int rutoken_cipher(sc_card_t *card, u8 keyid,
		const u8 *in, size_t inlen,
		u8 *out, size_t outlen, int oper)
{
	int r;
	struct sc_rutoken_decipherinfo inf = { in, inlen, out, outlen };
	sc_security_env_t env;
	int cmd = (oper == OP_ENCRYPT) ?
			SC_CARDCTL_RUTOKEN_GOST_ENCIPHER :
			SC_CARDCTL_RUTOKEN_GOST_DECIPHER;

	memset(&env, 0, sizeof(env));
	env.key_ref[0] = keyid;
	env.key_ref_len = 1;
	env.algorithm = SC_ALGORITHM_GOST;
	env.operation = SC_SEC_OPERATION_DECIPHER;

	/*  set security env  */
	r = sc_set_security_env(card, &env, 0);
	if (r) {
		fprintf(stderr, "Error: Cipher failed (set security environment): %s\n",
		        sc_strerror(r));
		return -1;
	}
	/*  cipher  */
	r = sc_card_ctl(card, cmd, &inf);
	if (r) {
		fprintf(stderr, "Error: Cipher failed: %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

/*  Compute MAC a buffer on token (used GOST key chosen by ID)  */

static int rutoken_mac(sc_card_t *card, u8 keyid,
		const u8 *in, size_t inlen,
		u8 *out, size_t outlen)
{
	int r;
	sc_security_env_t env;

	memset(&env, 0, sizeof(env));
	env.key_ref[0] = keyid;
	env.key_ref_len = 1;
	env.algorithm = SC_ALGORITHM_GOST;
	env.operation = SC_SEC_OPERATION_SIGN;

	/*  set security env  */
	r = sc_set_security_env(card, &env, 0);
	if (r) {
		fprintf(stderr, "Error: Computation signature (MAC) failed"
				" (set security environment): %s\n", sc_strerror(r));
		return -1;
	}
	/*  calculate hash  */
	r = sc_compute_signature(card, in, inlen, out, outlen);
	if (r) {
		fprintf(stderr, "Error: Computation signature (MAC) failed: %s\n",
				sc_strerror(r));
		return -1;
	}
	return 0;
}

/*  Encrypt/Decrupt infile to outfile  */

static int do_crypt(sc_card_t *card, u8 keyid,
		const char *path_infile, const char *path_outfile,
		const u8 IV[IV_SIZE], int oper)
{
	int err;
	int fd_in, fd_out;
	struct stat st;
	size_t insize, outsize, readsize;
	u8 *inbuf = NULL, *outbuf = NULL, *p;

	fd_in = open(path_infile, O_RDONLY | O_BINARY);
	if (fd_in < 0) {
		fprintf(stderr, "Error: Cannot open file '%s'\n", path_infile);
		return -1;
				}
	err = fstat(fd_in, &st);
	if (err || (oper == OP_DECRYPT && st.st_size < IV_SIZE)) {
		fprintf(stderr, "Error: File '%s' is invalid\n", path_infile);
		close(fd_in);
		return -1;
	}
	insize = st.st_size;
	if (oper == OP_ENCRYPT)
		insize += IV_SIZE;
	outsize = insize;
	if (oper == OP_DECRYPT)  /*  !(stat.st_size < IV_SIZE)  already true  */
		outsize -= IV_SIZE;

	inbuf = malloc(insize);
	outbuf = malloc(outsize);
	if (!inbuf || !outbuf) {
		fprintf(stderr, "Error: File '%s' is too big (allocate memory)\n",
				path_infile);
		err = -1;
	}
	if (err == 0) {
		p = inbuf;
		readsize = insize;
		if (oper == OP_ENCRYPT) {
			memcpy(inbuf, IV, IV_SIZE);  /*  Set IV in first bytes buf  */
			/*  insize >= IV_SIZE  already true  */
			p += IV_SIZE;
			readsize -= IV_SIZE;
		}
		err = read(fd_in, p, readsize);
		if (err < 0  ||  (size_t)err != readsize) {
			fprintf(stderr, "Error: Read file '%s' failed\n", path_infile);
			err = -1;
			}
			else
			err = 0;
		}
	close(fd_in);

	if (err == 0) {
		fd_out = open(path_outfile, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
				S_IRUSR | S_IWUSR);
		if (fd_out < 0) {
			fprintf(stderr, "Error: Cannot create file '%s'\n",path_outfile);
			err = -1;
		}
		else {
			err = rutoken_cipher(card, keyid, inbuf, insize,
					outbuf, outsize, oper);
			if (err == 0) {
				err = write(fd_out, outbuf, outsize);
				if (err < 0  ||  (size_t)err != outsize) {
					fprintf(stderr,"Error: Write file '%s' failed\n",
							path_outfile);
					err = -1;
	}
	else
					err = 0;
			}
			close(fd_out);
	}
	}
	if (outbuf)
		free(outbuf);
	if (inbuf)
		free(inbuf);
	return err;
}

/*  Cipher/Decipher
    (for cipher IV is parameters or random generated on token)  */

static int gostchiper(sc_card_t *card, u8 keyid,
		const char *path_infile, const char *path_outfile,
		const char IV[IV_SIZE], int is_iv, int op_oper)
{
	int r;
	u8 iv[IV_SIZE];

	if (op_oper == OP_ENCRYPT) {
		if (!is_iv) {
			/*  generated random on token  */
			r = sc_get_challenge(card, iv, IV_SIZE);
	if (r) {
				fprintf(stderr, "Error: Generate IV"
						" (get challenge) failed: %s\n",
		        sc_strerror(r));
				return -1;
			}
		}
		else
			memcpy(iv, IV, IV_SIZE);
	}
	return do_crypt(card, keyid, path_infile, path_outfile, iv, op_oper);
}

/*  Print MAC infile (used GOST key chosen by ID)  */

static int gostmac(sc_card_t *card, u8 keyid, const char *path_infile)
{
	int err;
	int fd;
	struct stat st;
	size_t insize;
	u8 *inbuf = NULL;
	u8 outbuf[HASH_SIZE];

	fd = open(path_infile, O_RDONLY | O_BINARY);
	if (fd < 0) {
		fprintf(stderr, "Error: Cannot open file '%s'\n", path_infile);
		return -1;
	}
	err = fstat(fd, &st);
	if (err) {
		fprintf(stderr, "Error: File '%s' is invalid\n", path_infile);
		close(fd);
		return -1;
	}
	insize = st.st_size;
	inbuf = malloc(insize);
	if (!inbuf) {
		fprintf(stderr, "Error: File '%s' is too big (allocate memory)\n",
				path_infile);
		err = -1;
	}
	if (err == 0) {
		err = read(fd, inbuf, insize);
		if (err < 0  ||  (size_t)err != insize) {
			fprintf(stderr, "Error: Read file '%s' failed\n", path_infile);
			err = -1;
	}
		else
			err = rutoken_mac(card, keyid, inbuf, insize,
					outbuf, sizeof(outbuf));
	}
	if (err == 0) {
		util_hex_dump(stdout, outbuf, sizeof(outbuf), NULL);
		putchar('\n');
	}
	if (inbuf)
		free(inbuf);
	close(fd);
	return err;
}

/*  Generate GOST key on ruToken card  */

static int generate_gostkey(sc_card_t *card, u8 keyid, u8 keyoptions)
{
	const sc_SecAttrV2_t gk_sec_attr = {
		0x44, 0, 0, 1, 0, 0, 0, 1,
		0, 0, 0, 0,
		0, 0, 0, 0,
		2, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		2, 0, 0, 0,
		0, 0, 0, 0
	};
	sc_DOHdrV2_t paramkey;
	int r;

	memset(&paramkey, 0, sizeof(paramkey));
	paramkey.wDOBodyLen         = SC_RUTOKEN_DEF_LEN_DO_GOST;
	paramkey.OTID.byObjectType  = SC_RUTOKEN_TYPE_KEY;
	paramkey.OTID.byObjectID    = keyid;
	paramkey.OP.byObjectOptions = keyoptions;

	/* assert(sizeof(*gk_sec_attr)); */
	/* assert(sizeof(*paramkey.SA_V2)); */
	/* assert(sizeof(paramkey.SA_V2) == sizeof(gk_sec_attr)); */
	memcpy(paramkey.SA_V2, gk_sec_attr, sizeof(gk_sec_attr));

        r = sc_card_ctl(card, SC_CARDCTL_RUTOKEN_GENERATE_KEY_DO, &paramkey);
	if (r) {
		fprintf(stderr, "Error: Generate GOST key failed: %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

int main(int argc, char* argv[])
{
	int             opt_wait = 0;
	const char     *opt_pin = NULL;
	const char     *opt_reader = NULL;
	int             opt_key = 0;
	int             opt_is_iv = 0;
	u8              opt_keytype = SC_RUTOKEN_OPTIONS_GOST_CRYPT_PZ;
	const char     *opt_input = NULL;
	const char     *opt_output = NULL;
	int             opt_operation = OP_NONE;
	int             opt_debug = 0;
	char IV[IV_SIZE];
	
	int err = 0;
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int c, long_optind, r, tries_left;
	
	while (1) {
		c = getopt_long(argc, argv, "r:wp:k:I:t:i:o:sgedmv",
				options, &long_optind);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			util_print_usage_and_die(app_name, options, option_help);
		case 'r':
			opt_reader = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'p':
			opt_pin = optarg;
			break;
		case 'k':
			opt_key = atoi(optarg);
			if (opt_key <= 0 || opt_key < SC_RUTOKEN_DO_ALL_MIN_ID
					|| opt_key > SC_RUTOKEN_DO_NOCHV_MAX_ID) {
				fprintf(stderr, "Error: Key ID is invalid"
						" (%d <= ID <= %d)\n",
						SC_RUTOKEN_DO_ALL_MIN_ID > 0 ?
						SC_RUTOKEN_DO_ALL_MIN_ID : 1,
						SC_RUTOKEN_DO_NOCHV_MAX_ID);
				return -1;
			}
			break;
		case 'I':
			opt_is_iv = 1;
			strncpy(IV, optarg, sizeof(IV));
			break;
		case 't':
			if (strcmp(optarg, "CFB") == 0)
				opt_keytype = SC_RUTOKEN_OPTIONS_GOST_CRYPT_GAMMOS;
			else if (strcmp(optarg, "SM") == 0)
				opt_keytype = SC_RUTOKEN_OPTIONS_GOST_CRYPT_GAMM;
			else if (strcmp(optarg, "ECB") != 0) {
				fprintf(stderr, "Error: Key type must be either"
						" ECB, SM or CFB\n");
				return -1;
			}
			break;
		case 'i':
			opt_input = optarg;
			break;
		case 'o':
			opt_output = optarg;
			break;
		case 's':
			opt_operation = OP_GET_INFO;
			break;
		case 'g':
			opt_operation = OP_GEN_KEY;
			break;
		case 'e':
			opt_operation = OP_ENCRYPT;
			break;
		case 'd':
			opt_operation = OP_DECRYPT;
			break;
		case 'm':
			opt_operation = OP_MAC;
			break;
		case 'v':
			opt_debug++;
			break;
		}
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.app_name = app_name;
	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Error: Failed to establish context: %s\n",
			sc_strerror(r));
		return -1;
	}

	if (opt_debug > 1) {
		ctx->debug = opt_debug;
		ctx->debug_file = stderr;
	}

	if (util_connect_card(ctx, &card, opt_reader, opt_wait, opt_debug) != 0)
		err = -1;
		
	if (err == 0  &&  opt_pin) {
		/*  verify  */
		r = sc_verify(card, SC_AC_CHV, SC_RUTOKEN_DEF_ID_GCHV_USER,
				(u8*)opt_pin, strlen(opt_pin), &tries_left);
		if (r) {
			fprintf(stderr, "Error: PIN verification failed: %s",
					sc_strerror(r));
			if (r == SC_ERROR_PIN_CODE_INCORRECT)
				fprintf(stderr, " (tries left %d)\n", tries_left);
			else
				putc('\n', stderr);
			err = 1;
		}
	}
	if (err == 0) {
		err = -1;
		switch (opt_operation) {
	case OP_GET_INFO:
			err = rutoken_info(card);
		break;
		case OP_DECRYPT:
		case OP_ENCRYPT:
		case OP_MAC:
			if (!opt_input) {
				fprintf(stderr, "Error: No input file specified\n");
			break;
		}
			if (opt_operation != OP_MAC  &&  !opt_output) {
				fprintf(stderr, "Error: No output file specified\n");
			break;
		}
		case OP_GEN_KEY:
			if (opt_key == 0) {
				fprintf(stderr, "Error: You must set key ID\n");
			break;
		}
			if (opt_operation == OP_GEN_KEY)
				err = generate_gostkey(card, (u8)opt_key, opt_keytype);
			else if (opt_operation == OP_MAC)
				err = gostmac(card, (u8)opt_key, opt_input);
			else
				err = gostchiper(card, (u8)opt_key, opt_input,opt_output,
						IV, opt_is_iv, opt_operation);
		break;
	default:
			fprintf(stderr, "Error: No operation specified\n");
		break;
	}
	}
	if (card) {
		/*  sc_lock  and  sc_connect_card  in  util_connect_card  */
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}

