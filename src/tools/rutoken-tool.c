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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <limits.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include "util.h"

//#define _DEBUG
#ifdef _DEBUG
#define trace(fmt)      printf("%s, %s line %d: " fmt, __FUNCTION__, __FILE__, __LINE__)
#define trace2(fmt,a)      printf("%s, %s line %d: " fmt, __FUNCTION__, __FILE__, __LINE__, a)
#define trace2(fmt,a,b)      printf("%s, %s line %d: " fmt, __FUNCTION__, __FILE__, __LINE__, a, b)
#else 
#define trace(fmt)
#define trace2(fmt,a)
#define trace3(fmt,a,b)
#endif


/*  globals  */
const char *app_name = "rutoken-tool";
sc_context_t *g_ctx = NULL;

enum {
	OP_NONE,
	OP_GET_INFO,
	OP_ENCIPHER,
	OP_DECIPHER,
	OP_SIGN,
	OP_FORMAT
};

enum {
	OPT_BASE = 0x100,
	OPT_PIN,
	OPT_SOPIN
};

const struct option options[] = {
	{"reader",	1, 0, 'r'},
	{"card-driver", 1, 0, 'c'},
	{"wait",	0, 0, 'w'},
	{"verbose",	0, 0, 'v'},
	{"getinfo",	0, 0, 'g'},
	{"encrypt",	0, 0, 'e'},
	{"decrypt",	0, 0, 'u'},
	{"sign",	0, 0, 's'},
	{"key",		1, 0, 'k'},
	{"i-vector",1, 0, 'I'},
	{"pin",		1, 0, OPT_PIN},
	{"so-pin",	1, 0, OPT_SOPIN},
	{"input",	1, 0, 'i'},
	{"output", 	1, 0, 'o'},
	{"format", 	0, 0, 'F'},
	{0, 0, 0, 0}
};

const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Forces the use of driver <arg> [auto-detect]",
	"Wait for a card to be inserted",
	"Verbose operation. Use several times to enable debug output.",
	"Get RuToken info",
	"GOST encrypt",
	"GOST decrypt",
	"sign",
	"use GOST key",
	"use initialization vector (synchro posylka)", 
	"user pin",
	"admin pin",
	"input file path",
	"output file path",
	"format card"
};


/*  Get ruToken device information  */
int rutoken_info(sc_card_t *card)
{	
	trace("enter\n");
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	char szInfo[SC_MAX_APDU_BUFFER_SIZE*4];
	int r;
	
	
	r = card->ops->card_ctl(card, SC_CARDCTL_RUTOKEN_GET_INFO, rbuf);
	if (r) {
		fprintf(stderr, "get info failed: %s\n",
		        sc_strerror(r));
		return 1;
	}
	sc_bin_to_hex(rbuf, 8, szInfo, sizeof(szInfo), 0);
	
	printf("Type: %d\n", *((char *)rbuf));
	printf("Version: %d.%d\n", (*((char *)rbuf+1))>>4, (*((char *)rbuf+1))&0x0F );
	printf("Memory: %d Kb\n", *((char *)rbuf+2)*8);
	printf("Protocol version: %d\n", *((char *)rbuf+3));
	printf("Software version: %d\n", *((char *)rbuf+4));
	printf("Order: %d\n", *((char *)rbuf+5));
	
	sc_serial_number_t serial;
	r = card->ops->card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r) {
		fprintf(stderr, "get serial failed: %s\n",
		        sc_strerror(r));
		return 1;
	}
	sc_bin_to_hex(serial.value, serial.len , szInfo, sizeof(szInfo), 0);
	printf("Serial number : %s\n", szInfo);
	return 0;
}

/*   Cryptografic routine  */

/*  Size of file  */

off_t get_file_size(int fd)
{
	off_t cur_pos;
	off_t file_size;
	cur_pos = lseek(fd, 0, SEEK_CUR);
	file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, cur_pos, SEEK_SET);
    return file_size;
}

/*  Allocate buffer and read file, insert initialization vector if needIV
    return buffer size  */

int get_file(sc_card_t *card, const char *filepath, u8 **ppBuf, int needIV, u8 *IV)
{
	int file = open(filepath, O_RDONLY);
	int ret = -1, size = -1;
	
	if(file > 0) 
	{
		size = get_file_size(file);
		trace2("size = %d\n", size);
		if(size > 0) *ppBuf = realloc(*ppBuf, needIV ? size + 8 : size);
		if(*ppBuf) 
		{
			trace3("needIV %d, %p\n", needIV, IV);
			if (needIV)
			{
				if (IV)
					ret = memcpy(*ppBuf, IV, 8) != *ppBuf;
				else 
				{
					trace("get_challenge\n");
					ret = card->ops->get_challenge(card, *ppBuf, 8);
				}
				if (ret == SC_SUCCESS) 
				{
					ret = read(file, *ppBuf + 8, size) + 8;
					size += 8;
				}
				else
					ret = -1;
			}
			else
				ret = read(file, *ppBuf, size);
		}
		trace3("ret = %d, size = %d\n", ret, size);
		if( ret != size)
		{
			printf("Read error!!!\n");
			free(*ppBuf);
			ret = -1;
		}
		close(file);
	}
	else
		printf("File %s not found\n", filepath);
	return ret;
}

/*  Write buffer to a file
    sync = NULL if not sync decrypt  */

int write_file(const char *filepath, u8 *buff, size_t len)
{
	int file, r;
	file = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR | S_IRGRP|S_IWGRP | S_IROTH|S_IWOTH);
	if( file < 0 ) {
		printf("File %s not found\n", filepath);
		return -1;
	}
	r = write(file, buff, len);
	if( r < 0) {
		printf("Write error!!!\n");
		return r;
	};
	return r;
}

/*  Decrypt a buffer  */

int rutoken_decipher(sc_card_t *card, u8 keyid, u8 *in, size_t inlen, u8 *out, size_t outlen, int oper)
{
	int r;/*
	u8 buff[24] = {0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 
			0x4E, 0x4F, 0xEB, 0x69, 0x5B, 0xFF, 0x01, 0x20, 0xE1, 0xA9, 0x2D, 0xAE, 0x59, 0xD4, 0xD1, 0xCA};
	u8 outbuff[24] = {0};*/
	struct sc_rutoken_decipherinfo inf = { in, inlen, out, outlen };
	sc_security_env_t env;
	env.key_ref[0] = keyid;
	env.key_ref_len = 1;
	env.algorithm = SC_ALGORITHM_GOST;
	env.algorithm_flags = SC_RUTOKEN_OPTIONS_GOST_CRYPT_GAMM;
	env.operation = SC_SEC_OPERATION_DECIPHER;

	/*  set security env  */
	trace2("try to set SE key = %02X\n", keyid);
	r = card->ops->set_security_env(card, &env, 0);
	if (r) {
		fprintf(stderr, "decipher failed: %d : %s\n",
		        r, sc_strerror(r));
		return 1;
	}
	trace("set SE - ok\n");
	/*  cipher  */
	r = card->ops->card_ctl(card, oper, &inf);
	if (r < 0) {
		fprintf(stderr, "decipher failed: %s\n",
		        sc_strerror(r));
		return 1;
	}
	trace2("return %d\n", r);
	return r;
}

/*  Decrypt a file  */

int crypt_file(sc_card_t *card,  u8 keyid, const char *szInFile, const char *szOutFile, int oper, u8* IV)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	int size = -1;
	u8 *pBuf = NULL, *pOut = NULL;
		
	size = get_file(card, szInFile, &pBuf, oper == OP_ENCIPHER, IV);
	trace3("size of %s is %d\n", szInFile, size);
	if(size > 0) 
	{
		pOut = malloc(size);
		size = rutoken_decipher
			(card, keyid, pBuf, size, pOut, size, 
			 oper == OP_ENCIPHER ? SC_CARDCTL_RUTOKEN_GOST_ENCIPHER : SC_CARDCTL_RUTOKEN_GOST_DECIPHER);
		if ((size > 0) && (write_file(szOutFile, pOut, size) == size)) ret = SC_SUCCESS;
		free(pBuf);	
		free(pOut);
	}
	return ret;
}

/*  external definitions  */
struct sc_profile_t;
extern int rutoken_erase(struct sc_profile_t *, sc_card_t *);
extern int rutoken_finalize_card(sc_card_t *);
extern int rutoken_init(struct sc_profile_t *, sc_card_t *);
/*  Format and initialize file system  */
int format_card(sc_card_t *card)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	trace("enter\n");
	if (( ret = (rutoken_erase(NULL, card)) == SC_SUCCESS) &&
	    ( ret = (rutoken_init(NULL, card)) == SC_SUCCESS)
	   )
		ret = rutoken_finalize_card(card);
	return ret;
}

int main(int argc, char *const argv[])
{
	int err = 0, r, c, long_optind = 0;
	const char *opt_driver = NULL;
	sc_context_param_t ctx_param;
	int opt_reader = -1, opt_debug = 0, opt_wait = 0, opt_key = 0, opt_is_IV,
		opt_is_pin = 0, opt_is_sopin = 0, opt_is_input = 0, opt_is_output = 0;
	char opt_pin[100] = {0}, opt_input[PATH_MAX] = {0}, opt_output[PATH_MAX] = {0}, opt_IV[16] = {0};
	
	int operation = 0;
	
	sc_context_t *ctx = NULL;
	sc_card_t *card = NULL;
	
	while (1) 
	{
		c = getopt_long(argc, argv, "r:vc:wgeusk:i:o:p:I:F", options,
				&long_optind);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
		case '?':
			print_usage_and_die(app_name, options, option_help);
		case 'r':
			opt_reader = atoi(optarg);
			break;
		case 'v':
			opt_debug++;
			break;
		case 'c':
			opt_driver = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'g':
			operation = OP_GET_INFO;
			break;
		case 'k':
			opt_key = atoi(optarg);
			opt_key = (opt_key / 10) * 0x10 + opt_key % 10;
			break;
		case 'I':
			opt_is_IV = 1;
			strncpy(opt_IV, optarg, 8);
			break;
		case 'u':
			operation = OP_DECIPHER;
			break;
		case 'e':
			operation = OP_ENCIPHER;
			break;
		case 's':
			operation = OP_SIGN;
			break;
		case OPT_PIN:
			if(opt_is_sopin || opt_is_pin)
			{
				fprintf(stderr, "You must specify only one pin\n");
				goto end;
			}
			opt_is_pin = 1;
			strcpy(opt_pin, optarg);
			break;
		case OPT_SOPIN:
			if(opt_is_sopin || opt_is_pin)
			{
				fprintf(stderr, "You must specify only one pin\n");
				goto end;
			}
			opt_is_sopin = 1;
			strcpy(opt_pin, optarg);
			break;
		case 'i':
			opt_is_input = 1;
			strcpy(opt_input, optarg);
			break;
		case 'o':
			opt_is_output = 1;
			strcpy(opt_output, optarg);
			break;
		case 'F':
			operation = OP_FORMAT;
			break;
		}
	}

	/* create sc_context_t object */
	trace("\n");
	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;
	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (opt_debug)
		ctx->debug = opt_debug;
	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n",
				opt_driver);
			err = -1;
			goto end;
		}
	}

	trace("\n");
	err = connect_card(ctx, &card, opt_reader, 0, opt_wait, opt_debug);
	if (err)
		goto end;
		
	if(opt_is_pin || opt_is_sopin){
		/*  verify  */
	    int tries_left = 0;
		err = sc_verify(card, SC_AC_CHV, opt_is_sopin ? 1 : 2 , (u8*)opt_pin, strlen(opt_pin), &tries_left);
	    if(err) 
		{
			fprintf(stderr, "verify failed  %d\n", err);
			goto end;
		}
		fprintf(stderr, "Verify ok\n");
	}
	switch(operation)
	{
	case OP_GET_INFO:
		if ((err = rutoken_info(card))) {
			goto end;
		}
		break;
	case OP_DECIPHER:
	case OP_ENCIPHER:
		if(!opt_key)
		{
			fprintf(stderr, "Not key\n");
			err = -1;
			break;
		}
		if (!opt_is_input)
		{
			fprintf(stderr, "Not input file\n");
			err = -1;
			break;
		}
		if (!opt_is_output)
		{
			fprintf(stderr, "Not output file\n");
			err = -1;
			break;
		}
		err = crypt_file(card, opt_key, opt_input, opt_output, operation, opt_is_IV ? (u8*)opt_IV : NULL);
		break;
	case OP_FORMAT:
		trace("OP_FORMAT\n");
		err = format_card(card);
		if(err != SC_SUCCESS) fprintf(stderr, "Initialization failed\n");
		
		break;
	default:
		printf("No operation --help\n");
		break;
	}
end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card, 0);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
