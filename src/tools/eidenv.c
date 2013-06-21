/*
 * eidenv.c: EstEID utility
 *
 * Copyright (C) 2004 Martin Paljak <martin@martinpaljak.net>
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
#ifndef _WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "common/compat_getopt.h"
#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/cards.h"
#include "libopensc/esteid.h"
#include "util.h"

static char *opt_reader = NULL;
static int stats = 0;
static int opt_wait = 0;
static char *exec_program = NULL;
static int exit_status = EXIT_FAILURE;

static const struct option options[] = {
	{"reader", required_argument, NULL, 'r'},
	{"print", no_argument, NULL, 'p'},
	{"exec", required_argument, NULL, 'x'},
	{"stats", no_argument, NULL, 't'},
	{"help", no_argument, NULL, 'h'},
	{"wait", no_argument, NULL, 'w'},
	{"version", no_argument, NULL, 'V'},
	{NULL, 0, NULL, 0}
};

/* Probably not used, but needed to build on Windows */
static const char *app_name = "eidenv";

static struct {
	const char *name;
	const char *env_name;
	int recno;
} esteid_data[] = {
	{"Surname", "ESTEID_SURNAME", 1},
	{"Given names 1", "ESTEID_GIVEN_NAMES1", 2},
	{"Given names 2", "ESTEID_GIVEN_NAMES2", 3},
	{"Sex", "ESTEID_SEX", 4},
	{"Citizenship", "ESTEID_CITIZENSHIP", 5},
	{"Date of birth", "ESTEID_DATE_OF_BIRTH", 6},
	{"Personal ID code", "ESTEID_PERSONAL_ID", 7},
	{"Document number", "ESTEID_DOCUMENT_NR", 8},
	{"Expiry date", "ESTEID_EXPIRY_DATE", 9},
	{"Place of birth", "ESTEID_PLACE_OF_BIRTH", 10},
	{"Issuing date", "ESTEID_ISSUING_DATE", 11},
	{"Permit type", "ESTEID_PERMIT_TYPE", 12},
	{"Remark 1", "ESTEID_REMARK1", 13},
	{"Remark 2", "ESTEID_REMARK2", 14},
	{"Remark 3", "ESTEID_REMARK3", 15},
	{"Remark 4", "ESTEID_REMARK4", 16},
	{NULL, NULL, 0}
};

static void show_version(void)
{
	fprintf(stderr,
		"eidenv - EstEID utility version " PACKAGE_VERSION "\n"
		"\n"
		"Copyright (c) 2004 Martin Paljak <martin@martinpaljak.net>\n"
		"Licensed under LGPL v2\n");
}

static void show_help(void)
{
	show_version();
	fprintf(stderr,
		"-h --help      -  show this text and exit\n"
		"-v --version   -  show version and exit\n"
		"-r --reader    -  the reader to use\n"
		"-w --wait      -  wait for a card to be inserted\n"
		"-p --print     -  print the datafile\n"
		"-t --stats     -  show usage counts of keys\n"
		"-x --exec      -  execute a program with data in env vars.\n");
}

static void decode_options(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv,"pwtr:x:hV", options, (int *) 0)) != EOF) {

		switch (c) {
		case 'r':
			opt_reader = optarg;
			break;
		case 't':
			stats = !stats;
			break;
		case 'x':
			if (exec_program)
				free(exec_program);
			exec_program = strdup(optarg);
			break;
		case 'h':
			show_help();
			exit(EXIT_SUCCESS);
			break;
		case 'p':
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
			break;
		default:
			show_help();
			exit(EXIT_FAILURE);
		}
	}
}

static void do_esteid(sc_card_t *card)
{
	sc_path_t path;
	int r, i;
	unsigned char buff[512];

	if (stats) {
		int key_used[4];
		sc_format_path("3f00eeee0013", &path);
		r = sc_select_file(card, &path, NULL);
		if (r) {
			fprintf(stderr, "Failed to select key counters: %s\n", sc_strerror(r));
			goto out;
		}

		/* print the counters */
		for (i = 1; i <= 4; i++) {
			r = sc_read_record(card, i, buff, 128, SC_RECORD_BY_REC_NR);
			key_used[i - 1] = 0xffffff - ((unsigned char) buff[0xc] * 65536
									+ (unsigned char) buff[0xd] * 256
									+ (unsigned char) buff[0xe]);
		}
		for (i = 0; i < 2; i++) {
			printf("Key generation #%d usage:\n\tsign: %d\n\tauth: %d\n",
					 i, key_used[i], key_used[i + 2]);
		}
		exit_status = EXIT_SUCCESS;
		goto out;
	}

	/* Or just read the datafile */
	sc_format_path("3f00eeee5044", &path);
	r = sc_select_file(card, &path, NULL);
	if (r) {
		fprintf(stderr, "Failed to select DF: %s\n", sc_strerror(r));
		goto out;
	}

	for (i = 0; esteid_data[i].recno != 0; i++) {
		r = sc_read_record(card, esteid_data[i].recno, buff, 50, SC_RECORD_BY_REC_NR);
		if (r < 0) {
			fprintf (stderr, "Failed to read record %d from card: %s\n",
						esteid_data[i].recno, sc_strerror (r));
			goto out;
		}
		buff[r] = '\0';
		if (exec_program) {
			unsigned char * cp;
			cp = malloc(strlen(esteid_data[i].env_name) +
				strlen((char *) buff) + 2);
			if (cp) {
				strcpy((char *) cp,esteid_data[i].env_name);
				strcat((char *) cp,"=");
				strcat((char *) cp,(char *) buff);
				putenv((char *) cp);
			}
		} else {
			printf("%s: %s\n", esteid_data[i].name, buff);
		}
	}

	exit_status = EXIT_SUCCESS;

out:
	return;
}

/* Select and read a transparent EF */
static int read_transp(sc_card_t *card, const char *pathstring, unsigned char *buf, int buflen)
{
	sc_path_t path;
	int r;

	sc_format_path(pathstring, &path);
	r = sc_select_file(card, &path, NULL);
	if (r < 0)
		fprintf(stderr, "\nFailed to select file %s: %s\n", pathstring, sc_strerror(r));
	else {
		r = sc_read_binary(card, 0, buf, buflen, 0);
		if (r < 0)
			fprintf(stderr, "\nFailed to read %s: %s\n", pathstring, sc_strerror(r));
	}

	return r;
}

/* Hex-encode the buf, 2*len+1 bytes must be reserved. E.g. {'1','2'} -> {'3','1','3','2','\0'} */
static const char hextable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'E'};
static void bintohex(char *buf, int len)
{
	int i;
	for (i = len - 1; i >= 0; i--) {
		buf[2 * i + 1] = hextable[((unsigned char) buf[i]) % 16];
		buf[2 * i] = hextable[((unsigned char) buf[i]) / 16];
	}
}

static void exportprint(const char *key, const char *val)
{
	if (exec_program) {
		char * cp;
		cp = malloc(strlen(key) + strlen(val) + 2);
		if (cp) {
			strcpy(cp, key);
			strcat(cp, "=");
			strcat(cp, val);
			putenv(cp);
		}
	} else
		printf("%s: %s\n", key, val);
}

static void do_belpic(sc_card_t *card)
{
	/* Contents of the ID file (3F00\DF01\4031) */
	struct {
		char cardnumber[12 + 1];
		char chipnumber[2 * 16 + 1];
		char validfrom[10 + 1];
		char validtill[10 + 1];
		char deliveringmunicipality[50 + 1];  /* UTF8 */
		char nationalnumber[12 + 1];
		char name[90 + 1]; /* UTF8 */
		char firstnames[75 + 1]; /* UTF8 */
		char initial[3 + 1]; /* UTF8 */
		char nationality[65 + 1]; /* UTF8 */
		char birthlocation[60 + 1]; /* UTF8 */
		char birthdate[12 + 1];
		char sex[1 + 1];
		char noblecondition[30 + 1]; /* UTF8 */
		char documenttype[5 + 1];
		char specialstatus[5 + 1];
	} id_data;
	int cardnumberlen = sizeof(id_data.cardnumber);
	int chipnumberlen = sizeof(id_data.chipnumber);
	int validfromlen = sizeof(id_data.validfrom);
	int validtilllen = sizeof(id_data.validtill);
	int deliveringmunicipalitylen = sizeof(id_data.deliveringmunicipality);
	int nationalnumberlen = sizeof(id_data.nationalnumber);
	int namelen = sizeof(id_data.name);
	int firstnameslen = sizeof(id_data.firstnames);
	int initiallen = sizeof(id_data.initial);
	int nationalitylen = sizeof(id_data.nationality);
	int birthlocationlen = sizeof(id_data.birthlocation);
	int birthdatelen = sizeof(id_data.birthdate);
	int sexlen = sizeof(id_data.sex);
	int nobleconditionlen = sizeof(id_data.noblecondition);
	int documenttypelen = sizeof(id_data.documenttype);
	int specialstatuslen = sizeof(id_data.specialstatus);

	struct sc_asn1_entry id[] = {
		{"cardnumber", SC_ASN1_UTF8STRING, 1, 0, id_data.cardnumber, &cardnumberlen},
		{"chipnumber", SC_ASN1_OCTET_STRING, 2, 0, id_data.chipnumber, &chipnumberlen},
		{"validfrom", SC_ASN1_UTF8STRING, 3, 0, id_data.validfrom, &validfromlen},
		{"validtill", SC_ASN1_UTF8STRING, 4, 0, id_data.validtill, &validtilllen},
		{"deliveringmunicipality", SC_ASN1_UTF8STRING, 5, 0, id_data.deliveringmunicipality, &deliveringmunicipalitylen},
		{"nationalnumber", SC_ASN1_UTF8STRING, 6, 0, id_data.nationalnumber, &nationalnumberlen},
		{"name", SC_ASN1_UTF8STRING, 7, 0, id_data.name, &namelen},
		{"firstname(s)", SC_ASN1_UTF8STRING, 8, 0, id_data.firstnames, &firstnameslen},
		{"initial", SC_ASN1_UTF8STRING, 9, 0, id_data.initial, &initiallen},
		{"nationality", SC_ASN1_UTF8STRING, 10, 0, id_data.nationality, &nationalitylen},
		{"birthlocation", SC_ASN1_UTF8STRING, 11, 0, id_data.birthlocation, &birthlocationlen},
		{"birthdate", SC_ASN1_UTF8STRING, 12, 0, id_data.birthdate, &birthdatelen},
		{"sex", SC_ASN1_UTF8STRING, 13, 0, id_data.sex, &sexlen},
		{"noblecondition", SC_ASN1_UTF8STRING, 14, 0, id_data.noblecondition, &nobleconditionlen},
		{"documenttype", SC_ASN1_UTF8STRING, 15, 0, id_data.documenttype, &documenttypelen},
		{"specialstatus", SC_ASN1_UTF8STRING, 16, 0, id_data.specialstatus, &specialstatuslen},
		{NULL, 0, 0, 0, NULL, NULL}
	};

	/* Contents of the Address file (3F00\DF01\4033) */
	struct {
		char streetandnumber[63 + 1]; /* UTF8 */
		char zipcode[4 + 1];
		char municipality[40 + 1]; /* UTF8 */
	} address_data;
	int streetandnumberlen = sizeof(address_data.streetandnumber);
	int zipcodelen = sizeof(address_data.zipcode);
	int municipalitylen = sizeof(address_data.municipality);
	struct sc_asn1_entry address[] = {
		{"streetandnumber", SC_ASN1_UTF8STRING, 1, 0, address_data.streetandnumber, &streetandnumberlen},
		{"zipcode", SC_ASN1_UTF8STRING, 2, 0, address_data.zipcode, &zipcodelen},
		{"municipal", SC_ASN1_UTF8STRING, 3, 0, address_data.municipality, &municipalitylen},
		{NULL, 0, 0, 0, NULL, NULL}};

	unsigned char buff[512];
	int r;

	r = read_transp(card, "3f00df014031", buff, sizeof(buff));
	if (r < 0)
		goto out;

	memset(&id_data, 0, sizeof(id_data));

	r = sc_asn1_decode(card->ctx, id, buff, r, NULL, NULL);
	if (r < 0) {
		fprintf(stderr, "\nFailed to decode the ID file: %s\n", sc_strerror(r));
		goto out;
	}

	exportprint("BELPIC_CARDNUMBER", id_data.cardnumber);
	bintohex(id_data.chipnumber, chipnumberlen);
	exportprint("BELPIC_CHIPNUMBER", id_data.chipnumber);
	exportprint("BELPIC_VALIDFROM", id_data.validfrom);
	exportprint("BELPIC_VALIDTILL", id_data.validtill);
	exportprint("BELPIC_DELIVERINGMUNICIPALITY", id_data.deliveringmunicipality);
	exportprint("BELPIC_NATIONALNUMBER", id_data.nationalnumber);
	exportprint("BELPIC_NAME", id_data.name);
	exportprint("BELPIC_FIRSTNAMES", id_data.firstnames);
	exportprint("BELPIC_INITIAL", id_data.initial);
	exportprint("BELPIC_NATIONALITY", id_data.nationality);
	exportprint("BELPIC_BIRTHLOCATION", id_data.birthlocation);
	exportprint("BELPIC_BIRTHDATE", id_data.birthdate);
	exportprint("BELPIC_SEX", id_data.sex);
	exportprint("BELPIC_NOBLECONDITION", id_data.noblecondition);
	exportprint("BELPIC_DOCUMENTTYPE", id_data.documenttype);
	exportprint("BELPIC_SPECIALSTATUS", id_data.specialstatus);

	r = read_transp(card, "3f00df014033", buff, sizeof(buff));
	if (r < 0)
		goto out;

	memset(&address_data, 0, sizeof(address_data));

	r = sc_asn1_decode(card->ctx, address, buff, r, NULL, NULL);
	if (r < 0) {
		fprintf(stderr, "\nFailed to decode the Address file: %s\n", sc_strerror(r));
		goto out;
	}

	exportprint("BELPIC_STREETANDNUMBER", address_data.streetandnumber);
	exportprint("BELPIC_ZIPCODE", address_data.zipcode);
	exportprint("BELPIC_MUNICIPALITY", address_data.municipality);

out:
	return;
}

int main(int argc, char **argv)
{
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int r;

	/* get options */
	decode_options(argc, argv);

	/* connect to the card */
	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
	fprintf(stderr, "Failed to establish context: %s\n",
		sc_strerror(r));
		return 1;
	}
	r = util_connect_card(ctx, &card, opt_reader, opt_wait, 0);
	if (r) {
		fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
		return 1;
	}

	/* Check card type */
	if (card->type == SC_CARD_TYPE_MCRD_ESTEID_V10 || card->type == SC_CARD_TYPE_MCRD_ESTEID_V11 || card->type == SC_CARD_TYPE_MCRD_ESTEID_V30)
		do_esteid(card);
	else if (card->type == SC_CARD_TYPE_BELPIC_EID)
		do_belpic(card);
	else {
		fprintf(stderr, "Not an EstEID or Belpic card!\n");
		goto out;
	}

	if (exec_program) {
		char *const largv[] = {exec_program, NULL};
		sc_unlock(card);
		sc_disconnect_card(card);
		sc_release_context(ctx);
		execv(exec_program, largv);
		/* we should not get here */
		perror("execv()");
		exit(1);
	}

out:
	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);
	exit(exit_status);
}
