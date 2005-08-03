/*
 * eidenv.c: EstEID utility
 *
 * Copyright (C) 2004 Martin Paljak <martin@paljak.pri.ee>
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
#ifndef _WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <opensc/opensc.h>
#include <opensc/asn1.h>

#include "../libopensc/cards.h"
#include "../libopensc/esteid.h"

static int reader_num = 0;
static int stats = 0;
static char *exec_program = NULL;
static int exit_status = EXIT_FAILURE;

static struct option const long_options[] = {
	{"reader", required_argument, 0, 'r'},
	{"print", no_argument, 0, 'n'},
	{"exec", required_argument, 0, 'x'},
	{"stats", no_argument, 0, 't'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{NULL, 0, NULL, 0}
};

/* Probably not used, but needed to build on Windows */
const char *app_name = "eidenv";
const struct option options[] = {NULL};
const char *option_help[] = {NULL};

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
		"eidenv - EstEID utility version " VERSION "\n"
		"\n"
		"Copyright (c) 2004 Martin Paljak <martin@paljak.pri.ee>\n"
		"Licensed under GPL v2\n");
}

static void show_help(void)
{
	show_version();
	fprintf(stderr,
		"-h --help      -  show this text and exit\n"
		"-v --version   -  show version and exit\n"
		"-r --reader    -  the reader to use\n"
		"-n --print     -  print the datafile\n"
		"-t --stats     -  show usage counts of keys\n"
		"-x --exec      -  execute a program with data in env vars.\n");
}

static void decode_options(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv,"ptr:x:hV", long_options, (int *) 0)) != EOF) {

		switch (c) {
		case 'r':
			reader_num = atoi(optarg);
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
		case 'n':
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
	char buff[512];

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
			char * cp;
			cp = malloc(strlen(esteid_data[i].env_name) + 
			strlen(buff) + 2);
			if (cp) { 
				strcpy(cp,esteid_data[i].env_name);
				strcat(cp,"=");
				strcat(cp,buff);
				putenv(cp);
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
const static char hextable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'E'};
static char bintohex(char *buf, int len)
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
	char cardnumber[12 + 1];
	int cardnumberlen = sizeof(cardnumber);
	char chipnumber[2 * 16 + 1];
	int chipnumberlen = sizeof(chipnumber);
	char validfrom[10 + 1];
	int validfromlen = sizeof(validfrom);
	char validtill[10 + 1];
	int validtilllen = sizeof(validtill);
	char deliveringmunicipality[50 + 1];  /* UTF8 */
	int deliveringmunicipalitylen = sizeof(deliveringmunicipality);
	char nationalnumber[12 + 1];
	int nationalnumberlen = sizeof(nationalnumber);
	char name[90 + 1]; /* UTF8 */
	int namelen = sizeof(name);
	char firstnames[75 + 1]; /* UTF8 */
	int firstnameslen = sizeof(firstnames);
	char initial[3 + 1]; /* UTF8 */
	int initiallen = sizeof(initial);
	char nationality[65 + 1]; /* UTF8 */
	int nationalitylen = sizeof(nationality);
	char birthlocation[60 + 1]; /* UTF8 */
	int birthlocationlen = sizeof(birthlocation);
	char birthdate[12 + 1];
	int birthdatelen = sizeof(birthdate);
	char sex[1 + 1];
	int sexlen = sizeof(sex);
	char noblecondition[30 + 1]; /* UTF8 */
	int nobleconditionlen = sizeof(noblecondition);
	char documenttype[5 + 1];
	int documenttypelen = sizeof(documenttype);
	char specialstatus[5 + 1];
	int specialstatuslen = sizeof(specialstatus);
	struct sc_asn1_entry id[] = {
		{"cardnumber", SC_ASN1_UTF8STRING, 1, 0, cardnumber, &cardnumberlen},
		{"chipnumber", SC_ASN1_OCTET_STRING, 2, 0, chipnumber, &chipnumberlen},
		{"validfrom", SC_ASN1_UTF8STRING, 3, 0, validfrom, &validfromlen},
		{"validtill", SC_ASN1_UTF8STRING, 4, 0, validtill, &validtilllen},
		{"deliveringmunicipality", SC_ASN1_UTF8STRING, 5, 0, deliveringmunicipality, &deliveringmunicipalitylen},
		{"nationalnumber", SC_ASN1_UTF8STRING, 6, 0, nationalnumber, &nationalnumberlen},
		{"name", SC_ASN1_UTF8STRING, 7, 0, name, &namelen},
		{"firstname(s)", SC_ASN1_UTF8STRING, 8, 0, firstnames, &firstnameslen},
		{"initial", SC_ASN1_UTF8STRING, 9, 0, initial, &initiallen},
		{"nationality", SC_ASN1_UTF8STRING, 10, 0, nationality, &nationalitylen},
		{"birthlocation", SC_ASN1_UTF8STRING, 11, 0, birthlocation, &birthlocationlen},
		{"birthdate", SC_ASN1_UTF8STRING, 12, 0, birthdate, &birthdatelen},
		{"sex", SC_ASN1_UTF8STRING, 13, 0, sex, &sexlen},
		{"noblecondition", SC_ASN1_UTF8STRING, 14, 0, noblecondition, &nobleconditionlen},
		{"documenttype", SC_ASN1_UTF8STRING, 15, 0, documenttype, &documenttypelen},
		{"specialstatus", SC_ASN1_UTF8STRING, 16, 0, specialstatus, &specialstatuslen},
		NULL};

	/* Contents of the Address file (3F00\DF01\4033) */
	char streetandnumber[63 + 1]; /* UTF8 */
	int streetandnumberlen = sizeof(streetandnumber);
	char zipcode[4 + 1];
	int zipcodelen = sizeof(zipcode);
	char municipality[40 + 1]; /* UTF8 */
	int municipalitylen = sizeof(municipality);
	struct sc_asn1_entry address[] = {
		{"streetandnumber", SC_ASN1_UTF8STRING, 1, 0, streetandnumber, &streetandnumberlen},
		{"zipcode", SC_ASN1_UTF8STRING, 2, 0, zipcode, &zipcodelen},
		{"municipal", SC_ASN1_UTF8STRING, 3, 0, municipality, &municipalitylen},
		NULL};

	char buff[512];
	int r;

	r = read_transp(card, "3f00df014031", buff, sizeof(buff));
	if (r < 0)
		goto out;

	memset(cardnumber, '\0', sizeof(cardnumber));
	memset(chipnumber, '\0', sizeof(chipnumber));
	memset(validfrom, '\0', sizeof(validfrom));
	memset(validtill, '\0', sizeof(validtill));
	memset(deliveringmunicipality, '\0', sizeof(deliveringmunicipality));
	memset(nationalnumber, '\0', sizeof(nationalnumber));
	memset(name, '\0', sizeof(name));
	memset(firstnames, '\0', sizeof(firstnames));
	memset(initial, '\0', sizeof(initial));
	memset(nationality, '\0', sizeof(nationality));
	memset(birthlocation, '\0', sizeof(birthlocation));
	memset(birthdate, '\0', sizeof(birthdate));
	memset(sex, '\0', sizeof(sexlen));
	memset(noblecondition, '\0', sizeof(noblecondition));
	memset(documenttype, '\0', sizeof(documenttype));
	memset(specialstatus, '\0', sizeof(specialstatus));

	r = sc_asn1_decode(card->ctx, id, buff, r, NULL, NULL);
	if (r < 0) {
		fprintf(stderr, "\nFailed to decode the ID file: %s\n", sc_strerror(r));
		goto out;
	}

	exportprint("BELPIC_CARDNUMBER", cardnumber);
	bintohex(chipnumber, chipnumberlen);
	exportprint("BELPIC_CHIPNUMBER", chipnumber);
	exportprint("BELPIC_VALIDFROM", validfrom);
	exportprint("BELPIC_VALIDTILL", validtill);
	exportprint("BELPIC_DELIVERINGMUNICIPALITY", deliveringmunicipality);
	exportprint("BELPIC_NATIONALNUMBER", nationalnumber);
	exportprint("BELPIC_NAME", name);
	exportprint("BELPIC_FIRSTNAMES", firstnames);
	exportprint("BELPIC_INITIAL", initial);
	exportprint("BELPIC_NATIONALITY", nationality);
	exportprint("BELPIC_BIRTHLOCATION", birthlocation);
	exportprint("BELPIC_BIRTHDATE", birthdate);
	exportprint("BELPIC_SEX", sex);
	exportprint("BELPIC_NOBLECONDITION", noblecondition);
	exportprint("BELPIC_DOCUMENTTYPE", documenttype);
	exportprint("BELPIC_SPECIALSTATUS", specialstatus);

	r = read_transp(card, "3f00df014033", buff, sizeof(buff));
	if (r < 0)
		goto out;

	memset(streetandnumber, '\0', sizeof(streetandnumber));
	memset(zipcode, '\0', sizeof(zipcode));
	memset(municipality, '\0', sizeof(municipality));

	r = sc_asn1_decode(card->ctx, address, buff, r, NULL, NULL);
	if (r < 0) {
		fprintf(stderr, "\nFailed to decode the Address file: %s\n", sc_strerror(r));
		goto out;
	}

	exportprint("BELPIC_STREETANDNUMBER", streetandnumber);
	exportprint("BELPIC_ZIPCODE", zipcode);
	exportprint("BELPIC_MUNICIPALITY", municipality);

out:
	return;
}

int main(int argc, char **argv)
{
	sc_context_t *ctx = NULL;
	sc_reader_t *reader = NULL;
	sc_card_t *card = NULL;
	sc_path_t path;
	int r;

	/* get options */
	decode_options(argc, argv);

	/* connect to the card */
	r = sc_establish_context(&ctx, "eidenv");
	if (r) {
	fprintf(stderr, "Failed to establish context: %s\n",
		sc_strerror(r));
		return 1;
	}
	if (reader_num > ctx->reader_count) {
		fprintf(stderr, "Illegal reader number. Only %d reader(s) configured.\n", ctx->reader_count);
		return 1;
	}
	reader = ctx->reader[reader_num];

	r = sc_connect_card(reader, 0, &card);
	if (r) {
		fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
		return 1;
	}

	r = sc_lock(card);
	if (r) {
		fprintf(stderr, "Failed to lock card: %s\n", sc_strerror(r));
		return 1;
	}

	/* Check card type */
	if (card->type == SC_CARD_TYPE_MCRD_ESTEID)
		do_esteid(card);
	else if (card->type == SC_CARD_TYPE_BELPIC_EID)
		do_belpic(card);
	else {
		fprintf(stderr, "Not an EstEID or Belpic card!\n");
		goto out;
	}
	
	if (exec_program) {
		char *largv[2];
		sc_unlock(card);
		sc_disconnect_card(card, 0);
		sc_release_context(ctx);
		largv[0] = exec_program;
		largv[1] = NULL;
		execv(exec_program, largv);
		/* we should not get here */
		perror("execv()");
	}
	
out:
	sc_unlock(card);
	sc_disconnect_card(card, 0);
	sc_release_context(ctx);
	exit(exit_status);
}
