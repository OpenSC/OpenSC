/*
 * $Id$
 *
 * Copyright (C) 2001, 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <sys/types.h>
#include "scldap.h"

static void hex_dump_asc(FILE * f, const unsigned char *in, size_t count, int addr)
{
	int lines = 0;

	while (count) {
		char ascbuf[17];
		unsigned int i;

		if (addr >= 0) {
			fprintf(f, "%08X: ", addr);
			addr += 16;
		}
		for (i = 0; i < count && i < 16; i++) {
			fprintf(f, "%02X ", *in);
			if (isprint(*in))
				ascbuf[i] = *in;
			else
				ascbuf[i] = '.';
			in++;
		}
		count -= i;
		ascbuf[i] = 0;
		for (; i < 16 && lines; i++)
			fprintf(f, "   ");
		fprintf(f, "%s\n", ascbuf);
		lines++;
	}
}

static void usage(void)
{
	printf("test-ldap: [options]\n");
	printf(" -h		Show help\n");
	printf("%s", scldap_show_arguments());
	printf(" -e <entry>	Use <entry> for search.\n\t\tAn URL is also accepted.\n");
	printf(" -s <string>	Fill the entry filter with a string.\n\t\tAlso used as a replacement for filter\n\t\twhen no entry filter found.\n");
	printf(" -F		Save results(s).\n");
	printf(" -d		Dump result(s) to screen in hex format.\n");
	printf(" -v		Increase verbose level.\n");
}

int main(int argc, char **argv)
{
	char *entry = NULL, *searchword = NULL;
	unsigned int i, verbose = 0, dump = 0, save = 0, ffound = 0;
	scldap_context *lctx = NULL;
	scldap_result *lresult = NULL;

	for (i = 0; i < (unsigned int) argc; i++) {
		if (argv[i][0] == '-') {
			char *optarg = (char *) argv[i + 1];
			switch (argv[i][1]) {
			case 'e':
				if (!optarg)
					continue;
				entry = optarg;
				break;
			case 's':
				if (!optarg)
					continue;
				searchword = optarg;
				break;
			case 'F':
				save = 1;
				break;
			case 'd':
				dump = 1;
				break;
			case 'v':
				verbose++;
				break;
			case 'h':
			case '?':
				usage();
				return 1;
				break;
			}
		}
	}
	lctx = scldap_parse_parameters(SCLDAP_CONF_PATH);
	if (!lctx) {
		return 1;
	}
	if (verbose > 2)
		scldap_show_parameters(lctx);
	scldap_parse_arguments(&lctx, argc, (const char **) argv);
	if (scldap_is_valid_url(entry)) {
		/* Valid test URL:
		 * "ldap://193.229.0.210:389/cn=finsign%20ca%20for%20test3,o=vrk-fin
		 * sign%20gov.%20ca,dmdname=fineid,c=FI?certificaterevocationlist"
		 */
		char *entryname = "LDAP URL";

		if (verbose)
			printf("Valid url.\n");
		if (scldap_url_to_entry(lctx, entryname, entry) < 0) {
			printf("scldap_url_to_entry failed.\n");
			scldap_free_parameters(lctx);
			return 1;
		}
		scldap_set_entry(lctx, entryname);
		entry = entryname;
	}
	if (lctx->entry[lctx->active].filter || searchword) {
		ffound = 1;
	}
	if (!lctx->entries && (!ffound && !entry)) {
		usage();
		printf("\nMissing entry for the search or the current\n");
		printf("entry needs to be filled in with a searchword.\n");
		scldap_free_parameters(lctx);
		return 1;
	}
	if (verbose > 2)
		scldap_show_parameters(lctx);
	if (scldap_search(lctx, entry, &lresult, 0, searchword) < 0) {
		fprintf(stderr, "scldap_search failed.\n");
		scldap_free_parameters(lctx);
		return 1;
	}
	printf("Success. (%i results)\n", lresult->results);
	for (i = 0; i < lresult->results; i++) {
		if (verbose)
			printf("%02i. %s[%li] = %s\n", i + 1,
			       lresult->result[i].name, lresult->result[i].datalen,
			       (lresult->result[i].binary ? "NOT ASCII" : (char *) lresult->result[i].data));
		if (verbose > 1)
			printf("%02i. dn = %s\n", i + 1, lresult->result[i].dn);
		if (dump)
			hex_dump_asc(stdout, lresult->result[i].data, lresult->result[i].datalen, 0);
		if (save && lresult->result[i].name) {
			const char *prefix = "ldap-dump-";
			int filenamelen = strlen(lresult->result[i].name) + strlen(prefix) + 6;
			char *filename = (char *) malloc(filenamelen);
			FILE *fp = NULL;

			if (!filename)
				break;
			memset(filename, 0, filenamelen);
			snprintf(filename, filenamelen, "%s%02i-", prefix, i + 1);
			strcat(filename, lresult->result[i].name);
			if ((fp = fopen(filename, "a"))) {
				fwrite(lresult->result[i].data, lresult->result[i].datalen, 1, fp);
				fclose(fp);
			} else {
				perror("fopen");
			}
			free(filename);
		}
	}
	scldap_free_result(lresult);
	lresult = NULL;
#if 0
	if (scldap_dn_to_result("C=FI, S=HST-KORTTI, G=ESIMERKKI679, CN=HST-KORTTI ESIMERKKI679 99999578U, SN=99999578U", &lresult, 1) < 0) {
		printf("scldap_dn_to_result failed.\n");
		scldap_free_parameters(lctx);
		return 1;
	}
	for (i = 0; i < lresult->results; i++) {
		printf("%02i. %s [%li]\n", i + 1,
		       lresult->result[i].data,
		       lresult->result[i].datalen);
	}
	scldap_free_result(lresult);
	lresult = NULL;
#endif
#if 0
	{
		char *binddn = NULL;

		if (scldap_approx_binddn_by_dn(lctx, "approx_binddn", "C=FI, O=VRK-FINSIGN Gov. CA, CN=FINSIGN CA for Test3", &binddn) < 0) {
			printf("scldap_approx_binddn_by_dn failed.\n");
			scldap_free_parameters(lctx);
			return 1;
		}
		printf("binddn: %s\n", binddn);
		free(binddn);
	}
#endif
	scldap_free_parameters(lctx);
	return 0;
}
