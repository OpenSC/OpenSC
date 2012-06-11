/*
 * iasecc-tool.c: Tool for accessing smart cards with libopensc
 *
 * Copyright (C) 2001 Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2011 Viktor TARASOV <viktor.tarasov@gmail.com>
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

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/asn1.h"
#include "libopensc/iasecc.h"
#include "util.h"

static const char *app_name = "iasecc-tool";

static char * opt_bind_to_aid = NULL;
static char * opt_reader = NULL;
static char * opt_sdo_tag = 0;
static int opt_wait = 0;
static int verbose = 0;

enum {
	OPT_READER = 0x100,
	OPT_BIND_TO_AID,
	OPT_LIST_SDOS,
	OPT_LIST_APPLICATIONS
};

static const struct option options[] = {
	{ "reader",	required_argument, NULL, OPT_READER },
	{ "aid",	required_argument, NULL, OPT_BIND_TO_AID },
	{ "list-applications",  no_argument, NULL,              OPT_LIST_APPLICATIONS },
	{ "list-sdos",	required_argument, NULL, OPT_LIST_SDOS },
	{ "wait",	no_argument, NULL, 'w' },
	{ "verbose",	no_argument, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Uses reader number <arg>",
	"Specify AID of the on-card PKCS#15 application to be binded to (in hexadecimal form)",
	"List the on-card PKCS#15 applications",
	"List the SDOs with the <arg> tag in the current ADF",
	"Wait for card insertion",
	"Verbose operation. Use several times to enable debug output.",
	NULL
};

static int list_sdos(char *sdo_tag);

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static struct sc_pkcs15_card *p15card = NULL;

static void
_iasecc_print_tlv(char *label, int format_text, struct iasecc_extended_tlv *tlv)
{
	unsigned ii;

	if (!tlv->value)
		return;

	printf("%s:\t", label);
	for(ii=0; ii<tlv->size; ii++)   {
		if (format_text)   {
			printf("%c", *(tlv->value + ii));
		}
		else   {
			if (ii) printf(":");
			printf("%02X", *(tlv->value + ii));
		}
	}
	printf("\n");

}

static void
_iasecc_print_docp(struct iasecc_sdo_docp *docp)
{
	_iasecc_print_tlv("\tname:", 1, &docp->name);
	_iasecc_print_tlv("\tcontact ACLs", 0, &docp->acls_contact);
	_iasecc_print_tlv("\tnon repudiation", 0, &docp->non_repudiation);
	_iasecc_print_tlv("\tsize", 0, &docp->size);
	_iasecc_print_tlv("\ttries maximum", 0, &docp->tries_maximum);
	_iasecc_print_tlv("\ttries remaining", 0, &docp->tries_remaining);
	_iasecc_print_tlv("\tusage maximum", 0, &docp->usage_maximum);
	_iasecc_print_tlv("\tusage remaining", 0, &docp->usage_remaining);
}

static void
_iasecc_print_crt(struct sc_crt *crt)
{
	printf("\tCRT #%X:\tusage %02X; algo %02X; ref %02X:%02X:...\n",
	crt->tag, crt->usage, crt->algo, crt->refs[0], crt->refs[1]);
}

static int list_sdos(char *sdo_tag)
{
	struct iasecc_sdo sdo;
	struct iasecc_se_info se;
	unsigned sdo_class = 0;
	int rv, ii, jj;

	if (!sdo_tag)
		goto usage;

	if (*sdo_tag == 'x' || *sdo_tag == 'X')
		sdo_class = strtol(sdo_tag + 1, NULL, 16);
	else if ((strlen(sdo_tag) > 2) && (*(sdo_tag + 1) == 'x' || *(sdo_tag + 1) == 'X'))
		sdo_class = strtol(sdo_tag + 2, NULL, 16);
	else
		sdo_class = strtol(sdo_tag, NULL, 10);

	sdo_class &= 0x7F;
	if (sdo_class == IASECC_SDO_CLASS_SE)   {
		for (ii=1; ii<0x20; ii++)   {
			memset(&se, 0, sizeof(se));
			se.reference = ii;

			rv = sc_card_ctl(card, SC_CARDCTL_GET_SE_INFO, &se);
			if (!rv)   {
				printf("Found SE #%X\n", se.reference);
				_iasecc_print_docp(&se.docp);
				for(jj=0; jj<SC_MAX_CRTS_IN_SE && se.crts[jj].tag; jj++)
					_iasecc_print_crt(&se.crts[jj]);
			}
		}
	}
	else   {
		for (ii=1; ii<0x20; ii++)   {
			memset(&sdo, 0, sizeof(sdo));
			sdo.sdo_class = sdo_class;
			sdo.sdo_ref  = ii;

			rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_GET_DATA, &sdo);
			if (!rv)   {
				printf("Found SDO class %X, reference %X\n", sdo.sdo_class, sdo.sdo_ref);
				_iasecc_print_docp(&sdo.docp);
			}
		}
	}
	return 0;
usage:
	puts("Usage: list_sdos <SDO class>");
	return -1;
}

static int list_apps(FILE *fout)
{
	unsigned j;
	int i;

	for (i=0; i < card->app_count; i++)   {
		struct sc_app_info *info = card->app[i];

		fprintf(fout, "Application '%s':\n", info->label);
		fprintf(fout, "\tAID: ");
		for(j=0;j<info->aid.len;j++)
			fprintf(fout, "%02X", info->aid.value[j]);
		fprintf(fout, "\n");

		if (info->ddo.value && info->ddo.len)   {
			fprintf(fout, "\tDDO: ");
			for(j=0;j<info->ddo.len;j++)
				fprintf(fout, "%02X", info->ddo.value[j]);
			fprintf(fout, "\n");
		}

		fprintf(fout, "\n");
	}
	return 0;
}

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_list_sdos = 0;
	int do_list_apps = 0;
	int action_count = 0;
	sc_context_param_t ctx_param;

	setbuf(stderr, NULL);
	setbuf(stdout, NULL);

	while (1) {
		c = getopt_long(argc, argv, "v", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
                case OPT_LIST_SDOS:
                        do_list_sdos = 1;
                        opt_sdo_tag = optarg;
                        action_count++;
                        break;
		case OPT_LIST_APPLICATIONS:
			do_list_apps = 1;
			action_count++;
			break;
                case OPT_BIND_TO_AID:
			opt_bind_to_aid = optarg;
			break;
		case OPT_READER:
			opt_reader = optarg;
			break;
		case 'v':
			verbose++;
			break;
		}
	}
	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

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

	if (action_count <= 0)
		goto end;

	err = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	if (err)
		goto end;

        if (opt_bind_to_aid)   {
		struct sc_aid aid;

		aid.len = sizeof(aid.value);
		if (sc_hex_to_bin(opt_bind_to_aid, aid.value, &aid.len))   {
			fprintf(stderr, "Invalid AID value: '%s'\n", opt_bind_to_aid);
			return 1;
		}

		r = sc_pkcs15_bind(card, &aid, &p15card);
	}
	else   if (!do_list_sdos) {
		r = sc_pkcs15_bind(card, NULL, &p15card);
	}

	if (do_list_sdos) {
		if ((err = list_sdos(opt_sdo_tag)))
			goto end;
		action_count--;
	}
	if (do_list_apps) {
		if ((err = list_apps(stdout)))
			goto end;
		action_count--;
	}
end:
	if (p15card)
		sc_pkcs15_unbind(p15card);

	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);

	return err;
}
