/*
 * $Id$
 *
 * Copyright (C) 2002
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
#include <errno.h>
#include "scconf.h"

static int ldap_cb(scconf_context * config, const scconf_block * block, scconf_entry * entry, int depth)
{
	scconf_entry ldap_entry[] =
	{
		{"ldaphost", SCCONF_STRING, SCCONF_VERBOSE, NULL, NULL},
		{"ldapport", SCCONF_INTEGER, SCCONF_VERBOSE, NULL, NULL},
		{"scope", SCCONF_INTEGER, SCCONF_VERBOSE, NULL, NULL},
		{"binddn", SCCONF_STRING, SCCONF_VERBOSE, NULL, NULL},
		{"passwd", SCCONF_STRING, SCCONF_VERBOSE, NULL, NULL},
		{"base", SCCONF_STRING, SCCONF_VERBOSE, NULL, NULL},
		{"attributes", SCCONF_LIST, SCCONF_VERBOSE, NULL, NULL},
		{"filter", SCCONF_STRING, SCCONF_VERBOSE, NULL, NULL},
		{NULL}
	};
	char *cardprefix = (char *) entry->arg;
	char *str = scconf_list_strdup(block->name, " ");

	if (!str)
		return 1;
	printf("LDAP entry[%s%s%s]\n", cardprefix ? cardprefix : "", cardprefix ? " " : "", str);
	free(str);
	if (scconf_parse_entries(config, block, ldap_entry) != 0) {
		printf("scconf_parse_entries failed\n");
		return 1;
	}
	return 0;		/* 0 for ok, 1 for error */
}

static int card_cb(scconf_context * config, const scconf_block * block, scconf_entry * entry, int depth)
{
	char *str = scconf_list_strdup(block->name, " ");
	scconf_entry card_entry[] =
	{
		{"ldap", SCCONF_CALLBACK, SCCONF_VERBOSE | SCCONF_ALL_BLOCKS, (void *) ldap_cb, str},
		{NULL}
	};

	if (!str)
		return 1;
	printf("CARD entry[%s]\n", str);
	if (scconf_parse_entries(config, block, card_entry) != 0) {
		printf("scconf_parse_entries failed\n");
		free(str);
		return 1;
	}
	free(str);
	return 0;		/* 0 for ok, 1 for error */
}

int main(int argc, char **argv)
{
	scconf_context *conf = NULL;
	scconf_entry entry[] =
	{
		{"ldap", SCCONF_CALLBACK, SCCONF_VERBOSE | SCCONF_ALL_BLOCKS, (void *) ldap_cb},
		{"card", SCCONF_CALLBACK, SCCONF_VERBOSE | SCCONF_ALL_BLOCKS, (void *) card_cb},
		{NULL}
	};
	char *in = NULL, *out = NULL;
	int r;

	if (argc != 3) {
		printf("Usage: test-conf <in.conf> <out.conf>\n");
		return 1;
	}
	in = argv[argc - 2];
	out = argv[argc - 1];

	conf = scconf_new(in);
	if (!conf) {
		printf("scconf_new failed\n");
		return 1;
	}
	if (scconf_parse(conf) < 1) {
		printf("scconf_parse failed\n");
		scconf_free(conf);
		return 1;
	}
	conf->debug = 1;
	if (scconf_parse_entries(conf, NULL, entry) != 0) {
		printf("scconf_parse_entries failed\n");
		scconf_free(conf);
		return 1;
	}
	if ((r = scconf_write(conf, out)) != 0) {
		printf("scconf_write: %s\n", strerror(r));
	} else {
		printf("Successfully rewrote file \"%s\" as \"%s\"\n", in, out);
	}
	scconf_free(conf);
	return 0;
}
