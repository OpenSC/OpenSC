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

void print_ldap_block(scconf_context * conf, scconf_block * block)
{
	scconf_block **blocks = NULL;
	unsigned int i;

	blocks = scconf_find_blocks(conf, block, "ldap", NULL);
	for (i = 0; blocks[i]; i++) {
		const scconf_block *block = blocks[i];
		const scconf_list *list, *tmp;

		printf("LDAP entry[%s]\n", block->name->data);
		printf("ldaphost: %s\n", scconf_get_str(block, "ldaphost", NULL));
		printf("ldapport: %s\n", scconf_get_str(block, "ldapport", NULL));
		printf("scope: %s\n", scconf_get_str(block, "scope", NULL));
		printf("binddn: %s\n", scconf_get_str(block, "binddn", NULL));
		printf("passwd: %s\n", scconf_get_str(block, "passwd", NULL));
		printf("base: %s\n", scconf_get_str(block, "base", NULL));
		printf("attributes: [");
		list = scconf_find_list(block, "attributes");
		for (tmp = list; tmp; tmp = tmp->next) {
			printf(" %s", tmp->data);
		}
		printf(" ]\n");
		printf("filter: %s\n", scconf_get_str(block, "filter", NULL));
		printf("\n");
	}
	free(blocks);
}

int main(int argc, char **argv)
{
	scconf_context *conf = NULL;
	char *in = NULL, *out = NULL;
	int r;

	if (argc != 3) {
		printf("Usage: test-conf <in.conf> <out.conf>\n");
		return 1;
	}
	in = argv[argc - 2];
	out = argv[argc - 1];

	conf = scconf_init(in);
	if (!conf) {
		printf("scconf_init failed\n");
		return 1;
	}
	if (scconf_parse(conf) < 1) {
		printf("scconf_parse failed\n");
		scconf_deinit(conf);
		return 1;
	}
	/* See if the file contains any ldap configuration blocks */
	print_ldap_block(conf, NULL);

	if ((r = scconf_write(conf, out)) != 0) {
		printf("scconf_write: %s\n", strerror(r));
	} else {
		printf("Successfully rewrote file \"%s\" as \"%s\"\n", in, out);
	}
	scconf_deinit(conf);
	return 0;
}
