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
#include "scconf.h"

void print_ldap_block(scconf_context * conf, scconf_block * block, char *cardprefix)
{
	scconf_block **blocks = NULL;
	int i;

	blocks = scconf_find_blocks(conf, block, "ldap");
	for (i = 0; blocks[i]; i++) {
		scconf_block *block = blocks[i];
		scconf_list *list, *tmp;

		printf("LDAP entry[%s%s]\n", !cardprefix ? "" : cardprefix, !block->name ? "Default" : block->name->data);
		printf("ldaphost: %s\n", scconf_find_value_first(block, "ldaphost"));
		printf("ldapport: %s\n", scconf_find_value_first(block, "ldapport"));
		printf("scope: %s\n", scconf_find_value_first(block, "scope"));
		printf("binddn: %s\n", scconf_find_value_first(block, "binddn"));
		printf("passwd: %s\n", scconf_find_value_first(block, "passwd"));
		printf("base: %s\n", scconf_find_value_first(block, "base"));
		printf("attributes: [");
		list = scconf_find_value(block, "attributes");
		for (tmp = list; tmp; tmp = tmp->next) {
			printf("%s ", tmp->data);
		}
		printf("]\n");
		printf("filter: %s\n", scconf_find_value_first(block, "filter"));
		printf("\n");
	}
	free(blocks);
}

int main(void)
{
	scconf_context *conf = NULL;
	scconf_block **blocks = NULL;
	int i;

	conf = scconf_init("test.conf");
	if (!conf) {
		printf("scconf_init failed\n");
		return 1;
	}
	if (scconf_parse(conf) < 1) {
		scconf_deinit(conf);
		return 1;
	}
	/* Parse normal LDAP blocks first */
	print_ldap_block(conf, NULL, NULL);

	/* Parse card specific LDAP blocks */
	blocks = scconf_find_blocks(conf, NULL, "card");
	for (i = 0; blocks[i]; i++) {
		scconf_block *block = blocks[i];
		char *name = NULL;

		name = scconf_list_strdup(block->name, " ");
		print_ldap_block(conf, block, name);
		if (name) {
			free(name);
		}
		name = NULL;
	}
	free(blocks);

	scconf_write(conf, "test.conf.write");
	scconf_deinit(conf);
	return 0;
}
