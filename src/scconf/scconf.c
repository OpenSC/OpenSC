/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
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
#include <stdlib.h>
#include <string.h>
#include "scconf.h"

scconf_context *scconf_init(const char *filename)
{
	scconf_context *config;

	config = malloc(sizeof(scconf_context));
	if (!config) {
		return NULL;
	}
	memset(config, 0, sizeof(scconf_context));
	config->filename = filename ? strdup(filename) : NULL;
	config->root = malloc(sizeof(scconf_block));
	if (!config->root) {
		if (config->filename) {
			free(config->filename);
		}
		free(config);
		return NULL;
	}
	memset(config->root, 0, sizeof(scconf_block));
	return config;
}

void scconf_deinit(scconf_context * config)
{
	if (config) {
		scconf_block_destroy(config->root);
		if (config->filename) {
			free(config->filename);
		}
		free(config);
	}
	config = NULL;
}

const scconf_block *scconf_find_block(scconf_context * config, const scconf_block * block, const char *item_name)
{
	scconf_item *item;

	if (!block) {
		block = config->root;
	}
	if (!item_name) {
		return NULL;
	}
	for (item = block->items; item; item = item->next) {
		if (item->type == SCCONF_ITEM_TYPE_BLOCK &&
		    strcasecmp(item_name, item->key) == 0) {
			return item->value.block;
		}
	}
	return NULL;
}

scconf_block **scconf_find_blocks(scconf_context * config, const scconf_block * block, const char *item_name, const char *key)
{
	scconf_block **blocks = NULL;
	int alloc_size, size;
	scconf_item *item;

	if (!block) {
		block = config->root;
	}
	if (!item_name) {
		return NULL;
	}
	size = 0;
	alloc_size = 10;
	blocks = realloc(blocks, sizeof(scconf_block *) * alloc_size);

	for (item = block->items; item; item = item->next) {
		if (item->type == SCCONF_ITEM_TYPE_BLOCK &&
		    strcasecmp(item_name, item->key) == 0) {
			if (key && strcasecmp(key, item->value.block->name->data)) {
				continue;
			}
			if (size + 1 >= alloc_size) {
				alloc_size *= 2;
				blocks = realloc(blocks, sizeof(scconf_block *) * alloc_size);
			}
			blocks[size++] = item->value.block;
		}
	}
	blocks[size] = NULL;
	return blocks;
}

const scconf_list *scconf_find_value(const scconf_block * block, const char *option)
{
	scconf_item *item;

	if (!block) {
		return NULL;
	}
	for (item = block->items; item; item = item->next) {
		if (item->type == SCCONF_ITEM_TYPE_VALUE &&
		    strcasecmp(option, item->key) == 0) {
			return item->value.list;
		}
	}
	return NULL;
}

const char *scconf_find_value_first(const scconf_block * block, const char *option)
{
	const scconf_list *list;

	if (!block) {
		return NULL;
	}
	list = scconf_find_value(block, option);
	return !list ? NULL : list->data;
}

void scconf_list_destroy(scconf_list * list)
{
	scconf_list *next;

	while (list) {
		next = list->next;
		if (list->data) {
			free(list->data);
		}
		free(list);
		list = next;
	}
}

void scconf_block_destroy(scconf_block * block);

static void scconf_items_destroy(scconf_item * items)
{
	scconf_item *next;

	while (items) {
		next = items->next;

		switch (items->type) {
		case SCCONF_ITEM_TYPE_COMMENT:
			if (items->value.comment) {
				free(items->value.comment);
			}
			items->value.comment = NULL;
			break;
		case SCCONF_ITEM_TYPE_BLOCK:
			scconf_block_destroy(items->value.block);
			break;
		case SCCONF_ITEM_TYPE_VALUE:
			scconf_list_destroy(items->value.list);
			break;
		}

		if (items->key) {
			free(items->key);
		}
		items->key = NULL;
		free(items);
		items = next;
	}
}

void scconf_block_destroy(scconf_block * block)
{
	if (block) {
		scconf_list_destroy(block->name);
		scconf_items_destroy(block->items);
		free(block);
	}
}

int scconf_list_array_length(const scconf_list * list)
{
	int len = 0;

	while (list) {
		len++;
		list = list->next;
	}
	return len;
}

int scconf_list_strings_length(const scconf_list * list)
{
	int len = 0;

	while (list && list->data) {
		len += strlen(list->data) + 1;
		list = list->next;
	}
	return len;
}

char *scconf_list_strdup(const scconf_list * list, const char *filler)
{
	char *buf = NULL;
	int len = 0;

	if (!list) {
		return NULL;
	}
	len = scconf_list_strings_length(list);
	if (filler) {
		len += scconf_list_array_length(list) * (strlen(filler) + 1);
	}
	buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	memset(buf, 0, len);
	while (list && list->data) {
		strcat(buf, list->data);
		if (filler) {
			strcat(buf, filler);
		}
		list = list->next;
	}
	return buf;
}
