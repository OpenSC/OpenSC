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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "common/compat_strlcat.h"
#include "scconf.h"

scconf_context *scconf_new(const char *filename)
{
	scconf_context *config;

	config = calloc(1, sizeof(scconf_context));
	if (!config) {
		return NULL;
	}
	config->filename = filename ? strdup(filename) : NULL;
	config->root = calloc(1, sizeof(scconf_block));
	if (!config->root) {
		if (config->filename) {
			free(config->filename);
		}
		free(config);
		return NULL;
	}
	return config;
}

void scconf_free(scconf_context * config)
{
	if (config) {
		scconf_block_destroy(config->root);
		if (config->filename) {
			free(config->filename);
		}
		free(config);
	}
}

const scconf_block *scconf_find_block(const scconf_context * config, const scconf_block * block, const char *item_name)
{
	scconf_item *item;

	if (!block) {
		if (!config)
			return NULL;
		block = config->root;
	}
	if (!block || !item_name) {
		return NULL;
	}
	for (item = block->items; item; item = item->next) {
		if (item->type == SCCONF_ITEM_TYPE_BLOCK &&
		    item->key && strcasecmp(item_name, item->key) == 0) {
			return item->value.block;
		}
	}
	return NULL;
}

scconf_block **scconf_find_blocks(const scconf_context * config, const scconf_block * block, const char *item_name, const char *key)
{
	scconf_block **blocks = NULL, **tmp;
	int alloc_size, size;
	scconf_item *item;

	if (!block) {
		if (!config)
			return NULL;
		block = config->root;
	}
	if (!block || !item_name) {
		return NULL;
	}
	size = 0;
	alloc_size = 10;
	tmp = (scconf_block **) realloc(blocks, sizeof(scconf_block *) * alloc_size);
	if (!tmp) {
		free(blocks);
		return NULL;
	}
	blocks = tmp;

	for (item = block->items; item; item = item->next) {
		if (item->type == SCCONF_ITEM_TYPE_BLOCK &&
		    item->key && strcasecmp(item_name, item->key) == 0) {
			if (!item->value.block)
				continue;
			if (key) {
				if (!item->value.block->name || !item->value.block->name->data ||
				    strcasecmp(key, item->value.block->name->data)) {
					continue;
				}
			}
			if (size + 1 >= alloc_size) {
				alloc_size *= 2;
				tmp = (scconf_block **) realloc(blocks, sizeof(scconf_block *) * alloc_size);
				if (!tmp) {
					free(blocks);
					return NULL;
				}
				blocks = tmp;
			}
			blocks[size++] = item->value.block;
		}
	}
	blocks[size] = NULL;
	return blocks;
}

const scconf_list *scconf_find_list(const scconf_block * block, const char *option)
{
	scconf_item *item;

	if (!block || !option)
		return NULL;

	for (item = block->items; item; item = item->next)
		if (item->type == SCCONF_ITEM_TYPE_VALUE && item->key && strcasecmp(option, item->key) == 0)
			return item->value.list;
	return NULL;
}

const char *scconf_get_str(const scconf_block * block, const char *option, const char *def)
{
	const scconf_list *list;

	list = scconf_find_list(block, option);
	if (!list || !list->data)
		return def;

	/* ignore non 'auto-configured' values */
	if (*list->data == '@' && *(list->data + strlen(list->data) - 1) == '@')
		return def;

	return list->data;
}

int scconf_get_int(const scconf_block * block, const char *option, int def)
{
	const scconf_list *list;
	char *endptr = NULL;
	long res;

	list = scconf_find_list(block, option);
	if (!list || !list->data || !*list->data) {
		return def;
	}
	errno = 0;
	res = strtol(list->data, &endptr, 0);
	if (errno == 0 && endptr != list->data && res >= INT_MIN && res <= INT_MAX) {
		return (int)res;
	}
	return def;
}

int scconf_get_bool(const scconf_block * block, const char *option, int def)
{
	const scconf_list *list;

	list = scconf_find_list(block, option);
	if (!list || !list->data || !*list->data) {
		return def;
	}
	return toupper((int)(unsigned char)*list->data) == 'T' || toupper((int)(unsigned char)*list->data) == 'Y';
}

const char *scconf_put_str(scconf_block * block, const char *option, const char *value)
{
	scconf_list *list = NULL;

	if (!block || !option)
		return NULL;

	if (!scconf_list_add(&list, value))
		return NULL;
	scconf_item_add(NULL, block, NULL, SCCONF_ITEM_TYPE_VALUE, option, list);
	scconf_list_destroy(list);
	return value;
}

int scconf_put_int(scconf_block * block, const char *option, int value)
{
	char str[64];

	if (!block || !option)
		return value;
	snprintf(str, sizeof(str), "%d", value);
	scconf_put_str(block, option, str);
	return value;
}

int scconf_put_bool(scconf_block * block, const char *option, int value)
{
	if (!block || !option)
		return value;
	scconf_put_str(block, option, !value ? "false" : "true");
	return value;
}

scconf_item *scconf_item_copy(const scconf_item * src, scconf_item ** dst)
{
	scconf_item *head = NULL, *tail = NULL;
	const scconf_item *curr;

	if (!dst)
		return NULL;
	*dst = NULL;
	if (!src)
		return NULL;

	for (curr = src; curr; curr = curr->next) {
		scconf_item *item = calloc(1, sizeof(scconf_item));
		if (!item) {
			scconf_item_destroy(head);
			*dst = NULL;
			return NULL;
		}
		item->type = curr->type;
		switch (curr->type) {
		case SCCONF_ITEM_TYPE_COMMENT:
			item->value.comment = curr->value.comment ? strdup(curr->value.comment) : NULL;
			break;
		case SCCONF_ITEM_TYPE_BLOCK:
			scconf_block_copy(curr->value.block, &item->value.block);
			break;
		case SCCONF_ITEM_TYPE_VALUE:
			scconf_list_copy(curr->value.list, &item->value.list);
			break;
		}
		item->key = curr->key ? strdup(curr->key) : NULL;
		if (!head)
			head = item;
		else
			tail->next = item;
		tail = item;
	}
	*dst = head;
	return head;
}

void scconf_item_destroy(scconf_item * item)
{
	scconf_item *next;

	while (item) {
		next = item->next;

		switch (item->type) {
		case SCCONF_ITEM_TYPE_COMMENT:
			if (item->value.comment) {
				free(item->value.comment);
			}
			item->value.comment = NULL;
			break;
		case SCCONF_ITEM_TYPE_BLOCK:
			scconf_block_destroy(item->value.block);
			break;
		case SCCONF_ITEM_TYPE_VALUE:
			scconf_list_destroy(item->value.list);
			break;
		}

		if (item->key) {
			free(item->key);
		}
		item->key = NULL;
		free(item);
		item = next;
	}
}

scconf_block *scconf_block_copy(const scconf_block * src, scconf_block ** dst)
{
	if (!dst)
		return NULL;
	*dst = NULL;
	if (src) {
		scconf_block *_dst = calloc(1, sizeof(scconf_block));
		if (!_dst) {
			return NULL;
		}
		if (src->name) {
			scconf_list_copy(src->name, &_dst->name);
		}
		if (src->items) {
			scconf_item_copy(src->items, &_dst->items);
		}
		*dst = _dst;
		return _dst;
	}
	return NULL;
}

void scconf_block_destroy(scconf_block * block)
{
	if (block) {
		scconf_list_destroy(block->name);
		scconf_item_destroy(block->items);
		free(block);
	}
}

scconf_list *scconf_list_add(scconf_list ** list, const char *value)
{
	scconf_list *rec, **tmp;

	if (!list)
		return NULL;

	rec = calloc(1, sizeof(scconf_list));
	if (!rec) {
		return NULL;
	}
	rec->data = value ? strdup(value) : NULL;

	if (!*list) {
		*list = rec;
	} else {
		for (tmp = list; *tmp; tmp = &(*tmp)->next);
		*tmp = rec;
	}
	return rec;
}

scconf_list *scconf_list_copy(const scconf_list * src, scconf_list ** dst)
{
	scconf_list *next;

	if (!dst)
		return NULL;
	*dst = NULL;
	while (src) {
		next = src->next;
		scconf_list_add(dst, src->data);
		src = next;
	}
	return *dst;
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

	while (list) {
		if (list->data)
			len += (int)strlen(list->data) + 1;
		list = list->next;
	}
	return len;
}

const char **scconf_list_toarray(const scconf_list * list)
{
	const scconf_list * lp = list;
	const char **tp;
	int len = 0;

	if (!list)
		return NULL;

	while (lp) {
		len++;
		lp = lp->next;
	}
	tp = malloc(sizeof(char *) * (len + 1));
	if (!tp)
		return NULL;
	lp = list;
	len = 0;
	while (lp) {
		tp[len] = lp->data;
		len++;
		lp = lp->next;
	}
	tp[len] = NULL;
	return tp;
}

char *scconf_list_strdup(const scconf_list * list, const char *filler)
{
	char *buf = NULL;
	int len = 0;
	size_t filler_len = 0;

	if (!list) {
		return NULL;
	}
	len = scconf_list_strings_length(list);
	if (filler) {
		filler_len = strlen(filler);
		len += scconf_list_array_length(list) * ((int)filler_len + 1);
	}
	if (len == 0)
		return NULL;
	buf = calloc(1, len + 1);
	if (!buf) {
		return NULL;
	}
	while (list) {
		if (list->data) {
			strlcat(buf, list->data, len + 1);
			if (filler) {
				strlcat(buf, filler, len + 1);
			}
		}
		list = list->next;
	}
	if (filler && filler_len > 0) {
		size_t blen = strlen(buf);
		if (blen >= filler_len)
			buf[blen - filler_len] = '\0';
	}
	return buf;
}
