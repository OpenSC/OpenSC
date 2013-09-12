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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "scconf.h"

#define INDENT_CHAR	'\t'
#define INDENT_LEVEL	1

typedef struct {
	FILE *f;

	int indent_char;
	int indent_pos;
	int indent_level;

	int error;
} scconf_writer;

static void write_line(scconf_writer * writer, const char *data)
{
	int i;

	if (writer->error) {
		return;
	}
	if (!((data) == NULL || (data)[0] == '\0')) {
		for (i = 0; i < writer->indent_pos; i++) {
			fputc(writer->indent_char, writer->f);
		}
		fputs(data, writer->f);
	}
	if (fputc('\n', writer->f) == EOF) {
		writer->error = errno;
	}
}

static int string_need_quotes(const char *str)
{
	/* quote only if there's any non-normal characters */
	while (*str != '\0') {
		if (!isalnum((int) ((unsigned char) *str)) && *str != '!' &&
		    *str != '.' && *str != '/') {
			return 1;
		}
		str++;
	}
	return 0;
}

static char *scconf_list_get_string(scconf_list * list)
{
	char *buffer = NULL, *tmp;
	int datalen, len, alloc_len, quote;

	if (!list) {
		return strdup("");
	}
	len = 0;
	alloc_len = 1024;
	tmp = (char *) realloc(buffer, alloc_len);
	if (!tmp) {
		free(buffer);
		return strdup("");
	}
	buffer = tmp;
	memset(buffer, 0, alloc_len);
	while (list) {
		datalen = strlen(list->data);
		if (len + datalen + 4 > alloc_len) {
			alloc_len += datalen + 2;
			tmp = (char *) realloc(buffer, alloc_len);
			if (!tmp) {
				free(buffer);
				return strdup("");
			}
			buffer = tmp;
		}
		if (len != 0) {
			memcpy(buffer + len, ", ", 2);
			len += 2;
		}
		quote = string_need_quotes(list->data);
		if (quote) {
			buffer[len++] = '"';
		}
		memcpy(buffer + len, list->data, datalen);
		len += datalen;
		if (quote) {
			buffer[len++] = '"';
		}
		list = list->next;
	}
	buffer[len] = '\0';
	return buffer;
}

static void scconf_write_items(scconf_writer * writer, const scconf_block * block)
{
	scconf_block *subblock;
	scconf_item *item;
	char *data = NULL, *name = NULL;
	size_t datalen;

	for (item = block->items; item; item = item->next) {
		switch (item->type) {
		case SCCONF_ITEM_TYPE_COMMENT:
			write_line(writer, item->value.comment);
			break;
		case SCCONF_ITEM_TYPE_BLOCK:
			subblock = item->value.block;

			if (!subblock) {
				fprintf(stderr, "scconf_write_items: Skipping invalid block!\n");
				continue;
			}

			/* header */
			name = scconf_list_get_string(subblock->name);
			datalen = strlen(item->key) + strlen(name) + 6;
			data = malloc(datalen);
			if (!data) {
				free(name);
				continue;
			}
			snprintf(data, datalen, "%s %s {", item->key, name);
			write_line(writer, data);
			free(data);
			free(name);

			/* items */
			writer->indent_pos += writer->indent_level;
			scconf_write_items(writer, subblock);
			writer->indent_pos -= writer->indent_level;

			/* footer */
			write_line(writer, "}");
			break;
		case SCCONF_ITEM_TYPE_VALUE:
			name = scconf_list_get_string(item->value.list);
			datalen = strlen(item->key) + strlen(name) + 6;
			data = malloc(datalen);
			if (!data) {
				free(name);
				continue;
			}
			snprintf(data, datalen, "%s = %s;", item->key, name);
			write_line(writer, data);
			free(data);
			free(name);
			break;
		}
	}
}

int scconf_write(scconf_context * config, const char *filename)
{
	scconf_writer writer;

	if (!filename) {
		filename = config->filename;
	}
	writer.f = fopen(filename, "w");
	if (!writer.f) {
		return errno;
	}
	writer.indent_char = INDENT_CHAR;
	writer.indent_pos = 0;
	writer.indent_level = INDENT_LEVEL;
	writer.error = 0;
	scconf_write_items(&writer, config->root);
	fclose(writer.f);
	return writer.error;
}
