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
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "scconf.h"

#define STATE_NAME	0x01
#define STATE_VALUE	0x02
#define STATE_SET	0x10

static scconf_item *scconf_get_last_item(scconf_block *root)
{
	scconf_block *block = root;
	scconf_item *item;

	for (item = root->items; item; item = item->next) {
		if (!item->next) {
			return item;
		}
	}
	return block->items;
}

static void scconf_parse_error(scconf_parser * parser, const char *error)
{
	/* FIXME: save the error somewhere */
	parser->error = 1;

	snprintf(parser->emesg, sizeof(parser->emesg), "Line %d: %s\n", parser->line, error);
}

static void scconf_parse_error_not_expect(scconf_parser * parser,
					  const char *token)
{
	/* FIXME: save the error somewhere */
	parser->error = 1;

	snprintf(parser->emesg, sizeof(parser->emesg), "Line %d: not expecting '%s'\n", parser->line, token);
}

static void scconf_parse_warning_expect(scconf_parser * parser, const char *token)
{
	/* FIXME: save the warnings somewhere */
	parser->warnings = 1;

	snprintf(parser->emesg, sizeof(parser->emesg),
		"Line %d: missing '%s', ignoring\n",
		parser->line, token);
}

static scconf_item *scconf_item_find(scconf_parser * parser)
{
	scconf_item *item;

	for (item = parser->block->items; item; item = item->next) {
		if (item && item->type == SCCONF_ITEM_TYPE_VALUE
			   	&& item->key && parser->key
			   	&& strcasecmp(item->key, parser->key) == 0) {
			return item;
		}
	}
	return item;
}

static scconf_item *scconf_item_add_internal(scconf_parser * parser, int type)
{
	scconf_item *item;

	if (type == SCCONF_ITEM_TYPE_VALUE) {
		/* if item with same key already exists, use it */
		item = scconf_item_find(parser);
		if (item) {
			free(parser->key);
			parser->key = NULL;
			parser->current_item = item;
			return item;
		}
	}
	item = calloc(1, sizeof(scconf_item));
	if (!item) {
		return NULL;
	}
	item->type = type;

	item->key = parser->key;
	parser->key = NULL;

	if (parser->last_item) {
		parser->last_item->next = item;
	} else {
		parser->block->items = item;
	}
	parser->current_item = parser->last_item = item;
	return item;
}

scconf_item *scconf_item_add(scconf_context * config, scconf_block * block, scconf_item * item, int type, const char *key, const void *data)
{
	scconf_parser parser;
	scconf_block *dst = NULL;

	if (!config && !block)
		return NULL;
	if (!data)
		return NULL;

	memset(&parser, 0, sizeof(scconf_parser));
	parser.config = config ? config : NULL;
	parser.key = key ? strdup(key) : NULL;
	parser.block = block ? block : config->root;
	parser.name = NULL;
	parser.last_item = scconf_get_last_item(parser.block);
	parser.current_item = item;

	if (type == SCCONF_ITEM_TYPE_BLOCK) {
		scconf_block_copy((const scconf_block *) data, &dst);
		scconf_list_copy(dst->name, &parser.name);
	}
	if (scconf_item_add_internal(&parser, type)) {
		switch (parser.current_item->type) {
			case SCCONF_ITEM_TYPE_COMMENT:
				parser.current_item->value.comment = strdup((const char *) data);
				break;
			case SCCONF_ITEM_TYPE_BLOCK:
				if (!dst)
					return NULL;
				dst->parent = parser.block;
				parser.current_item->value.block = dst;
				scconf_list_destroy(parser.name);
				break;
			case SCCONF_ITEM_TYPE_VALUE:
				scconf_list_copy((const scconf_list *) data, &parser.current_item->value.list);
				break;
		}
	} else {
		/* FIXME is it an error if item is NULL? */
		free(parser.key);
		parser.key = NULL;
	}
	return parser.current_item;
}

static void scconf_block_add_internal(scconf_parser * parser)
{
	scconf_block *block;
	scconf_item *item;

	item = scconf_item_add_internal(parser, SCCONF_ITEM_TYPE_BLOCK);
	if (!item) {
		return;
	}

	block = calloc(1, sizeof(scconf_block));
	if (!block) {
		return;
	}
	block->parent = parser->block;
	item->value.block = block;

	if (!parser->name) {
		scconf_list_add(&parser->name, "");
	}
	block->name = parser->name;
	parser->name = NULL;

	parser->block = block;
	parser->last_item = NULL;
}

scconf_block *scconf_block_add(scconf_context * config, scconf_block * block, const char *key, const scconf_list *name)
{
	scconf_parser parser;

	if (!config)
		return NULL;

	memset(&parser, 0, sizeof(scconf_parser));
	parser.config = config;
	parser.key = key ? strdup(key) : NULL;
	parser.block = block ? block : config->root;
	scconf_list_copy(name, &parser.name);
	parser.last_item = scconf_get_last_item(parser.block);
	parser.current_item = parser.block->items;

	scconf_block_add_internal(&parser);
	return parser.block;
}

static void scconf_parse_parent(scconf_parser * parser)
{
	parser->block = parser->block->parent;

	parser->last_item = parser->block->items;
	if (parser->last_item) {
		while (parser->last_item->next) {
			parser->last_item = parser->last_item->next;
		}
	}
}

static void scconf_parse_reset_state(scconf_parser * parser)
{
	if (parser) {
		if (parser->key) {
			free(parser->key);
		}
		scconf_list_destroy(parser->name);

		parser->key = NULL;
		parser->name = NULL;
		parser->state = 0;
	}
}

void scconf_parse_token(scconf_parser * parser, int token_type, const char *token)
{
	scconf_item *item;
	int len;

	if (parser->error) {
		/* fatal error */
		return;
	}
	switch (token_type) {
	case TOKEN_TYPE_NEWLINE:
		parser->line++;
		if (parser->last_token_type != TOKEN_TYPE_NEWLINE) {
			break;
		}
		/* fall through - treat empty lines as comments */
	case TOKEN_TYPE_COMMENT:
		item = scconf_item_add_internal(parser, SCCONF_ITEM_TYPE_COMMENT);
		if (!item) {
			return;
		}
		item->value.comment = token ? strdup(token) : NULL;
		break;
	case TOKEN_TYPE_STRING:
		{
			char *stoken = NULL;

			if ((parser->state & (STATE_VALUE | STATE_SET)) ==
			    (STATE_VALUE | STATE_SET)) {
				scconf_parse_warning_expect(parser, ";");
				scconf_parse_reset_state(parser);
			}
			if (token && *token == '"') {
				/* quoted string, remove them */
				token++;
				len = strlen(token);
				if (len < 1 || token[len - 1] != '"') {
					scconf_parse_warning_expect(parser, "\"");
				} else {
					/* stoken */
					stoken = strdup(token);
					if (stoken) {
						stoken[len - 1] = '\0';
					}
				}
			}
			if (!stoken) {
				stoken = token ? strdup(token) : NULL;
			}
			if (parser->state == 0) {
				/* key */
				parser->key = stoken ? strdup(stoken) : NULL;
				parser->state = STATE_NAME;
			} else if (parser->state == STATE_NAME) {
				/* name */
				parser->state |= STATE_SET;
				scconf_list_add(&parser->name, stoken);
			} else if (parser->state == STATE_VALUE) {
				/* value */
				parser->state |= STATE_SET;
				scconf_list_add(&parser->current_item->value.list,
						      stoken);
			} else {
				/* error */
				scconf_parse_error_not_expect(parser, stoken);
			}
			if (stoken) {
				free(stoken);
			}
			stoken = NULL;
		}
		break;
	case TOKEN_TYPE_PUNCT:
		switch (*token) {
		case '{':
			if ((parser->state & STATE_NAME) == 0) {
				scconf_parse_error_not_expect(parser, "{");
				break;
			}
			scconf_block_add_internal(parser);
			scconf_parse_reset_state(parser);
			break;
		case '}':
			if (parser->state != 0) {
				if ((parser->state & STATE_VALUE) == 0 ||
				    (parser->state & STATE_SET) == 0) {
					scconf_parse_error_not_expect(parser,
								      "}");
					break;
				}
				/* foo = bar } */
				scconf_parse_warning_expect(parser, ";");
				scconf_parse_reset_state(parser);
			}
			if (!parser->block->parent) {
				/* too many '}' */
				scconf_parse_error(parser,
						   "missing matching '{'");
				break;
			}
			scconf_parse_parent(parser);
			break;
		case ',':
			if ((parser->state & (STATE_NAME | STATE_VALUE)) == 0) {
				scconf_parse_error_not_expect(parser, ",");
			}
			parser->state &= ~STATE_SET;
			break;
		case '=':
			if ((parser->state & STATE_NAME) == 0) {
				scconf_parse_error_not_expect(parser, "=");
				break;
			}
			scconf_item_add_internal(parser, SCCONF_ITEM_TYPE_VALUE);
			parser->state = STATE_VALUE;
			break;
		case ';':
			scconf_parse_reset_state(parser);
			break;
		default:
			snprintf(parser->emesg, sizeof(parser->emesg),
				"Line %d: bad token ignoring\n",
				parser->line);
		}
		break;
	}

	parser->last_token_type = token_type;
}

int scconf_parse(scconf_context * config)
{
	static char buffer[256];
	scconf_parser p;
	int r = 1;

	memset(&p, 0, sizeof(p));
	p.config = config;
	p.block = config->root;
	p.line = 1;

	if (!scconf_lex_parse(&p, config->filename)) {
		snprintf(buffer, sizeof(buffer),
				"Unable to open \"%s\": %s",
				config->filename, strerror(errno));
		r = -1;
	} else if (p.error) {
		strlcpy(buffer, p.emesg, sizeof(buffer));
		r = 0;
	} else {
		r = 1;
	}

	if (r <= 0)
		config->errmsg = buffer;
	return r;
}

int scconf_parse_string(scconf_context * config, const char *string)
{
	static char buffer[256];
	scconf_parser p;
	int r;

	memset(&p, 0, sizeof(p));
	p.config = config;
	p.block = config->root;
	p.line = 1;

	if (!scconf_lex_parse_string(&p, string)) {
		snprintf(buffer, sizeof(buffer),
				"Failed to parse configuration string");
		r = -1;
	} else if (p.error) {
		strlcpy(buffer, p.emesg, sizeof(buffer));
		r = 0;
	} else {
		r = 1;
	}

	if (r <= 0)
		config->errmsg = buffer;
	return r;
}
