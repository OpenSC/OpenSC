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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scconf.h"
#include "internal.h"

#define STATE_NAME	0x01
#define STATE_VALUE	0x02
#define STATE_SET	0x10

static void scconf_parse_error(scconf_parser * parser, const char *error)
{
	/* FIXME: save the error somewhere */
	parser->error = 1;

	fprintf(stderr, "Line %d: %s\n", parser->line, error);
}

static void scconf_parse_error_not_expect(scconf_parser * parser,
					  const char *token)
{
	/* FIXME: save the error somewhere */
	parser->error = 1;

	fprintf(stderr, "Line %d: not expecting '%s'\n", parser->line, token);
}

static void scconf_parse_warning_expect(scconf_parser * parser, const char *token)
{
	/* FIXME: save the warnings somewhere */
	parser->warnings = 1;

	fprintf(stderr, "Line %d: missing '%s', ignoring\n",
		parser->line, token);
}

static scconf_item *scconf_item_find(scconf_parser * parser, const char *key)
{
	scconf_item *item;

	for (item = parser->block->items; item; item = item->next) {
		if (item->type == SCCONF_ITEM_TYPE_VALUE &&
		    strcasecmp(item->key, parser->key) == 0) {
			return item;
		}
	}

	return item;
}

static scconf_item *scconf_item_add(scconf_parser * parser, int type)
{
	scconf_item *item;

	if (type == SCCONF_ITEM_TYPE_VALUE) {
		/* if item with same key already exists, use it */
		item = scconf_item_find(parser, parser->key);
		if (item) {
			if (parser->key) {
				free(parser->key);
			}
			parser->key = NULL;
			parser->current_item = item;
			return item;
		}
	}
	item = malloc(sizeof(scconf_item));
	if (!item) {
		return NULL;
	}
	memset(item, 0, sizeof(scconf_item));
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

static void scconf_parse_add_list(scconf_parser * parser, scconf_list ** list,
				  const char *value)
{
	scconf_list *rec, **tmp;

	rec = malloc(sizeof(scconf_list));
	if (!rec) {
		return;
	}
	memset(rec, 0, sizeof(scconf_list));
	rec->data = value ? strdup(value) : NULL;

	if (!*list) {
		*list = rec;
	} else {
		for (tmp = list; *tmp; tmp = &(*tmp)->next);
		*tmp = rec;
	}
}

static void scconf_block_add(scconf_parser * parser)
{
	scconf_block *block;
	scconf_item *item;

	item = scconf_item_add(parser, SCCONF_ITEM_TYPE_BLOCK);

	block = malloc(sizeof(scconf_block));
	if (!block) {
		return;
	}
	memset(block, 0, sizeof(scconf_block));
	block->parent = parser->block;
	item->value.block = block;

	if (!parser->name) {
		scconf_parse_add_list(parser, &parser->name, "");
	}
	block->name = parser->name;
	parser->name = NULL;

	parser->block = block;
	parser->last_item = NULL;
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
		item = scconf_item_add(parser, SCCONF_ITEM_TYPE_COMMENT);
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
			if (*token == '"') {
				/* quoted string, remove them */
				token++;
				len = strlen(token);
				if (len < 1 || token[len - 1] != '"') {
					scconf_parse_warning_expect(parser, "\"");
				} else {
					/* stoken */
					stoken = token ? strdup(token) : NULL;
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
				scconf_parse_add_list(parser, &parser->name, stoken);
			} else if (parser->state == STATE_VALUE) {
				/* value */
				parser->state |= STATE_SET;
				scconf_parse_add_list(parser,
						      &parser->current_item->value.list,
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
			scconf_block_add(parser);
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
			scconf_item_add(parser, SCCONF_ITEM_TYPE_VALUE);
			parser->state = STATE_VALUE;
			break;
		case ';':
			if ((parser->state & STATE_VALUE) == 0 ||
			    (parser->state & STATE_SET) == 0) {
				scconf_parse_error_not_expect(parser, ";");
				break;
			}
			scconf_parse_reset_state(parser);
			break;
		default:
			fprintf(stderr, "scconf_parse_token: shouldn't happen\n");
		}
		break;
	}

	parser->last_token_type = token_type;
}

int scconf_parse(scconf_context * config)
{
	scconf_parser p;

	memset(&p, 0, sizeof(p));
	p.config = config;
	p.block = config->root;
	p.line = 1;

	if (!scconf_lex_parse(&p, config->filename)) {
		return -1;
	}
	return p.error ? 0 : 1;
}
