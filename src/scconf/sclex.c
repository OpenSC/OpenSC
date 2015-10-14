/*
 * $Id$
 *
 * Copyright (C) 2003
 *  Jamie Honan <jhonan@optusnet.com.au>
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

#include "scconf.h"
#include "internal.h"

typedef struct {
	char *buf;
	size_t bufmax;
	size_t bufcur;
	int saved_char;
	const char *saved_string;
	FILE *fp;
} BUFHAN;

static void buf_init(BUFHAN * bp, FILE * fp, const char *saved_string)
{
	bp->fp = fp;
	bp->saved_char = 0;
	bp->buf = malloc(256);
	bp->bufmax = 256;
	bp->bufcur = 0;
	bp->buf[0] = '\0';
	bp->saved_string = saved_string;
}

static void buf_addch(BUFHAN * bp, char ch)
{
	if (bp->bufcur >= bp->bufmax) {
		bp->bufmax += 256;
		bp->buf = (char *) realloc(bp->buf, bp->bufmax);
	}
	if (bp->buf) {
		bp->buf[bp->bufcur++] = ch;
		bp->buf[bp->bufcur] = '\0';
	}
}

static int buf_nextch(BUFHAN * bp)
{
	int saved;

	if (bp->saved_char) {
		saved = bp->saved_char;
		bp->saved_char = 0;
		return saved;
	}
	if (bp->saved_string) {
		if (*(bp->saved_string) == '\0')
			return EOF;
		saved = (unsigned char) (*(bp->saved_string++));
		return saved;
	} else {
		saved = fgetc(bp->fp);
		return saved;
	}
}

static void buf_finished(BUFHAN * bp)
{
	if (bp->buf) {
		free(bp->buf);
		bp->buf = NULL;
	}
}

static void buf_eat_till(BUFHAN * bp, char start, const char *end)
{
	int i;

	if (start) {
		buf_addch(bp, start);
	}
	while (1) {
		i = buf_nextch(bp);
		if (i == EOF)
			return;
		if (strchr(end, i)) {
			bp->saved_char = i;
			return;
		}
		buf_addch(bp, (char) i);
	}
}

static void buf_zero(BUFHAN * bp)
{
	bp->bufcur = 0;
	bp->buf[0] = '\0';
}

static int scconf_lex_engine(scconf_parser * parser, BUFHAN * bp)
{
	int this_char;

	while (1) {
		switch (this_char = buf_nextch(bp)) {
		case '#':
			/* comment till end of line */
			buf_eat_till(bp, '#', "\r\n");
			scconf_parse_token(parser, TOKEN_TYPE_COMMENT, bp->buf);
			buf_zero(bp);
			continue;
		case '\n':
			scconf_parse_token(parser, TOKEN_TYPE_NEWLINE, NULL);
			continue;
		case ' ':
		case '\t':
		case '\r':
			/* eat up whitespace */
			continue;
		case ',':
		case '{':
		case '}':
		case '=':
		case ';':
			buf_addch(bp, (char) this_char);
			scconf_parse_token(parser, TOKEN_TYPE_PUNCT, bp->buf);
			buf_zero(bp);
			continue;
		case '"':
			buf_eat_till(bp, (char) this_char, "\"\r\n");
			buf_addch(bp, (char) buf_nextch(bp));
			scconf_parse_token(parser, TOKEN_TYPE_STRING, bp->buf);
			buf_zero(bp);
			continue;
		case EOF:
			break;
		default:
			buf_eat_till(bp, (char) this_char, ";, \t\r\n");
			scconf_parse_token(parser, TOKEN_TYPE_STRING, bp->buf);
			buf_zero(bp);
			continue;
		}
		break;
	}
	buf_finished(bp);
	return 1;
}

int scconf_lex_parse(scconf_parser * parser, const char *filename)
{
	FILE *fp;
	BUFHAN bhan;
	int ret;

	fp = fopen(filename, "r");
	if (!fp) {
		parser->error = 1;
		snprintf(parser->emesg, sizeof(parser->emesg),
			 "File %s can't be opened\n", filename);
		return 0;
	}
	buf_init(&bhan, fp, (char *) NULL);
	ret = scconf_lex_engine(parser, &bhan);
	fclose(fp);
	return ret;
}

int scconf_lex_parse_string(scconf_parser * parser, const char *string)
{
	BUFHAN bhan;
	int ret;

	buf_init(&bhan, (FILE *) NULL, string);
	ret = scconf_lex_engine(parser, &bhan);
	return ret;
}
