%{
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
#include "scconf.h"
#include "internal.h"

static scconf_parser *parser;

%}

%option noyywrap
%option nounput

%%

"#"[^\n]*	scconf_parse_token(parser, TOKEN_TYPE_COMMENT, yytext);

\n		scconf_parse_token(parser, TOKEN_TYPE_NEWLINE, NULL);

[ \t]+		/* eat up whitespace */

[,{}=;]		scconf_parse_token(parser, TOKEN_TYPE_PUNCT, yytext);

\"[^\"\n]*[\"\n] scconf_parse_token(parser, TOKEN_TYPE_STRING, yytext);

[^;, \t\n]+    	scconf_parse_token(parser, TOKEN_TYPE_STRING, yytext);

%%

int scconf_lex_parse(scconf_parser *p, const char *filename)
{
	parser = p;

	yyin = fopen(filename, "r");
	if (yyin == NULL)
		return 0;

	yylex();
	yy_delete_buffer(yy_current_buffer);
	yy_current_buffer = NULL;
	fclose(yyin);
	return 1;
}
