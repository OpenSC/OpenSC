/*
 * $Id$
 *
 * Copyright (C) 2001, 2002
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

#ifndef _SC_LDAP_H
#define _SC_LDAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <opensc/scconf.h>

/* Hard limit, tables are allocated dynamically */
#define SCLDAP_MAX_ENTRIES            16
#define SCLDAP_MAX_ATTRIBUTES         32
#define SCLDAP_MAX_RESULTS            64

typedef struct _scldap_param_entry {
	char *entry;
	char *ldaphost;
	unsigned int ldapport;
	unsigned int scope;
	char *binddn;
	char *passwd;
	char *base;
	unsigned int attrsonly, numattrs;
	char **attributes;
	char *filter;
} scldap_param_entry;

typedef struct _scldap_context {
	unsigned entries, active;
	scconf_context *conf;
	scldap_param_entry *entry;
} scldap_context;

typedef struct _scldap_result_entry {
	char *name;
	char *dn;
	unsigned char *data;
	unsigned long datalen;
	unsigned int binary;
} scldap_result_entry;

typedef struct _scldap_result {
	unsigned results;
	scldap_result_entry *result;
} scldap_result;

/* Allocate scldap_context
 * The filename can be NULL
 */
extern scldap_context *scldap_parse_parameters(const char *filename);

/* Print all entries and configurations to stdout
 */
extern void scldap_show_parameters(scldap_context * ctx);

/* Free scldap_context
 */
extern void scldap_free_parameters(scldap_context * ctx);

/* Parse command line arguments
 */
extern void scldap_parse_arguments(scldap_context ** ctx, int argc, const char **argv);

/* Return a string that contains all
 * known command line arguments
 */
extern const char *scldap_show_arguments(void);

/* Add new configuration entry
 */
extern int scldap_add_entry(scldap_context * ctx, const char *entry);

/* Return entry index number
 */
extern int scldap_get_entry(scldap_context * ctx, const char *entry);

/* Set entry as the current active entry
 */
extern void scldap_set_entry(scldap_context * ctx, const char *entry);

/* Remove entry and all configurations for it
 */
extern void scldap_remove_entry(scldap_context * ctx, const char *entry);

/* See if the string is a valid URL
 * Returns 1 = ok, 0 = not valid
 */
extern int scldap_is_valid_url(const char *url);

/* Convert URL to a search entry
 */
extern int scldap_url_to_entry(scldap_context * ctx, const char *entry, const char *url);

extern int scldap_approx_base_by_dn(scldap_context * ctx, const char *entry, const char *dn, char **base);

/* Split DN to result entries
 *
 * If notypes is a non-zero, just values
 * will be added to result entries
 */
extern int scldap_dn_to_result(const char *dn, scldap_result ** result, int notypes);

/* Search data from LDAP server
 *
 * If numwantedresults is a non-zero, we require
 * that the given value will match with the number
 * of the actual results we have got from the server
 */
extern int scldap_search(scldap_context * ctx, const char *entry,
			 scldap_result ** result, unsigned int numwantedresults,
			 const char *searchpattern);

/* Free search results
 */
extern void scldap_free_result(scldap_result * result);

#ifdef __cplusplus
}
#endif
#endif
