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
#include <stdarg.h>
#include <pwd.h>
#include <sys/types.h>
#include "sia_support.h"
#include "scam.h"

static scam_context sctx = {0,};

typedef struct _scam_msg_data {
	sia_collect_func_t *collect;
	SIAENTITY *entity;
} scam_msg_data;

static void printmsg(scam_context * sctx, char *str)
{
	scam_msg_data *msg = (scam_msg_data *) sctx->msg_data;

	if (msg->collect)
		sia_warning(msg->collect, str);
}

static void logmsg(scam_context * sctx, char *str)
{
	scam_msg_data *msg = (scam_msg_data *) sctx->msg_data;

	opensc_sia_log(str);
}

/* siad_init - Once per reboot processing goes here. */
int siad_init(void)
{
	return SIADSUCCESS;
}

/* malloc any needed space required over the authentication session here. */
int siad_ses_init(SIAENTITY * entity, int pkgind)
{
	return SIADSUCCESS;
}

/* We set the pwd entry in siad_ses_authent if we succeed in authenticating. 
 * Otherwise the BSD mechanism will incur a core dump.
 */
int siad_ses_estab(sia_collect_func_t * collect, SIAENTITY * entity, int pkgind)
{
	return SIASUCCESS;
}

int siad_ses_launch(sia_collect_func_t * collect, SIAENTITY * entity, int pkgind)
{
	return SIADSUCCESS;
}

/* Free up space malloc'd in siad_ses_init() */
int siad_ses_release(SIAENTITY * entity, int pkgind)
{
	return SIADSUCCESS;
}

int siad_get_groups(struct sia_context *context, const char *username,
		    gid_t * buf, int *numgroups, int maxgroups)
{
	log_message("siad_get_groups returning failure.\n");
	return SIADFAIL;
}

/* siad_get_name_password

 * Common code for siad_ses_authent and siad_ses_reauthent. Gather name and 
 * password if required.
 *
 * Arguments:
 * collect - prompt collection function.
 * entity - SIA entity
 * got_pass - set to 1 if we gather'd the password ourselves.
 *
 *
 * Return value:
 * SIADFAIL - failed to malloc, calling routine should return SIADFAIL.
 * SIADSUCESS - name and password have been collected (maybe not by us).
 * SIADFAIL | SIADSTOP - calling routine should return.
 */
int siad_get_name_password(sia_collect_func_t * collect, SIAENTITY * entity,
			   const char *pinentry,
			   int *got_pass)
{
	int need_name = 0, need_pass = 0, code = SIADFAIL;
	struct prompt_t prompts[2];
	const char *str = pinentry ? pinentry : DEFAULT_PINENTRY;
	int n_prompts = 0;

	*got_pass = 0;

	if ((!entity->name) || (!(*entity->name))) {
		entity->name = malloc(SIANAMEMIN + 1);
		if (entity->name == NULL) {
			log_message("siad_get_name_password: failed to malloc name.\n");
			code = SIADFAIL;
			goto fail_free;
		}
		*(entity->name) = '\0';
		need_name = 1;
	}
	if ((!entity->password) || (!(*entity->password))) {
		entity->password = malloc(SIAMXPASSWORD + 1);
		if (entity->password == NULL) {
			log_message("siad_get_name_password: failed to malloc password.\n");
			code = SIADFAIL;
			goto fail_free;
		}
		*(entity->password) = '\0';
		need_pass = 1;
	}
	if (need_name || need_pass) {
		if (!collect || !entity->colinput) {
			code = SIADFAIL;
			goto fail_free;
		}
		if (need_name) {
			prompts[n_prompts].prompt = (unsigned char *) "login: ";
			prompts[n_prompts].result = (unsigned char *) entity->name;
			prompts[n_prompts].min_result_length = 1;
			prompts[n_prompts].max_result_length = SIANAMEMIN;
			prompts[n_prompts].control_flags = SIAPRINTABLE;
			n_prompts++;
		}
		if (need_pass) {
			prompts[n_prompts].prompt = (unsigned char *) str;
			prompts[n_prompts].result = (unsigned char *) entity->password;
			prompts[n_prompts].min_result_length = 0;
			prompts[n_prompts].max_result_length = SIAMXPASSWORD;
			prompts[n_prompts].control_flags = SIARESINVIS;
			n_prompts++;
		}
		if (n_prompts > 1)
			code = (*collect) (0, SIAFORM, (uchar_t *) "", n_prompts, prompts);
		else
			code = (*collect) (240, SIAONELINER, (uchar_t *) "", 1, prompts);
		if (code != SIACOLSUCCESS) {
			code = SIADFAIL | SIADSTOP;
			goto fail_free;
		}
	}
	*got_pass = need_pass;
	return SIADSUCCESS;

      fail_free:
	if (need_name) {
		free(entity->name);
	}
	entity->name = NULL;
	if (need_pass) {
		free(entity->password);
	}
	entity->password = NULL;
	return code;
}

/* siad_ses_authent

 * Authenticate user for sia_opensc.
 *
 * This is an integrated login environment.
 *
 * entityhdl->colinput == 1 means the collect function can be used to prompt
 * for input. If it's 0, then it can only be used to print messages.
 * For this case, one also has to test for a non-null collect function.
 */
int siad_ses_authent(sia_collect_func_t * collect, SIAENTITY * entity,
		     int siastat, int pkgind)
{
	int got_pass = 0;
	int code = 0, rv;
	const char *pinentry = NULL;
	struct passwd *pwd = NULL;

	memset(&sctx, 0, sizeof(scam_context));
	if (sctx.auth_method) {
		sctx.method = scam_select_by_name(sctx.auth_method);
		free(sctx.auth_method);
		sctx.auth_method = NULL;
	}
	if (sctx.method < 0) {
		code = SIADFAIL;
		goto authent_fail;
	}
	rv = scam_init(&sctx, 0, NULL);
	if (rv != SCAM_SUCCESS) {
		code = SIADFAIL;
		goto authent_fail;
	}
	pinentry = scam_pinentry(&sctx);
	code = siad_get_name_password(collect, entity, pinentry, &got_pass);
	if (code != SIADSUCCESS) {
		goto authent_fail;
	}
	pwd = getpwnam(entity->name);
	if (!pwd) {
		/* Only authenticate if user is in /etc/passwd. */
		code = SIADFAIL;
		goto authent_fail;
	}
	if ((pwd->pw_passwd[0] == '*') && (pwd->pw_passwd[1] == '\0')) {
		log_message("siad_ses_authent: refusing to authenticate\n");
		code = SIADFAIL;
		goto authent_fail;
	}
	code = scam_auth(&sctx, 0, NULL, entity->name, entity->password);
	if (code != SCAM_SUCCESS) {
		log_message("siad_sis_authent: auth1 failure\n");
		code = SIADFAIL;
		goto authent_fail;
	}
	if (!entity->pwd) {
		entity->pwd = (struct passwd *) malloc(sizeof(struct passwd));
		if (!entity->pwd) {
			code = SIADFAIL;
			goto authent_fail;
		}
		memset((void *) entity->pwd, '\0', sizeof(struct passwd));
		if (sia_make_entity_pwd(pwd, entity) != SIASUCCESS) {
			log_message("siad_ses_authent: Can't set pwd into entity.\n");
			code = SIADFAIL;
			goto authent_fail;
		}
	}
	log_message("siad_ses_authent returning success.\n");
	opensc_sia_log("siad_ses_authent returning success.\n");
	scam_deinit(&sctx);
	return SIADSUCCESS;
      authent_fail:
	opensc_sia_log("siad_ses_authent fails, code=%d.\n", code);
	log_message("siad_ses_authent fails, code=%d.\n", code);
	scam_deinit(&sctx);
	return code;
}

/* siad_ses_reauthent.
 * Used for such things as as locking/unlocking terminal. This implies
 * authenticate, but do not set a pag. The oher differences is that we
 * accept vouching from other mechanism.
 *
 * Note the dtsession collects the password itself and will always pass it
 * in. Also, colinput is typically false in this case as well as collect
 * being null.
 */
int siad_ses_reauthent(sia_collect_func_t * collect, SIAENTITY * entity,
		       int siastat, int pkgind)
{
	int got_pass = 0;
	int code = 0, rv;
	const char *pinentry = NULL;
	struct passwd *pwd = NULL;

	if (siastat == SIADSUCCESS)
		return SIADSUCCESS;

	memset(&sctx, 0, sizeof(scam_context));
	if (sctx.auth_method) {
		sctx.method = scam_select_by_name(sctx.auth_method);
		free(sctx.auth_method);
		sctx.auth_method = NULL;
	}
	if (sctx.method < 0) {
		code = SIADFAIL;
		goto reauthent_fail;
	}
	rv = scam_init(&sctx, 0, NULL);
	if (rv != SCAM_SUCCESS) {
		code = SIADFAIL;
		goto reauthent_fail;
	}
	pinentry = scam_pinentry(&sctx);
	code = siad_get_name_password(collect, entity, pinentry, &got_pass);
	if (code != SIADSUCCESS) {
		goto reauthent_fail;
	}
	pwd = getpwnam(entity->name);
	if (!pwd) {
		code = SIADFAIL;
		goto reauthent_fail;
	}
	code = scam_auth(&sctx, 0, NULL, entity->name, entity->password);
	if (code != SCAM_SUCCESS) {
		log_message("siad_sis_reauthent: auth failure\n");
		code = SIADFAIL;
		goto reauthent_fail;
	}
	if (!entity->pwd) {
		entity->pwd = (struct passwd *) malloc(sizeof(struct passwd));
		if (!entity->pwd) {
			code = SIADFAIL;
			goto reauthent_fail;
		}
		memset((void *) entity->pwd, '\0', sizeof(struct passwd));
		if (sia_make_entity_pwd(pwd, entity) != SIASUCCESS) {
			log_message("siad_ses_reauthent: Can't set pwd into entity.\n");
			code = SIADFAIL;
			goto reauthent_fail;
		}
	}
	log_message("siad_ses_reauthent returning success.\n");
	opensc_sia_log("siad_ses_reauthent returning success.\n");
	scam_deinit(&sctx);
	return SIADSUCCESS;
      reauthent_fail:
	opensc_sia_log("siad_ses_reauthent fails, code=%d.\n", code);
	log_message("siad_ses_reauthent fails, code=%d.\n", code);
	scam_deinit(&sctx);
	return code;
}

int siad_chk_invoker(void)
{
	log_message("siad_chk_invoker returning failure.\n");
	return SIADFAIL;
}

int siad_ses_suauthent(sia_collect_func_t * collect, SIAENTITY * entity,
		       int siastat, int pkgind)
{
	log_message("siad_ses_suauthent returning failure.\n");
	return SIADFAIL;
}

int siad_chg_finger(sia_collect_func_t * collect, const char *username,
		    int argc, char *argv[])
{
	log_message("siad_chg_finger returning failure.\n");
	return SIADFAIL;
}

int siad_chg_password(sia_collect_func_t * collect, const char *username,
		      int argc, char *argv[])
{
	log_message("siad_chg_passwd returning failure.\n");
	return SIADFAIL;
}

int siad_chg_shell(sia_collect_func_t * collect, const char *username,
		   int argc, char *argv[])
{
	log_message("siad_chg_shell returning failure.\n");
	return SIADFAIL;
}

int siad_getpwent(struct passwd *result, char *buf, int bufsize,
		  struct sia_context *context)
{
	log_message("siad_getpwent returning failure.\n");
	return SIADFAIL;
}

int siad_getpwuid(uid_t uid, struct passwd *result, char *buf, int bufsize,
		  struct sia_context *context)
{
	log_message("siad_getpwuid returning failure.\n");
	return SIADFAIL;
}

int siad_getpwnam(const char *name, struct passwd *result, char *buf,
		  int bufsize, struct sia_context *context)
{
	log_message("siad_ses_getpwnam returning failure.\n");
	return SIADFAIL;
}

int siad_setpwent(struct sia_context *context)
{
	log_message("siad_ses_setpwent returning failure.\n");
	return SIADFAIL;
}

int siad_endpwent(struct sia_context *context)
{
	log_message("siad_ses_endpwent returning failure.\n");
	return SIADFAIL;
}

int siad_getgrent(struct group *result, char *buf, int bufsize,
		  struct sia_context *context)
{
	log_message("siad_ses_getgrent returning failure.\n");
	return SIADFAIL;
}

int siad_getgrgid(gid_t gid, struct group *result, char *buf, int bufsize,
		  struct sia_context *context)
{
	log_message("siad_ses_getgrgid returning failure.\n");
	return SIADFAIL;
}

int siad_getgrnam(const char *name, struct group *result, char *buf,
		  int bufsize, struct sia_context *context)
{
	log_message("siad_ses_getgrnam returning failure.\n");
	return SIADFAIL;
}

int siad_setgrent(struct sia_context *context)
{
	log_message("siad_ses_setgrent returning failure.\n");
	return SIADFAIL;
}

int siad_endgrent(struct sia_context *context)
{
	log_message("siad_ses_endgrent returning failure.\n");
	return SIADFAIL;
}

int siad_chk_user(const char *logname, int checkflag)
{
	log_message("siad_ses_chk_user returning success.\n");
	return SIADFAIL;
}

#ifdef notdef
/* These are not in the current implementation. */
void siad_ses_toggle_privs(SIAENTITY * entity, int pkgind, int elevate)
{
	log_message("siad_ses_toggle_privs.\n");
	return;
}

void siad_ses_update_audit_record(SIAENTITY * entity, int pkgind, int event,
				  char *tokenp, char **datap, int *used,
				  int maxused)
{
	log_message("siad_ses_update_audit_record.\n");
	return;
}
#endif
