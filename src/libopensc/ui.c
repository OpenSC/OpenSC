/*
 * User interface layer. This library adds an abstraction layer to
 * user interaction, allowing to configure at run time with ui
 * to use (tty, qt, gnome, win32, ...)
 *
 * Dynamically loads user interface libraries for different platforms,
 * if configured. Otherwise, uses default functions that communicate
 * with the user through stdin/stdout.
 *
 * Copyright (C) 2003  Olaf Kirch <okir@lse.de>
 */

#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#include <compat_getpass.h>
#include <ltdl.h>

/*
 * We keep a global shared library handle here.
 * This is ugly; we should somehow tie this to the sc_context.
 */
static void *		sc_ui_lib_handle = NULL;
static int		sc_ui_lib_loaded = 0;

typedef int		sc_ui_get_pin_fn_t(sc_ui_hints_t *, char **);
typedef int		sc_ui_get_pin_pair_fn_t(sc_ui_hints_t *,
				char **, char **);
typedef int		sc_ui_display_fn_t(sc_context_t *, const char *);

static int		sc_ui_get_func(sc_context_t *, const char *, void **);
static int		sc_ui_get_pin_default(sc_ui_hints_t *, char **);
static int		sc_ui_get_pin_pair_default(sc_ui_hints_t *,
				char **, char **);
static int		sc_ui_display_error_default(sc_context_t *, const char *);
static int		sc_ui_display_debug_default(sc_context_t *, const char *);

static int		__sc_ui_read_pin(sc_context_t *, const char *,
				const char *label, int flags,
				sc_pkcs15_pin_info_t *pin_info,
				char **out);

/*
 * Set the language
 */
int
sc_ui_set_language(sc_context_t *ctx, const char *lang)
{
	if (ctx->preferred_language)
		free(ctx->preferred_language);
	ctx->preferred_language = NULL;
	if (lang)
		ctx->preferred_language = strdup(lang);
	return 0;
}

/*
 * Retrieve a PIN from the user.
 */
int
sc_ui_get_pin(sc_ui_hints_t *hints, char **out)
{
	static sc_ui_get_pin_fn_t *get_pin_fn, **t_fn = &get_pin_fn;
	int		r;

	if (!get_pin_fn) {
		void	*addr;

		r = sc_ui_get_func(hints->card->ctx,
				"sc_ui_get_pin_handler",
				&addr);
		if (r < 0)
			return r;
		*(void **)(t_fn) = addr;
		if (get_pin_fn == NULL)
			get_pin_fn = sc_ui_get_pin_default;
	}

	return get_pin_fn(hints, out);
}

int
sc_ui_get_pin_pair(sc_ui_hints_t *hints, char **old_out, char **new_out)
{
	static sc_ui_get_pin_pair_fn_t *get_pin_pair_fn, **t_fn = &get_pin_pair_fn;
	int		r;

	if (!get_pin_pair_fn) {
		void	*addr;

		r = sc_ui_get_func(hints->card->ctx,
				"sc_ui_get_pin_pair_handler",
				&addr);
		if (r < 0)
			return r;
		*(void **)(t_fn) = addr;
		if (get_pin_pair_fn == NULL)
			get_pin_pair_fn = sc_ui_get_pin_pair_default;
	}

	return get_pin_pair_fn(hints, old_out, new_out);
}

int
sc_ui_display_error(sc_context_t *ctx, const char *msg)
{
	static sc_ui_display_fn_t *display_fn, **t_fn = &display_fn;
	int		r;

	if (!display_fn) {
		void	*addr;

		r = sc_ui_get_func(ctx,
				"sc_ui_display_error_handler",
				&addr);
		if (r < 0)
			return r;
		*(void **)(t_fn) = addr;
		if (display_fn == NULL)
			display_fn = sc_ui_display_error_default;
	}

	return display_fn(ctx, msg);
}

int
sc_ui_display_debug(sc_context_t *ctx, const char *msg)
{
	static sc_ui_display_fn_t *display_fn, **t_fn = &display_fn;
	int		r;

	if (!display_fn) {
		void	*addr;

		r = sc_ui_get_func(ctx,
				"sc_ui_display_debug_handler",
				&addr);
		if (r < 0)
			return r;
		*(void **)t_fn = addr;
		if (display_fn == NULL)
			display_fn = sc_ui_display_debug_default;
	}

	return display_fn(ctx, msg);
}

/*
 * Get the named functions from the user interface
 * library. If no library is configured, or if the
 * libray doesn't define the named symbol, fall back
 * to the default function
 */
static int sc_ui_get_func(sc_context_t *ctx, const char *name, void **ret)
{
	*ret = NULL;
	if (!sc_ui_lib_handle && !sc_ui_lib_loaded) {
		const char	*lib_name = NULL;
		scconf_block	*blk;
		int		i;

		/* Prevent recursion */
		sc_ui_lib_loaded = 1;

		for (i = 0; (blk = ctx->conf_blocks[i]); i++) {
			lib_name = scconf_get_str(blk,
				       	"user_interface",
					NULL);
			if (lib_name)
				break;
		}

		if (!lib_name)
			return 0;

		sc_ui_lib_handle = lt_dlopen(lib_name);
		if (!sc_ui_lib_handle) {
			sc_error(ctx,
				"Unable to open user interface library '%s': %s\n",
				lib_name, lt_dlerror());
			return SC_ERROR_INTERNAL;
		}
	}

	if (sc_ui_lib_handle == NULL)
		return 0;

	*ret = lt_dlsym(sc_ui_lib_handle, name);

	return *ret ? SC_SUCCESS : SC_ERROR_UNKNOWN;
}

/*
 * Default ui functions
 */
static int sc_ui_get_pin_default(sc_ui_hints_t *hints, char **out)
{
	sc_context_t	*ctx = hints->card->ctx;
	sc_pkcs15_pin_info_t *pin_info;
	const char	*label, *language = "en";
	int		flags = hints->flags;

	pin_info = hints->info.pin;
	if (!(label = hints->obj_label)) {
		if (pin_info == NULL) {
			label = "PIN";
		} else if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
			label = "Security Officer PIN";
		} else {
			label = "User PIN";
		}
	}

	if (hints->p15card) {
		/* TBD: get preferredCard from TokenInfo */
	}

#if defined(HAVE_SETLOCALE) && !defined(_WIN32)
	setlocale(LC_MESSAGES, language);
#else
	(void) language;
#endif

	return __sc_ui_read_pin(ctx, hints->prompt, label,
				flags, pin_info, out);
}

static int sc_ui_get_pin_pair_default(sc_ui_hints_t *hints, char **old_out,
				char **new_out)
{
	sc_context_t	*ctx = hints->card->ctx;
	sc_pkcs15_pin_info_t *pin_info;
	const char	*label, *language = "en";
	int		r, flags = hints->flags, old_flags;

	if (hints->prompt)
		printf("%s\n", hints->prompt);

	pin_info = hints->info.pin;
	if (!(label = hints->obj_label)) {
		if (pin_info == NULL) {
			label = "PIN";
		} else if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
			label = "Security Officer PIN";
		} else {
			label = "User PIN";
		}
	}

	if (hints->p15card) {
		/* TBD: get preferredCard from TokenInfo */
	}

#if defined(HAVE_SETLOCALE) && !defined(_WIN32)
	setlocale(LC_MESSAGES, language);
#else
	(void) language;
#endif

	old_flags = flags;
	if (hints->usage == SC_UI_USAGE_UNBLOCK_PIN
	 || hints->usage == SC_UI_USAGE_CHANGE_PIN) {
		old_flags &= ~(SC_UI_PIN_RETYPE|SC_UI_PIN_CHECK_LENGTH);
	}

	r = __sc_ui_read_pin(ctx, NULL, label, old_flags, NULL, old_out);
	if (r >= 0)
		r = __sc_ui_read_pin(ctx, NULL, label, flags, NULL, new_out);

	return r;
}

static int __sc_ui_read_pin(sc_context_t *ctx, const char *prompt,
			const char *label, int flags,
			sc_pkcs15_pin_info_t *pin_info,
			char **out)
{
	if (prompt) {
		printf("%s", prompt);
		if (flags & SC_UI_PIN_OPTIONAL)
			printf(" (Optional - press return for no PIN)");
		printf(".\n");
	}

	*out = NULL;
	while (1) {
		char	buffer[64], *pin;
		size_t	len;

		snprintf(buffer, sizeof(buffer),
				"Please enter %s: ", label);
		
		if ((pin = getpass(buffer)) == NULL)
			return SC_ERROR_INTERNAL;

		len = strlen(pin);
		if (len == 0 && (flags & SC_UI_PIN_OPTIONAL))
			return 0;

		if (pin_info && (flags & SC_UI_PIN_CHECK_LENGTH)) {
			if (len < pin_info->min_length) {
				fprintf(stderr,
					"PIN too short (min %lu characters)\n",
					(unsigned long) pin_info->min_length);
				continue;
			}
			if (pin_info->max_length
			 && len > pin_info->max_length) {
				fprintf(stderr,
					"PIN too long (max %lu characters)\n",
					(unsigned long) pin_info->max_length);
				continue;
			}
		}

		*out = strdup(pin);
		sc_mem_clear(pin, len);

		if (!(flags & SC_UI_PIN_RETYPE))
			break;

		pin = getpass("Please type again to verify: ");
		if (!strcmp(*out, pin)) {
			sc_mem_clear(pin, len);
			break;
		}

		free(*out);
		*out = NULL;

		if (!(flags & SC_UI_PIN_MISMATCH_RETRY)) {
			fprintf(stderr, "PINs do not match.\n");
			return SC_ERROR_KEYPAD_PIN_MISMATCH;
		}

		fprintf(stderr,
			"Sorry, the two pins did not match. "
			"Please try again.\n");
		sc_mem_clear(pin, strlen(pin));

		/* Currently, there's no way out of this dialog.
		 * We should allow the user to bail out after n
		 * attempts. */
	}

	return 0;
}

/*
 * Default debug/error message output
 */
static int
use_color(sc_context_t *ctx, FILE * outf)
{
	static const char *terms[] = { "linux", "xterm", "Eterm", "rxvt", "rxvt-unicode" };
	static char	*term = NULL;
	int		term_count = sizeof(terms) / sizeof(terms[0]);
	int		do_color, i;

	if (!isatty(fileno(outf)))
		return 0;
	if (term == NULL) {
		term = getenv("TERM");
		if (term == NULL)
			return 0;
	}

	do_color = 0;
	for (i = 0; i < term_count; i++) {
		if (strcmp(terms[i], term) == 0) {
			do_color = 1;
			break;
		}
	}

	return do_color;
}

static int
sc_ui_display_msg(sc_context_t *ctx, int type, const char *msg)
{
	const char	*color_pfx = "", *color_sfx = "";
	FILE		*outf = NULL;
	int		n;

	switch (type) {
	case SC_LOG_TYPE_ERROR:
		outf = ctx->error_file;
		break;

	case SC_LOG_TYPE_DEBUG:
		outf = ctx->debug_file;
		break;
	}
	if (outf == NULL)
		return 0;

	if (use_color(ctx, outf)) {
		color_sfx = "\33[0m";
		switch (type) {
		case SC_LOG_TYPE_ERROR:
			color_pfx = "\33[01;31m";
			break;
		case SC_LOG_TYPE_DEBUG:
			color_pfx = "\33[00;32m";
			break;
		}
	}

	fprintf(outf, "%s%s%s", color_pfx, msg, color_sfx);
	n = strlen(msg);
	if (n == 0 || msg[n-1] != '\n')
		fprintf(outf, "\n");
	fflush(outf);
	return 0;
}

static int sc_ui_display_error_default(sc_context_t *ctx, const char *msg)
{
	return sc_ui_display_msg(ctx, SC_LOG_TYPE_ERROR, msg);
}

static int sc_ui_display_debug_default(sc_context_t *ctx, const char *msg)
{
	return sc_ui_display_msg(ctx, SC_LOG_TYPE_DEBUG, msg);
}
