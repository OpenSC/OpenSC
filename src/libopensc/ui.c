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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <opensc/opensc.h>
#include <opensc/scdl.h>
#include <opensc/log.h>
#include <opensc/ui.h>
#include "internal.h"

/*
 * We keep a global shared library handle here.
 * This is ugly; we should somehow tie this to the sc_context.
 */
static void *		sc_ui_lib_handle = NULL;
static int		sc_ui_lib_loaded = 0;

typedef int		sc_ui_get_pin_fn_t(sc_context_t *, const char *,
				const char *,
				const sc_ui_get_pin_info_t *, char **);
typedef int		sc_ui_get_pin_pair_fn_t(sc_context_t *, const char *,
				const char *,
				const sc_ui_get_pin_info_t *, char **,
				const sc_ui_get_pin_info_t *, char **);

static int		sc_ui_get_func(sc_context_t *, const char *, void **);
static int		sc_ui_get_pin_default(sc_context_t *, const char *,
				const char *,
				const sc_ui_get_pin_info_t *, char **);
static int		sc_ui_get_pin_pair_default(sc_context_t *, const char *,
				const char *,
				const sc_ui_get_pin_info_t *, char **,
				const sc_ui_get_pin_info_t *, char **);

/*
 * Retrieve a PIN from the user.
 */
int
sc_ui_get_pin(sc_context_t *ctx, const char *name, const char *prompt,
		const sc_ui_get_pin_info_t *info, char **out)
{
	static sc_ui_get_pin_fn_t *get_pin_fn;
	int		r;

	if (!get_pin_fn) {
		void	*addr;

		r = sc_ui_get_func(ctx,
				"sc_ui_get_pin_handler",
				&addr);
		if (r < 0)
			return r;
		get_pin_fn = (sc_ui_get_pin_fn_t *) addr;
		if (get_pin_fn == NULL)
			get_pin_fn = sc_ui_get_pin_default;
	}

	return get_pin_fn(ctx, name, prompt, info, out);
}

int
sc_ui_get_pin_pair(sc_context_t *ctx, const char *name, const char *prompt,
		const sc_ui_get_pin_info_t *old_info, char **old_out,
		const sc_ui_get_pin_info_t *new_info, char **new_out)
{
	static sc_ui_get_pin_pair_fn_t *get_pin_pair_fn;
	int		r;

	if (!get_pin_pair_fn) {
		void	*addr;

		r = sc_ui_get_func(ctx,
				"sc_ui_get_pin_pair_handler",
				&addr);
		if (r < 0)
			return r;
		get_pin_pair_fn = (sc_ui_get_pin_pair_fn_t *) addr;
		if (get_pin_pair_fn == NULL)
			get_pin_pair_fn = sc_ui_get_pin_pair_default;
	}

	return get_pin_pair_fn(ctx, name, prompt, 
				old_info, old_out,
				new_info, new_out);
}

/*
 * Get the named functions from the user interface
 * library. If no library is configured, or if the
 * libray doesn't define the named symbol, fall back
 * to the default function
 */
int
sc_ui_get_func(sc_context_t *ctx, const char *name, void **ret)
{
	int	r;

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

		r = sc_module_open(ctx, &sc_ui_lib_handle, lib_name);
		if (r < 0) {
			sc_error(ctx,
				"Unable to open user interface library %s\n",
				lib_name);
			return r;
		}
	}

	return sc_module_get_address(ctx, sc_ui_lib_handle, ret, name);
}

/*
 * Default ui functions
 */
int
sc_ui_get_pin_default(sc_context_t *ctx, const char *name,
				const char *prompt,
				const sc_ui_get_pin_info_t *info,
				char **out)
{
	const char	*name_hint;

	if ((name_hint = info->name_hint) == NULL)
		name_hint = "PIN";

	if (prompt) {
		printf("%s%s.\n", prompt,
			(info->flags & SC_UI_PIN_OPTIONAL)? "" :
				" (Optional - press return for no PIN)");
	}

	*out = NULL;
	while (1) {
		char	buffer[64], *pin;
		size_t	len;

		snprintf(buffer, sizeof(buffer),
				"Please enter %s: ", name_hint);
		
		if ((pin = getpass(buffer)) == NULL)
			return SC_ERROR_INTERNAL;

		len = strlen(pin);
		if (len == 0 && (info->flags & SC_UI_PIN_OPTIONAL))
			return SC_ERROR_KEYPAD_CANCELLED;

		if (info->flags & SC_UI_PIN_CHECK_LENGTH) {
			if (len < info->min_len) {
				fprintf(stderr,
					"PIN too short (min %u characters)\n",
					info->min_len);
				continue;
			}
			if (len > info->max_len) {
				fprintf(stderr,
					"PIN too long (max %u characters)\n",
					info->max_len);
				continue;
			}
		}

		*out = strdup(pin);
		memset(pin, 0, len);

		if (!(info->flags & SC_UI_PIN_RETYPE))
			break;

		pin = getpass("Please type again to verify: ");
		if (!strcmp(*out, pin)) {
			memset(pin, 0, len);
			break;
		}

		free(*out);
		*out = NULL;

		if (!(info->flags & SC_UI_PIN_MISMATCH_RETRY)) {
			fprintf(stderr, "PINs do not match.\n");
			return SC_ERROR_KEYPAD_PIN_MISMATCH;
		}

		memset(pin, 0, strlen(pin));

		/* Currently, there's no way out of this dialog.
		 * We should allow the user to bail out after n
		 * attempts. */
	}

	return 0;
}

int
sc_ui_get_pin_pair_default(sc_context_t *ctx, const char *name,
			const char *prompt,
			const sc_ui_get_pin_info_t *old_info, char **old_out,
			const sc_ui_get_pin_info_t *new_info, char **new_out)
{
	int	r;

	if (prompt)
		printf("%s\n", prompt);

	r = sc_ui_get_pin_default(ctx, "foo", NULL, old_info, old_out);
	if (r < 0)
		return r;

	return sc_ui_get_pin_default(ctx, "foo", NULL, new_info, new_out);
}
