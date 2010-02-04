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
#include <opensc/log.h>
#include "ui.h"

/*
 * Retrieve a PIN from the user.
 */
int sc_ui_get_pin(sc_ui_hints_t *hints, char **out)
{
	sc_context_t	*ctx = hints->card->ctx;
	sc_pkcs15_pin_info_t *pin_info;
	const char	*label;
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

	if (hints->prompt) {
		printf("%s", hints->prompt);
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
