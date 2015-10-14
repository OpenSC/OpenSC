/**
 * user-interface.c: Support for GUI functions
 *
 * This file contains code for several related user-interface
 * functions:
 * - Ask user confirmation
 * - Let user enter pin
 *
 * Copyright (C) 2010 Juan Antonio Martinez <jonsito@terra.es>
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

#ifndef __USER_INTERFACE_H__
#define __USER_INTERFACE_H__

/**
 * To handle user interface routines
 */
typedef struct ui_context {
    int user_consent_enabled;
    char *user_consent_app;
} ui_context_t;

struct sc_card;
struct sc_pin_cmd_pin;

/**
 * Ask for user consent.
 *
 * Check for user consent configuration,
 * invoke proper gui app and check result
 *
 * @param card pointer to sc_card structure
 * @param title Text to appear in the window header
 * @param text Message to show to the user
 * @return SC_SUCCESS if user accepts , else error code
 */
int sc_ask_user_consent(struct sc_card * card, const char *title, const char *message);

/**
 * Ask user for pin.
 *
 * Check the user pin configuration,
 * invoke proper gui app and check result
 *
 * @param card pointer to sc_card structure
 * @param title Text to appear in the window header
 * @param pin Structure to handle/store pin related data
 * @return SC_SUCCESS if user accepts , else error code
 */
int sc_ask_user_pin(struct sc_card * card, const char *title, struct sc_pin_cmd_pin *pin);

#endif
