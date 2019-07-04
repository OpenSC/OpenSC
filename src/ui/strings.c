/*
 * strings.c: Implementation of default UI strings
 *
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
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

#include "libopensc/internal.h"
#include "ui/strings.h"
#include <locale.h>
#include <stdlib.h>
#include <string.h>

enum ui_langs {
	EN,
	DE,
};

static const char *get_inserted_text(struct sc_pkcs15_card *p15card, struct sc_atr *atr)
{
	static char text[3*SC_MAX_ATR_SIZE] = {0};
	const char prefix[] = "ATR: ";

	if (p15card && p15card->card && p15card->card->name) {
		return p15card->card->name;
	}

	if (!atr)
		return NULL;

	strcpy(text, prefix);
	sc_bin_to_hex(atr->value, atr->len, text + (sizeof prefix) - 1,
			sizeof(text) - (sizeof prefix) - 1, ':');

	return text;
}

static const char *get_removed_text(struct sc_pkcs15_card *p15card)
{
	if (p15card && p15card->card && p15card->card->reader
			&& p15card->card->reader->name) {
		return p15card->card->reader->name;
	}

	return NULL;
}

static const char *ui_get_config_str(struct sc_context *ctx,
		struct sc_atr *atr, const char *flag_name, const char *ret_default)
{
	const char *ret = ret_default;

	scconf_block *atrblock = _sc_match_atr_block(ctx, NULL, atr);

	if (atrblock)
		ret = scconf_get_str(atrblock, flag_name, ret_default);

	return ret;
}

static int find_lang_str(const char *str, enum ui_langs *lang)
{
	if (str) {
		if (0 == strncmp(str, "de", 2)) {
			if (lang) {
				*lang = DE;
			}
			return 1;
		} else if (0 == strncmp(str, "en", 2)) {
			if (lang) {
				*lang = EN;
			}
			return 1;
		}
	}

	return 0;
}

const char *ui_get_str(struct sc_context *ctx, struct sc_atr *atr,
		struct sc_pkcs15_card *p15card, enum ui_str id)
{
	enum ui_langs lang = EN;
	const char *str, *option;

	/* load option strings */
	switch (id) {
		case MD_PINPAD_DLG_TITLE:
			option = "md_pinpad_dlg_title";
			break;
		case MD_PINPAD_DLG_MAIN:
			option = "md_pinpad_dlg_main";
			break;
		case MD_PINPAD_DLG_CONTENT_USER:
			option = "md_pinpad_dlg_content_user";
			break;
		case MD_PINPAD_DLG_CONTENT_USER_SIGN:
			option = "md_pinpad_dlg_content_user_sign";
			break;
		case MD_PINPAD_DLG_CONTENT_ADMIN:
			option = "md_pinpad_dlg_content_admin";
			break;
		case MD_PINPAD_DLG_EXPANDED:
			option = "md_pinpad_dlg_expanded";
			break;
		case MD_PINPAD_DLG_ICON:
			option = "md_pinpad_dlg_icon";
			break;
		case NOTIFY_CARD_INSERTED:
			option = "notify_card_inserted";
			break;
		case NOTIFY_CARD_INSERTED_TEXT:
			option = "notify_card_inserted_text";
			break;
		case NOTIFY_CARD_REMOVED:
			option = "notify_card_removed";
			break;
		case NOTIFY_CARD_REMOVED_TEXT:
			option = "notify_card_removed_text";
			break;
		case NOTIFY_PIN_GOOD:
			option = "notify_pin_good";
			break;
		case NOTIFY_PIN_GOOD_TEXT:
			option = "notify_pin_good_text";
			break;
		case NOTIFY_PIN_BAD:
			option = "notify_pin_bad";
			break;
		case NOTIFY_PIN_BAD_TEXT:
			option = "notify_pin_bad_text";
			break;
		case MD_PINPAD_DLG_VERIFICATION:
			option = "md_pinpad_dlg_verification";
			break;
		default:
			option = NULL;
			break;
	}

	/* load language */
	/* card's language supersedes system's language */
	if (!p15card || !p15card->tokeninfo
			|| !find_lang_str(p15card->tokeninfo->preferred_language, &lang)) {
#ifdef _WIN32
		LANGID langid = GetUserDefaultUILanguage();
		if ((langid & LANG_GERMAN) == LANG_GERMAN) {
			lang = DE;
		}
#else
		/* LANGUAGE supersedes locale */
		if (!find_lang_str(getenv("LANGUAGE"), &lang)) {
			/* XXX Should we use LC_MESSAGES instead? */
			find_lang_str(setlocale(LC_ALL, ""), &lang);
		}
#endif
	}

	/* load default strings */
	switch (lang) {
		case DE:
			switch (id) {
				case MD_PINPAD_DLG_TITLE:
					str = "Windows-Sicherheit";
					break;
				case MD_PINPAD_DLG_MAIN:
					str = "OpenSC Smartcard-Anbieter";
					break;
				case MD_PINPAD_DLG_CONTENT_USER:
					str = "Bitte geben Sie Ihre PIN auf dem PIN-Pad ein.";
					break;
				case MD_PINPAD_DLG_CONTENT_USER_SIGN:
					str = "Bitte geben Sie Ihre PIN für die digitale Signatur auf dem PIN-Pad ein.";
					break;
				case MD_PINPAD_DLG_CONTENT_ADMIN:
					str = "Bitte geben Sie Ihre PIN zum Entsperren der Nutzer-PIN auf dem PIN-Pad ein.";
					break;
				case MD_PINPAD_DLG_EXPANDED:
					str = "Dieses Fenster wird automatisch geschlossen, wenn die PIN am PIN-Pad eingegeben wurde (Timeout typischerweise nach 30 Sekunden).";
					break;
				case NOTIFY_CARD_INSERTED:
					if (p15card) {
						str = "Smartcard kann jetzt verwendet werden";
					} else {
						str = "Smartcard erkannt";
					}
					break;
				case NOTIFY_CARD_INSERTED_TEXT:
					str = get_inserted_text(p15card, atr);
					break;
				case NOTIFY_CARD_REMOVED:
					str = "Smartcard entfernt";
					break;
				case NOTIFY_CARD_REMOVED_TEXT:
					str = get_removed_text(p15card);
					break;
				case NOTIFY_PIN_GOOD:
					str = "PIN verifiziert";
					break;
				case NOTIFY_PIN_GOOD_TEXT:
					str = "Smartcard ist entsperrt";
					break;
				case NOTIFY_PIN_BAD:
					str = "PIN nicht verifiziert";
					break;
				case NOTIFY_PIN_BAD_TEXT:
					str = "Smartcard ist gesperrt";
					break;
				case MD_PINPAD_DLG_VERIFICATION:
					str = "Sofort PIN am PIN-Pad abfragen";
					break;

				case MD_PINPAD_DLG_CONTROL_COLLAPSED:
				case MD_PINPAD_DLG_CONTROL_EXPANDED:
					str = "Weitere Informationen";
					break;
				case MD_PINPAD_DLG_CANCEL:
					str = "Abbrechen";
					break;
				case NOTIFY_EXIT:
					str = "Beenden";
					break;
				default:
					str = NULL;
					break;
			}
			break;
		case EN:
		default:
			switch (id) {
				case MD_PINPAD_DLG_TITLE:
					str = "Windows Security";
					break;
				case MD_PINPAD_DLG_MAIN:
					str = "OpenSC Smart Card Provider";
					break;
				case MD_PINPAD_DLG_CONTENT_USER:
					str = "Please enter your PIN on the PIN pad.";
					break;
				case MD_PINPAD_DLG_CONTENT_USER_SIGN:
					str = "Please enter your digital signature PIN on the PIN pad.";
					break;
				case MD_PINPAD_DLG_CONTENT_ADMIN:
					str = "Please enter your PIN to unblock the user PIN on the PIN pad.";
					break;
				case MD_PINPAD_DLG_EXPANDED:
					str = "This window will be closed automatically after the PIN has been submitted on the PIN pad (timeout typically after 30 seconds).";
					break;
				case NOTIFY_CARD_INSERTED:
					if (p15card) {
						str = "Smart card is ready to use";
					} else {
						str = "Smart card detected";
					}
					break;
				case NOTIFY_CARD_INSERTED_TEXT:
					str = get_inserted_text(p15card, atr);
					break;
				case NOTIFY_CARD_REMOVED:
					str = "Smart card removed";
					break;
				case NOTIFY_CARD_REMOVED_TEXT:
					str = get_removed_text(p15card);
					break;
				case NOTIFY_PIN_GOOD:
					str = "PIN verified";
					break;
				case NOTIFY_PIN_GOOD_TEXT:
					str = "Smart card is unlocked";
					break;
				case NOTIFY_PIN_BAD:
					str = "PIN not verified";
					break;
				case NOTIFY_PIN_BAD_TEXT:
					str = "Smart card is locked";
					break;
				case MD_PINPAD_DLG_VERIFICATION:
					str = "Immediately request PIN on PIN-Pad";
					break;

				case MD_PINPAD_DLG_CONTROL_COLLAPSED:
				case MD_PINPAD_DLG_CONTROL_EXPANDED:
					str = "Click here for more information";
					break;
				case MD_PINPAD_DLG_CANCEL:
					str = "Cancel";
					break;
				case NOTIFY_EXIT:
					str = "Exit";
					break;
				default:
					str = NULL;
					break;
			}
			break;
	}

	/* user's strings supersede default strings */
	if (option != NULL) {
		/* overwrite str with the user's choice */
		str = ui_get_config_str(ctx, atr, option, str);
	}

	return str;
}
