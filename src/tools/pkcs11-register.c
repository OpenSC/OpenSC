/*
 * Copyright (C) 2019 Frank Morgner <frankmorgner@gmail.com>
 *
 * This file is part of OpenSC.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fread_to_eof.h"
#include "pkcs11-register-cmdline.h"
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
const char path_sep = '\\';
#else
const char path_sep = '/';
#endif

const char *default_pkcs11_provider = DEFAULT_PKCS11_PROVIDER;
const char *default_onepin_pkcs11_provider = DEFAULT_ONEPIN_PKCS11_PROVIDER;

int
get_profiles_ini(const char *home, const char *basedir, char **profiles_ini)
{
	size_t profiles_ini_len = 0;
	char profiles_ini_path[PATH_MAX];
	int r;

	if (!home || !basedir || !profiles_ini)
		return 0;

	*profiles_ini = NULL;
	r = snprintf(profiles_ini_path, sizeof(profiles_ini_path),
			"%s%c%s%c%s", home, path_sep, basedir, path_sep, "profiles.ini");
	if (r >= 0 && (size_t)r < sizeof(profiles_ini_path)
			&& fread_to_eof(profiles_ini_path,
				(unsigned char **) profiles_ini, &profiles_ini_len)) {
		char *p = realloc(*profiles_ini, profiles_ini_len + 1);
		if (p) {
			p[profiles_ini_len] = '\0';
			*profiles_ini = p;
			return 1;
		}
		free(*profiles_ini);
		*profiles_ini = NULL;
	}
	return 0;
}

const char *
get_next_profile_path(const char **profiles_ini, const char *home, const char *basedir)
{
	static char profile_path[PATH_MAX];

	if (!home || !profiles_ini)
		return NULL;

	while (*profiles_ini) {
		const char *this_profile = strstr(*profiles_ini, "[");
		const char *next_profile;
		const char *is_relative;
		const char *path;
		char *p;
		size_t p_len;
		char format[32];
		int r, r_fmt;

		if (!this_profile) {
			return NULL;
		}

		next_profile = strstr(this_profile + 1, "[");
		is_relative = strstr(this_profile, "IsRelative=1");
		path = strstr(this_profile, "Path=");

		/* advance profile_ini for the next iteration */
		if (next_profile) {
			*profiles_ini = next_profile;

			if (path && next_profile < path) {
				/* path belongs to the next profile */
				path = NULL;
			}
			if (is_relative && next_profile < is_relative) {
				/* IsRelative belongs to the next profile */
				is_relative = NULL;
			}
		} else {
			*profiles_ini = NULL;
		}

		if (!path)
			continue;

		/* build the path to the profile */
		p = profile_path;
		p_len = sizeof(profile_path);
		if (is_relative) {
			if (!basedir)
				continue;
			r = snprintf(p, p_len, "%s%c%s%c", home, path_sep, basedir, path_sep);
			if (r < 0 || (size_t)r >= p_len)
				continue;
			p_len -= (size_t)r;
			p += (size_t)r;
		}
		if (p_len <= 1)
			continue;

		/* adjust format to respect the maximum length of profile_path */
		r_fmt = snprintf(format, sizeof(format), "Path=%%%d[^\n]", (int)(p_len - 1));
		if (r_fmt < 0 || (size_t)r_fmt >= sizeof(format)
				|| 1 != sscanf(path, format, p))
			continue;

		return profile_path;
	}

	return NULL;
}

void
add_module_pkcs11_txt(const char *profile_dir,
		const char *module_path, const char *module_name, const char *exclude_module_path)
{
	char pkcs11_txt_path[PATH_MAX];
	char *pkcs11_txt = NULL;
	size_t pkcs11_txt_len = 0;
	unsigned char *txt = NULL;
	char *p;
	int r;

	if (!profile_dir || !module_path || !module_name)
		return;

	r = snprintf(pkcs11_txt_path, sizeof(pkcs11_txt_path),
			"%s%c%s", profile_dir, path_sep, "pkcs11.txt");
	if (r < 0 || (size_t)r >= sizeof(pkcs11_txt_path)
			|| !fread_to_eof(pkcs11_txt_path, &txt, &pkcs11_txt_len)) {
		goto err;
	}
	pkcs11_txt = (char *)txt;
	p = realloc(pkcs11_txt, pkcs11_txt_len + 1);
	if (!p)
		goto err;
	p[pkcs11_txt_len] = '\0';
	pkcs11_txt = p;

	if (!strstr(pkcs11_txt, module_path)
			&& (!exclude_module_path || !strstr(pkcs11_txt, exclude_module_path))) {
		/* module is not yet present */
		FILE *f = fopen(pkcs11_txt_path, "a");
		if (f) {
			if (fprintf(f,
					"library=%s\n"
					"name=%s\n"
					"\n", module_path, module_name) >= 0) {
				printf("Added %s to %s\n", module_name, pkcs11_txt_path);
			}
			fclose(f);
		}
	}
err:
	free(pkcs11_txt);
}

struct location {
	const char *var;
	const char *dir;
};

void
add_module_mozilla(const struct location *locations, size_t locations_len,
		const char *module_path, const char *module_name, const char *exclude_module_path)
{
	size_t i;

	for (i = 0; i < locations_len; i++) {
		char *profiles_ini = NULL;
		const char *home = getenv(locations[i].var);
		if (!home)
			continue;

		if (get_profiles_ini(home, locations[i].dir, &profiles_ini)) {
			const char *p = profiles_ini;

			while (1) {
				const char *profile_path = get_next_profile_path(&p, home, locations[i].dir);
				if (!profile_path)
					break;
				add_module_pkcs11_txt(profile_path, module_path, module_name, exclude_module_path);
			}
		}
		free(profiles_ini);
	}
}

#include "pkcs11/pkcs11.h"
#include "common/libpkcs11.h"

const char *
get_module_name(const char *module_path)
{
	const char *name = NULL;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	void *module;

	if (!module_path)
		return NULL;

	module = C_LoadModule(module_path, &p11);
	if (module) {
		if (p11 && p11->C_Initialize && p11->C_GetInfo && p11->C_Finalize) {
			CK_INFO info;
			if (CKR_OK == p11->C_Initialize(NULL)) {
				if (CKR_OK == p11->C_GetInfo(&info)) {
					static char module_name[32+sizeof " (255.255)"];
					int libraryDescription_len = 32;

					while (libraryDescription_len > 0
							&& info.libraryDescription[libraryDescription_len-1] == ' ')
						libraryDescription_len--;

					snprintf(module_name, sizeof module_name,
							"%.*s (%d.%d)",
							libraryDescription_len, info.libraryDescription,
							info.libraryVersion.major, info.libraryVersion.minor);

					name = module_name;
				}
				p11->C_Finalize(NULL);
			}
		}
		C_UnloadModule(module);
	}
	return name;
}

void
add_module_firefox(const char *module_path, const char *module_name, const char *exclude_module_path)
{
	struct location locations[] = {
#if   defined(__APPLE__)
		{"HOME", "Library/Application Support/Firefox"},
		{"HOME", "Library/Mozilla/Firefox"},
#elif defined(_WIN32)
		{"APPDATA", "Mozilla\\Firefox"},
#else
			{"XDG_CONFIG_HOME", "mozilla/firefox"}, /* Firefox >= 147 XDG profile */
			{"HOME", ".config/mozilla/firefox"},	/* XDG default when XDG_CONFIG_HOME unset */
			{"HOME", ".mozilla/firefox"},
			{"HOME", ".mozilla/firefox-esr"},
#endif
	};

	add_module_mozilla(locations, sizeof locations/sizeof *locations,
			module_path, module_name, exclude_module_path);
}

void
add_module_thunderbird(const char *module_path, const char *module_name, const char *exclude_module_path)
{
	struct location locations[] = {
#if   defined(__APPLE__)
		{"HOME", "Library/Application Support/Thunderbird"},
		{"HOME", "Library/Mozilla/Thunderbird"},
#elif defined(_WIN32)
		{"APPDATA", "Mozilla\\Thunderbird"},
#else
		{"HOME", ".thunderbird"},
		{"HOME", ".mozilla-thunderbird"},
#endif
	};

	add_module_mozilla(locations, sizeof locations/sizeof *locations,
			module_path, module_name, exclude_module_path);
}

void
add_module_seamonkey(const char *module_path, const char *module_name, const char *exclude_module_path)
{
	struct location locations[] = {
#if   defined(__APPLE__)
		{"HOME", "Library/Application Support/SeaMonkey"},
		{"HOME", "Library/Mozilla/SeaMonkey"},
#elif defined(_WIN32)
		{"APPDATA", "Mozilla\\SeaMonkey"},
#else
		{"HOME", ".mozilla/seamonkey"},
#endif
	};

	add_module_mozilla(locations, sizeof locations/sizeof *locations,
			module_path, module_name, exclude_module_path);
}

void
add_module_chrome(const char *module_path, const char *module_name, const char *exclude_module_path)
{
#if defined(__APPLE__) || defined(_WIN32)
	/* OS specific framework will be used by Chrome instead of PKCS#11 */
#else
	char profile_path[PATH_MAX];
	const char *home = getenv("HOME");
	int r;

	if (0 == strcmp(module_path, default_pkcs11_provider)) {
		module_path = default_onepin_pkcs11_provider;
		exclude_module_path = default_pkcs11_provider;
	}

	if (home) {
		r = snprintf(profile_path, sizeof(profile_path),
				"%s%c%s", home, path_sep, ".pki/nssdb");
		if (r >= 0 && (size_t)r < sizeof(profile_path))
			add_module_pkcs11_txt(profile_path, module_path, module_name, exclude_module_path);
	}

	/* Chrome M146+ uses XDG_DATA_HOME/pki/nssdb when ~/.pki doesn't exist */
	const char *xdg_data_home = getenv("XDG_DATA_HOME");
	if (xdg_data_home) {
		r = snprintf(profile_path, sizeof(profile_path),
				"%s%c%s", xdg_data_home, path_sep, "pki/nssdb");
		if (r >= 0 && (size_t)r < sizeof(profile_path))
			add_module_pkcs11_txt(profile_path, module_path, module_name, exclude_module_path);
	} else if (home) {
		r = snprintf(profile_path, sizeof(profile_path),
				"%s%c%s", home, path_sep, ".local/share/pki/nssdb");
		if (r >= 0 && (size_t)r < sizeof(profile_path))
			add_module_pkcs11_txt(profile_path, module_path, module_name, exclude_module_path);
	}
#endif
}

#define expand(path, expanded, len) \
	do { \
		if (path) { \
			len = ExpandEnvironmentStringsA(path, \
					expanded, sizeof(expanded)); \
			if (0 < len && len < sizeof(expanded)) \
				path = expanded; \
		} \
	} while (0)

int
main(int argc, char **argv)
{
	struct gengetopt_args_info cmdline;
	const char *exclude_module_path = NULL;
	const char *module_path;
	const char *module_name;
#ifdef _WIN32
	DWORD expanded_len;
	char module_path_expanded[PATH_MAX], default_expanded[PATH_MAX], onepin_expanded[PATH_MAX];
#endif

	if (cmdline_parser(argc, argv, &cmdline) != 0)
		return 1;

	module_path = cmdline.module_arg;
	if (!cmdline.module_given) {
		module_path = default_pkcs11_provider;
		exclude_module_path = default_onepin_pkcs11_provider;
	}

	if (!module_path) {
		fprintf(stderr, "No module path specified\n");
		cmdline_parser_free(&cmdline);
		return 1;
	}

#ifdef _WIN32
	expand(module_path, module_path_expanded, expanded_len);
	expand(default_pkcs11_provider, default_expanded, expanded_len);
	expand(default_onepin_pkcs11_provider, onepin_expanded, expanded_len);
#endif

	module_name = get_module_name(module_path);
	if (!module_name) {
		fprintf(stderr, "Could not load/initialize %s\n", module_path);
		cmdline_parser_free (&cmdline);
		return 1;
	}

	if (cmdline.skip_chrome_arg != skip_chrome_arg_on)
		add_module_chrome(module_path, module_name, exclude_module_path);
	if (cmdline.skip_firefox_arg != skip_firefox_arg_on)
		add_module_firefox(module_path, module_name, exclude_module_path);
	if (cmdline.skip_thunderbird_arg != skip_thunderbird_arg_on)
		add_module_thunderbird(module_path, module_name, exclude_module_path);
	if (cmdline.skip_seamonkey_arg != skip_seamonkey_arg_on)
		add_module_seamonkey(module_path, module_name, exclude_module_path);

	cmdline_parser_free (&cmdline);

	return 0;
}
