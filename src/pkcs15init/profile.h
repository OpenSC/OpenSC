/*
 * Card profile information (internal)
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef _OPENSC_PROFILE_H
#define _OPENSC_PROFILE_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <opensc/pkcs15.h>

#ifndef SC_PKCS15_PROFILE_DIRECTORY
#define SC_PKCS15_PROFILE_DIRECTORY	"/usr/lib/opensc/profiles"
#endif
#ifndef SC_PKCS15_PROFILE_SUFFIX
#define SC_PKCS15_PROFILE_SUFFIX	"profile"
#endif

struct auth_info {
	struct auth_info *	next;
	unsigned int		type;		/* CHV, AUT, PRO */
	unsigned int		ref;
	size_t			key_len;
	u8			key[32];
};

struct file_info {
	char *			ident;
	struct file_info *	next;
	struct sc_file *	file;
	unsigned int		dont_free;
	struct file_info *	parent;
};

/* For now, we assume the PUK always resides
 * in the same file as the PIN
 */
struct pin_info {
	unsigned int		id;
	struct pin_info *	next;
	char *			file_name;
	unsigned int		file_offset;
	struct file_info *	file;

	struct sc_pkcs15_pin_info pin;
};

struct sc_profile {
	char *			driver;
	struct sc_pkcs15init_operations *ops;
	struct sc_pkcs15init_callbacks *cbs;

	struct file_info *	mf_info;
	struct file_info *	df_info;
	struct file_info *	ef_list;
	struct sc_file *	df[SC_PKCS15_DF_TYPE_COUNT];

	struct pin_info *	pin_list;
	struct auth_info *	auth_list;

	unsigned int		pin_maxlen;
	unsigned int		pin_minlen;
	unsigned int		pin_pad_char;
	unsigned int		pin_encoding;
	unsigned int		pin_attempts;
	unsigned int		puk_attempts;
	unsigned int		rsa_access_flags;
	unsigned int		dsa_access_flags;

	/* PKCS15 information */
	struct sc_pkcs15_card *	p15_card;
};

struct sc_profile *sc_profile_new();
int		sc_profile_load(struct sc_profile *, const char *);
int		sc_profile_finish(struct sc_profile *);
void		sc_profile_free(struct sc_profile *);
int		sc_profile_build_pkcs15(struct sc_profile *);
void		sc_profile_set_so_pin(struct sc_profile *, const char *);
void		sc_profile_set_user_pin(struct sc_profile *, const char *);
void		sc_profile_set_secret(struct sc_profile *,
			unsigned int, unsigned int, const u8 *, size_t);
int		sc_profile_get_secret(struct sc_profile *,
			unsigned int, unsigned int, u8 *, size_t *);
void		sc_profile_forget_secrets(struct sc_profile *,
			unsigned int, int);
void		sc_profile_get_pin_info(struct sc_profile *,
			unsigned int, struct sc_pkcs15_pin_info *);
int		sc_profile_get_pin_id(struct sc_profile *,
			unsigned int, unsigned int *);
void		sc_profile_set_pin_info(struct sc_profile *,
			unsigned int, const struct sc_pkcs15_pin_info *);
int		sc_profile_get_file(struct sc_profile *, const char *,
			struct sc_file **);
int		sc_profile_get_file_by_path(struct sc_profile *,
			const struct sc_path *, struct sc_file **);
int		sc_profile_get_path(struct sc_profile *,
			const char *, struct sc_path *);

#ifdef  __cplusplus
}
#endif

#endif /* _OPENSC_PROFILE_H */
