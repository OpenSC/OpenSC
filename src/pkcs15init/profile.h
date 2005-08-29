/*
 * Card profile information (internal)
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef _OPENSC_PROFILE_H
#define _OPENSC_PROFILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <opensc/pkcs15.h>
#include "keycache.h"

#ifndef SC_PKCS15_PROFILE_SUFFIX
#define SC_PKCS15_PROFILE_SUFFIX	"profile"
#endif

/* Obsolete */
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

	/* Template support */
	struct file_info *	instance;
	struct sc_profile *	base_template;
	unsigned int		inst_index;
	sc_path_t		inst_path;
};

/* For now, we assume the PUK always resides
 * in the same file as the PIN
 */
struct pin_info {
	unsigned int		id;
	struct pin_info *	next;
	char *			file_name;	/* obsolete */
	unsigned int		file_offset;	/* obsolete */
	struct file_info *	file;		/* obsolete */

	sc_pkcs15_pin_info_t	pin;
};

typedef struct sc_macro {
	char *			name;
	struct sc_macro *	next;
	scconf_list *		value;
} sc_macro_t;

/* Template support.
 *
 * Templates are EFs or entire hierarchies of DFs/EFs.
 * When instantiating a template, the file IDs of the
 * EFs and DFs are combined from the value given in the
 * profile, and the last octet of the pkcs15 ID.
 */
typedef struct sc_template {
	char *			name;
	struct sc_template *	next;
	struct sc_profile *	data;
	struct file_info *	file;
} sc_template_t;

#define SC_PKCS15INIT_MAX_OPTIONS 16
struct sc_profile {
	char *			name;
	char *			options[SC_PKCS15INIT_MAX_OPTIONS];

	sc_card_t *		card;
	char *			driver;
	struct sc_pkcs15init_operations *ops;
	struct sc_pkcs15init_callbacks *cbs;
	void *			dll;	/* handle for dynamic modules */

	struct file_info *	mf_info;
	struct file_info *	df_info;
	struct file_info *	ef_list;
	struct sc_file *	df[SC_PKCS15_DF_TYPE_COUNT];

	struct pin_info *	pin_list;
	struct auth_info *	auth_list;
	sc_template_t *		template_list;
	sc_macro_t *		macro_list;

	unsigned int		pin_domains;
	unsigned int		pin_maxlen;
	unsigned int		pin_minlen;
	unsigned int		pin_pad_char;
	unsigned int		pin_encoding;
	unsigned int		pin_attempts;
	unsigned int		puk_attempts;
	unsigned int		rsa_access_flags;
	unsigned int		dsa_access_flags;
	unsigned int		protect_certificates;
	unsigned int		keep_public_key;

	struct {
		unsigned int	direct_certificates;
		unsigned int	encode_df_length;
		unsigned int	do_last_update;
	} pkcs15;

	/* PKCS15 information */
	sc_pkcs15_card_t *	p15_spec; /* as given by profile */
	sc_pkcs15_card_t *	p15_data; /* as found on card */
	/* flag to indicate whether the TokenInfo::lastUpdate field
	 * needs to be updated (in other words: if the card content
	 * has been changed) */
	int			dirty;
};

struct sc_profile *sc_profile_new(void);
int		sc_profile_load(struct sc_profile *, const char *);
int		sc_profile_finish(struct sc_profile *);
void		sc_profile_free(struct sc_profile *);
int		sc_profile_build_pkcs15(struct sc_profile *);
void		sc_profile_get_pin_info(struct sc_profile *,
			unsigned int, struct sc_pkcs15_pin_info *);
int		sc_profile_get_pin_id(struct sc_profile *,
			unsigned int, unsigned int *);
int		sc_profile_get_file(struct sc_profile *, const char *,
			struct sc_file **);
int		sc_profile_get_file_by_path(struct sc_profile *,
			const struct sc_path *, struct sc_file **);
int		sc_profile_get_path(struct sc_profile *,
			const char *, struct sc_path *);
int		sc_profile_get_file_in(struct sc_profile *,
			const sc_path_t *, const char *, sc_file_t **);
int		sc_profile_instantiate_template(struct sc_profile *,
			const char *, const sc_path_t *,
			const char *, const sc_pkcs15_id_t *,
			sc_file_t **);
int		sc_profile_add_file(struct sc_profile *,
			const char *, sc_file_t *);

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_PROFILE_H */
