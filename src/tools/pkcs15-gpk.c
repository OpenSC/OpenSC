/*
 * GPK specific operation for PKCS15 initialization
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#include <sys/types.h>
#include <string.h>
#include "opensc.h"
#include "cardctl.h"
#include "pkcs15-init.h"

#define GPK_MAX_PINS	8

/*
 * Erase the card
 */
static int
gpk_erase_card(struct sc_profile *pro, struct sc_card *card)
{
	return sc_card_ctl(card, SC_CARDCTL_ERASE_CARD, NULL);
}

/*
 * Lock a file operation
 */
static int
gpk_lock(struct sc_card *card, struct sc_file *file, unsigned int op)
{
	struct sc_cardctl_gpk_lock	args;

	args.file = file;
	args.operation = op;
	return sc_card_ctl(card, SC_CARDCTL_GPK_LOCK, &args);
}

/*
 * Update the contents of a PIN file
 */
static int
gpk_update_pins(struct sc_card *card, struct pin_info *info)
{
	u_int8_t	buffer[GPK_MAX_PINS * 8], *blk;
	u_int8_t	temp[16];
	unsigned int	npins, i, j, tries, cks;
	int		r;

	npins = info->attempt[1]? 2 : 1;

	memset(buffer, 0, sizeof(buffer));
	for (i = 0, blk = buffer; i < npins; i++, blk += 8) {
		tries = info->attempt[i];
		if (tries == 0 || tries > 7) {
			/*
			error("invalid number of PIN attempts %u "
					"(must be 1 ... 7)",
					tries);
			 */
			return SC_ERROR_INVALID_ARGUMENTS;
		}

		blk[0] = tries;
		if (i < npins)
			blk[2] = 0x8 | (i + 1);

		memset(temp, 0, sizeof(temp));
		strncpy(temp, info->secret[i], 8);
		blk[4] = (temp[0] << 4) | (temp[1] & 0xF);
		blk[5] = (temp[2] << 4) | (temp[3] & 0xF);
		blk[6] = (temp[4] << 4) | (temp[5] & 0xF);
		blk[7] = (temp[6] << 4) | (temp[7] & 0xF);

		/* Compute the CKS */
		for (j = 0, cks = 0; j < 8; j++)
			cks ^= blk[j];
		blk[3] = ~cks;
	}

	/* FIXME: we shouldn't have to know about the offset shift
	 * here. Implement a gpk_update_binary function that just
	 * shifts the offset if required.
	 */
	r = sc_update_binary(card, info->file_offset/4, buffer, npins * 8, 0);

	return r < 0;
}

/*
 * Create the PIN file and write the PINs
 */
static int
gpk_store_pin(struct sc_profile *profile, struct sc_card *card,
		struct pin_info *info, int *lockit)
{
	const struct sc_acl_entry *acl;
	struct sc_file	*pinfile;
	int		r;

	sc_file_dup(&pinfile, info->file->file);

	/* Create the PIN file. If the UPDATE AC is NEVER,
	 * we change it to NONE so we're able to init the
	 * file, and then lock it.
	 * If the UPDATE AC is anything else, we assume that
	 * we have the required keys/pins to be granted access. */
	acl = sc_file_get_acl_entry(pinfile, SC_AC_OP_UPDATE);
	if (acl->method == SC_AC_NEVER) {
		sc_file_add_acl_entry(pinfile, SC_AC_OP_UPDATE, SC_AC_NONE, 0);
		*lockit = 1;
	}
	for (; acl; acl = acl->next) {
		if (acl->method == SC_AC_CHV) {
			fprintf(stderr,
				"CHV protected PIN files not supported\n");
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto out;
		}
	}

	/* Now create the file */
	if ((r = do_create_file(profile, pinfile)) < 0)
		goto out;

	/* If messing with the PIN file requires any sort of
	 * authentication, send it to the card now */
	if ((r = sc_select_file(card, &pinfile->path, NULL)) < 0
	 || (r = do_verify_authinfo(profile, pinfile, SC_AC_OP_UPDATE)) < 0)
		goto out;

	r = gpk_update_pins(card, info);

out:	sc_file_free(pinfile);
	return r;
}

static int
gpk_lock_pinfile(struct sc_profile *profile, struct sc_card *card,
		struct sc_file *pinfile)
{
	struct sc_file	*parent = NULL;
	int		r;

	/* If the UPDATE AC should be NEVER, set the AC now */
	if ((r = do_select_parent(profile, pinfile, &parent)) != 0
	 || (r = do_verify_authinfo(profile, parent, SC_AC_OP_LOCK)) != 0)
		goto out;
	r = gpk_lock(card, pinfile, SC_AC_OP_UPDATE);
out:	if (parent)
		sc_file_free(parent);
	return r;
}

/*
 * Initialize the Application DF and store the PINs
 *
 * Restrictions:
 * For the GPK, it's fairly tricky to store the CHV1 in a
 * file and protect the update operation with CHV2.
 *
 * There are two properties of the GPK that make this difficult:
 *  -	you can have only one secret key file per DF
 *
 *  -	you cannot create the file without PIN protection, then
 *  	write the contents, then set the PIN protection. The GPK
 *  	has a somewhat cumbersome feature where you first protect
 *  	the file with the global PIN, write to it after presenting
 *  	the global PIN, and then "localize" the access condition,
 *  	telling it to use the local PIN EF instead of the global
 *  	one.
 *
 *  A.	Put CHV2 into the MF. This works, but makes dealing with
 *  	CHV2 tricky for applications, because you must first select
 *  	the DF in which the PIN file resides, and then call Verify.
 *
 *  B.	Store both CHV1 and CHV2 in the same PIN file in the 
 *  	application DF. But in order to allow CHV2 to update the
 *  	PIN file directly using you need to create a global PIN file in
 *  	the MF first, and "localize" the application pin file's
 *  	access conditions later.
 *
 * Neither option is really appealing, which is why for now, I
 * simply reject CHV protected pin files.
 */
static int
gpk_init_app(struct sc_profile *profile, struct sc_card *card)
{
	struct pin_info	*pin1, *pin2;
	int		lockit = 0;

	pin1 = sc_profile_find_pin(profile, "CHV1");
	pin2 = sc_profile_find_pin(profile, "CHV2");
	if (pin1 == NULL) {
		fprintf(stderr, "No CHV1 defined\n");
		return 1;
	}

	/* XXX TODO:
	 * if the CHV2 pin file is required to create files
	 * in the application DF, create that file first */

	/* Create the application DF */
	if (do_create_file(profile, profile->df_info.file))
		return 1;

	/* Store CHV2 */
	lockit = 0;
	if (pin2) {
		if (gpk_store_pin(profile, card, pin2, &lockit))
			return 1;
		/* If both PINs reside in the same file, don't lock
		 * it yet. */
		if (pin1->file != pin2->file && lockit) {
			if (gpk_lock_pinfile(profile, card, pin2->file->file))
				return 1;
			lockit = 0;
		}
	}

	/* Store CHV1 */
	if (gpk_store_pin(profile, card, pin1, &lockit))
		return 1;
	
	if (lockit && gpk_lock_pinfile(profile, card, pin2->file->file))
		return 1;

	return 0;
}

void
bind_gpk_operations(struct sc_profile *profile)
{
	profile->erase_card = gpk_erase_card;
	profile->init_app = gpk_init_app;
}
