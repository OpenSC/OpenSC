/*
 * card_ctl command numbers
 *
 * There is a range of generic card_ctls, and card-specific
 * ranges. I've used a 3-letter abbreviation of the card in
 * the prefix, but that's just a fad :)
 *
 * For now, I've reserved these:
 * 	0x0000xxxx	generic
 * 	0x4C4658xx	Cryptoflex
 * 	0x47504Bxx	GPK
 *      0x544353xx      TCOS
 */

#ifndef _OPENSC_CARDCTL_H
#define _OPENSC_CARDCTL_H

#include <opensc/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define _CTL_PREFIX(a, b, c) (((a) << 24) | ((b) << 16) | ((c) << 8))

enum {
	/*
	 * Generic card_ctl calls
	 */
	SC_CARDCTL_GENERIC_BASE = 0x00000000,
	SC_CARDCTL_ERASE_CARD,
	SC_CARDCTL_GET_DEFAULT_KEY,
	SC_CARDCTL_LIFECYCLE_GET,
	SC_CARDCTL_LIFECYCLE_SET,

	/*
	 * GPK specific calls
	 */
	SC_CARDCTL_GPK_BASE = _CTL_PREFIX('G', 'P', 'K'),
	SC_CARDCTL_GPK_VARIANT,
	SC_CARDCTL_GPK_LOCK,
	SC_CARDCTL_GPK_PKINIT,
	SC_CARDCTL_GPK_PKLOAD,
	SC_CARDCTL_GPK_IS_LOCKED,

	/*
	 * Cryptoflex specific calls
	 */
	SC_CARDCTL_CRYPTOFLEX_BASE = _CTL_PREFIX('C', 'F', 'X'),

	/*
	 * MioCOS specific calls
	 */
	SC_CARDCTL_MIOCOS_BASE = _CTL_PREFIX('M', 'I', 'O'),
	SC_CARDCTL_MIOCOS_CREATE_AC,

        /*
         * TCOS specific calls
         */
        SC_CARDCTL_TCOS_BASE = _CTL_PREFIX('T','C','S'),
        SC_CARDCTL_TCOS_SETPERM,

	/*
	 * eToken specific calls
	 */
	SC_CARDCTL_ETOKEN_BASE = _CTL_PREFIX('E', 'T', 'K'),
	SC_CARDCTL_ETOKEN_PUT_DATA_FCI,
	SC_CARDCTL_ETOKEN_PUT_DATA_OCI,
	SC_CARDCTL_ETOKEN_PUT_DATA_SECI,
	SC_CARDCTL_ETOKEN_GENERATE_KEY,
};

enum {
	SC_CARDCTRL_LIFECYCLE_ADMIN,
	SC_CARDCTRL_LIFECYCLE_USER,
};

/*
 * Generic cardctl - check if the required key is a default
 * key (such as the GPK "TEST KEYTEST KEY" key, or the Cryptoflex AAK)
 */
struct sc_cardctl_default_key {
	int		method;		/* SC_AC_XXX */
	int		key_ref;	/* key reference */

	size_t		len;		/* in: max size, out: actual size */
	u8 *		key_data;	/* out: key data */
};

/*
 * GPK lock file.
 * Parent DF of file must be selected.
 */
struct sc_cardctl_gpk_lock {
	struct sc_file *	file;
	unsigned int		operation;
};

/*
 * GPK initialize private key file.
 * Parent DF must be selected.
 */
struct sc_cardctl_gpk_pkinit {
	struct sc_file *	file;
	unsigned int		privlen;
};

/*
 * GPK load private key portion.
 */
struct sc_cardctl_gpk_pkload {
	struct sc_file *	file;
	u8 *			data;
	unsigned int		len;
	unsigned int		datalen;
};

enum {
	SC_CARDCTL_MIOCOS_AC_PIN,
	SC_CARDCTL_MIOCOS_AC_CHAL,
	SC_CARDCTL_MIOCOS_AC_LOGICAL,
	SC_CARDCTL_MIOCOS_AC_SMARTPIN,
};

/*
 * MioCOS AC info
 */
struct sc_cardctl_miocos_ac_info {
	int type;
	int ref;
	int max_tries;
	int enable_ac;		/* only applicable to PINs */
	u8 key_value[8];
	int max_unblock_tries;	/* same here */
	u8 unblock_value[8];	/* and here */
};

/*
 * eToken PIN info
 */
struct sc_cardctl_etoken_obj_info {
	u8 *		data;
	size_t		len;
};

struct sc_cardctl_etoken_genkey_info {
	u8 *		random_data;
	size_t		random_len;
	unsigned int	key_id;
	unsigned int	key_bits;
	unsigned short	fid;
};

#ifdef  __cplusplus
}
#endif

#endif /* _OPENSC_CARDCTL_H */
