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
 */

#ifndef _OPENSC_CARDCTL_H
#define _OPENSC_CARDCTL_H

#define _CTL_PREFIX(a, b, c) (((a) << 24) | ((b) << 16) | ((c) << 8))

enum {
	/*
	 * Generic card_ctl calls
	 */
	SC_CARDCTL_GENERIC_BASE = 0x00000000,
	SC_CARDCTL_ERASE_CARD,

	/*
	 * GPK specific calls
	 */
	SC_CARDCTL_GPK_BASE = _CTL_PREFIX('G', 'P', 'K'),
	SC_CARDCTL_GPK_LOCK,
	SC_CARDCTL_GPK_PKINIT,
	SC_CARDCTL_GPK_PKLOAD,

	/*
	 * Cryptoflex specific calls
	 */
	SC_CARDCTL_CRYPTOFLEX_BASE = _CTL_PREFIX('C', 'F', 'X'),

	/*
	 * MioCOS specific calls
	 */
	SC_CARDCTL_MIOCOS_BASE = _CTL_PREFIX('M', 'I', 'O'),
	SC_CARDCTL_MIOCOS_CREATE_AC,
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

#endif /* _OPENSC_CARDCTL_H */
