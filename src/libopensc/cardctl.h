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
	SC_CARDCTL_GET_PK_ALGORITHMS,

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

};

/*
 * Per algorithm/key size info
 */
struct sc_pk_info {
	unsigned int	pk_algorithm;
	unsigned int	pk_keylength;
	unsigned char	pk_onboard_generation;
	union {
	    struct {
		unsigned long	exponent;
		unsigned int	unwrap;
	    } _rsa;
	} u;
};
#define pk_rsa_exponent	u._rsa.exponent
#define pk_rsa_unwrap	u._rsa.unwrap

/*
 * Get list of supported algorithm/key sizes.
 * This is not really an argument to the cardctl, but
 * a return struct.
 */
struct sc_cardctl_pk_algorithms {
	unsigned int		count;
	struct sc_pk_info	*algorithms;
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

#endif /* _OPENSC_CARDCTL_H */
