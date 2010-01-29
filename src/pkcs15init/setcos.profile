#
# General purpose PKCS15 profile for SetCOS4.4 cards
#
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0x00;
}

# Addtional default settings
option default {
    macros {
        protected	= *=$SOPIN, READ=NONE;
        mf_prot     = *=NONE, CREATE=$SOPIN;  # Allow to delete the MF
        p15_prot    = *=$SOPIN, SELECT=NONE, FILES=NONE, CREATE=NONE;
        pin_prot    = *=NEVER, WRITE=$SOPIN, UPDATE=$SOPIN; # WATCH OUT IF YOU CHANGE THESE!!
        prkey_prot  = *=NEVER, ERASE=$SOPIN, READ=NONE, CRYPTO=$PIN, UPDATE=$SOPIN;
        exkey_prot  = *=NEVER, ERASE=$SOPIN, READ=$PIN, UPDATE=$SOPIN;
	so-pin-flags    = initialized, soPin;
    }
}

# Addtional onepin option settings
option onepin {
    macros {
        protected	= *=$PIN, READ=NONE;
        mf_prot     = *=NONE, CREATE=$PIN;  # Allow to delete the MF
        p15_prot    = *=$PIN, SELECT=NONE, FILES=NONE, CREATE=NONE;
        pin_prot    = *=NEVER, WRITE=$PIN, UPDATE=$PIN; # WATCH OUT IF YOU CHANGE THESE!!
        prkey_prot  = *=NEVER, ERASE=$PIN, READ=NONE, CRYPTO=$PIN, UPDATE=$PIN; # READ: only applies on public key
        exkey_prot  = *=NEVER, ERASE=$PIN, READ=$PIN, UPDATE=$PIN;
        so-pin-flags    = initialized;
    }
}

# Define reasonable limits for PINs and PUK
PIN user-pin {
    attempts	= 3;
    flags	= initialized, needs-padding;
}
PIN user-puk {
    attempts	= 5;
}

PIN so-pin {
    reference	= 1;
    flags	= $so-pin-flags;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        ACL    = $mf_prot;
        size   = 42;  # size = 2 + 2*(number of sub-files) -> 20 sub-files

		# There's 1 pin/key file
        EF pinfile {
            file-id       = 0080;  # Recommended by Setec
            structure     = 0x22;  # ISF key-file, Setcos V4.4 specific
            record-length = 28;
            size          = 112;   # 28 * 4 = 112 -> 1 SO + 3 user pins/puks
            ACL           = $pin_prot;
        }

        DF PKCS15-AppDF {
            ACL         = *=$SOPIN, SELECT=NONE, FILES=NONE, CREATE=NONE;
            size        = 82;  # size = 2 + 2*(number of sub-files) -> 40 sub-files

            EF PKCS15-PrKDF {
                file-id     = 4402;
                size        = 480;
                acl         = $protected;
            }

            EF PKCS15-PuKDF {
                file-id     = 4403;
                size        = 480;
                acl         = $protected;
            }

            EF PKCS15-CDF {
                file-id     = 4404;
                size        = 960;
                acl         = $protected;
            }

            EF PKCS15-DODF {
                file-id     = 4405;
                size        = 480;
                acl         = $protected;
            }

            EF template-private-key {
                file-id     = 5100;
                type        = internal-ef;
                size        = 512;    # enough for a 1024 bit RSA key
                ACL         = $prkey_prot;
            }
            EF template-extractable-key {
                file-id     = 5300;
                type        = internal-ef;
                size        = 512;    # enough for a 1024 bit RSA key
                ACL         = $exkey_prot;
            }

            EF template-public-key {
                file-id     = 5200;
                acl         = $protected;
            }

            EF template-certificate {
                file-id     = 5500;
                acl         = $protected;
            }

            EF template-data {
                file-id     = 5000;
                structure   = transparent;
                acl         = $protected;
            }
        }
    }
}
