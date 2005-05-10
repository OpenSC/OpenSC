#
# General purpose PKCS15 profile for SetCOS4.4 cards
#
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0x00;
}

# Define reasonable limits for PINs and PUK
PIN user-pin {
    attempts	= 3;
}
PIN user-puk {
    attempts	= 5;
}

PIN so-pin {
    reference	= 1;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        ACL    = *=NONE, CREATE=$SOPIN;  # Allow to delete the MF
        size   = 42;  # size = 2 + 2*(number of sub-files) -> 20 sub-files

		# There's 1 pin/key file
        EF pinfile {
            file-id       = 0080;  # Recommended by Setec
            structure     = 0x22;  # ISF key-file, Setcos V4.4 specific
            record-length = 28;
            size          = 112;   # 28 * 4 = 112 -> 1 SO + 3 user pins/puks
            ACL           = WRITE=$SOPIN, UPDATE=$SOPIN; # WATCH OUT IF YOU CHANGE THESE!!
        }

        DF PKCS15-AppDF {
            ACL         = *=$SOPIN, SELECT=NONE, FILES=NONE, CREATE=NONE;
            size        = 82;  # size = 2 + 2*(number of sub-files) -> 40 sub-files

            EF PKCS15-PrKDF {
                file-id     = 4401;
                size        = 480;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF PKCS15-PuKDF {
                file-id     = 4403;
                size        = 480;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF PKCS15-CDF {
                file-id     = 4404;
                size        = 960;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF PKCS15-DODF {
                file-id     = 4405;
                size        = 480;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF template-private-key {
                file-id     = 5100;
                type        = internal-ef;
                size        = 512;    # enough for a 1024 bit RSA key
                ACL         = *=NEVER, READ=NONE, CRYPTO=$PIN, UPDATE=$SOPIN; # READ: only for public key
            }
            EF template-extractable-key {
                file-id     = 5300;
                type        = internal-ef;
                size        = 512;    # enough for a 1024 bit RSA key
                ACL         = *=NEVER, READ=$PIN, UPDATE=$SOPIN;
            }

            EF template-public-key {
                file-id     = 5200;
                ACL         = *=$SOPIN, READ=NONE;
            }

            EF template-certificate {
                file-id     = 5500;
                ACL         = *=$SOPIN, READ=NONE;
            }

            EF template-data {
                file-id     = 5000;
                structure   = transparent;
                ACL         = *=$SOPIN, READ=NONE;
            }
        }
    }
}
