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
                file-id     = 4402;
                size        = 512;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF PKCS15-PuKDF {
                file-id     = 4403;
                size        = 512;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF PKCS15-CDF {
                file-id     = 4404;
                size        = 1024;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF PKCS15-DODF {
                file-id     = 4405;
                size        = 512;
                acl         = *=$SOPIN, READ=NONE;
            }

            EF template-private-key {
                file-id     = 5101;   # incremented for following objects: 5102, 5103 ...
                type        = internal-ef;
                size        = 512;    # 512bit=196, 768bit=410, 1024bit:512
                ACL         = *=NEVER, READ=NONE, CRYPTO=$PIN, UPDATE=$SOPIN; # READ: only for public key
            }
            EF template-extractable-key {
                file-id     = 7000;   # incremented for following objects: 5102, 5103 ...
                type        = internal-ef;
                size        = 512;    # 512bit=196, 768bit=410, 1024bit:512
                ACL         = *=NEVER, READ=$PIN, UPDATE=$SOPIN;
            }

            EF template-public-key {
                file-id     = 5201;   # incremented for following objects: 5202, 5203 ...
                ACL         = *=$SOPIN, READ=NONE;
            }

            EF template-certificate {
                file-id     = 5501;   # incremented for following objects: 5502, 5503 ...
                ACL         = *=$SOPIN, READ=NONE;
            }

            EF template-data {
                file-id     = 5000;
                structure   = transparent;
                size        = 1000;
                ACL         = *=$SOPIN, *=NONE;
            }
        }
    }
}
