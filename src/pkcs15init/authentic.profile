#
# PKCS15 r/w profile for Oberthur AuthentIC v3 cards
#
cardinfo {
    label       = "AuthentIC.v3";
    manufacturer    = "Oberthur COSMO.v7";

    max-pin-length    = 63;
    min-pin-length    = 4;
    pin-encoding    = ascii-numeric;
    pin-pad-char    = 0xFF;
}

pkcs15 {
    # Put certificates into the CDF itself?
    direct-certificates    = no;
    # Put the DF length into the ODF file?
    encode-df-length    = no;
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update        = yes;
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
    attempts            = 5;
    max-length          = 63;
    min-length          = 4;
    flags               = 0x10; # initialized
    reference           = 1;
}
PIN so-pin {
    auth-id = FF;
    attempts    = 5;
    max-length  = 4;
    min-length  = 4;
    flags   = 0xB2;
    reference = 2
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        ACL = *=CHV4;
        path    = 3F00;
        type    = DF;

        # This is the DIR file
        EF DIR {
            type    = EF;
            file-id = 2F00;
            size    = 128;
            acl     = *=NONE;
        }

        DF PKCS15-AppDF {
            type    = DF;	
            aid     = A0:00:00:00:77:01:00:70:0A:10:00:F1:00:00:01:00;
            file-id = 5015;

            EF PKCS15-ODF {
                file-id = 5031;
            	ACL     = *=NEVER;
                ACL     = READ=NONE;
            }

            EF PKCS15-TokenInfo {
                file-id = 5032;
            	ACL     = *=NEVER;
                ACL     = READ=NONE;
            }

            EF PKCS15-AODF {
                file-id = 7001;
            	ACL     = *=NEVER;
                ACL     = READ=NONE;
            }

            EF PKCS15-PrKDF {
                file-id = 7002;
                ACL     = *=NONE;
            }

            EF PKCS15-PuKDF {
                file-id = 7004;
                ACL     = *=NONE;
            }

            EF PKCS15-SKDF {
                file-id = 7003;
                ACL     = *=NONE;
            }

            EF PKCS15-CDF {
                file-id = 7005;
                ACL     = *=NONE;
            }

            EF PKCS15-DODF {
                file-id = 7006;
                ACL     = *=NONE;
            }

            BSO template-private-key {
		ACL     = UPDATE=CHV1, DELETE=CHV1;
		ACL     = PSO-DECRYPT=CHV1, INTERNAL-AUTHENTICATE=CHV1, GENERATE=CHV1, PSO-COMPUTE-SIGNATURE=NEVER;
            }

            BSO template-public-key {
                ACL     = *=NONE;
            }
         
            EF template-certificate {
                file-id = B000;
		ACL     = READ=NONE, DELETE=NONE, UPDATE=CHV1, RESIZE=CHV1;
            }
        }
    }
}

