#
# PKCS15 r/w profile for Oberthur cards
#
cardinfo {
    label           = "IAS/ECC v1.0.1";
    manufacturer    = "OpenSC/Oberthur";

    max-pin-length  = 4;
    min-pin-length  = 4;
    pin-encoding    = ascii-numeric;
    pin-pad-char    = 0xFF;
}

pkcs15 {
    # Put certificates into the CDF itself?
    direct-certificates = no;
    # Put the DF length into the ODF file?
    encode-df-length    = no;
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update      = yes;
}

option ecc {
    macros {
        odf-size    = 96;
        aodf-size   = 300;
        cdf-size    = 3000;
        prkdf-size  = 6700;
        pukdf-size  = 2300;
        dodf-size   = 3000;
        skdf-size   = 3000;
    }
}


# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
    attempts        = 5;
    max-length      = 4;
    min-length      = 4;
    flags           = 0x10; # initialized
    reference       = 0xC1;
}
PIN so-pin {
    auth-id     = FF;
    attempts    = 5;
    max-length  = 4;
    min-length  = 4;
    flags       = 0xB2;
    reference   = 2
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
            ACL     = *=NONE;
        }

        # Here comes the application DF
        DF PKCS15-AppDF {
            type    = DF;
            exclusive-aid = E8:28:BD:08:0F:F2:50:4F:54:20:41:57:50;
            ACL     = *=NONE;
            ACL     = CREATE=SCB0x12;
            size    = 5000;

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
            	ACL     = *=NEVER;
                ACL     = WRITE=SCB0x12, UPDATE=SCB0x12, READ=NONE;
            }

            EF PKCS15-PuKDF {
                file-id = 7004;
            	ACL     = *=NEVER;
                ACL     = WRITE=SCB0x12, UPDATE=SCB0x12, READ=NONE;
            }

            EF PKCS15-SKDF {
                file-id = 7003;
            	ACL     = *=NEVER;
                ACL     = WRITE=SCB0x12, UPDATE=SCB0x12, READ=NONE;
            }

            EF PKCS15-CDF {
                file-id = 7005;
                ACL     = WRITE=SCB0x12, UPDATE=SCB0x12, READ=NONE;
            }

            EF PKCS15-DODF {
                file-id = 7006;
            	ACL     = *=NEVER;
                ACL     = WRITE=SCB0x12, UPDATE=SCB0x12, READ=NONE;
            }

            template key-domain {
                # Private RSA keys
                BSO private-key {
                    ACL     = *=NEVER;
                    ACL = UPDATE=SCB0x12, READ=NONE;
                    ACL = PSO-COMPUTE-SIGNATURE=SCB0x12, INTERNAL-AUTHENTICATE=SCB0x12, PSO-DECRYPT=SCB0x12, GENERATE=SCB0x12;

                }

                # Private DES keys
                BSO private-des {
                    size = 24;  # 192 bits
                    # READ acl used insted of DECIPHER/ENCIPHER/CHECKSUM
                }

                # Private data
                EF  private-data {
                    file-id = E000;
                    ACL     = *=NEVER;
                    ACL     = WRITE=SCB0x12, UPDATE=SCB0x12, READ=SCB0x12;
                }
                # Certificate
                EF certificate {
                    file-id = 3401;
                    ACL     = *=NEVER;
                    ACL     = UPDATE=SCB0x12, READ=NONE, DELETE=NONE;
                }

                #Public Key
                BSO public-key {
                    ACL     = *=NEVER;
                    ACL     = INTERNAL-AUTHENTICATE=SCB0x12, GENERATE=SCB0x12, UPDATE=SCB0x12, READ=NONE;
                }

                # Public DES keys
                BSO public-des {
                    size    = 24;  # 192 bits
                    ACL     = *=NONE;
                }

                # Public data
                EF  public-data {
                    file-id = F000;
                    ACL     = *=NONE;
                }
            }
        }
    }
}

