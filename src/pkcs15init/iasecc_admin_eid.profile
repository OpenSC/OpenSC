#
# PKCS15 r/w profile for Oberthur cards
#
cardinfo {
    label           = "ECC v1.0.1";
    manufacturer    = "Gemalto";

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
    # Style of pkcs#15-init support of minidriver: 'none', 'gemalto';
    minidriver-support-style	= none;
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
    reference       = 1;
}
PIN so-pin {
    auth-id     = FF;
    attempts    = 5;
    max-length  = 4;
    min-length  = 4;
    flags       = 0xB2;
    reference   = 2
}

# CHV5 used for Oberthur's specifique access condition "PIN or SOPIN"
# Any value for this pin can given, when the OpenSC tools are asking for.

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

        # Here comes the application DF

        DF PKCS15-AppDF  {
            type    = DF;
            exclusive-aid = E8:28:BD:08:0F:D2:50:45:43:43:2D:65:49:44;
            acl     = *=NONE;
            size    = 5000;

            EF PKCS15-ODF {
                file-id = 5031;
                size    = 60;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            EF PKCS15-TokenInfo {
                file-id = 5032;
                size    = 400;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            EF PKCS15-AODF {
                file-id = 7001;
                size    = 225;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            EF PKCS15-PrKDF {
                file-id = 7002;
                size    = 450;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            EF PKCS15-PuKDF {
                file-id = 7004;
                size    = 450;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            EF PKCS15-SKDF {
                file-id = 7003;
                size    = 450;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            EF PKCS15-CDF {
                file-id = 7005;
                size    = 300;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            EF PKCS15-DODF {
                file-id = 7006;
                size    = 650;
                ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=NONE;
            }

            template key-domain {

                # Private RSA keys
                BSO private-key {
                    ACL     = *=NEVER;
                    ACL     = PSO-COMPUTE-SIGNATURE=SCBx13, INTERNAL-AUTHENTICATE=SCBx13, PSO-DECRYPT=SCBx13, GENERATE=SCBx44, UPDATE=SCBx44, READ=NONE;
                }

                # Private DES keys
                BSO private-des {
                    size    = 24;  # 192 bits
                    # READ acl used insted of DECIPHER/ENCIPHER/CHECKSUM
                }

                # Private data
                EF  private-data {
                    file-id = E000;
                    size    = 36;
                    ACL     = *=NONE;
                    ACL     = WRITE=SCBx44, UPDATE=SCBx44, READ=SCBx13;
                }

                # Certificate
                EF certificate {
                    file-id = B000;
                    ACL     = *=NEVER;
                    ACL     = UPDATE=SCBx44, READ=NONE, DELETE=NONE;
                }

                #Public Key
                BSO public-key {
                    ACL     = *=NEVER;
                    ACL     = INTERNAL-AUTHENTICATE=SCBx13, GENERATE=SCBx44, UPDATE=SCBx44, READ=NONE;
                }

                # Public DES keys
                BSO public-des {
                    size    = 24;  # 192 bits
                    ACL     = *=NONE;
                }

                # Public data
                EF  public-data {
                    file-id = B104;
                    ACL     = *=NONE;
                    ACL     = WRITE=SCBx44, UPDATE=SCBx44;
                }
            }
        }
    }
}

