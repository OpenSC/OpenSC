#
# PKCS15 profile, generic information.
# This profile is loaded before any card specific profile.
#

cardinfo {
    label = "Rutoken ECP";
    manufacturer = "Aktiv Co.";

    max-pin-length      = 32;
    min-pin-length      = 1;
    pin-encoding        = ascii-numeric;
}

#
# The following controls some aspects of the PKCS15 we put onto
# the card.
#
pkcs15 {
    # Put certificates into the CDF itself?
    direct-certificates = no;
    # Put the DF length into the ODF file?
    encode-df-length    = no;
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update      = yes;

    pkcs15-id-style     = mozilla;
}

# Default settings.
# This option block will always be processed.
option default {
    macros {
        ti-size     = 128;
        odf-size    = 128;
        aodf-size   = 256;
        dodf-size   = 2048;
        cdf-size    = 2048;
        prkdf-size  = 2048;
        pukdf-size  = 2048;
    }
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# for the user pin; that is done dynamically.
PIN user-pin {
    auth-id     = 2;
    reference   = 2;
    attempts    = 5;
    min-length  = 4;
    max-length  = 32;
    flags       = case-sensitive, initialized;
}
PIN user-puk {
    min-length  = 0;
    max-length  = 0;
}

PIN so-pin {
    auth-id     = 1;
    reference   = 1;
    attempts    = 10;
    min-length  = 8;
    max-length  = 32;
    flags       = case-sensitive, initialized, soPin;
}
PIN so-puk {
    min-length  = 0;
    max-length  = 0;
}

filesystem {
    EF CHV2 {
        file-id = 0002;
        ACL     = *=NEVER, UPDATE=$SOPIN, PIN-RESET=$SOPIN;
    }

    DF MF {
        path    = 3F00;
        type    = DF;
        acl     = *=NEVER, SELECT=NONE, DELETE=NEVER, CREATE=CHV2, READ=NONE;

        DF Sys-DF {
            file-id = 1000;

            DF SysKey-DF {
                file-id = 1000;

                DF PuKey-DF {
                    file-id = 6001;
                }

                DF PrKey-DF {
                    file-id = 6002;
                }

                DF SKey-DF {
                    file-id = 6003;
                }

                DF Cer-DF {
                    file-id = 6004;
                }

                DF LCHV-DF {
                    file-id = 6005;
                }
            }

            DF Resrv1-DF {
                file-id = 1001;
            }
            DF Resrv2-DF {
                file-id = 1002;
            }
            DF Resrv3-DF {
                file-id = 1003;
            }
            DF Resrv4-DF {
                file-id = 1004;
            }
        }

        EF DIR {
            type    = EF;
            file-id = 2F00;
            size    = 128;
            acl     = *=NEVER, READ=NONE, UPDATE=CHV1, WRITE=CHV1, DELETE=CHV1;
        }

        # Here comes the application DF
        DF PKCS15-AppDF {
            type    = DF;
            file-id = 5000;
            acl     = *=NONE, DELETE=CHV2;
#           acl     = *=NEVER, SELECT=NONE, DELETE=CHV2, CREATE=CHV2, READ=NONE;

            EF PKCS15-ODF {
                file-id = 5031;
                size    = $odf-size;
                acl     = *=NONE, DELETE=$SOPIN;
            }

            EF PKCS15-TokenInfo {
                file-id = 5032;
                size    = $ti-size;
                acl     = *=NONE, DELETE=CHV2;
            }

            EF PKCS15-AODF {
                file-id = 6005;
                size    = $aodf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$SOPIN, WRITE=$SOPIN, DELETE=$SOPIN;
            }

            EF PKCS15-PrKDF {
                file-id = 6002;
                size    = $prkdf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
            }

            EF PKCS15-PuKDF {
                file-id = 6001;
                size    = $pukdf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
            }

            EF PKCS15-CDF {
                file-id = 6004;
                size    = $cdf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
            }

            EF PKCS15-DODF {
                file-id = 6006;
                size    = $dodf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
            }

            # This template defines files for keys, certificates etc.
            #
            # When instantiating the template, each file id will be
            # combined with the last octet of the object's pkcs15 id
            # to form a unique file ID.
            template key-domain {
                EF private-key {
                    file-id     = 0100;
                    structure   = transparent;
                    acl         = *=NEVER, READ=$PIN, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
                }

                EF public-key {
                    file-id     = 0200;
                    structure   = transparent;
                    acl         = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
                }

                # Certificate template
                EF certificate {
                    file-id     = 0300;
                    structure   = transparent;
                    acl         = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
                }

                # data objects are stored in transparent EFs.
                EF data {
                    file-id     = 0400;
                    structure   = transparent;
                    acl         = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
                }

                # private data objects are stored in transparent EFs.
                EF privdata {
                    file-id     = 0500;
                    structure   = transparent;
                    acl         = *=NEVER, READ=$PIN, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
                }
            }
        }
    }
}

