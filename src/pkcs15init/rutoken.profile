#
# PKCS15 profile, generic information.
# This profile is loaded before any card specific profile.
#

cardinfo {
    label = "Rutoken S";
    manufacturer = "Aktiv Co.";

    max-pin-length      = 16;
    min-pin-length      = 1;
    pin-encoding        = ascii-numeric;
    pin-pad-char        = 0xFF;
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

# This option is for cards with very little memory.
# It sets the size of various PKCS15 directory files
# to 128 or 256, respectively.
option small {
    macros {
        ti-size     = 64;
        odf-size    = 128;
        aodf-size   = 128;
        dodf-size   = 512;
        cdf-size    = 512;
        prkdf-size  = 512;
        pukdf-size  = 512;
    }
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# for the user pin; that is done dynamically.
PIN user-pin {
    auth-id     = 2;
    reference   = 2;
    min-length  = 8;
    max-length  = 16;
    flags       = case-sensitive, initialized;
}
PIN user-puk {
    min-length  = 0;
    max-length  = 0;
}

PIN so-pin {
    auth-id     = 1;
    reference   = 1;
    min-length  = 8;
    max-length  = 16;
    flags       = case-sensitive, initialized, soPin;
}
PIN so-puk {
    min-length  = 0;
    max-length  = 0;
}

filesystem {
    DF MF {
        path    = 3F00;
        type    = DF;
        acl     = *=NEVER, SELECT=NONE, DELETE=NEVER, CREATE=CHV2, READ=NONE;

        EF DIR {
            type    = EF;
            file-id = 2F00;
            size    = 128;
            acl     = *=NEVER, READ=NONE, UPDATE=CHV2, WRITE=CHV2, DELETE=CHV2;
        }

        # Here comes the application DF
        DF PKCS15-AppDF {
            type    = DF;
            file-id = 5015;
            aid     = A0:00:00:00:63:50:4B:43:53:2D:31:35;
            size    = 0;
            acl     = *=NEVER, SELECT=NONE, DELETE=CHV2, CREATE=CHV2, READ=NONE;

            EF PKCS15-ODF {
                file-id = 5031;
                size    = $odf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=CHV2, WRITE=CHV2, DELETE=CHV2;
            }

            EF PKCS15-TokenInfo {
                file-id = 5032;
                size    = $ti-size;
                acl     = *=NEVER, READ=NONE, UPDATE=CHV2, WRITE=CHV2, DELETE=CHV2;
            }

            EF PKCS15-AODF {
                file-id = 4401;
                size    = $aodf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=CHV2, WRITE=CHV2, DELETE=CHV2;
            }

            EF PKCS15-PrKDF {
                file-id = 4402;
                size    = $prkdf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
            }

            EF PKCS15-PuKDF {
                file-id = 4403;
                size    = $pukdf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
            }

            EF PKCS15-CDF {
                file-id = 4404;
                size    = $cdf-size;
                acl     = *=NEVER, READ=NONE, UPDATE=$PIN, WRITE=$PIN, DELETE=$PIN;
            }

            EF PKCS15-DODF {
                file-id = 4405;
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

