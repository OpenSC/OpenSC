#
# PKCS15 profile, generic information.
# This profile is loaded before any card specific profile.
#

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
option default_32k {
	macros {
        odf-size    = 0;
        aodf-size   = 0;
        dodf-size   = 2048;
        cdf-size    = 2048;
        prkdf-size  = 2048;
        pukdf-size  = 2048;
	}
}

# This option is for cards with very little memory.
# It sets the size of various PKCS15 directory files
# to 128 or 256, respectively.
#option small {
option default {
    macros {
        odf-size    = 0;
        aodf-size   = 0;
        dodf-size   = 512;
        cdf-size    = 512;
        prkdf-size  = 512;
        pukdf-size  = 512;
    }
}

filesystem {
	DF MF {
        path    = 3F00;
			type	= DF;
			
        # Here comes the application DF
        DF PKCS15-AppDF {
					type	= DF;
            file-id = FF00;

            EF PKCS15-ODF {
                file-id = 00DF;
                size    = $odf-size;
				}
				
            EF PKCS15-AODF {
                file-id = A0DF;
                size    = $aodf-size;
            }

            EF PKCS15-PrKDF {
					file-id	= 0001;
                size    = $prkdf-size;
				}
				
            EF PKCS15-PuKDF {
					file-id	= 0002;
                size    = $pukdf-size;
				}

            EF PKCS15-CDF {
                file-id = 0003;
                size    = $cdf-size;
			}
			
            EF PKCS15-DODF {
                file-id = 0004;
                size    = $dodf-size;
            }
		}
	}
}

