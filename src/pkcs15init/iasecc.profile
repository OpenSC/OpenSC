#
# PKCS15 r/w profile for Oberthur cards
#
cardinfo {
    label       = "IAS";
    manufacturer    = "IAS Gemalto";

    max-pin-length    = 4;
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

option ecc {
  macros {
    odf-size        = 96;
    aodf-size       = 300;
    cdf-size        = 3000;
    prkdf-size      = 6700;
    pukdf-size      = 2300;
    dodf-size       = 3000;
    skdf-size       = 3000;
  }
}


# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
    attempts            = 5;
    max-length          = 4;
    min-length          = 4;
    flags                = 0x10; # initialized
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

# CHV5 used for Oberthur's specific access condition "PIN or SOPIN"
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
        DF CIA-Adele-AppDF {
            type    = DF;
            exclusive-aid	= E8:28:BD:08:0F:D2:50:00:00:04:01:01;
            profile-extension	= "ias_adele_admin1";
        }

        DF AdeleAdmin2-AppDF {
            type    = DF;
            exclusive-aid	= E8:28:BD:08:0F:D2:50:00:00:04:02:01;
            profile-extension	= "ias_adele_admin2";
        }

        DF AdeleCommon-AppDF {
            type    = DF;
            exclusive-aid	= E8:28:BD:08:0F:D2:50:00:00:04:03:01;
            profile-extension	= "ias_adele_common";
        }

        DF ECCeID-AppDF {
            type    = DF;
            exclusive-aid	= E8:28:BD:08:0F:D2:50:45:43:43:2D:65:49:44;
            profile-extension	= "iasecc_admin_eid";
        }

        DF ECCGeneric-AppDF {
            type    = DF;
            exclusive-aid	= E8:28:BD:08:0F:D2:50:47:65:6E:65:72:69:63;
            profile-extension	= "iasecc_generic_pki";
        }

	DF ECCGenericOberthur-AppDF  {
            type = DF;
            exclusive-aid	= E8:28:BD:08:0F:F2:50:4F:54:20:41:57:50;
            profile-extension	= "iasecc_generic_oberthur";
            ACL     = *=NONE;
            ACL     = CREATE=SCB0x12;
        }
    }
}

