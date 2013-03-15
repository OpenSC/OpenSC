#
# PKCS15 r/w profile for MyEID cards
#

cardinfo {
	label           = "MyEID";
	manufacturer    = "Aventra Ltd.";
	min-pin-length	= 4;
	max-pin-length	= 8;
	pin-encoding	= ascii-numeric;
   	pin-pad-char	= 0xFF;
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
    do-last-update	    = no;
}

option default {
    macros {
        #protected   = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
        #unprotected = READ=NONE, UPDATE=CHV1, DELETE=CHV1;
		
	unusedspace-size = 510;
	odf-size	     = 255;
	aodf-size	     = 255;
	cdf-size	     = 1530;
	cdf-trusted-size = 510;
	prkdf-size	     = 1530;
	pukdf-size	     = 1530;
	dodf-size	     = 1530;
    }
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
    reference  = 1;
    min-length = 4;
    max-length = 8;
    attempts   = 3;
    flags      = initialized, needs-padding;
}

PIN user-puk {
    min-length = 4;
    max-length = 8;
    attempts   = 10;
    flags      = needs-padding;
}

PIN so-pin {
    reference  = 3;
    auth-id    = FF;
    min-length = 4;
    max-length = 8;
    attempts   = 3;
    flags      = initialized, soPin, needs-padding;
}

PIN so-puk {
    min-length = 4;
    max-length = 8;
    attempts   = 10;
   flags       = needs-padding;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        path  = 3F00;
        type  = DF;
        acl	  = CREATE=$PIN, DELETE=$SOPIN;

    	# This is the DIR file
        EF DIR {	    
    	    file-id   = 2F00;
            structure = transparent;
	        size      = 128;
	        acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
	    }
        DF PKCS15-AppDF {
 	        type      = DF;
	        file-id   = 5015;
            acl       = DELETE=$PIN, CREATE=$PIN;
	    
            EF PKCS15-ODF {
        	    file-id   = 5031;
                structure = transparent;
        	    size      = $odf-size;
	            acl       = READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
        	}

            EF PKCS15-TokenInfo {
        	   file-id	  = 5032;
	           structure  = transparent;
        	   acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
            }

            EF PKCS15-UnusedSpace {
                file-id	  = 5033;
                structure = transparent;
                size	  = $unusedspace-size;
                acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
            }

            EF PKCS15-AODF {
                file-id	  = 4401;
                structure = transparent;
                size	  = $aodf-size;
                acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
            }

            EF PKCS15-PrKDF {
                file-id	  = 4402;
                structure = transparent;
                size	  = $prkdf-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-PuKDF {
                file-id	  = 4404;
                structure = transparent;
                size	  = $pukdf-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-CDF {
                file-id	  = 4403;
                structure = transparent;
                size	  = $cdf-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-CDF-TRUSTED {
                file-id	  = 4405;
                structure = transparent;
                size	  = $cdf-trusted-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-DODF {
                file-id	  = 4406;
                structure = transparent;
                size	  = $dodf-size;
                acl       = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }
            
            EF template-private-key {
                type      = internal-ef;
    	        file-id   = 4B01;	
    	        acl       = CRYPTO=$PIN, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
            }
            
            EF template-public-key {
                structure = transparent;
                file-id	  = 5501;
                acl	      = READ=NONE, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
            }

            EF template-certificate {
                file-id   = 4301;
                structure = transparent;
                acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN;
            }

            template key-domain {
                # This is a dummy entry - pkcs15-init insists that
                # this is present
                EF private-key {
                    file-id   = 4B01;
                    type      = internal-ef;
                    acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
                }
                EF public-key {
                    file-id	  = 5501;
                    structure = transparent;
                    acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
                }
		
                # Certificate template
                EF certificate {
                    file-id	  = 4301;
                    structure = transparent;
                    acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN;
                }
                EF privdata {
                    file-id   = 4501;
                    structure = transparent;
                    acl       = READ=$PIN, UPDATE=$PIN, DELETE=$PIN;
                }
                EF data {
                    file-id   = 4601;
                    structure = transparent;
                    acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN;
                }
            }
	    }
    }
}
