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
    direct-certificates	= no;
    # Put the DF length into the ODF file?
    encode-df-length	= no;
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update	= no;
}

option default {
    macros {
        #protected	= READ=NONE, UPDATE=CHV1, DELETE=CHV2;
        #unprotected	= READ=NONE, UPDATE=CHV1, DELETE=CHV1;
		
	unusedspace-size = 512;
	odf-size	= 256;
	aodf-size	= 384;
	cdf-size	= 512;
	prkdf-size	= 1485;
	pukdf-size	= 1200;
	dodf-size	= 256;
    }
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
    reference  = 1;
    auth-id    = 1;    
    min-length = 4;
    max-length = 8;
    attempts	= 3;
    flags      = initialized, needs-padding;
}

PIN user-puk {
    min-length = 4;
    max-length = 8;
    attempts	= 10;
   flags       = needs-padding;
}

PIN so-pin {
    reference  = 2;
    auth-id    = 2;
    min-length = 4;
    max-length = 8;
    attempts   = 4;
    flags      = initialized, soPin, needs-padding;
}

PIN so-puk {
    min-length = 4;
    max-length = 8;
    attempts   = 9;
   flags       = needs-padding;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        path	= 3F00;
        type	= DF;
        acl    = DELETE=CHV2; #Erase PIN

	# This is the DIR file
	EF DIR {	    
	    file-id	= 2F00;
            structure   = transparent;
	    size	= 128;
	    acl		= READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	}
        DF PKCS15-AppDF {
 		type	= DF;
		file-id	= 5015;
        	acl     = DELETE=NONE, CREATE=CHV1;
	    
            EF PKCS15-ODF {
	        file-id	  = 5031;
                structure = transparent;
		size	  = $odf-size;
		ACL	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }

	    EF PKCS15-TokenInfo {
		file-id	  = 5032;
		structure = transparent;
		ACL	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }

	    EF PKCS15-UnusedSpace {
		file-id	  = 5033;
		structure = transparent;
		size	  = $unusedspace-size;
		ACL	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }

	    EF PKCS15-AODF {
	        file-id	  = 4401;
		structure = transparent;
		size	  = $aodf-size;
		ACL	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }

	    EF PKCS15-PrKDF {
	        file-id	  = 4402;
		structure = transparent;
		size	  = $prkdf-size;
		acl	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }

	    EF PKCS15-PuKDF {
	        file-id	  = 4403;
		structure = transparent;
		size	  = $pukdf-size;
		acl	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }

	    EF PKCS15-CDF {
	        file-id	  = 4404;
		structure = transparent;
		size	  = $cdf-size;
		acl	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }

	    EF PKCS15-DODF {
	        file-id	  = 4405;
		structure = transparent;
		size	  = $dodf-size;
		ACL	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
	    }
            EF template-private-key {
			type	= internal-ef;
	    	        file-id	= 4B01;	
			size	= 1024;
	    	        ACL		= CRYPTO=CHV1, UPDATE=CHV1, DELETE=CHV2;
            }
		    EF template-public-key {
			structure = transparent;
			file-id		= 5501;
			ACL	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
		    }
		    EF template-certificate {
				file-id		= 4301;
			structure = transparent;
			ACL	  = READ=NONE, UPDATE=CHV1, DELETE=CHV2;
		}

                template key-domain {
		# This is a dummy entry - pkcs15-init insists that
		# this is present
		EF private-key {
		    file-id	= 4B00;
                    type	= internal-ef;
		    ACL		= READ=NONE, UPDATE=CHV1, DELETE=CHV2;
		}
		EF public-key {
    	            file-id	= 4300;
    	            structure	= transparent;
		    ACL		= READ=NONE, UPDATE=CHV1, DELETE=CHV2;
                }   
		
		# Certificate template
                EF certificate {
    	            file-id	= 5300;
    	            structure	= transparent;
		    ACL		= READ=NONE, UPDATE=CHV1, DELETE=CHV2;
		    }
            }
	}
    }
}
