#
# PKCS15 r/w profile for MuscleCards
#

cardinfo {
    label       = "MUSCLE";
    manufacturer    = "Identity Alliance";

    max-pin-length	= 8;
    min-pin-length	= 4;
    pin-encoding	= ascii-numeric;
	
}
option default {
    macros {
        protected	= *=$PIN, READ=NONE;
        unprotected	= *=NONE;
	so-pin-flags	= local, initialized; #, soPin;
	so-min-pin-length = 4;
	so-pin-attempts	= 2;
	so-auth-id	= 1;
	so-puk-attempts	= 4;
	so-min-puk-length = 4;
	unusedspace-size = 128;
	odf-size	= 256;
	aodf-size	= 256;
	cdf-size	= 512;
	prkdf-size	= 256;
	pukdf-size	= 256;
	dodf-size	= 256;
    }
}

PIN so-pin {
    reference = 0;
	flags = local, initialized;
}
PIN so-puk {
    reference = 0;
}
PIN user-pin {
	reference = 1;
    attempts	= 3;
	flags	= local, initialized;
}
PIN user-puk {
	reference = 1;
    attempts	= 10;
}


filesystem {
    DF MF {
        path	= 3F00;
        type	= DF;
		acl = *=NONE, ERASE=$PIN;
	# This is the DIR file
	EF DIR {
	    type	= EF;
	    file-id	= 2F00;
	    size	= 128;
	    acl		= *=NONE;
	}

	# Here comes the application DF
	DF PKCS15-AppDF {
	    type	= DF;
	    file-id	= 5015;
	    aid		= A0:00:00:00:63:50:4B:43:53:2D:31:35;
	    acl		= *=$PIN;
	    size	= 1; # NO DATA SHOULD BE STORED DIRECTLY HERE!

	    EF PKCS15-ODF {
	        file-id		= 5031;
		size		= $odf-size;
		ACL		= $unprotected;
	    }

	    EF PKCS15-TokenInfo {
		file-id		= 5032;
		ACL		= $unprotected;
		size = 128;
	    }

	    EF PKCS15-UnusedSpace {
		file-id		= 5033;
		size		= $unusedspace-size;
		ACL		= $unprotected;
	    }

	    EF PKCS15-AODF {
	        file-id		= 4401;
		size		= $aodf-size;
		ACL		= $protected;
	    }

	    EF PKCS15-PrKDF {
	        file-id		= 4402;
		size		= $prkdf-size;
		acl		= $protected;
	    }

	    EF PKCS15-PuKDF {
	        file-id		= 4403;
		size		= $pukdf-size;
		acl		= $protected;
	    }

	    EF PKCS15-CDF {
	        file-id		= 4404;
		size		= $cdf-size;
		acl		= $protected;
	    }

	    EF PKCS15-DODF {
	        file-id		= 4405;
		size		= $dodf-size;
		ACL		= $protected;
	    }
	template key-domain {
		BSO private-key {
		    ACL	= *=$PIN, READ=NEVER;
		}
                EF public-key {
    	            file-id	= 3000;
    	            structure	= transparent;
		    ACL		= *=NEVER,
		    			READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

                # Certificate template
                EF certificate {
    	            file-id	= 3100;
    	            structure	= transparent;
		    ACL		= *=NEVER,
		    			READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

	        # Extractable private keys are stored in transparent EFs.
	        # Encryption of the content is performed by libopensc.
                EF extractable-key {
    	            file-id	= 3200;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
		    			READ=$PIN,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

	        # data objects are stored in transparent EFs.
                EF data {
    	            file-id	= 3300;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
					READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
		}
	        # private data objects are stored in transparent EFs.
                EF privdata {
    	            file-id	= 3400;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
					READ=$PIN,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

	    }
	}
    }
}
