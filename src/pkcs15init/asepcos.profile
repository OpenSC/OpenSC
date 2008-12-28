#
# PKCS15 r/w profile for Athena APCOS cards 
#
cardinfo {
	max-pin-length	= 16;
	pin-encoding	= ascii-numeric;
	pin-pad-char	= 0x00;
}

# Default settings.
# This option block will always be processed.
option default {
    macros {
        so-pin-flags    = local, initialized, soPin;
	df_acl		= *=$SOPIN;
    }
}

# This option sets up the card so that a single
# user PIN protects all files
option onepin {
    macros {
        so-pin-flags    = local, initialized;
	df_acl		= *=$PIN;
    }
}


# Define reasonable limits for PINs and PUK
PIN so-pin {
	reference	= 1;
	flags		= $so-pin-flags;
}
PIN so-puk {
	reference	= 2;
}
PIN user-pin {
	attempts	= 3;
	flags		= local, initialized;
}
PIN user-puk {
	attempts	= 10;
        flags           = local, initialized;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
	ACL	= *=AUT0;

        DF PKCS15-AppDF {
	    size		= 0;

	    ACL			= $df_acl;

	    EF PKCS15-PrKDF {
		size		= 384;
	    }

	    EF PKCS15-PuKDF {
		size		= 384;
	    }

	    # This template defines files for keys, certificates etc.
	    #
	    # When instantiating the template, each file id will be
	    # combined with the last octet of the object's pkcs15 id
	    # to form a unique file ID.
	    template key-domain {
		# This is a dummy entry - pkcs15-init insists that
		# this is present
		EF private-key {
			file-id	= 0100;
			ACL	= *=NEVER, CRYPTO=$PIN, UPDATE=$PIN;
		}
		# public keys 
		EF public-key {
                    file-id     = 3003;
                    structure   = transparent;
                    ACL         = *=NEVER,
                                  READ=NONE,
                                  UPDATE=$PIN,
                                  ERASE=$PIN;
                }
                # Certificate template
                EF certificate {
    	            file-id	= 3104;
    	            structure	= transparent;
		    ACL		= *=NEVER,
		    			READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
                }
	        # data objects are stored in transparent EFs.
                EF data {
    	            file-id	= 3302;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
					READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
                }
	        # private data objects are stored in transparent EFs.
                EF privdata {
    	            file-id	= 3402;
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
