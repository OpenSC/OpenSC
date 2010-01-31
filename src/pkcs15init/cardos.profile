#
# PKCS15 r/w profile for Siemens CardOS M4 
# smart cards and crypto tokens (for example Aladdin eToken)
#
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0x00;
}

# Define reasonable limits for PINs and PUK
# We set the reference for SO pin+puk here, because
# those are hard-coded (if a PUK us assigned).
PIN so-pin {
    reference = 0;
}
PIN so-puk {
    reference = 1;
}
PIN user-pin {
    attempts	= 3;
}
PIN user-puk {
    attempts	= 10;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        DF PKCS15-AppDF {
	    size		= 4096;

	    # Prevent unauthorized updates of basic security
	    # objects via PUT DATA OCI.
	    # ACL = UPDATE=NEVER;
	    ACL = UPDATE=$SOPIN;

	    # Bump the size of the EF(PrKDF) - with split
	    # keys, we may need a little more room.
	    EF PKCS15-PrKDF {
		size		= 1024;
	    }

	    EF PKCS15-PuKDF {
		size		= 768;
	    }

	    EF PKCS15-CDF {
		size		= 1536;
	    }

	    # This template defines files for keys, certificates etc.
	    #
	    # When instantiating the template, each file id will be
	    # combined with the last octet of the object's pkcs15 id
	    # to form a unique file ID.
	    template key-domain {
		BSO private-key {
		}

                EF public-key {
    	            file-id	= 3003;
    	            structure	= transparent;
		    ACL		= *=NEVER,
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

	        # Extractable private keys are stored in transparent EFs.
	        # Encryption of the content is performed by libopensc.
                EF extractable-key {
    	            file-id	= 3201;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
		    			READ=$PIN,
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
    	            file-id	= 3403;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
					READ=$PIN,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

	    }

	    # This is needed when generating a key on-card.
	    EF tempfile {
	        file-id		= 7EAD;
		structure	= linear-variable-tlv;
		ACL		= *=NONE;
		size		= 512;
	    }
	}
    }
}
