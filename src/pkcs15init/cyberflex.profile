#
# General purpose PKCS15 profile for Cyberflex Access 16K cards
#
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0x00;
    pin-domains		= yes;
}

# Define reasonable limits for PINs and PUK
# The user pin must always be CHV1, otherwise things
# won't work (crypto operations are protected by CHV1)
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
    # Define default ACLs and file ids for CHV1/CHV2
    EF CHV1 {
    	file-id	= 0000;
	ACL	= *=NEVER, UPDATE=CHV1;
    }
    EF CHV2 {
    	file-id	= 0100;
	ACL	= *=NEVER, UPDATE=CHV2;
    }

    DF MF {
	ACL	= *=AUT0;

	# The DELETE=NONE ACLs will go away once the code
	# works. It's here to make sure I can erase the card
	# even if I mess up big time.
	#
	# If you have a 16K card and wish to store
	# two cert/key pairs.
	# Note if you want the two keys to be protected by the
	# same pin, you need to increase the size of the pin-dir.
	DF PKCS15-AppDF {
	    ACL		= *=$SOPIN, FILES=NONE, DELETE=NONE;
	    # Cyberflex Access 16K
	    size	= 7500;

	    # This "pin-domain" DF is a template that is
	    # instantiated for each PIN created on the card.
	    #
	    # When instantiating the template, each file id will be
	    # combined with the last octet of the object's pkcs15 id
	    # to form a unique file ID. That is, PIN 01 will reside
	    # in 4b01, PIN 02 will reside in 4b02, etc.
    	    template pin-domain {
		DF pin-dir {
		    ACL		= *=$SOPIN, FILES=NONE, DELETE=NONE;
		    file-id	= 4B00;

		    # The minimum size for a 2048 bit key is 1396
		    size	= 2800;
		}
	    }

	    # For PIN-protected files, instantiate this template
	    # below the pin directory.
	    # For unprotected objects, install within the application DF.
	    #
	    # When instantiating the template, each file id will be
	    # combined with the last octet of the object's pkcs15 id
	    # to form a unique file ID.
	    template key-domain {
		# In order to support more than one key per PIN,
		# each key must be within its own subdirectory.
	    	DF key-directory {
		    ACL	= *=$PIN, FILES=NONE;
		    file-id	= 3000;
		    size	= 1400;

	            EF private-key {
		        file-id	= 0012;
		        ACL		= *=NEVER, CRYPTO=$PIN, UPDATE=$PIN;
		    }
		    EF internal-pubkey-file {
		        file-id	= 1012;
		        ACL		= *=$PIN, READ=NONE;
		    }
		}
		EF extractable-key {
    	            file-id	= 4300;
    	            ACL		= *=NEVER, READ=$PIN, UPDATE=$PIN;
		}
		EF public-key {
		    file-id	= 4400;
		    ACL		= *=$PIN, READ=NONE;
		}
		EF certificate {
		    file-id	= 4500;
		    ACL		= *=$PIN, READ=NONE;
		}
		EF data {
		    file-id	= 4600;
		    ACL		= *=$PIN, READ=NONE;
		}
		EF privdata {
		    file-id	= 4700;
		    ACL		= *=$PIN;
		}
	    }
	}
    }
}
