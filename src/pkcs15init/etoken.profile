#
# PKCS15 r/w profile for Aladdin eToken
#
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0x00;
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
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
	    size		= 2048;

	    # Bump the size of the EF(PrKDF) - with split
	    # keys, we may need a little more room.
	    EF PKCS15-PrKDF {
		size		= 256;
	    }

            EF template-private-key {
		type		= internal-ef;
    	        file-id		= 4B01;	# This is the base FileID
		size		= 266;  # 266 is enough for 1024-bit keys
    	        ACL		= *=NEVER, UPDATE=$PIN, ERASE=$PIN;
            }
	    EF template-public-key {
		file-id		= 5501;
		ACL		= *=NEVER, READ=NONE, UPDATE=$PIN, ERASE=$PIN;
	    }
	    EF template-certificate {
		file-id		= 4301;
		ACL		= *=NEVER, READ=NONE, UPDATE=$PIN, ERASE=$PIN;
	    }
            EF template-extractable-key {
    	        file-id		= 7000;
    	        ACL		= *=NEVER, READ=$PIN, UPDATE=$PIN, ERASE=$PIN;
            }
	    EF tempfile {
	        file-id		= 7EAD;
		structure	= linear-variable-tlv;
		ACL		= *=NONE;
		size		= 512;
	    }
	}
    }
}

# Define an SO pin
# This PIN is not used yet.
#PIN sopin {
#    file	= sopinfile;
#    reference	= 0;
#}
