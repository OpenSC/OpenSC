#
# PKCS15 r/w profile for MioCOS cards
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
            EF template-private-key {
		type		= internal-ef;
    	        file-id		= 4B01;	# This is the base FileID
		size		= 266;  # 266 is enough for 1024-bit keys
    	        ACL		= *=NEVER, CRYPTO=$PIN, UPDATE=$PIN;
            }
	    EF template-public-key {
		file-id		= 5501;
		ACL		= *=NEVER, READ=NONE, UPDATE=$PIN;
	    }
	    EF template-certificate {
		file-id		= 4301;
		ACL		= *=NEVER, READ=NONE, UPDATE=$PIN;
	    }
            EF template-extractable-key {
    	        file-id		= 7000;
    	        ACL		= *=NEVER, READ=$PIN, UPDATE=$PIN;
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
