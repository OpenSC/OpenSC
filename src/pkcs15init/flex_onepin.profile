#
# PKCS15 r/w profile for Cryptoflex cards,
# where the user (CHV1 pin) is in charge of the PKCS15 DF.
#
# A consequence is that only 1 user PIN is possible.
#
# Note 1: the PKCS15 files (DODF, PrKDF, PuKDF, ...) are unprotected
# (or protected by the SO PIN), as they are defined that way in
# "pkcs15.profile". If you don't want this, change the ACs
# to "*=$CVH1, READ=NONE;".
#
# Note 2: after you do sc_pkcs15init_add_app() (e.g. "pkcs15-init -EC"),
# the user PIN hasn't been added to the PrKDF yet. This will be done in
# sc_pkcs15init_store_pin() (e.g. "pkcs15-init -P --pin 1234 --puk 1234
# -a 1 -l userpin")
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
    flags	= 0x32; # local, initialized, needs-padding
}
PIN user-puk {
    attempts	= 10;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
	ACL	= *=AUT1;

	EF pinfile-1 {
            file-id		= 0000;
            size		= 23;
            ACL			= *=NEVER, UPDATE=AUT1;
    	}

	DF PKCS15-AppDF {
	    ACL		= *=CHV1, FILES=NONE;
	    DF keydir-1 {
		ACL		= *=CHV1, FILES=NONE;
		file-id		= 4B01;
		size		= 1370;	# Sufficient for a 2048-bit key
		EF template-private-key-1 {
		    file-id		= 0012;
		    ACL			= *=NEVER, CRYPTO=$PIN, UPDATE=CHV1;
		}
                EF template-extractable-key-1 {
    	            file-id		= 7000;
    	            ACL			= *=NEVER, READ=CHV1, UPDATE=CHV1;
                }
            }
	    DF keydir-2 {
		ACL		= *=CHV1, FILES=NONE;
		file-id		= 4B02;
		size		= 1370;	# Sufficient for a 2048-bit key
		EF template-private-key-2 {
		    file-id		= 0012;
		    ACL			= *=NEVER, CRYPTO=CHV1, UPDATE=CHV1;
		}
                EF template-extractable-key-2 {
    	            file-id		= 7000;
    	            ACL			= *=NEVER, READ=$PIN, UPDATE=CHV1;
                }
            }
	    EF template-public-key-1 {
		file-id		= 5201;
		ACL		= *=CHV1, READ=NONE;
	    }
	    EF template-public-key-2 {
		file-id		= 5202;
		ACL		= *=CHV1, READ=NONE;
	    }
	    EF template-public-key-3 {
		file-id		= 5203;
		ACL		= *=CHV1, READ=NONE;
	    }
	    EF template-certificate-1 {
		file-id		= 5501;
		ACL		= *=CHV1, READ=NONE;
	    }
	    EF template-certificate-2 {
		file-id		= 5502;
		ACL		= *=CHV1, READ=NONE;
	    }
	    EF template-certificate-3 {
		file-id		= 5503;
		ACL		= *=CHV1, READ=NONE;
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
