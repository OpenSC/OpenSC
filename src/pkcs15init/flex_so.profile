#
# PKCS15 r/w profile for Cryptoflex cards,
# where the Security Officer (CHV2 pin) is in charge of the PKCS15 DF.
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

	DF PKCS15-AppDF {
	    ACL		= DELETE=$SOPIN, CREATE=NONE, FILES=NONE;
            size = 7500;  # enough for 2 2048 bit keys, and 1 cert each
	    EF sopinfile {
                 file-id		= 0100;
                 size		= 23;
                 ACL			= *=NEVER, UPDATE=AUT1;
            }
            EF extkey {
                 file-id                = 0011;
                 size                   = 15;
                 ACL                    = *=NEVER, UPDATE=AUT1;
            }
	    DF keydir-1 {
		ACL		= *=$SOPIN, FILES=NONE;
		file-id		= 4B01;
		size		= 1370;	# Sufficient for a 2048-bit key
		EF pinfile-2 {
    	            file-id		= 0000;
    	            size		= 23;
    	            ACL			= *=NEVER, UPDATE=$SOPIN;
            	}
		EF template-private-key-1 {
		    file-id		= 0012;
		    ACL			= *=NEVER, CRYPTO=CHV1, UPDATE=$SOPIN;
		}
                EF template-extractable-key-1 {
    	            file-id		= 7000;
    	            ACL			= *=NEVER, READ=$PIN, UPDATE=$SOPIN;
                }
            }
	    DF keydir-2 {
		ACL		= *=$SOPIN, FILES=NONE;
		file-id		= 4B02;
		size		= 1370;	# Sufficient for a 2048-bit key
		EF pinfile-3 {
    	            file-id		= 0000;
    	            size		= 23;
    	            ACL			= *=NEVER, UPDATE=$SOPIN;
            	}
		EF template-private-key-2 {
		    file-id		= 0012;
		    ACL			= *=NEVER, CRYPTO=CHV1, UPDATE=$SOPIN;
		}
                EF template-extractable-key-2 {
    	            file-id		= 7000;
    	            ACL			= *=NEVER, READ=$PIN, UPDATE=$SOPIN;
                }
            }
	    EF template-public-key-1 {
		file-id		= 5201;
		ACL		= *=$SOPIN, READ=NONE;
	    }
	    EF template-public-key-2 {
		file-id		= 5202;
		ACL		= *=$SOPIN, READ=NONE;
	    }
	    EF template-certificate-1 {
		file-id		= 5501;
		ACL		= *=$SOPIN, READ=NONE;
	    }
	    EF template-certificate-2 {
		file-id		= 5502;
		ACL		= *=$SOPIN, READ=NONE;
	    }
            EF PKCS15-AODF {
                size            = 160;     # 1 SOPIN + 2 user pins
            }
	}
    }
}

# Define an SO pin
# This PIN is not used yet.
PIN so-pin {
    file	= sopinfile;
    reference	= 0;
}
