#
# pkcs15 profile for starcos spk 2.3
#
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0x00;
}

PIN so-pin {
    reference = 1;
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
	size	= 768;

	# INTERNAL SECRET KEY file of the MF
	EF mf_isf {
		file-id = ffff;
		size	= 256;
	}

	EF mf_ipf {
		file-id = 0010;
		size    = 256;
	}

        DF PKCS15-AppDF {
		size		= 16000;

		# INTERNAL SECRET KEY file of the application DF
		EF p15_isf {
			file-id		= ffff;
			size		= 2560;
		}

		EF p15_ipf {
			file-id		= 0010;
			size		= 1280;
		}
	

            template key-domain {
		# This is a dummy entry - pkcs15-init insists that
		# this is present
		EF private-key {
		    file-id	= FFFF;
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
    	            file-id	= 3004;
    	            structure	= transparent;
		    ACL		= *=NEVER,
		    			READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

	        # Extractable private keys are stored in transparent EFs.
	        # Encryption of the content is performed by libopensc.
                EF extractable-key {
    	            file-id	= 3001;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
		    			READ=$PIN,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

	        # data objects are stored in transparent EFs.
                EF data {
    	            file-id	= 3002;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
					READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
                }

	    }

	}
    }
}
