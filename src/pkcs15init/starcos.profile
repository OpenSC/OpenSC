#
# pkcs15 profile for starcos spk 2.3
#
cardinfo {
	max-pin-length	= 8;
	pin-encoding	= ascii-numeric;
	pin-pad-char	= 0x00;
}

option default {
	macros {
		so-pin-flags	= initialized, needs-padding, soPin;
		isf_acl		= WRITE=$SOPIN, CREATE=$SOPIN;
		df_acl		= *=$SOPIN;
	}
}

option onepin {
	macros {
		so-pin-flags    = initialized, needs-padding;
		isf_acl		= WRITE=$PIN, CREATE=$PIN;
		df_acl		= *=$PIN;
	}
}

PIN so-pin {
	reference	= 1;
	flags		= $so-pin-flags;
}
PIN so-puk {
	reference	= 1;
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
	ACL	= $df_acl;
	size	= 768;

	# INTERNAL SECRET KEY file of the MF
	EF mf_isf {
		size	= 256;
		ACL	= $isf_acl;
	}

	EF mf_ipf {
		file-id = 0010;
		size    = 256;
	}

        DF PKCS15-AppDF {
		ACL	= $df_acl;
		size	= 16000;

		# INTERNAL SECRET KEY file of the application DF
		# Note: if the WRITE ACL is commented out or no
		# sopin is specified the ACs must be activated via
		# 'pkcs15-init --finalize' (in this case the
		# AC WRITE is NEVER as the required state can't
		# be reached).
		EF p15_isf {
			path		= 3f005015;
			size		= 2560;
			ACL		= $isf_acl;
		}

		EF p15_ipf {
			file-id		= 0010;
			size		= 1280;
		}
	

            template key-domain {
		BSO private-key {
			# here ACLs should be defined
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
    	            file-id	= 3301;
    	            structure	= transparent;
    	            ACL		= *=NEVER,
					READ=NONE,
					UPDATE=$PIN,
					ERASE=$PIN;
		}
	        # private data objects are stored in transparent EFs.
                EF privdata {
    	            file-id	= 3401;
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
