#
# pkcs15 profile for entersafe
#
cardinfo {
    manufacturer	= "EnterSafe";
    min-pin-length	= 4;
	max-pin-length	= 16;
	pin-encoding	= ascii-numeric;
	pin-pad-char	= 0x00;
}

option default {
	macros {
		pin-flags		 = local, initialized, needs-padding;
		min-pin-length	 = 4;
		df_acl			 = *=NEVER;
		protected		 = *=$PIN,READ=NONE;
		dir-size		 = 128;
		tinfo-size		 = 128;
		unusedspace-size = 128;
		odf-size		 = 256;
		aodf-size		 = 256;
		cdf-size		 = 512;
		prkdf-size		 = 256;
		pukdf-size		 = 256;
		dodf-size		 = 256;
		info-size		 = 128;
	}
}

option onepin {
	macros {
		pin-flags		 = local, initialized, needs-padding;
		df_acl			 = *=$PIN;
		protected		 = *=$PIN,READ=NONE;
		dir-size		 = 128;
		tinfo-size		 = 128;
		unusedspace-size = 128;
		odf-size		 = 512;
		aodf-size		 = 256;
		cdf-size		 = 2048;
		prkdf-size		 = 1024;
		pukdf-size		 = 1024;
		dodf-size		 = 256;
		info-size		 = 128;
	}
}

PIN so-pin {
	reference	= 1;
	attempts	= 3;
	flags		= $pin-flags;
	min-length	= $min-pin-length;
}
PIN so-puk {
	reference	= 1;
	attempts	= 3;
	flags		= $pin-flags;
	min-length	= $min-pin-length;
}
PIN user-pin {
	reference	= 1;
	attempts	= 3;
	flags		= $pin-flags;
	min-length	= $min-pin-length;
}
PIN user-puk {
	reference	= 1;
	attempts	= 3;
	flags		= $pin-flags;
	min-length	= $min-pin-length;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
	DF MF {
	    ACL		= $df_acl;
	   	size	= 768;

		EF dir {
		    type		= EF;
			size		= $dir-size;
			ACL			= $protected;
			file-id		= 2F00;
			structure	= transparent;
	    	}

       	DF PKCS15-AppDF {
		    ACL			= $df_acl;
		   	size		= 16000;

			# INTERNAL SECRET KEY file of the application DF
			# Note: if the WRITE ACL is commented out or no
			# sopin is specified the ACs must be activated via
			# 'pkcs15-init --finalize' (in this case the
			# AC WRITE is NEVER as the required state can't
			# be reached).
			EF p15_gpkf {
		   	   	file-id 	= FFFD;
				structure	= transparent;
				size		= 2560;
				ACL		  	= $df_acl;
			}

	    	EF PKCS15-ODF {
			size	= $odf-size;
			ACL		= $protected;
	    	}

	    	EF PKCS15-TokenInfo {
			size	= $tinfo-size;
			ACL		= $protected;
	    	}

	    	EF PKCS15-UnusedSpace {
			size    = $unusedspace-size;
			ACL		= $protected;
			}

	    	EF PKCS15-AODF {
			size	= $aodf-size;
			ACL		= $protected;
	    	}

	    	EF PKCS15-PrKDF {
			size	= $prkdf-size;
			ACL		= $protected;
	    	}

	    	EF PKCS15-PuKDF {
			size	= $pukdf-size;
			ACL		= $protected;
	    	}

	    	EF PKCS15-CDF {
			size	= $cdf-size;
			ACL		= $protected;
	    	}

	    	EF PKCS15-DODF {
			size	= $dodf-size;
			ACL		= $protected;
	    	}

			template key-domain {
				BSO private-key {
					# here ACLs should be defined
				}
        		EF public-key {
    	    	    file-id	  = 3000;
   					structure = transparent;
					ACL	  	  = *=NEVER,READ=NONE,UPDATE=$PIN;
        		}

        		# Certificate template
        		EF certificate {
            	    file-id	   = 3100;
            		structure  = transparent;
					ACL	  	   = *=NEVER,READ=NONE,UPDATE=$PIN;
        		}

        		# Extractable private keys are stored in transparent EFs.
        		# Encryption of the content is performed by libopensc.
        		EF extractable-key {
            	    file-id		   = 3200;
            		structure	   = transparent;
					ACL	  	  	   = *=NEVER,READ=NONE,UPDATE=$PIN;
        		}

        		# data objects are stored in transparent EFs.
        		EF data {
            	    file-id		= 3300;
            		structure	= transparent;
					ACL	  	  	= *=NEVER,READ=NONE,UPDATE=NONE;
        		}
        		# data objects are stored in transparent EFs.
        		EF privdata {
            	    file-id		= 3400;
            		structure	= transparent;
					ACL	  	  	= *=NEVER,READ=$PIN,UPDATE=$PIN;
        		}

			}
		}
    }
}
