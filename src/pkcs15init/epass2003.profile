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
		ef_acl			 = *=NEVER, READ=NONE, UPDATE=NONE, WRITE=NONE, DELETE=NONE;
		sf_acl			 = *=NEVER, UPDATE=NONE;
		protected		 = *=$PIN,READ=NONE;
        unprotected      = *=NONE;
		dir-size		 = 112;
		tinfo-size		 = 128;
		unusedspace-size = 128;
		odf-size		 = 256;
		aodf-size		 = 256;
		cdf-size		 = 512;
		prkdf-size		 = 256;
		pukdf-size		 = 256;
		dodf-size		 = 256;
		info-size		 = 128;
		maxPin-size      = 2;
	}
}

option onepin {
	macros {
		pin-flags		 = local, initialized, needs-padding;
#		df_acl			 = *=$PIN;
		df_acl			 = *=NEVER, CRYPTO=NONE, FILES=NONE, CREATE=NONE, DELETE=NONE;
		ef_acl			 = *=NEVER, READ=NONE, UPDATE=NONE, WRITE=NONE, DELETE=NONE;
		sf_acl			 = *=NEVER, UPDATE=NONE;
		protected		 = *=NEVER,READ=NONE, UPDATE=$PIN, DELETE=$PIN;
        unprotected      = *=NONE;
		dir-size		 = 112;
		tinfo-size		 = 128;
		unusedspace-size = 128;
		odf-size		 = 512;
		aodf-size		 = 256;
		cdf-size		 = 2048;
		prkdf-size		 = 1024;
		pukdf-size		 = 1024;
		dodf-size		 = 256;
		info-size		 = 128;
		maxPin-size      = 2;
	}
}

PIN so-pin {
	reference	= 1;
	attempts	= 6;
	flags		= $pin-flags;
	min-length	= $min-pin-length;
}
PIN so-puk {
	attempts	= 6;
	flags		= $pin-flags;
	min-length	= $min-pin-length;
}
PIN user-pin {
	reference	= 2;
	attempts	= 6;
	flags		= $pin-flags;
	min-length	= $min-pin-length;
}
PIN user-puk {
	attempts	= 6;
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
		file-id		= 3F00;
		aid		= 65:6e:74:65:72:73:61:66:65:2d:66:69:70:73

		BSO SKey-MF {
			file-id		= 5300;
			ACL		= $sf_acl
			size	= 4;
		}

		EF DIR {
		    type		= EF;
			size		= $dir-size;
			ACL			= $ef_acl;
			file-id		= 2F00;
   			structure = linear-variable;
	    	}

       	DF PKCS15-AppDF {
		    ACL			= $df_acl;
		   	size		= 16000;

			BSO SKey-AppDF {
				file-id		= 5301;
				ACL		= $sf_acl
				size	= 32;
			}

			EF MAXPIN {
			file-id = 9F00;
			size	= $maxPin-size;
			ACL		= $unprotected;
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
				EF private-key {
		    	    file-id	   = 2900;
#type	= internal-ef;
					structure = 0xA3;
#ACL = READ=CHV1,UPDATE=CHV1,CRYPTO=CHV1;
					ACL = *=NONE;
				}

        		EF public-key {
    	    	    file-id	  = 3000;
   					structure = transparent;
					ACL	 = *=NONE;
        		}

        		# Certificate template
        		EF certificate {
            	    file-id	   = 3100;
            		structure  = transparent;
					ACL = READ=NONE,UPDATE=NONE;
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
