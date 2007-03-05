#
# PKCS15 r/w profile for Oberthur cards
#
cardinfo {
    label       = "SCM";
    manufacturer    = "Oberthur/OpenSC";
		
    max-pin-length	= 64;
    min-pin-length	= 4;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0xFF;
	
	# Delete or not the public key when inconporating the 
	# corresponding certificate.
	keep-public-key		= no;   # yes/no 
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
    attempts	= 5;
	max-length  = 64;
	min-length  = 4;
    flags	= 0x32; # local, initialized, needs-padding
	reference = 1
}
PIN user-puk {
    attempts	= 5;
	max-length  = 16;
	min-length  = 4;
    flags	= 0x32; # local, initialized, needs-padding
}
PIN so-pin {
    auth-id = FF;
    attempts    = 3;
    max-length  = 64;
    min-length  = 4;
    flags   = 0xB2;
	reference = 4
#	default-value = "31:32:33:34:35:36:37:38";
}

# CHV5 used for Oberthur's specifique access condition "PIN or SOPIN"
# Any value for this pin can given, when the OpenSC tools are asking for.

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
		ACL = *=CHV4;

		DF OberthurAWP-AppDF {
			ACL = *=NONE;
	    	#ACL	= CREATE=CHV4, CRYPTO=NEVER, PIN_SET=CHV4, PIN_RESET=PRO0x78;
	    	ACL	= CREATE=CHV4, CRYPTO=NEVER;
			file-id 	= 5011;
			size = 40;
			
	    	DF private-DF {
				ACL = *=NEVER;
				ACL = CREATE=CHV1, CRYPTO=CHV1, FILES=NONE, DELETE=NONE;
				file-id		= 9002;
				size		= 40;
			
				# Private RSA keys
				EF OberthurAWP-private-key-info   {
					ACL     = WRITE=CHV1, UPDATE=CHV1, READ=CHV1;
				}
				EF template-private-key {
		    		file-id		= 3000;
					type	= internal-ef;
					# READ acl used instead of DECRYPT/SIGN
					#ACL     = UPDATE=PRO0x78, READ=CHV1;
					ACL     = UPDATE=CHV1, READ=CHV1;
				}
				
				# Private DES keys
				EF OberthurAWP-private-des-info   {
					ACL     = WRITE=CHV1, UPDATE=CHV1, READ=CHV1;
				}
				EF template-private-des {
            	    file-id     = 4000;
					type	= internal-ef;
					size = 24;  # 192 bits
					# READ acl used insted of DECRYPT/ENCRYPT/CHECKSUM
					ACL = UPDATE=CHV1, READ=CHV1;
            	}
			
				# Private data
				EF OberthurAWP-private-data-info   {
					ACL = WRITE=CHV1, UPDATE=CHV1, READ=CHV1;
				}
				EF  template-private-data {
					file-id     = 6000;
					ACL = WRITE=CHV1, UPDATE=CHV1, READ=CHV1;
				}
			}
	    
			DF public-DF {
				ACL = CREATE=NONE, CRYPTO=NONE, FILES=NONE, DELETE=NONE;
				file-id		= 9001;
				size		= 80;
			
				# Certificate
				EF OberthurAWP-certificate-info  {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=NONE;
				}
				EF template-certificate {
					file-id		= 2000;
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=NONE;
	    		}
				
				#Public Key
				EF OberthurAWP-public-key-info {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=NONE;
				}
	            EF template-public-key {
					file-id     = 1000;
					type	= internal-ef;
					ACL     = *=NONE;
				}
			
				# Public DES keys
				EF OberthurAWP-public-des-info   {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=NONE;
				}
				EF template-public-des {
    	            file-id     = 7000;
					type	= internal-ef;
					size = 24;  # 192 bits
					ACL = *=NONE;
        	     }
			
				# Public data
				EF OberthurAWP-public-data-info   {
					ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=NONE;
				}
				EF  template-public-data {
					file-id     = 5000;
					ACL = *=NONE;
				}
			}

			EF OberthurAWP-token-info {
				file-id 	= 1000;
				size	= 36;
				ACL     = WRITE=CHV4, UPDATE=CHV4, READ=NONE, ERASE=NEVER;
			}
			
			EF OberthurAWP-puk-file {
				file-id 	= 2000;
				size	= 16;
				#ACL     = WRITE=NEVER, UPDATE=CHV4, READ=PRO0x68, ERASE=NEVER;
				ACL     = WRITE=NEVER, UPDATE=CHV4, READ=NONE, ERASE=NEVER;
			}
			
			EF OberthurAWP-container-list {
				file-id 	= 3000;
				structure	= linear-variable;
				size 		= 20;
				record-length = 141; 
				ACL = WRITE=NONE, UPDATE=NONE, READ=NONE, ERASE=CHV5;
			}
			
			EF OberthurAWP-public-list {
				file-id 	= 4000;
				size	= 250;
				ACL     = *=NONE, ERASE=NEVER;
			}
			
			EF OberthurAWP-private-list {
				file-id 	= 5000;
				size	= 125;
				ACL     = WRITE=CHV1, UPDATE=CHV1, READ=NONE, ERASE=NEVER;
			}
		}
		
        DF PKCS15-AppDF { 
			ACL     = *=CHV4, FILES=NONE;
			size = 20;

			EF template-data-1 {
				file-id     = 3301;
				ACL     = *=CHV4, READ=NONE;
			}

			EF template-data-2 {
				file-id     = 3302;
				ACL     = *=CHV4, READ=NONE;
			}
		}
    }
}

