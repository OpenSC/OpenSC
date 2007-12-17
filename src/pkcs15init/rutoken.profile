
cardinfo {
    max-pin-length	= 8;
    pin-encoding	= ascii-numeric;
    pin-pad-char	= 0x00;
}
option default {
	macros {
		so-pin-flags	= initialized, needs-padding, soPin;
		isf_acl		= WRITE=$SOPIN;
		df_acl		= *=$SOPIN;
	}
}


# Define reasonable limits for PINs and PUK
# We set the reference for SO pin+puk here, because
# those are hard-coded (if a PUK us assigned).
PIN so-pin {
    reference = 0;
}
PIN so-puk {
    reference = 1;
}
PIN user-pin {
    attempts	= 15;
}
PIN user-puk {
    attempts	= 15;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.

filesystem {
	DF MF {
		DF {
			type	= DF;
			file-id	= 0000;
			acl	= *=NONE;
			DF {
				type	= DF;
				file-id	= 0000;
				acl	= *=NONE;
			
				DF {
					type	= DF;
					file-id	= 0000;
					acl	= *=NONE;
				}
				
				DF {
					type	= DF;
					file-id	= 0001;
					acl	= *=NONE;
				}
				
				DF {
					type	= DF;
					file-id	= 0002;
					acl	= *=NONE;
				}

			}
			DF {
				type	= DF;
				file-id	= 0001;
				acl	= *=NONE;
			}
			
		
		}
	}
}

