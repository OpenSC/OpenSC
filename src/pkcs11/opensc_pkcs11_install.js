////////////////////////////////////////////////////////////////////////////////////////
// Crypto Mechanism Flags
PKCS11_MECH_RSA_FLAG           =  0x1<<0;
PKCS11_MECH_DSA_FLAG           =  0x1<<1;
PKCS11_MECH_RC2_FLAG           =  0x1<<2;
PKCS11_MECH_RC4_FLAG           =  0x1<<3;
PKCS11_MECH_DES_FLAG           =  0x1<<4;
PKCS11_MECH_DH_FLAG            =  0x1<<5; //Diffie-Hellman
PKCS11_MECH_SKIPJACK_FLAG      =  0x1<<6; //SKIPJACK algorithm as in Fortezza cards
PKCS11_MECH_RC5_FLAG           =  0x1<<7;
PKCS11_MECH_SHA1_FLAG          =  0x1<<8;
PKCS11_MECH_MD5_FLAG           =  0x1<<9;
PKCS11_MECH_MD2_FLAG           =  0x1<<10;
PKCS11_MECH_RANDOM_FLAG        =  0x1<<27; //Random number generator
PKCS11_PUB_READABLE_CERT_FLAG  =  0x1<<28; //Stored certs can be read off the token w/o logging in
PKCS11_DISABLE_FLAG            =  0x1<<30; //tell Navigator to disable this slot by default

// Important:
// 0x1<<11, 0x1<<12, ... , 0x1<<26, 0x1<<29, and 0x1<<31 are reserved
// for internal use in Navigator.
// Therefore, these bits should always be set to 0; otherwise,
// Navigator might exhibit unpredictable behavior.

// These flags indicate which mechanisms should be turned on by
var pkcs11MechanismFlags = PKCS11_PUB_READABLE_CERT_FLAG;
 
////////////////////////////////////////////////////////////////////////////////////////
// Ciphers that support SSL or S/MIME
PKCS11_CIPHER_FORTEZZA_FLAG    = 0x1<<0;

// Important:
// 0x1<<1, 0x1<<2, ... , 0x1<<31 are reserved
// for internal use in Navigator.
// Therefore, these bits should ALWAYS be set to 0; otherwise,
// Navigator might exhibit unpredictable behavior.

// These flags indicate which SSL ciphers are supported
var pkcs11CipherFlags = 0;
 
////////////////////////////////////////////////////////////////////////////////////////
// Return values of pkcs11.addmodule() & pkcs11.delmodule()
// success codes
JS_OK_ADD_MODULE                 = 3; // Successfully added a module
JS_OK_DEL_EXTERNAL_MODULE        = 2; // Successfully deleted ext. module
JS_OK_DEL_INTERNAL_MODULE        = 1; // Successfully deleted int. module

// failure codes
JS_ERR_OTHER                     = -1; // Other errors than the followings
JS_ERR_USER_CANCEL_ACTION        = -2; // User abort an action
JS_ERR_INCORRECT_NUM_OF_ARGUMENTS= -3; // Calling a method w/ incorrect # of arguments
JS_ERR_DEL_MODULE                = -4; // Error deleting a module
JS_ERR_ADD_MODULE                = -5; // Error adding a module
JS_ERR_BAD_MODULE_NAME           = -6; // The module name is invalid
JS_ERR_BAD_DLL_NAME              = -7; // The DLL name is bad
JS_ERR_BAD_MECHANISM_FLAGS       = -8; // The mechanism flags are invalid
JS_ERR_BAD_CIPHER_ENABLE_FLAGS   = -9; // The SSL, S/MIME cipher flags are invalid
JS_ERR_ADD_MODULE_DULICATE       =-10; // Module with the same name already installed

var vendor = "opensc";
var plat = navigator.platform;

function installFiles() {
	// Step 1. Create a version object and a software update object.
	vi = new netscape.softupdate.VersionInfo(0, 5, 0, 0);
	su = new netscape.softupdate.SoftwareUpdate(this,
						    "OpenSC PKCS#11 Module");

	// Step 2. Start the install process.
	err = su.StartInstall("pkcs11/"+vendor+"/opensc",
			      vi,
			      netscape.softupdate.SoftwareUpdate.FULL_INSTALL);
	if (err != 0) {
		return false;
	}

	// Step 3. Find out the physical location of the Program dir.
	Folder = su.GetFolder("Program");

	// Step 4. Install the files. Unpack them and list where they go.
	err = su.AddSubcomponent("OpenSC_PKCS11", //component name (logical)
				 vi, // version info
				 "opensc-pkcs11.so", // source file in JAR (physical)
				 Folder, // target folder (physical)
			 "pkcs11/"+vendor+"/"+plat+"/opensc-pkcs11.so", // target path & filename (physical)
				 true); // forces update
	if (err != 0) {
		window.alert("Error adding sub-component: "+"("+err+")");
                su.AbortInstall();
		return false;
	}

	// Step 5. Unless there was a problem, move files to final location
	// and update the Client Version Registry.
	err = su.FinalizeInstall();

	if (err != 0) {
		window.alert("Error Finalizing Install: "+"("+err+")");
		return false;
	}

	return true;
}


installFiles();

// Step 6: Call pkcs11.addmodule() to register the newly downloaded module
result = pkcs11.addmodule("OpenSC PKCS#11 Module " + plat,
			  Folder + "pkcs11/" + vendor + "/" + plat + "/opensc-pkcs11.so",
			  pkcs11MechanismFlags,
			  pkcs11CipherFlags);
if (result == -10) {
	window.alert("New module was copied to destination, \nbut setup failed because a module "
		     +"having the same name has been installed. \nTry deleting the module "
		     + moduleCommonName +" first.")
} else if (result < 0) {
	window.alert("New module was copied to destination, but setup failed.  Error code: " + result);


