CreateObject("Wscript.Shell").Run """" & CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName) + "/" + "pkcs11-register.exe" & """", 0, False
