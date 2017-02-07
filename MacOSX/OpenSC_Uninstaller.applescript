tell application "System Events"
	if exists file "/usr/local/bin/opensc-uninstall" then
		set result to do shell script "/usr/local/bin/opensc-uninstall" with administrator privileges
		display alert "Removal complete" message result giving up after 10
	else
		display alert "OpenSC is not installed" message "Could not find /usr/local/bin/opensc-uninstall" as critical giving up after 10
	end if
end tell