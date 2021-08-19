#!/bin/bash -e

# This file is made to be sourced into other test scripts and not executed
# manually because it sets trap to restore pcscd to working state

function pcscd_cleanup {
	sudo pkill pcscd
	sudo systemctl start pcscd.socket
}

# register cleanup handler
trap pcscd_cleanup EXIT

# stop the pcscd service and run it from console to see possible errors
sudo systemctl stop pcscd.service pcscd.socket
sudo /usr/sbin/pcscd -f &
