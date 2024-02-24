#!/bin/bash -e

# This file is made to be sourced into other test scripts and not executed
# manually because it sets trap to restore pcscd to working state

# Set PCSCD_DEBUG="-d -a" to debug APDUs before sourcing this file

# register cleanup handler
function pcscd_cleanup {
	echo "Process terminated: resetting pcscd"
	sudo pkill pcscd
	if which systemctl && systemctl is-system-running; then
		sudo systemctl start pcscd.socket
	fi
}
trap pcscd_cleanup EXIT


# stop the pcscd service and run it from console to see possible errors
if which systemctl && systemctl is-system-running; then
	sudo systemctl stop pcscd.service pcscd.socket
else
	sudo pkill pcscd || echo "no pcscd process was running"
fi
sudo /usr/sbin/pcscd -f $PCSCD_DEBUG 2>&1 | sed -e 's/^/pcscd: /' &


# Try to wait up to 30 seconds for pcscd to come up and create PID file
for ((i=1;i<=30;i++)); do
	echo "Waiting for pcscd to start: $i s"
	if [ -f "/var/run/pcscd/pcscd.pid" ]; then
		echo "PCSC PID: `cat /var/run/pcscd/pcscd.pid`"
		break
	fi
	sleep 1
done


# if it did not come up, warn, but continue
if [ ! -f "/var/run/pcscd/pcscd.pid" ]; then
	echo "WARNING: The pcscd pid file does not exist ... trying anyway"
fi
