do shell script "killall opensc-notify || true"
do shell script "nohup /Library/OpenSC/bin/opensc-notify > /dev/null 2>&1 &"
