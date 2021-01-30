#!/bin/sh

yum install gcc
yum install python3
yum install python-devel
yum install python3-devel
pip3 install configobj
pip3 install psutil
pip3 install requests
pip3 install supervisor

# add crontab
crontab -l |grep -v agent-monitor-master > /tmp/crontab.bak
echo "* * * * * cd /agent-monitor-master; sh check.sh" >> /tmp/crontab.bak
crontab /tmp/crontab.bak
