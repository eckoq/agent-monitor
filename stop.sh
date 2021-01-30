#!/bin/sh

exist=$(ps -ef |grep agent_monitor |grep -v grep |wc -l)
if [[ $exist -eq 1 ]];then
    /usr/local/bin/supervisorctl stop agent_monitor
fi
