#!/bin/sh

status=$(ps -ef |grep agent_monitor |grep -v grep|wc -l)
if [[ $status -eq 1 ]];then
   exit 0
fi

sh start.sh
