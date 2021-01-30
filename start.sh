#!/bin/sh

exist=$(ps -ef |grep supervisord |grep -v grep |wc -l)
if [[ $exist -eq 1 ]]; then
    echo "[info] supervisord exist. reload it now"
    /usr/local/bin/supervisorctl reload
else
    echo "[info] supervisord start"
    /usr/local/bin/supervisord -c /agent-monitor-master/supervisord.conf
fi

sleep 1

status=$(ps -ef |grep agent_monitor |grep -v grep|wc -l)
if [[ $status -eq 1 ]];then
   echo "[info] agent_monitor exist. exit now"
   exit 0
fi

echo "[info] supervisord exist. restart agent_monitor"
/usr/local/bin/supervisorctl restart agent_monitor
