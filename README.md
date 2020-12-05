### Introduction
-----
agent_monitor is tool for collecting netflow information. and it also can use to pppoe dial.


### Preparation
-----
python >= 3.6, psutil, configobj, requests
```
yum install gcc
yum install python3
yum install python-devel
yum install python3-devel
pip3 install configobj
pip3 install psutil
pip3 install requests
```

### Start
----
```
Usage: agent_monitor.py [options]

Options:
  -h, --help  show this help message and exit
  -v          show version
  -s SIGNAL   send signal process: start, stop or restart
  -u U_ID     node unique indentification
```
