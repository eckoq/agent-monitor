#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2020 , Inc

""" The file is main enterance, it prepares env and init
"""

import sys, os, uuid
import time, threading
from optparse import OptionParser

import log
import __version__
import pppoe_dial
import agent_api
from net_flow import NetFlow

from daemon import Daemon

_u_id = uuid.uuid1()
_ppp_config_dir = os.getcwd() + "/conf/"
_ppp_config_path = os.getcwd() + "/conf/ppp_configs"

_pppoe_flag = True
_net_flow_flag = True

try:
  if not os.path.exists(_ppp_config_dir):
    os.makedirs(_ppp_config_dir)
except Exception as e:
  pass

def version():
  print("{}".format(__version__.__version__))

def handle_signal(option):
  if option == "start":
    _agent.start()
  elif option == "stop":
    _agent.stop()
  elif option == "restart":
    _agent.restart()
  else:
    print("agent-monitor: invalid option: '-s {}'".format(option))

def pppoe_run():
  log.logger.info("pppoe thread start...")
  log.logger.info("ppp_config_path {}".format(_ppp_config_path))
  pppoe_mgr = pppoe_dial.PPPoEManager(_ppp_config_path)
  while True:
    pppoe_mgr.on_timer()
    time.sleep(0.01)

def net_flow_run():
  log.logger.info("net_flow thread start...")
  net = NetFlow(_u_id)
  while True:
    net.on_timer()
    time.sleep(0.01)

def handle_cmd(cmd):
  global _pppoe_flag, _net_flow_flag
  if cmd == "charge":
    _net_flow_flag = True
    _pppoe_flag = False
  elif cmd == "dial":
    _net_flow_flag = False
    _pppoe_flag = True
  elif cmd == "all":
    _net_flow_flag = True
    _pppoe_flag = True
  else:
    print("agent-monitor: invalid option: '-c {}'".format(cmd))
    sys.exit(0)

class AgentMonitor(Daemon):
  def run(self):
    # pppoe dial
    if _pppoe_flag:
      pppoe_th = threading.Thread(target=pppoe_run)
      pppoe_th.start()

    # net flow
    if _net_flow_flag:
      net_flow_th = threading.Thread(target=net_flow_run)
      net_flow_th.start()

    while True:
      agent_api.load_ppp_config(_u_id, _ppp_config_path)
      if _pppoe_flag and not pppoe_th.is_alive():
        log.logger("pppoe thread not alive. restart now.")
        pppoe_th.start()

      if _net_flow_flag and not net_flow_th.is_alive():
        log.logger("net_flow thread not alive. restart now.")
        net_flow_th.start()

      time.sleep(20*60)

_agent_pid = os.getcwd() + "/agent-monitor.pid"
_agent_stdout = os.getcwd() + "/agent-monitor.stdout"
_agent_stderr = os.getcwd() + "/agent-monitor.stderr"
_agent = AgentMonitor(_agent_pid, stdout=_agent_stdout, stderr=_agent_stderr)

if __name__ == "__main__":
  parser = OptionParser()
  parser.add_option("-v", action="store_true", dest="verbose", help="show version")
  parser.add_option("-s", dest="signal", help="send signal process: start, stop or restart")
  parser.add_option("-u", dest="u_id", help="node unique indentification")
  parser.add_option("-c", dest="cmd", help="command :all, charge, dial. default is all")
  (options, args)  =  parser.parse_args()
  if options.verbose:
    version()
  if options.u_id:
    _u_id = options.u_id
  if options.cmd:
    handle_cmd(options.cmd)
  if options.signal:
    handle_signal(options.signal)
