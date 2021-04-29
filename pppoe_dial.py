#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2020 , Inc

"""This file for pppoe dial
1. create vlan interface. Use ip tools, after interface create OK, store the if config
file to /etc/sysconfig/network-scripts/.
2. pppoe dial. Use pppoe-connect tools, such as pppoe-connect /etc/sysconfig/network-scripts/ifcfg-ppp101.
3. route tables config. Use ip route and ip rule tools.
"""

import subprocess, os, time
import psutil
from configobj import ConfigObj

import log

class AgentConfigObj(ConfigObj):
  """AgentConfigObj for writing config file without blank
  """
  def __init__(self, *args, **kwargs):
    ConfigObj.__init__(self, *args, **kwargs)

  def _write_line(self, indent_string, entry, this_entry, comment):
    if not self.unrepr:
      val = self._decode_element(self._quote(this_entry))
    else:
      val = repr(this_entry)
    return '%s%s%s%s%s' % (indent_string,
                           self._decode_element(self._quote(entry, multiline=False)),
                           self._a_to_u('='),
                           val,
                           self._decode_element(comment))

class Config(object):
  """
  offer operation to dumps and load config from /etc/sysconfig/network-scripts/
  """
  def __init__(self, file_name):
    self.file_name = file_name
    self.config = None

  def loads(self):
    """load config from file.
    """
    try:
      self.config = AgentConfigObj(self.file_name)
      return True
    except Exception as e:
      raise IOError("ConfigObj init failed file_name {}".format(self.file_name))

  def dumps(self):
    """Flush config obj to disk
    """
    return self.config.write()

  def get_key(self, key):
    return self.config.get(key)

  def set_key(self, key, value):
    self.config[key] = value

  def del_key(self, key):
    if key in self.config:
      del self.config[key]

class ShellCmd(object):
  """run shell cmd in local
  """
  def run_shell(self, cmd, cmd_type="sync"):
    log.logger.debug(cmd)
    p = subprocess.Popen(cmd, shell = True,
                         stdin = subprocess.PIPE,
                         stdout = subprocess.PIPE,
                         stderr = subprocess.PIPE)
    if cmd_type == "sync":
      stdout, stderr = p.communicate()
      if p.returncode != 0:
        log.logger.debug("exec cmd failed code {} msg {}".format(p.returncode, stderr.decode().strip()))
        return p.returncode, stderr.decode().strip()
      else:
        log.logger.debug("exec cmd success code {} msg {}".format(p.returncode, stdout.decode().strip()))
        return p.returncode, stdout.decode().strip()
    else:
      # async do not wait process result
      return p

class RouteTable(ShellCmd):
  """
  route table
  """
  _centos_route_table = "/etc/iproute2/rt_tables"
  def __init__(self, ifname, ip, table_id, table_name, os="centos"):
    self.ifname = ifname
    self.ip = ip
    self.table_id = table_id
    self.table_name = table_name
    if os == "centos":
      self.route_table = self._centos_route_table

  def check(self):
    if not self.is_exist_table():
      self.add_route_table()

    if not self.is_exist_default_router():
      self.add_default_router()

    if not self.is_fine_table_rule():
      self.add_table_rule()

  def is_exist_table(self):
    cmd = ("cat {route_table} |grep {table_name} |wc -l"
          ).format( route_table=self.route_table, table_name=self.table_name)
    code, msg = self.run_shell(cmd)
    if code:
      return False
    try:
      count = int(msg.strip())
      if count != 1:
        return False
      return True
    except Exception as e:
      log.logger.error("check routetable failed. table_name {} code {} msg {} }".format(
        self.table_name, code, msg))
      return False

  def add_route_table(self):
    cmd = ("cat {route_table} | grep -v {table_name} > {route_table}.bak"
           " && echo '{table_id} {table_name}' >> {route_table}.bak"
           " && mv {route_table}.bak {route_table}"
          ).format(route_table=self.route_table, table_id=self.table_id,
                  table_name=self.table_name)
    self.run_shell(cmd)

  def del_route_table(self):
    cmd = ("cat {route_table} | grep -v {table_name} > {route_table}.bak"
           " && mv {route_table}.bak {route_table}"
          ).format(route_table=self.route_table, table_id=self.table_id,
                  table_name=self.table_name)
    self.run_shell(cmd)

  def is_exist_default_router(self):
    cmd = ("ip route show table {table_name} | grep {ifname} "
           "| grep default | wc -l"
          ).format(ifname=self.ifname, table_name=self.table_name)
    code, msg = self.run_shell(cmd)
    if code:
      return False
    try:
      count = int(msg.strip())
      if count != 1:
        return False
      return True
    except Exception as e:
      log.logger.error("check default router failed. table_name {} code {} msg {} }".format(
        self.table_name, code, msg))
      return False

  def add_default_router(self):
    cmd = ("ip route add default dev {ifname} table {table_name}"
          ).format(ifname=self.ifname, table_name=self.table_name)
    self.run_shell(cmd)

  def del_default_router(self):
    cmd = ("ip route del default table {table_name}"
          ).format(ifname=self.ifname, table_name=self.table_name)
    self.run_shell(cmd)

  def is_fine_table_rule(self):
    if not self.ip:
      return True

    cmd = "ip rule show | grep {} | wc -l".format(self.ip)
    code, msg = self.run_shell(cmd)
    if code:
      return False

    try:
      count = int(msg.strip())
      if count == 0:
        return False
      return True
    except Exception as e:
      log.logger.error("check rule failed. ip {} code {} msg {} }".format(ip, code, msg))
      return False

  def add_table_rule(self):
    self.del_table_rule()
    cmd = "ip rule add from {} table {}".format(self.ip, self.table_name)
    self.run_shell(cmd)

  def del_table_rule(self):
    cmd = "ip rule list |grep {} |awk -F':' '{{print $1}}'".format(self.table_name)
    code, msg = self.run_shell(cmd)
    if code:
      return None

    prios = msg.strip().split()
    for prio in prios:
      cmd = "ip rule del prio {}".format(prio)
      self.run_shell(cmd)

  def down(self):
    self.del_default_router()
    self.del_table_rule()
    self.del_route_table()

class Interface(object):
  """Base interface operation
  """
  def is_up(self, if_name):
    # interface config stats
    ifstats = psutil.net_if_stats()
    if if_name not in ifstats:
      return False
    else:
      if not ifstats[if_name].isup:
        return False
    return True

  def is_exist(self, if_name):
    # interface config stats
    ifstats = psutil.net_if_stats()
    if if_name not in ifstats:
      return False
    return True

  def ip_addr(self, ifname):
    ifcfgs = psutil.net_if_addrs()
    if ifname not in ifcfgs:
      log.logger.error("something wrong {} not exist.".format(ifname))
      return None

    for item in ifcfgs[ifname]:
      if item.family.name == "AF_INET":
        ip = item.address
        return ip

    return None

  def mac_addr(self, ifname):
    ifcfgs = psutil.net_if_addrs()
    if ifname not in ifcfgs:
      log.logger.error("something wrong {} not exist.".format(ifname))
      return None

    for item in ifcfgs[ifname]:
      if item.family.name == "AF_PACKET":
        mac = item.address
        return mac

    return None

class Vlan(Interface, ShellCmd):
  """
  config vlan
  """
  _centos_config_path = "/etc/sysconfig/network-scripts/"

  def __init__(self, parent, address,
               vlan_id, check_time = 60, os="centos"):
    self.parent = parent
    self.address = address
    self.vlan_id = vlan_id
    self.vlan_name =  "{}.{}".format(parent, vlan_id)
    self.check_time = check_time

    # platform params
    if os == "centos":
      self.config_name = "ifcfg-{}.{}".format(parent, vlan_id)
    else:
      self.config_name = "ifcfg-{}.{}".format(parent, vlan_id)
    self.config = Config("{}{}".format(self._centos_config_path, self.config_name))
    self.config.loads()

  def check_config(self):
    """check config file, if config file exist, check DEVICE and MACADDR
    :return True config do not need change
            False config need to update
    """
    if os.path.exists(self.config.file_name):
      if self.config.get_key("DEVICE") == self.vlan_name \
          and self.config.get_key("MACADDR") == self.address:
        return True
    return False

  def dump_config(self):
    self.config.set_key("DEVICE", self.vlan_name)
    self.config.set_key("BOOTPROTO", "none")
    self.config.set_key("ONBOOT", "yes")
    self.config.set_key("VLAN", "yes")
    self.config.set_key("MACADDR", self.address)
    self.config.dumps()

  def check_status(self):
    # interface config
    ifcfgs = psutil.net_if_addrs()
    if self.vlan_name not in ifcfgs:
      return False
    else:
      if self.mac_addr(self.vlan_name) != self.address:
        return False

    return self.is_up(self.vlan_name)

  def create(self):
    """create vlan interface with ip tools.
    1. ip link add link ${parent} name ${vlan_interface} type vlan id ${vlan_id}
    2. ip link set ${vlan_interface} address ${mac}
    3. ip link set dev ${vlan_interface} up
    """
    log.logger.info("vlan check_status {} check_config {}".format(self.check_status(),self.check_config()))
    if self.check_status() and self.check_config():
      return True

    if not self.check_config():
      self.dump_config()

    cmd = ""
    if self.is_up(self.vlan_name):
      cmd += "ip link set {vlan_name} down".format(vlan_name=self.vlan_name)

    if self.is_exist(self.vlan_name):
      if len(cmd) != 0:
        cmd += " && "
      cmd += "ip link del {vlan_name}".format(vlan_name=self.vlan_name)

    if len(cmd) != 0:
      cmd += " && "
    cmd += ("ip link add link {parent} name {vlan_name} type vlan id {vlan_id}"
            " && ip link set {vlan_name} address {address}"
            " && ip link set dev {vlan_name} up".format(parent=self.parent,
                                                        vlan_name=self.vlan_name,
                                                        vlan_id=self.vlan_id,
                                                        address=self.address))
    code, msg = self.run_shell(cmd)
    if code:
      return False

    return True

  def down(self):
    cmd = "ip link set {vlan_name} down && ip link del {vlan_name}".format(vlan_name=self.vlan_name)
    self.run_shell(cmd)
    if os.path.exists(self.config.file_name):
      os.remove(self.config.file_name)

class PPPoE(Interface, ShellCmd):
  """
  PPPoe dial
  """
  _centos_config_path = "/etc/sysconfig/network-scripts/"
  _passwd_chap_secrets = "/etc/ppp/chap-secrets"
  _passwd_pap_secrets = "/etc/ppp/pap-secrets"
  _pppoe_connect = "./tools/pppoe-connect"

  def __init__(self, p_id, p_user, p_passwd, p_addr,
               p_vlan_id, p_vlan_addr, p_vlan_parent):
    self.p_id = p_id
    self.p_ppp_name = "ppp{}".format(p_id)
    self.p_user = p_user
    self.p_passwd = p_passwd
    self.p_addr = p_addr
    self.p_macvlan = "macvlan{}.{}".format(p_vlan_id, self.p_id)

    # platform params
    if os == "centos":
      self.config_name = "ifcfg-ppp{}".format(self.p_id)
    else:
      self.config_name = "ifcfg-ppp{}".format(self.p_id)
    self.config = Config("{}{}".format(self._centos_config_path, self.config_name))
    self.config.loads()

    # create vlan obj
    self.vlan = Vlan(p_vlan_parent, p_vlan_addr, p_vlan_id)

  def dump_config(self):
    self.config.set_key("USERCTL", "yes")
    self.config.set_key("BOOTPROTO", "dialup")
    self.config.set_key("NAME", "DSLppp{}".format(self.p_id))
    self.config.set_key("DEVICE", "ppp{}".format(self.p_id))
    self.config.set_key("TYPE", "xDSL")
    self.config.set_key("ONBOOT", "no")
    self.config.set_key("PIDFILE", "/var/run/pppoe-adsl-ppp{}.pid".format(self.p_id))
    self.config.set_key("FIREWALL", "NONE")
    self.config.set_key("PING", ".")
    self.config.set_key("PPPOE_TIMEOUT", "80")
    self.config.set_key("LCP_FAILURE", "3")
    self.config.set_key("LCP_INTERVAL", "20")
    self.config.set_key("CLAMPMSS", "1412")
    self.config.set_key("CONNECT_POLL", "6")
    self.config.set_key("CONNECT_TIMEOUT", "60")
    self.config.set_key("DEFROUTE", "no")
    self.config.set_key("SYNCHRONOUS", "no")
    self.config.set_key("ETH", "{}".format(self.p_macvlan))
    self.config.set_key("PROVIDER", "DSLppp{}".format(self.p_id))
    self.config.set_key("USER", "{}".format(self.p_user))
    self.config.set_key("PEERDNS", "no")
    self.config.set_key("DEMAND", "no")
    self.config.set_key("LINUX_PLUGIN", "rp-pppoe.so")
    self.config.set_key("METRIC", "8")
    self.config.dumps()

    self.dump_passwd()

  def check_passwd(self, passwd_file):
    if os.path.exists(passwd_file):
      cmd = "cat {} |grep '{}' | awk -F'*' '{{print $2}}'".format(passwd_file, self.p_user)
      code, msg = self.run_shell(cmd)
      if code != 0:
        return False
      else:
        try:
          passwd = msg.strip()
          if passwd != self.p_passwd:
            log.logger.error("passwd not equal user {} passwd {} {}"
                             " passwd {}".format(self.p_user, self.p_passwd,
                                                 passwd_file, passwd))
            return False
          return True
        except Exception as e:
          log.logger.error(str(e))
          return False
    else:
      log.logger.error("passwd file {} not exist.".format(passwd_file))
      return False

  def dump_passwd(self):
    passwd_files = [self._passwd_chap_secrets, self._passwd_pap_secrets]
    for passwd_file in passwd_files:
      if self.check_passwd(passwd_file):
        continue
      else:
        cmd = ("cat {passwd_file}| grep -v {user} > {passwd_file}.bak "
            "&& echo '{user} * {passwd}' >> {passwd_file}.bak "
            "&& mv {passwd_file}.bak {passwd_file}").format(passwd_file=passwd_file,
                                                            passwd=self.p_passwd, user=self.p_user)
        self.run_shell(cmd)

  def down_passwd(self):
    passwd_files = [self._passwd_chap_secrets, self._passwd_pap_secrets]
    for passwd_file in passwd_files:
      if self.check_passwd(passwd_file):
        cmd = ("cat {passwd_file}| grep -v {user} > {passwd_file}.bak "
            "&& mv {passwd_file}.bak {passwd_file}").format(passwd_file=passwd_file,
                                                            user=self.p_user)
        self.run_shell(cmd)

  def check_config(self):
    """check interface config file and passwd
    """
    if not os.path.exists(self.config.file_name):
      return False
    else:
      if self.config.get_key("ETH") != self.p_macvlan \
          or self.config.get_key("USER") != self.p_user:
        log.logger.error("pppoe config error {} {}".format(self.p_macvlan, self.p_user))
        return False

    # check passwd
    passwd_files = [self._passwd_chap_secrets, self._passwd_pap_secrets]
    for passwd_file in passwd_files:
      if not self.check_passwd(passwd_file):
        return False

    return True

  def down_config(self):
    if os.path.exists(self.config.file_name):
      os.remove(self.config.file_name)

    self.down_passwd()

  def check_macvlan(self):
    # interface config
    ifcfgs = psutil.net_if_addrs()
    if self.p_macvlan not in ifcfgs:
      log.logger.error("macvlan {} not in psutil dectect".format(self.p_macvlan))
      return False
    else:
      if self.mac_addr(self.p_macvlan) != self.p_addr:
        log.logger.error("macvlan {} psutil address {}"
                         " cur address {}".format(self.p_macvlan,
                                                  self.mac_addr(self.p_macvlan), self.p_addr))
        return False

    return self.is_up(self.p_macvlan)

  def create_macvlan(self):
    cmd = ""
    if self.is_up(self.p_macvlan):
      cmd += "ip link set {macvlan} down".format(macvlan=self.p_macvlan)

    if self.is_exist(self.p_macvlan):
      if len(cmd) != 0:
        cmd += " && "
      cmd += "ip link del {macvlan}".format(macvlan=self.p_macvlan)

    if len(cmd) != 0:
      cmd += " && "
    cmd += ("ip link add link {vlan_name} name {macvlan} type macvlan"
            " && ip link set {macvlan} address {address}"
            " && ip link set dev {macvlan} up".format(vlan_name=self.vlan.vlan_name,
                                                      macvlan=self.p_macvlan,
                                                      address=self.p_addr))
    self.run_shell(cmd)

  def down_macvlan(self):
    cmd = "ip link set {macvlan} down && ip link del {macvlan}".format(macvlan=self.p_macvlan)
    self.run_shell(cmd)

  def check_ppp_interface(self):
    ifcfgs = psutil.net_if_addrs()
    if self.p_ppp_name not in ifcfgs:
      log.logger.error("ppp interface {} not in psutil dectect".format(self.p_ppp_name))
      return False
    return True

  def create_ppp_interface(self):
    # kill exist pppoe proccess
    cmd = "ps -ef |grep {} |grep -v grep  |awk '{{print $2}}' |xargs kill -9".format(self.p_ppp_name)
    self.run_shell(cmd)

    cmd = "{} {}".format(self._pppoe_connect, self.config.file_name)
    self.run_shell(cmd, "async")

    # router wait pppoe up to config
    return True

  def down_ppp_interface(self):
    # kill exist pppoe proccess
    cmd = "ps -ef |grep {} |grep -v grep  |awk '{{print $2}}' |xargs kill -9".format(self.p_ppp_name)
    self.run_shell(cmd)

  def create_route(self):
    if self.check_ppp_interface():
      ip = self.ip_addr(self.p_ppp_name)
      if not ip:
        log.logger.error("load {} ip addr failed".format(self.p_ppp_name))
        return None
      router = RouteTable(self.p_ppp_name, ip, self.p_id, "tb{}".format(self.p_id))
      return router
    return None

  def check_route(self):
    route = self.create_route()
    if route:
      route.check()

  def dial(self):
    """PPPoe dial
    """
    # create vlan
    if not self.vlan.create():
      return False

    # dump config
    if not self.check_config():
      self.dump_config()

    # create macvlan
    if not self.check_macvlan():
      self.create_macvlan()

    # pppoe-connect
    if not self.check_ppp_interface():
      self.create_ppp_interface()

    return True

  def down(self):
    self.vlan.down()
    self.down_config()
    self.down_macvlan()
    self.down_ppp_interface()
    route = self.create_route()
    if route:
      route.down()

  def check(self):
    self.check_route()
    return self.dial()

class PPPoEManager():
  """manager pppoe dial
  """
  _params = ["ppp_id", "ppp_user", "ppp_passwd",
        "ppp_addr", "ppp_vlan_id", "ppp_vlan_addr", "ppp_vlan_parent"]
  def __init__(self, config_path="./conf/ppp_configs", check_interval=10):
    self.pppoes = {}
    self.configs = {}
    self.config_path = config_path
    self.check_interval = check_interval
    self.last_time = time.time()

  def check_params(self, config):
    """create pppoe by config
    :param config is json
           {
              "ppp_id":
              "ppp_user"
              "ppp_passwd"
              "ppp_addr":
              "ppp_vlan_id":
              "ppp_vlan_parent":
              "ppp_vlan_addr":
           }
    """
    for param in self._params:
      if param not in config:
        return False

    return True

  def gen_keys(self, config):
    key = ""
    for param in self._params:
      key += "{}".format(config[param])
    return key

  def is_exist(self, config):
    key = self.gen_keys(config)
    if not key:
      return False

    ppp_id = config.get("ppp_id")
    if ppp_id in self.configs and self.configs[ppp_id] == key:
      return True
    return False

  def add_pppoe(self, config):
    log.logger.info(config)
    if not self.check_params(config):
      return None

    if self.is_exist(config):
      return None

    ppp_id = config.get("ppp_id")
    self.configs[ppp_id] = self.gen_keys(config)

    if ppp_id in self.pppoes:
      log.logger.info("ppp{} has exist. so down it".format(ppp_id))
      self.pppoes[ppp_id].down()

    pppoe = PPPoE(config.get("ppp_id"), config.get("ppp_user"),
                  config.get("ppp_passwd"), config.get("ppp_addr"),
                  config.get("ppp_vlan_id"), config.get("ppp_vlan_addr"),
                  config.get("ppp_vlan_parent"))
    self.pppoes[ppp_id] = pppoe
    return True

  def load_config(self):
    configs = AgentConfigObj(self.config_path)
    for section, config in configs.items():
      self.add_pppoe(config)

  def on_timer(self):
    now = time.time()
    if now < self.last_time + self.check_interval:
      return None

    log.logger.info("on_timer to check pppoe")
    self.load_config()
    for ppp_id, pppoe in self.pppoes.items():
      log.logger.info("check ppp {}".format(ppp_id))
      pppoe.check()

    self.last_time = now

if __name__ == "__main__":
  #obj = PPPoE(100, "1234567", "123456", "52:54:00:3c:45:01" , 102, "52:54:00:3c:44:f9", "eth1")
  #print(obj.check())
  obj = PPPoEManager()
  while True:
    obj.on_timer()
    time.sleep(1)
  #obj = Interface()
  #print(obj.mac_addr("em1.101"))
