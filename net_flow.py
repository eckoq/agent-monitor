#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2020 , Inc

import psutil, time
import urllib

import log

class NetFlow(object):
  def __init__(self, uuid, interval=60):
    self.recv = {}
    self.sent = {}
    self.interval = interval
    self.uuid = uuid
    self.last_time = time.time()

  def flow(self):
    recv = {}
    sent = {}
    for ifname in psutil.net_io_counters(pernic=True).keys():
      recv.setdefault(ifname, psutil.net_io_counters(pernic=True).get(ifname).bytes_recv)
      sent.setdefault(ifname, psutil.net_io_counters(pernic=True).get(ifname).bytes_sent)
    self.last_time = time.time()
    return recv, sent

  def report(self, payload):
    #urllib.request.urlopen()
    log.logger.info("report need to dev")

  def on_timer(self):
    now = time.time()
    if now < self.last_time +  self.interval:
      return None

    payload = {
        "uuid": self.uuid,
        "date": time.strftime("%Y-%m-%d", time.localtime(now)),
        "time": time.strftime("%H:%M", time.localtime(now)),
        }

    recv, sent = self.flow()

    netflow = {}
    # down
    for ifname, recv_bytes in recv.items():
      if ifname in self.recv:
        delta =  recv_bytes - self.recv[ifname]
        if delta <= 0:
          delta = 0

        if ifname not in netflow:
          netflow[ifname] = {}
        netflow[ifname]["down"] = round(delta * 8 / self.interval / 1000, 2)
        log.logger.info("{} last_recv {} now_recv {} down {} kb/s".format(ifname, self.recv[ifname],
          recv_bytes, netflow[ifname]["down"]))

    #  up
    for ifname, sent_bytes in sent.items():
      if ifname in self.sent:
        delta =  sent_bytes - self.sent[ifname]
        if delta <= 0:
          delta = 0

        if ifname not in netflow:
          netflow[ifname] = {}
        netflow[ifname]["up"] = round(delta * 8 / self.interval / 1000 , 2)
        log.logger.info("{} last_sent {} now_sent {} up {} kb/s".format(ifname, self.sent[ifname],
          sent_bytes, netflow[ifname]["up"]))

    payload["netflow"] = netflow
    self.recv = recv
    self.sent = sent
    log.logger.info(payload)
    self.report(payload)

if __name__ == "__main__":
  obj = NetFlow("hello")
  while True:
    obj.on_timer()
    time.sleep(1)


