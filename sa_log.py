#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2021 , Inc

import sys
import json
from datetime import datetime
from optparse import OptionParser

from http_sync import HttpRequests

__url = "http://132.232.94.178/api/gold-digger/agent/report_net_flow"

def report(uuid, sa_date, sa_path):
  with open(sa_path, "r") as f:
    for line in f:
      items = line.strip().split()
      try:
        times = datetime.strptime(_date + " " + items[0] + " " + items[1], "%Y-%m-%d %I:%M:%S %p")
        up = float(items[6])

        payload = {
            "uuid": uuid,
            "date": times.strftime("%Y-%m-%d"),
            "time": times.strftime("%H:%M"),
            }
        net_flow = {}
        net_flow["em1"] = {}
        net_flow["em1"]["down"] = 0
        net_flow["em1"]["up"] = up * 8

        payload["netflow"] = net_flow
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        response = HttpRequests.post(__url, json.dumps(payload), headers)
      except Exception as e:
        print(str(e))
        pass

if __name__ == "__main__":
  parser = OptionParser()
  parser.add_option("-u", dest="u_id", help="uuid")
  parser.add_option("-d", dest="date", help="sa log file")
  parser.add_option("-f", dest="file_path", help="sa log file")
  (options, args)  =  parser.parse_args()

  _u_id = None
  _file_path = None
  _date = None
  if options.u_id:
    _u_id = options.u_id

  if options.file_path:
    _file_path = options.file_path

  if options.date:
    _date = options.date

  if _u_id and _file_path and _date:
    report(_u_id, _date, _file_path)
  else:
    print("sa-log: invalid option '-u {}' '-f {}' '-d {}'".format(_u_id, _file_path, _date))
