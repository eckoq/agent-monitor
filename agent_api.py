#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2020 , Inc

from configobj import ConfigObj
import log
from http_sync import HttpRequests

def load_ppp_config(u_id, config_path):
  url = "http://132.232.94.178/api/gold-digger/agent/load_config"
  response = HttpRequests.get(url, "uuid={}".format(u_id))
  log.logger.info(response)
  if response['code'] != 0 or response["api_response"]["code"] != 0:
    return None

  result  = response["api_response"]['result']
  if (type(result) is not dict
      or 'configs' not in result
      or type(result['configs']) is not list):
    return None

  if len(result['configs']) == 0:
    return None

  config_file = ConfigObj(config_path)
  for config in result["configs"]:
    if 'ppp_id' in config:
      config_file[str(config['ppp_id'])] = config

  config_file.write()

def load_version(u_id):
  """ request for version update
  result {
    'image_url' :
    'image_id' :
    'image_md5' :
    'flag': 0 check image_id with local , 1 force install
  }
  """

  url = "http://132.232.94.178/api/gold-digger/agent/load_version"
  response = HttpRequests.get(url, "uuid={}".format(u_id))
  log.logger.info(response)
  if response['code'] != 0 or response["api_response"]["code"] != 0:
    return None

  result  = response["api_response"]['result']
  if (type(result) is not dict or "image_url" not in result):
    return None

  return result

if __name__ == "__main__":
  #load_ppp_config("9370b917-3639-11eb-8a9e-525400c9700", "./hello")
  print(load_version("asfs"))

