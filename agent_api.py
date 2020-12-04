#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2020 , Inc

from configobj import ConfigObj
import requests
import log

class HttpRequests(object):
  @staticmethod
  def get(url, params=None, headers=None, timeout=120, error_key=None):
    try:
      response = requests.get(url=url, params=params, headers=headers, timeout=120)
      status_code = response.status_code
      response_json = response.json()
      if status_code == 0:
        return HttpResponse.third_party(ERR_OK.code, ERR_OK.message, None, None, response_json)
      else:
        return {"code": 0, "msg":"", "api_response": response_json}
    except requests.exceptions.ConnectTimeout:
      return {"code": -1000, "msg": "connect timeout"}
    except requests.exceptions.ConnectionError:
      return {"code": -1001, "msg":"connect error"}
    except HTTPException as error_msg:
      return {"code": -1002, "msg": str(error_msg)}

  @staticmethod
  def post(url, params=None, headers=None, timeout=60, error_key=None):
    try:
      response = requests.post(url=url, params=params, headers=headers, timeout=60)
      status_code = response.status_code
      response_json = response.json()
      if status_code == 0:
          return {"code": 0, "msg":"", "api_response": response_json}
      else:
          return {
              "code": 0,
              "msg": "",
              "api_response": response_json
          }
    except requests.exceptions.ConnectTimeout:
      return {"code": 0, "msg":"", "api_response": response_json}
    except requests.exceptions.ConnectionError:
      return {"code": -1001, "msg":"connect error"}
    except HTTPException as error_msg:
      return {"code": -1002, "msg": str(error_msg)}

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

  config_file = ConfigObj(config_path)
  for config in result["configs"]:
    if 'ppp_id' in config:
      config_file[str(config['ppp_id'])] = config

  config_file.write()

if __name__ == "__main__":
  load_ppp_config("9370b917-3639-11eb-8a9e-525400c970", "./hello")

