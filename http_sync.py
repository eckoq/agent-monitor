#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2020 , Inc

import requests

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
    except Exception as error_msg:
      return {"code": -1002, "msg": str(error_msg)}

  @staticmethod
  def post(url, params=None, headers=None, timeout=60, error_key=None):
    response_json = ""
    try:
      response = requests.post(url=url, data=params, headers=headers, timeout=60)
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
    except Exception as error_msg:
      return {"code": -1002, "msg": str(error_msg)}

