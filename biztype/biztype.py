#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2021 , Inc

import time

from .tx_p2p import TxP2p

class BizType(object):
    def __init__(self, u_id, ppp_config, env_config):
        self.__u_id = u_id
        self.__ppp_config_path = ppp_config
        self.__env_config_path = env_config
        self.__tx_p2p = TxP2p(self.__u_id, self.__ppp_config_path, self.__env_config_path)

    def on_timer(self):
        """all biz app install and run
        """
        self.__tx_p2p.on_timer()

if __name__ == "__main__":
    obj = BizType()
    while True:
        print(obj.on_timer())
        time.sleep(1)
