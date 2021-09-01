#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2021 , Inc

"""function to run p2p docker container
"""

import sys, requests, hashlib, time, os
sys.path.append("..")

import log
from pppoe_dial import AgentConfigObj
from pppoe_dial import ShellCmd
from agent_api import load_version

class TxP2p(ShellCmd):
    def __init__(self, u_id, ppp_config, env_config):
        self.__u_id = u_id
        self.__ppp_config_path = ppp_config
        self.__env_config_path = env_config
        self.__image_url = None
        self.__image_md5 = None
        self.__store_file_name = "tx_p2p_image.tgz"
        self.__nics = []
        self.__macs = []
        self.__storage_ssd = {}
        self.__storage_hdd = {}
        self.__provider = None
        self.__threads = None
        self.__image_name = None
        self.__image_id = None
        self.__container_name = "tx_p2p"
        self.__last_time = time.time()
        self.__check_interval = 60
        self.__recover_image_local()

    def __load_image_id(self):
        try:
            repo = self.__image_name.strip().split(":")[0]
            tag = self.__image_name.strip().split(":")[1]
            cmd = "docker image ls |grep {} |grep {}| awk '{{print $3}}'".format(repo, tag)
            code, msg = self.run_shell(cmd)
            if code != 0:
                return None
            self.__image_id = msg.strip()
        except Exception as e:
            log.logger.info("load_image_id error. msg:{}".format(msg))

    def __recover_image_local(self):
        cmd = "docker ps -a |grep test |awk '{{print $2}}'"
        code, msg = self.run_shell(cmd)
        if code != 0:
            return None

        if len(msg.strip()) == 0:
            return None

        self.__image_name = msg.strip()
        self.__load_image_id()

    def __download_image(self):
        if self.__image_url is None:
            return False

        try:
            r = requests.get(self.__image_url)
            with open(self.__store_file_name, "wb") as fd:
        	    fd.write(r.content)
            md5hash = hashlib.md5(r.content)
            md5 = md5hash.hexdigest()
            log.logger.info("file_name:{} file_md5:{}".format(self.__store_file_name, md5))
            if md5 != self.__image_md5:
                log.logger.error("md5 is not equal.file_md5:{} target_md5:{}".format(md5,
                    self.__image_md5))
                return False

        except Exception as e:
            log.logger.error("Except {}".format(str(e)))
            return False

        return True

    def init_nic_mac_param(self):
        self.__nics.clear()
        self.__macs.clear()
        configs = AgentConfigObj(self.__ppp_config_path)
        for section, config in configs.items():
            self.__nics.append("ppp{}".format(config["ppp_id"]))
            self.__macs.append(config["ppp_addr"])

    def init_env_param(self):
        self.__storage_ssd.clear()
        self.__storage_hdd.clear()
        configs = AgentConfigObj(self.__env_config_path)
        for section, config in configs.items():
            if section == "ssd":
                for disk_src_dir, disk_dst_dir in config.items():
                    self.__storage_ssd[disk_src_dir] = disk_dst_dir
            elif section == "hdd":
                for disk_src_dir, disk_dst_dir in config.items():
                    self.__storage_hdd[disk_src_dir] = disk_dst_dir
            elif section == "user":
                if "provider" in config:
                    self.__provider = config["provider"]
            elif section == "cpu":
                if "threads" in config:
                    self.__threads = config["threads"]

    def __load_storage_cmd(self):
        cmd = ""
        for src_dir, dst_dir in self.__storage_ssd.items():
            cmd += " -v {}:{} ".format(src_dir, dst_dir)

        for src_dir, dst_dir in self.__storage_hdd.items():
            cmd += " -v {}:{} ".format(src_dir, dst_dir)
        return cmd

    def __load_diskparams_env(self):
        env = ""
        for src_dir, dst_dir in self.__storage_ssd.items():
            env += "{}:ssd;".format(src_dir)

        for src_dir, dst_dir in self.__storage_hdd.items():
            env += "{}:hdd;".format(src_dir)
        return env

    def load_image(self):
        if not self.__download_image():
            return

        cmd = "docker load < {}".format(self.__store_file_name)
        code, msg = self.run_shell(cmd)
        if code != 0:
            log.logger.error("load image failed. code {} msg {}".format(code, msg))
            return
        for line in msg.strip().split('\n'):
            if line.find("Loaded image: ") >= 0:
                self.__image_name = line.replace("Loaded image: ", "")
                os.remove(self.__store_file_name)
            else:
                log.logger.error("load unkown image name")

    def uninstall(self):
        cmd = "docker stop {} && docker rm {} && docker image rm {}".format(
                self.__container_name, self.__container_name, self.__image_id)
        code, msg = self.run_shell(cmd)
        if code != 0:
            log.logger.error("uninstall fail. msg {}".format(msg))

    def install(self):
        self.init_nic_mac_param()
        self.init_env_param()
        log.logger.info("nics {} macs {} ssd {} hdd {} provider {} threads {}".format(self.__nics, self.__macs,
            self.__storage_ssd, self.__storage_hdd, self.__provider, self.__threads))

        self.load_image()

        cmd = "docker run -d -it {} --network host --privileged ".format(self.__load_storage_cmd())
        cmd += " -e MAC={} ".format(",".join(self.__macs))
        cmd += " -e NIC={} ".format(",".join(self.__nics))
        cmd += " -e PROVIDERID={} ".format(self.__provider)
        cmd += " -e THREADS={} ".format(self.__threads)
        cmd += " -e DISKPARAMS=\"{}\" ".format(self.__load_diskparams_env())
        cmd += " --name {} ".format(self.__container_name)
        cmd += " {} ".format(self.__image_name)
        code, msg = self.run_shell(cmd)
        log.logger.info("cmd {} code {} msg {}".format(cmd, code, msg))

    def check(self):
        result = load_version(self.__u_id)
        if result is None:
            return None
        if result["flag"] == 0 and self.__image_id == result["image_id"]:
            log.logger.error("check not to install. flag {} local_image_id {} remote_image_id {}".format(
                result["flag"], self.__image_id, result["image_id"]))
            return None

        if (self.__image_id is not None and self.__image_name is not None):
            self.uninstall()

        self.__image_url = result["image_url"]
        self.__image_md5 = result["image_md5"]
        self.install()

    def on_timer(self):
        now = time.time()
        if now < self.__last_time + self.__check_interval:
            return None

        log.logger.info("tx_p2p start check...")
        self.check()
        log.logger.info("tx_p2p end check...")

        self.__last_time = now

if __name__ == "__main__":
    obj = TxP2p()
    #print(obj.download())
    #obj.init_nic_mac_param()
    obj.check()
