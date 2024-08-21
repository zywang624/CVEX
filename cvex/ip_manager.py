import logging
import os
import re
import sys

from cvex.consts import *
from cvex.logger import get_logger


class IPManager:
    log: logging.Logger
    ips: dict

    def __init__(self):
        self.log = get_logger("IPManager")
        self.ips = {}
        destination = os.path.expanduser(ROUTER_DESTINATION)
        ip = self.read_private_ip(destination)
        if ip:
            self.log.debug("Loaded IP for %s: %s", destination, ip)
            self.ips[destination] = ip
        root = os.path.expanduser(CVEX_ROOT)
        for image in os.scandir(root):
            if not image.is_dir() or image.name == ROUTER_VM:
                continue
            image = os.path.join(root, image.name)
            for version in os.scandir(image):
                if not version.is_dir():
                    continue
                version = os.path.join(image, version.name)
                for instance in os.scandir(version):
                    if not instance.is_dir():
                        continue
                    destination = os.path.join(version, instance.name)
                    ip = self.read_private_ip(destination)
                    if ip:
                        self.log.debug("Loaded IP for %s: %s", destination, ip)
                        self.ips[destination] = ip

    def generate_new_ip(self, destination: str) -> str:
        for c in range(1, 255):
            ip = f"192.168.56.{c}"
            if ip in self.ips.values():
                continue
            self.log.debug("Generated new IP for %s: %s", destination, ip)
            self.ips[destination] = ip
            return ip
        self.log.error("Failed to generate new IP for %s; address space exceeded", destination)
        sys.exit(1)

    def read_private_ip(self, destination: str) -> str | None:
        vagrantfile = f"{destination}/Vagrantfile"
        if not os.path.exists(vagrantfile):
            return None
        with open(vagrantfile, "r") as f:
            data = f.read()
        ip = re.search(r'config\.vm\.network "private_network", ip: "(192\.168\.56\.\d+)"', data)
        if not ip:
            return None
        return ip.group(1)

    def write_private_ip(self, destination: str, image: str, ip: str):
        vagrantfile = os.path.join(destination, "Vagrantfile")
        if not os.path.exists(vagrantfile):
            return
        with open(vagrantfile, "r") as f:
            data = f.read()
        config = f"  config.vm.box = \"{image}\""
        pos = data.find(config)
        if pos == -1:
            return
        with open(vagrantfile, "w") as f:
            f.write(data[:pos + len(config)])
            f.write((f"\n"
                     f"  config.vm.network \"private_network\", ip: \"{ip}\"\n"
                     f"\n"
                     ))
            f.write(data[pos + len(config):])
