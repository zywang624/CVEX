import argparse
import logging
import os
import shutil
import sys

import yaml

from cvex.consts import *
from cvex.exploit import Exploit
from cvex.logger import get_logger, set_log_level
from cvex.vm import VM


def verify_infrastructure_config(config: dict, config_dir: str) -> dict | None:
    if 'cve' not in config:
        return None
    if 'ports' in config:
        if type(config['ports']) != int and type(config['ports']) != list:
            return None
        if type(config['ports']) == list:
            for port in config['ports']:
                if type(port) != int:
                    return None
    if 'vms' not in config or not config['vms']:
        return None
    if ROUTER_VM in config['vms']:
        return None
    for vm_name, data in config['vms'].items():
        if 'image' not in data or 'version' not in data:
            return None
        if 'type' not in data or data['type'] not in ["linux", "windows"]:
            return None
        if 'playbook' in data:
            playbook = os.path.join(config_dir, data['playbook'])
            if not os.path.exists(playbook):
                return None
            config['vms'][vm_name]['playbook'] = playbook
    if 'exploit' not in config or 'vm' not in config['exploit'] or 'command' not in config['exploit']:
        return None
    if config['exploit']['vm'] not in config['vms']:
        return None
    return config


def main():
    parser = argparse.ArgumentParser(
        prog="cvex",
        description="",
    )
    parser.add_argument("-c", "--config", help="Directory with the configuration of the infrastructure")
    parser.add_argument("-o", "--output", help="Directory for generated logs", default="out")
    parser.add_argument("-l", "--list", help="List all cached VMs", default=False, action="store_true")
    parser.add_argument("-d", "--destroy", help="Destroy cached VMs (destroy all if empty)")
    parser.add_argument("-v", "--verbose", help="Verbose logs", default=False, action="store_true")
    args = parser.parse_args()

    if args.verbose:
        set_log_level(logging.DEBUG)
    log = get_logger("main")

    CVEX_ROOT.mkdir(exist_ok=True)

    if args.list or args.destroy != None:
        images = [f.name for f in os.scandir(os.path.expanduser(CVEX_ROOT)) if f.is_dir()]
        if not images:
            log.info("There are no cached VMs")
            sys.exit(0)
        if args.list:
            log.info("Cached VMs:")
        if ROUTER_VM in images:
            if args.list:
                log.info("%s", ROUTER_VM)
            if args.destroy == "" or args.destroy == ROUTER_VM:
                vm = VM([],
                        ROUTER_VM,
                        ROUTER_CONFIG,
                        cve=ROUTER_VM,
                        destination=os.path.expanduser(ROUTER_DESTINATION))
                vm.destroy()
        for image in images:
            if image != ROUTER_VM:
                versions = [f.name for f in os.scandir(os.path.join(os.path.expanduser(CVEX_ROOT), image)) if
                            f.is_dir()]
                for version in versions:
                    if args.list:
                        log.info("%s/%s", image, version)
                    if args.destroy == "" or args.destroy == f"{image}/{version}":
                        config = {
                            "image": image.replace("_", "/"),
                            "version": version,
                            "type": "unknown"
                        }
                        vm = VM("unknown", config)
                        vm.destroy()
        try:
            shutil.rmtree(CVEX_ROOT)
        except:
            pass
        sys.exit(0)

    output_dir = Path(args.output)
    if not output_dir.exists():
        output_dir.mkdir()
    elif not output_dir.is_dir():
        log.critical("%s is not a directory", output_dir)
        sys.exit(1)

    infrastructure_file = Path(args.config, INFRASTRUCTURE_FILE)
    if not infrastructure_file.exists():
        parser.print_help()
        sys.exit(1)

    with open(infrastructure_file, "r") as f:
        infrastructure = yaml.safe_load(f)

    infrastructure = verify_infrastructure_config(infrastructure, args.config)
    if not infrastructure:
        log.critical("Configuration mismatch")
        sys.exit(1)

    vms = []

    if len(infrastructure['vms']) > 1:
        vm = VM([],
                ROUTER_VM,
                ROUTER_CONFIG,
                cve=ROUTER_VM,
                destination=os.path.abspath(os.path.expanduser(ROUTER_DESTINATION)))
        vm.run_vm()
        vms.append(vm)
    for vm_name, config in infrastructure['vms'].items():
        vm = VM(vms, vm_name, config, cve=infrastructure['cve'])
        vm.run_vm()
        vms.append(vm)

    for vm in vms:
        if vm.vm_name != ROUTER_VM:
            vm.update_hosts(vms)

    if 'ports' in infrastructure:
        if type(infrastructure['ports']) == list:
            ports = infrastructure['ports']
        else:
            ports = [infrastructure['ports']]
    else:
        ports = [DEFAULT_MITMDUM_PORT]

    exploit = Exploit(vms, ports)
    exploit.run(infrastructure['exploit']['vm'], infrastructure['exploit']['command'], args.output)

    # for vm in vms:
    #    vm.stop()

    sys.exit(0)


if __name__ == "__main__":
    main()
